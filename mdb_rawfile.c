/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Raw File Target
 *
 * The raw file target is invoked whenever a file of unrecognizable type is
 * specified on the command line, or when raw file examination is forced using
 * the -f option.  If one file is specified, that file will be opened as the
 * "object" file.  If two files are specified, the second one will be opened
 * as the "core" file.  Each file is opened using the fdio backend, which
 * internally supports both byte-oriented i/o and block-oriented i/o as needed.
 */

#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>
#include <mdb/mdb_kvm.h>
#include <mdb/mdb_ctf.h>

#include <string.h>

#include <sys/dtrace.h>
#include <fcntl.h>

/* these are taken straight from mdb_kvm.c, except the names are KT_... */
#define	RF_RELOC_BUF(buf, obase, nbase) \
	((uintptr_t)(buf) - (uintptr_t)(obase) + (uintptr_t)(nbase))

#define	RF_BAD_BUF(buf, base, size) \
	((uintptr_t)(buf) < (uintptr_t)(base) || \
	((uintptr_t)(buf) >= (uintptr_t)(base) + (uintptr_t)(size)))

/*
 * the following struct rf_module is straight from kt_module in mdb/mdb_kvm.h
 * it is here to support loading of ctf info so that ::print type works
 * with raw disks.  in mdb_kvm.h it is a kt_module.  If that changes, this
 * will also need to change. (ugh).
 */
typedef struct rf_module {
	mdb_list_t km_list;		/* List forward/back pointers */
	char *km_name;			/* Module name */
	void *km_data;			/* Data buffer (module->symspace) */
	size_t km_datasz;		/* Size of km_data in bytes */
	void *km_symbuf;		/* Base of symbol table in km_data */
	char *km_strtab;		/* Base of string table in km_data */
	mdb_gelf_symtab_t *km_symtab;	/* Symbol table for module */
	uintptr_t km_symspace_va;	/* Kernel VA of krtld symspace */
	uintptr_t km_symtab_va;		/* Kernel VA of krtld symtab */
	uintptr_t km_strtab_va;		/* Kernel VA of krtld strtab */
	Shdr km_symtab_hdr;		/* Native .symtab section header */
	Shdr km_strtab_hdr;		/* Native .strtab section header */
	uintptr_t km_text_va;		/* Kernel VA of start of module text */
	size_t km_text_size;		/* Size of module text */
	uintptr_t km_data_va;		/* Kernel VA of start of module data */
	size_t km_data_size;		/* Size of module data */
	uintptr_t km_bss_va;		/* Kernel VA of start of module BSS */
	size_t km_bss_size;		/* Size of module BSS */
	uintptr_t km_ctf_va;		/* Kernel VA of CTF data */
	size_t km_ctf_size;		/* Size of CTF data */
	void *km_ctf_buf;		/* CTF data for this module */
	ctf_file_t *km_ctfp;		/* CTF container for this module */
} rf_module_t;

/* the following 2 const chars are also from mdb_kvm.c */
static const char KT_MODULE[] = "/usr/lib/mdb/kvm/amd64/mdb_ks.so";
static const char KT_CTFPARENT[] = "genunix";

/*
 * In the original mdb_rawfile.c, the following two functions did not exist.
 * They are used in the mdb_tgt_ops_t definition.  I have not tested rf_addr_to_ctf(),
 * and doubt it works.  But rf_name_to_ctf is the one I use, and it works fine...
 */
struct ctf_file *rf_addr_to_ctf(mdb_tgt_t *, uintptr_t);
struct ctf_file *rf_name_to_ctf(mdb_tgt_t *, const char *);

typedef struct rf_data {
	mdb_io_t *r_object_fio;
	mdb_io_t *r_core_fio;
	mdb_list_t r_modlist;  /* from kvm */
	mdb_tgt_t *r_kt;	/* a "shadow" target for kernel CTF info */
} rf_data_t;

#define	RF_OBJECT(p)	(((rf_data_t *)(p))->r_object_fio)
#define	RF_CORE(p)	(((rf_data_t *)(p))->r_core_fio)

/*
 * rf_module_by_name is a modified version of kt_module_by_name.  It gets
 * the "shadow" kt_data_t from the rf_data_t and iterates through kernel
 * modules looking for a match on name
 */
static rf_module_t *
rf_module_by_name(rf_data_t *rf, const char *name)
{
	rf_module_t *km;
	kt_data_t *kt = rf->r_kt->t_data;

	for (km = mdb_list_next(&kt->k_modlist); km; km = mdb_list_next(km)) {
		if (strcmp(name, km->km_name) == 0)
			return (km);
	}

	return (NULL);
}

/*
 * rf_load_module is identical to kt_load_module.  It's here because
 * kt_load_module is declared static in mdb_kvm.c  If kt_load_module changes,
 * this needs to change as well.
 */
static void
rf_load_module(kt_data_t *kt, mdb_tgt_t *t, rf_module_t *km)
{
	km->km_data = mdb_alloc(km->km_datasz, UM_SLEEP);

	(void) mdb_tgt_vread(t, km->km_data, km->km_datasz, km->km_symspace_va);

	km->km_symbuf = (void *)
	    RF_RELOC_BUF(km->km_symtab_va, km->km_symspace_va, km->km_data);

	km->km_strtab = (char *)
	    RF_RELOC_BUF(km->km_strtab_va, km->km_symspace_va, km->km_data);

	km->km_symtab = mdb_gelf_symtab_create_raw(&kt->k_file->gf_ehdr,
	    &km->km_symtab_hdr, km->km_symbuf,
	    &km->km_strtab_hdr, km->km_strtab, MDB_TGT_SYMTAB);
}

/*
 * Again, from kt_load_modules in mdb_kvm.c.  The main difference is that
 * the kt_data_t (first arg to kt_load_modules) is accessed indirectly from
 * rf_data_t.
 */
static void
rf_load_modules(rf_data_t *rf, mdb_tgt_t *t)
{
	char name[MAXNAMELEN];
	uintptr_t addr, head;

	struct module kmod;
	struct modctl ctl;
	Shdr symhdr, strhdr;
	GElf_Sym sym;

	kt_module_t *km;

	if (mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "modules", &sym, NULL) == -1) {
		warn("failed to get 'modules' symbol");
		return;
	}

	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &ctl, sizeof (ctl),
	    MDB_TGT_OBJ_EXEC, "modules") != sizeof (ctl)) {
		warn("failed to read 'modules' struct");
		return;
	}

	addr = head = (uintptr_t)sym.st_value;

	do {
		if (addr == NULL)
			break; /* Avoid spurious NULL pointers in list */

		if (mdb_tgt_vread(t, &ctl, sizeof (ctl), addr) == -1) {
			warn("failed to read modctl at %p", (void *)addr);
			return;
		}

		if (ctl.mod_mp == NULL)
			continue; /* No associated krtld structure */

		if (mdb_tgt_readstr(t, MDB_TGT_AS_VIRT, name, MAXNAMELEN,
		    (uintptr_t)ctl.mod_modname) <= 0) {
			warn("failed to read module name at %p",
			    (void *)ctl.mod_modname);
			continue;
		}

		/*
		 * indirect through rf_data_t to get k_modules
		 */
		if (mdb_nv_lookup(&((kt_data_t *)(rf->r_kt->t_data))->k_modules, name) != NULL) {
			warn("skipping duplicate module '%s', id=%d\n",
			    name, ctl.mod_id);
			continue;
		}

		if (mdb_tgt_vread(t, &kmod, sizeof (kmod),
		    (uintptr_t)ctl.mod_mp) == -1) {
			warn("failed to read module at %p\n",
			    (void *)ctl.mod_mp);
			continue;
		}

		if (kmod.symspace == NULL || kmod.symhdr == NULL ||
		    kmod.strhdr == NULL) {
			/*
			 * If no buffer for the symbols has been allocated,
			 * or the shdrs for .symtab and .strtab are missing,
			 * then we're out of luck.
			 */
			continue;
		}

		if (mdb_tgt_vread(t, &symhdr, sizeof (Shdr),
		    (uintptr_t)kmod.symhdr) == -1) {
			warn("failed to read .symtab header for '%s', id=%d",
			    name, ctl.mod_id);
			continue;
		}

		if (mdb_tgt_vread(t, &strhdr, sizeof (Shdr),
		    (uintptr_t)kmod.strhdr) == -1) {
			warn("failed to read .strtab header for '%s', id=%d",
			    name, ctl.mod_id);
			continue;
		}

		/*
		 * Now get clever: f(*^ing krtld didn't used to bother updating
		 * its own kmod.symsize value.  We know that prior to this bug
		 * being fixed, symspace was a contiguous buffer containing
		 * .symtab, .strtab, and the symbol hash table in that order.
		 * So if symsize is zero, recompute it as the size of .symtab
		 * plus the size of .strtab.  We don't need to load the hash
		 * table anyway since we re-hash all the symbols internally.
		 */
		if (kmod.symsize == 0)
			kmod.symsize = symhdr.sh_size + strhdr.sh_size;

		/*
		 * Similar logic can be used to make educated guesses
		 * at the values of kmod.symtbl and kmod.strings.
		 */
		if (kmod.symtbl == NULL)
			kmod.symtbl = kmod.symspace;
		if (kmod.strings == NULL)
			kmod.strings = kmod.symspace + symhdr.sh_size;

		/*
		 * Make sure things seem reasonable before we proceed
		 * to actually read and decipher the symspace.
		 */
		if (RF_BAD_BUF(kmod.symtbl, kmod.symspace, kmod.symsize) ||
		    RF_BAD_BUF(kmod.strings, kmod.symspace, kmod.symsize)) {
			warn("skipping module '%s', id=%d (corrupt symspace)\n",
			    name, ctl.mod_id);
			continue;
		}

		km = mdb_zalloc(sizeof (rf_module_t), UM_SLEEP);
		km->km_name = strdup(name);

		/* again, indirect through rf_data_t to get k_modules */
		(void) mdb_nv_insert(&((kt_data_t *)(rf->r_kt->t_data))->k_modules, km->km_name, NULL,
		    (uintptr_t)km, MDB_NV_EXTNAME);

		km->km_datasz = kmod.symsize;
		km->km_symspace_va = (uintptr_t)kmod.symspace;
		km->km_symtab_va = (uintptr_t)kmod.symtbl;
		km->km_strtab_va = (uintptr_t)kmod.strings;
		km->km_symtab_hdr = symhdr;
		km->km_strtab_hdr = strhdr;
		km->km_text_va = (uintptr_t)kmod.text;
		km->km_text_size = kmod.text_size;
		km->km_data_va = (uintptr_t)kmod.data;
		km->km_data_size = kmod.data_size;
		km->km_bss_va = (uintptr_t)kmod.bss;
		km->km_bss_size = kmod.bss_size;

		/* and again, indirect ... */
		if (((kt_data_t *)(rf->r_kt->t_data))->k_ctfvalid) {
			km->km_ctf_va = (uintptr_t)kmod.ctfdata;
			km->km_ctf_size = kmod.ctfsize;
		}

		/*
		 * Add the module to the end of the list of modules in load-
		 * dependency order.  This is needed to load the corresponding
		 * debugger modules in the same order for layering purposes.
		 */
		mdb_list_append(&((kt_data_t *)(rf->r_kt->t_data))->k_modlist, km);

		if (t->t_flags & MDB_TGT_F_PRELOAD) {
			mdb_iob_printf(mdb.m_out, " %s", name);
			mdb_iob_flush(mdb.m_out);
			rf_load_module((kt_data_t *)(rf->r_kt->t_data), rf->r_kt, (rf_module_t *)km);
		}

	} while ((addr = (uintptr_t)ctl.mod_next) != head);
}
/*
 * rf_load_ctfdata comes from kt_load_ctfdata.  It uses the kt_data_t hanging off
 * of rf_data_t, and calls rf_... routines instead of kt_... routines.
 */
ctf_file_t *
rf_load_ctfdata(mdb_tgt_t *t, rf_module_t *km)
{
	rf_data_t *rf = t->t_data;
	kt_data_t *kt = rf->r_kt->t_data;
	int err;

	if (km->km_ctfp != NULL)
		return (km->km_ctfp);

	if (km->km_ctf_va == NULL) {
		(void) set_errno(EMDB_NOCTF);
		return (NULL);
	}

	if (km->km_symtab == NULL)
		rf_load_module(kt, rf->r_kt, km);

	if ((km->km_ctf_buf = mdb_alloc(km->km_ctf_size, UM_NOSLEEP)) == NULL) {
		warn("failed to allocate memory to load %s debugging "
		    "information", km->km_name);
		return (NULL);
	}

	/* here, read the kt target, not the rf target... */
	if (mdb_tgt_vread(rf->r_kt, km->km_ctf_buf, km->km_ctf_size,
	    km->km_ctf_va) != km->km_ctf_size) {
		warn("failed to read %lu bytes of debug data for %s at %p",
		    (ulong_t)km->km_ctf_size, km->km_name,
		    (void *)km->km_ctf_va);
		mdb_free(km->km_ctf_buf, km->km_ctf_size);
		km->km_ctf_buf = NULL;
		return (NULL);
	}

	if ((km->km_ctfp = mdb_ctf_bufopen((const void *)km->km_ctf_buf,
	    km->km_ctf_size, km->km_symbuf, &km->km_symtab_hdr,
	    km->km_strtab, &km->km_strtab_hdr, &err)) == NULL) {
		mdb_free(km->km_ctf_buf, km->km_ctf_size);
		km->km_ctf_buf = NULL;
		(void) set_errno(ctf_to_errno(err));
		return (NULL);
	}

	if (ctf_parent_name(km->km_ctfp) != NULL) {
		mdb_var_t *v;

		if ((v = mdb_nv_lookup(&kt->k_modules,
		    ctf_parent_name(km->km_ctfp))) == NULL) {
			warn("failed to load CTF data for %s - parent %s not "
			    "loaded\n", km->km_name,
			    ctf_parent_name(km->km_ctfp));
		}

		if (v != NULL) {
			rf_module_t *pm = mdb_nv_get_cookie(v);

			if (pm->km_ctfp == NULL)
				(void) rf_load_ctfdata(t, pm);

			if (pm->km_ctfp != NULL && ctf_import(km->km_ctfp,
			    pm->km_ctfp) == CTF_ERR) {
				warn("failed to import parent types into "
				    "%s: %s\n", km->km_name,
				    ctf_errmsg(ctf_errno(km->km_ctfp)));
			}
		}
	}

	return (km->km_ctfp);
}

/*
 * this function probably doesn't work.  The idea is, given an address, return (loaded)
 * ctf info for that address.  However, the rawfile does not have ctf info.  The
 * code is straight from kt_addr_to_ctf in mdb_kvm.c.
 */
ctf_file_t *
rf_addr_to_ctf(mdb_tgt_t *t, uintptr_t addr)
{
	rf_data_t *rf = t->t_data;
	rf_module_t *km;

	for (km = mdb_list_next(&rf->r_modlist); km; km = mdb_list_next(km)) {
		if (addr - km->km_text_va < km->km_text_size ||
		    addr - km->km_data_va < km->km_data_size ||
		    addr - km->km_bss_va < km->km_bss_size)
			return ((ctf_file_t *)rf_load_ctfdata(t, km));
	}

	(void) set_errno(EMDB_NOMAP);
	return (NULL);
}

/*
 * this function is called to load ctf data for a given name.
 * it is almost identical to kt_name_to_ctf in mdb_kvm.c
 */
ctf_file_t *
rf_name_to_ctf(mdb_tgt_t *t, const char *name)
{
	rf_data_t *rf = t->t_data;
	rf_module_t *km;

	if (name == MDB_TGT_OBJ_EXEC)
		name = KT_CTFPARENT;
	else if (name == MDB_TGT_OBJ_RTLD)
		name =  ((kt_data_t *)(rf->r_kt->t_data))->k_rtld_name;

	if ((km = rf_module_by_name(rf, name)) != NULL)
		return ((ctf_file_t *)rf_load_ctfdata(t, km));

	(void) set_errno(EMDB_NOOBJ);
	return (NULL);
}

static void
rf_data_destroy(rf_data_t *rf)
{
	if (rf->r_object_fio != NULL)
		mdb_io_destroy(rf->r_object_fio);

	if (rf->r_core_fio != NULL)
		mdb_io_destroy(rf->r_core_fio);

	mdb_free(rf, sizeof (rf_data_t));
}

static int
rf_setflags(mdb_tgt_t *t, int flags)
{
	if ((flags ^ t->t_flags) & MDB_TGT_F_RDWR) {
		uint_t otflags = t->t_flags;
		rf_data_t *orf = t->t_data;
		const char *argv[2];
		int argc = 0;

		if (orf->r_object_fio != NULL)
			argv[argc++] = IOP_NAME(orf->r_object_fio);
		if (orf->r_core_fio != NULL)
			argv[argc++] = IOP_NAME(orf->r_core_fio);

		t->t_flags = (t->t_flags & ~MDB_TGT_F_RDWR) |
		    (flags & MDB_TGT_F_RDWR);

		if (mdb_rawfile_tgt_create(t, argc, argv) == -1) {
			t->t_flags = otflags;
			t->t_data = orf;
			return (-1);
		}

		rf_data_destroy(orf);
	}

	return (0);
}

static void
rf_destroy(mdb_tgt_t *t)
{
	rf_data_destroy(t->t_data);
}

/*ARGSUSED*/
static const char *
rf_name(mdb_tgt_t *t)
{
	return ("raw");
}

static ssize_t
rf_read(mdb_io_t *io, void *buf, size_t nbytes, uint64_t addr)
{
	ssize_t rbytes;

	if (io == NULL)
		return (set_errno(EMDB_NOMAP));

	if (IOP_SEEK(io, addr, SEEK_SET) == -1)
		return (-1); /* errno is set for us */

	if ((rbytes = IOP_READ(io, buf, nbytes)) == 0)
		(void) set_errno(EMDB_EOF);

	return (rbytes);
}

static ssize_t
rf_write(mdb_io_t *io, const void *buf, size_t nbytes, uint64_t addr)
{
	if (io == NULL)
		return (set_errno(EMDB_NOMAP));

	if (IOP_SEEK(io, addr, SEEK_SET) == -1)
		return (-1); /* errno is set for us */

	return (IOP_WRITE(io, buf, nbytes));
}

static ssize_t
rf_aread(mdb_tgt_t *t, mdb_tgt_as_t as, void *buf,
    size_t len, mdb_tgt_addr_t addr)
{
	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
	case (uintptr_t)MDB_TGT_AS_PHYS:
		if (RF_CORE(t->t_data) != NULL)
			return (rf_read(RF_CORE(t->t_data), buf, len, addr));
		/*FALLTHRU*/
	case (uintptr_t)MDB_TGT_AS_FILE:
		return (rf_read(RF_OBJECT(t->t_data), buf, len, addr));
	default:
		return (set_errno(EMDB_NOMAP));
	}
}

static ssize_t
rf_awrite(mdb_tgt_t *t, mdb_tgt_as_t as, const void *buf,
    size_t len, mdb_tgt_addr_t addr)
{
	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
	case (uintptr_t)MDB_TGT_AS_PHYS:
		if (RF_CORE(t->t_data) != NULL)
			return (rf_write(RF_CORE(t->t_data), buf, len, addr));
		/*FALLTHRU*/
	case (uintptr_t)MDB_TGT_AS_FILE:
		return (rf_write(RF_OBJECT(t->t_data), buf, len, addr));
	default:
		return (set_errno(EMDB_NOMAP));
	}
}

static ssize_t
rf_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_read(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_read(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_vwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_write(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_write(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_pread(mdb_tgt_t *t, void *buf, size_t nbytes, physaddr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_read(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_read(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_pwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, physaddr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_write(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_write(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_fread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	return (rf_read(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_fwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (rf_write(RF_OBJECT(t->t_data), buf, nbytes, addr));
}


static int
rf_print_map(mdb_io_t *io, const char *type, int tflags,
    mdb_tgt_map_f *func, void *private)
{
	mdb_map_t map;

	(void) mdb_iob_snprintf(map.map_name, MDB_TGT_MAPSZ,
	    "%s (%s)", IOP_NAME(io), type);

	map.map_base = 0;
	map.map_size = IOP_SEEK(io, 0, SEEK_END);
	map.map_flags = MDB_TGT_MAP_R;

	if (tflags & MDB_TGT_F_RDWR)
		map.map_flags |= MDB_TGT_MAP_W;

	return (func(private, &map, map.map_name));
}

static int
rf_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	rf_data_t *rf = t->t_data;

	if (rf->r_object_fio != NULL && rf_print_map(rf->r_object_fio,
	    "object file", t->t_flags, func, private) != 0)
		return (0);

	if (rf->r_core_fio != NULL && rf_print_map(rf->r_core_fio,
	    "core file", t->t_flags, func, private) != 0)
		return (0);

	return (0);
}

/*ARGSUSED*/
static int
rf_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	bzero(tsp, sizeof (mdb_tgt_status_t));

	if (RF_CORE(t->t_data) != NULL)
		tsp->st_state = MDB_TGT_DEAD;
	else
		tsp->st_state = MDB_TGT_IDLE;

	return (0);
}

/*
 * the following routine loads CTF info.  Currently, only loading of running kernel
 * CTF is supported.  I'll add loading of kernel crash dumps (and user level CTF) later.
 * This code is from kt_activate in mdb_kvm.c.
 * NOTE: this is only tested for 32-bit x86.  
 */

/*ARGSUSED*/
static int
rf_loadctf_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rf_data_t *rf = mdb.m_target->t_data;
	const char *tgt_argv[2];
	int tgt_argc = 2;

	/* add support for ctf, from kt_activate */
	if (mdb_module_load(KT_MODULE, MDB_MOD_GLOBAL) < 0) {
	  warn("failed to load kernel support module -- "
	       "some modules may not load\n");
	}

	bzero(tgt_argv, 2*sizeof(char*));
	tgt_argv[0] = "/dev/ksyms";
	tgt_argv[1] = "/dev/kmem";
	rf->r_kt = mdb_tgt_create(mdb_kvm_tgt_create, mdb.m_tgtflags, 2, tgt_argv);

	rf_load_modules(rf, rf->r_kt);
	((kt_data_t *)(rf->r_kt->t_data))->k_rtld_name = "krtld";

	if (rf_module_by_name(rf, "krtld") == NULL) {
		(void) mdb_module_load("krtld", MDB_MOD_SILENT);
		((kt_data_t *)(rf->r_kt->t_data))->k_rtld_name = "unix";
	}
	((kt_data_t *)(rf->r_kt->t_data))->k_activated = TRUE;
	mdb_tgt_elf_export(((kt_data_t *)(rf->r_kt->t_data))->k_file);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
rf_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rf_data_t *rf = mdb.m_target->t_data;

	if (rf->r_object_fio != NULL) {
		mdb_printf("debugging file '%s' (object file)",
		    IOP_NAME(rf->r_object_fio));

		if (rf->r_core_fio != NULL) {
			mdb_printf(" and file '%s' (core file)",
			    IOP_NAME(rf->r_core_fio));
		}

		mdb_printf("\n");
	} else {
		mdb_printf("debugging empty target\n");
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t rf_dcmds[] = {
	{ "status", NULL, "print summary of current target", rf_status_dcmd },
	{ "loadctf", "[-k]", "loadctf information (currently only current kernel)", rf_loadctf_dcmd },
	{ NULL }
};

static const struct rf_magic {
	const char *rfm_str;
	size_t rfm_len;
	const char *rfm_mod;
} rf_magic[] = {
	{ DOF_MAG_STRING, DOF_MAG_STRLEN, "dof" },
	{ NULL, 0, NULL }
};

static void
rf_activate(mdb_tgt_t *t)
{
	rf_data_t *rf = t->t_data;
	const struct rf_magic *m;
	mdb_var_t *v;
	off64_t size;

	(void) mdb_tgt_register_dcmds(t, &rf_dcmds[0], MDB_MOD_FORCE);

	/*
	 * We set the legacy adb variable 'd' to be the size of the file (data
	 * segment).  To get this value, we call seek() on the underlying fdio.
	 */
	if (rf->r_object_fio != NULL) {
		size = IOP_SEEK(rf->r_object_fio, 0, SEEK_END);
		if ((v = mdb_nv_lookup(&mdb.m_nv, "d")) != NULL)
			mdb_nv_set_value(v, size);
	}

	/*
	 * Load any debugging support modules that match the file type, as
	 * determined by our poor man's /etc/magic.  If many clients need
	 * to use this feature, rf_magic[] should be computed dynamically.
	 */
	for (m = rf_magic; m->rfm_str != NULL; m++) {
		char *buf = mdb_alloc(m->rfm_len, UM_SLEEP);

		if (mdb_tgt_vread(t, buf, m->rfm_len, 0) == m->rfm_len &&
		    bcmp(buf, m->rfm_str, m->rfm_len) == 0) {
			(void) mdb_module_load(m->rfm_mod,
			    MDB_MOD_LOCAL | MDB_MOD_SILENT);
		}

		mdb_free(buf, m->rfm_len);
	}
}

static void
rf_deactivate(mdb_tgt_t *t)
{
	const mdb_dcmd_t *dcp;

	for (dcp = &rf_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_remove_dcmd(t->t_module, dcp->dc_name) == -1)
			warn("failed to remove dcmd %s", dcp->dc_name);
	}
}

static const mdb_tgt_ops_t rawfile_ops = {
	rf_setflags,				/* t_setflags */
	(int (*)()) mdb_tgt_notsup,		/* t_setcontext */
	rf_activate,				/* t_activate */
	rf_deactivate,				/* t_deactivate */
	(void (*)()) mdb_tgt_nop,		/* t_periodic */
	rf_destroy,				/* t_destroy */
	rf_name,				/* t_name */
	(const char *(*)()) mdb_conf_isa,	/* t_isa */
	(const char *(*)()) mdb_conf_platform,	/* t_platform */
	(int (*)()) mdb_tgt_notsup,		/* t_uname */
	(int (*)()) mdb_tgt_notsup,		/* t_dmodel */
	rf_aread,				/* t_aread */
	rf_awrite,				/* t_awrite */
	rf_vread,				/* t_vread */
	rf_vwrite,				/* t_vwrite */
	rf_pread,				/* t_pread */
	rf_pwrite,				/* t_pwrite */
	rf_fread,				/* t_fread */
	rf_fwrite,				/* t_fwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_ioread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_iowrite */
	(int (*)()) mdb_tgt_notsup,		/* t_vtop */
	(int (*)()) mdb_tgt_notsup,		/* t_lookup_by_name */
	(int (*)()) mdb_tgt_notsup,		/* t_lookup_by_addr */
	(int (*)()) mdb_tgt_notsup,		/* t_symbol_iter */
	rf_mapping_iter,			/* t_mapping_iter */
	rf_mapping_iter,			/* t_object_iter */
	(const mdb_map_t *(*)()) mdb_tgt_null,	/* t_addr_to_map */
	(const mdb_map_t *(*)()) mdb_tgt_null,	/* t_name_to_map */
	(struct ctf_file *(*)()) rf_addr_to_ctf,	/* t_addr_to_ctf */
	(struct ctf_file *(*)()) rf_name_to_ctf,	/* t_name_to_ctf */
	rf_status,				/* t_status */
	(int (*)()) mdb_tgt_notsup,		/* t_run */
	(int (*)()) mdb_tgt_notsup,		/* t_step */
	(int (*)()) mdb_tgt_notsup,		/* t_step_out */
	(int (*)()) mdb_tgt_notsup,		/* t_step_branch */
	(int (*)()) mdb_tgt_notsup,		/* t_next */
	(int (*)()) mdb_tgt_notsup,		/* t_cont */
	(int (*)()) mdb_tgt_notsup,		/* t_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_vbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_sbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_pwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_vwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_iowapt */
	(int (*)()) mdb_tgt_null,		/* t_add_sysenter */
	(int (*)()) mdb_tgt_null,		/* t_add_sysexit */
	(int (*)()) mdb_tgt_null,		/* t_add_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_fault */
	(int (*)()) mdb_tgt_notsup,		/* t_getareg */
	(int (*)()) mdb_tgt_notsup,		/* t_putareg */
	(int (*)()) mdb_tgt_notsup,		/* t_stack_iter */
	(int (*)()) mdb_tgt_notsup		/* t_auxv */
};

int
mdb_rawfile_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	mdb_io_t *io[2] = { NULL, NULL };
	rf_data_t *rf;
	int oflags, i;

	if (argc > 2)
		return (set_errno(EINVAL));

	rf = mdb_zalloc(sizeof (rf_data_t), UM_SLEEP);
	t->t_ops = &rawfile_ops;
	t->t_data = rf;

	if (t->t_flags & MDB_TGT_F_RDWR)
		oflags = O_RDWR;
	else
		oflags = O_RDONLY;

	for (i = 0; i < argc; i++) {
		io[i] = mdb_fdio_create_path(NULL, argv[i], oflags, 0);
		if (io[i] == NULL) {
			warn("failed to open %s", argv[i]);
			goto err;
		}
	}

	rf->r_object_fio = io[0];	/* first file is the "object" */
	rf->r_core_fio = io[1];		/* second file is the "core" */
	t->t_flags |= MDB_TGT_F_ASIO;	/* do i/o using aread and awrite */

	return (0);

err:
	for (i = 0; i < argc; i++) {
		if (io[i] != NULL)
			mdb_io_destroy(io[i]);
	}


	mdb_free(rf, sizeof (rf_data_t));
	return (set_errno(EMDB_TGT));
}

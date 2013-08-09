/*
 * Copyright 2007,2008 Max Bruning
 */

#include <sys/mdb_modapi.h>
#include <sys/uberblock_impl.h>

#include <sys/types.h>
#include <sys/sysmacros.h>

/*#include <mdb/mdb_ctf.h>*/
#include <sys/zfs_context.h>
#include <sys/mdb_modapi.h>
#include <sys/dbuf.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/metaslab_impl.h>
#include <sys/space_map.h>
#include <sys/list.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>
#include <sys/dmu_traverse.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>

#include <unistd.h>
#include <string.h>

#undef verify
#undef ZFS_MAXNAMELEN
#include <libzfs.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

libzfs_handle_t *g_zfs;

/*
 * Initialize the uberblock walker by using fixed address 128k into the fs.
 * Also allocate an uberblock_t for storage, and save this using the walk_data pointer.
 */

static int nubers = 0;
#define MAXUBERS 128

static int
ub_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
	  wsp->walk_addr = (128*1024);
	}

	nubers = 0;
	wsp->walk_data = mdb_alloc(sizeof (uberblock_t), UM_SLEEP);
	return (WALK_NEXT);
}

static int
ub_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (nubers++ >= MAXUBERS)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)((char *)wsp->walk_addr + 1024);
	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a proc_t in sp_walk_init, we must free it now.
 */
static void
ub_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (uberblock_t));
	nubers = 0;
	
}

static int
lzjbdcompress(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char sbuf[8192], dbuf[8192];  /* hopefully, large enough for decompressed data */
	int dsize = 8192;
	int ssize;
	char *fname = "/tmp/mdb.lz";
	int fd;

	if (argc != 2) {
		mdb_warn("Usage: lzjbdcompress lsize psize\n");
		return (DCMD_ERR);
	}

	bzero(dbuf, 8192);

	if ((fd = open(fname, O_RDWR|O_CREAT|O_TRUNC)) < 0) {
		mdb_warn("cannot create temp file %s\n", fname);
		return (DCMD_ERR);
	}

	ssize = (int) mdb_strtoull(argv[1].a_un.a_str);
	dsize = (int) mdb_strtoull(argv[0].a_un.a_str);

	if (mdb_vread(sbuf, ssize, addr) != ssize) {
		mdb_warn("failed to read %lu bytes at %llx",
		    (ulong_t)ssize, addr);
		return (DCMD_ERR);
	}

	lzjb_decompress(sbuf, dbuf, ssize, dsize, 0);
	mdb_printf("ssize = %x, dsize = %x\n", ssize, dsize);

	if (write(fd, dbuf, dsize) != dsize) {
		mdb_warn("failed to write tmp file\n");
		return DCMD_ERR;
	}

	sprintf(sbuf, "echo 0::print -a -p zfs\\`objset_phys_t | /maxmovies/max/opensolaris.02222007/usr/src/cmd/mdb/intel/ia32/mdb/mdb %s", fname);
	mdb_printf("sbuf = %s\n", sbuf);
	system(sbuf);
	close(fd);
	return DCMD_OK;
}

#ifdef NOTNOW
/*ARGSUSED*/
static int
rawzfs_blkptr_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	blkptr_t bp;
	int i;
	const struct dmu_object_type_info *doti = dmu_ot;
	zio_compress_info_t *zct = zio_compress_table;
	zio_checksum_info_t *zci = zio_checksum_table;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_vread(&bp, sizeof(blkptr_t), addr) == -1) {
		mdb_warn("cannot read blkptr at %p\n", addr);
		return (DCMD_ERR);
	}

	/*
	 * Super-ick warning:  This code is also duplicated in
	 * cmd/zdb.c and in cmd/mdb/common/modules/zfs/zfs.c.
	 * Yeah, I hate code replication, three.
	 */
	for (i = 0; i < BP_GET_NDVAS(&bp); i++) {
		dva_t *dva = &bp.blk_dva[i];

		mdb_printf("DVA[%d]: vdev_id %lld / %llx\n", i,
		    DVA_GET_VDEV(dva), DVA_GET_OFFSET(dva));
		mdb_printf("DVA[%d]:       GANG: %-5s  GRID:  %04x\t"
		    "ASIZE: %llx\n", i, DVA_GET_GANG(dva) ? "TRUE" : "FALSE",
		    DVA_GET_GRID(dva), DVA_GET_ASIZE(dva));
		mdb_printf("DVA[%d]: :%llu:%llx:%llx:%s%s%s%s\n", i,
		    DVA_GET_VDEV(dva), DVA_GET_OFFSET(dva), BP_GET_PSIZE(&bp),
		    BP_SHOULD_BYTESWAP(&bp) ? "e" : "",
		    !DVA_GET_GANG(dva) && BP_GET_LEVEL(&bp) != 0 ? "i" : "",
		    DVA_GET_GANG(dva) ? "g" : "",
		    BP_GET_COMPRESS(&bp) != 0 ? "d" : "");
	}
	mdb_printf("LSIZE:  %-16llx\t\tPSIZE: %llx\n",
	    BP_GET_LSIZE(&bp), BP_GET_PSIZE(&bp));
	mdb_printf("ENDIAN: %6s\t\t\t\t\tTYPE:  %s\n",
	    BP_GET_BYTEORDER(&bp) ? "LITTLE" : "BIG",
	    doti[BP_GET_TYPE(&bp)].ot_name);
	mdb_printf("BIRTH:  %-16llx   LEVEL: %-2d\tFILL:  %llx\n",
	    bp.blk_birth, BP_GET_LEVEL(&bp), bp.blk_fill);
	mdb_printf("CKFUNC: %-16s\t\tCOMP:  %s\n",
	    zci[BP_GET_CHECKSUM(&bp)].ci_name,
	    zct[BP_GET_COMPRESS(&bp)].ci_name);
	mdb_printf("CKSUM:  %llx:%llx:%llx:%llx\n",
	    bp.blk_cksum.zc_word[0],
	    bp.blk_cksum.zc_word[1],
	    bp.blk_cksum.zc_word[2],
	    bp.blk_cksum.zc_word[3]);

	return (DCMD_OK);
}
#endif /*NOTNOW*/


/*
 *  Given a blkptr, ::print the information from the disk location
 *  the blkptr refers to.  This routine reads the blkptr, does any
 *  necessary de-compression, and uses the object type information in
 *  the blkptr to determine what is to be printed.
 */

/*ARGSUSED*/
static int
rawzfs_zprint_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	blkptr_t bp;
	int compress;
	const struct dmu_object_type_info *doti = dmu_ot;
	zio_compress_info_t *zct = zio_compress_table;
	zio_checksum_info_t *zci = zio_checksum_table;
	uintptr_t daddr;
	size_t lsize, asize, psize;
	char *fname = "/tmp/mdb.lz";
	int fd;
	char *otype;
	char *sbuf, *dbuf;
	char cbuf[8192];
	zio_compress_info_t *ci;
	char *tbuf;
	u_longlong_t level;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if ((fd = open(fname, O_RDWR|O_CREAT|O_TRUNC)) < 0) {
		mdb_warn("cannot create temp file %s\n", fname);
		return (DCMD_ERR);
	}

	if (mdb_vread(&bp, sizeof(blkptr_t), addr) == -1) {
		mdb_warn("cannot read blkptr at %p\n", addr);
		return (DCMD_ERR);
	}

	/*
	 * when i get around to making a zfs target, i'll probably need
	 * to look at the vdev and other fields in the dva.
         * for right now, i only
	 * use the offset of the first dva and ignore the vdev and the rest.
	 */


	daddr = (DVA_GET_OFFSET(&bp.blk_dva[0]))+0x400000;
	mdb_printf("daddr = %x\n", daddr);
	lsize = BP_GET_LSIZE(&bp);
	psize = BP_GET_PSIZE(&bp);
	asize = DVA_GET_ASIZE(&bp.blk_dva[0]);  /* will need this later... */
	otype = doti[BP_GET_TYPE(&bp)].ot_name;
	level = BP_GET_LEVEL(&bp);
	compress = BP_GET_COMPRESS(&bp);

	mdb_printf("lsize = %x, psize = %x, asize = %x, level = %d, otype = %s, compress = %p\n",
		   lsize, psize, asize, level, otype, &zio_compress_table[compress]);
	sbuf = mdb_alloc(psize, UM_SLEEP);
	dbuf = mdb_alloc(lsize, UM_SLEEP);

	if (mdb_vread(sbuf, psize, daddr) == -1) {
		mdb_warn("cannot read object at %p\n", daddr);
		return (DCMD_ERR);
	}


	ci = &zio_compress_table[compress];

	if (ci->ci_decompress) {
	
		(void) (*ci->ci_decompress)(sbuf, dbuf, psize, lsize, ci->ci_level);
	} else
		bcopy(sbuf, dbuf, psize);

	mdb_printf("blkptr refers to %s", otype);
	if (level > 0)
		mdb_printf(" (level %d indirection)", level);
	mdb_printf("\n lsize = %x, psize = %x, asize = %x\n", lsize, psize, asize);
	mdb_printf("dva[0] offset = %x\n", DVA_GET_OFFSET(&bp.blk_dva[0]));

	if (write(fd, dbuf, lsize) != lsize) {
		mdb_warn("cannot write temp file\n");
		return (DCMD_ERR);
	}

	if (level > 0)
		tbuf = "blkptr";
	else if (strcmp(otype, "DMU objset") == 0) {
		tbuf = "objset_phys_t";
		sprintf(cbuf, "(echo \"0::print -a -p zfs\\`%s os_meta_dnode.dn_blkptr | ::blkptr\") | /root/mdb %s", tbuf, fname);
		system(cbuf);
	}
	else if (strcmp(otype, "bplist") == 0)
		tbuf = "bplist_phys_t";
	else if (strcmp(otype, "DMU dnode") == 0)
		tbuf = "dnode_phys_t";
	else if (strcmp(otype, "DSL dataset") == 0)
		tbuf = "dsl_dataset_phys_t";
	else if (strcmp(otype, "DSL directory") == 0)
		tbuf = "dsl_dir_phys_t";
	else if (strcmp(otype, "SPA history") == 0)
		tbuf = "spa_history_phys_t";
	else {  /* plain file contents or other?  */
		mdb_printf("cannot use ::zprint, try \'%x,20/B\' or \'%x,20/K\'\n",
		     daddr, daddr);
		return (DCMD_OK);
	}

	/* we know the type, run mdb on the tmp file with the type */

	/* build the command string */	
	if (level > 0)
		sprintf(cbuf, "(echo 0,%d::%s) | /root/mdb %s", lsize/sizeof(blkptr_t), tbuf, fname);
	else
		sprintf(cbuf, "(echo \"0::print -a -p zfs\\`%s dn_blkptr | ::blkptr\") | /root/mdb %s", tbuf, fname);
	system(cbuf);
	
	close(fd);

	return (DCMD_OK);

}


/*
 * from zdb.c
 */
static void
dump_nvlist(nvlist_t *list, int indent)
{
	nvpair_t *elem = NULL;

	while ((elem = nvlist_next_nvpair(list, elem)) != NULL) {
		switch (nvpair_type(elem)) {
		case DATA_TYPE_STRING:
			{
				char *value;

				VERIFY(nvpair_value_string(elem, &value) == 0);
				(void) printf("%*s%s='%s'\n", indent, "",
				    nvpair_name(elem), value);
			}
			break;

		case DATA_TYPE_UINT64:
			{
				uint64_t value;

				VERIFY(nvpair_value_uint64(elem, &value) == 0);
				(void) printf("%*s%s=%llu\n", indent, "",
				    nvpair_name(elem), (u_longlong_t)value);
			}
			break;

		case DATA_TYPE_NVLIST:
			{
				nvlist_t *value;

				VERIFY(nvpair_value_nvlist(elem, &value) == 0);
				(void) printf("%*s%s\n", indent, "",
				    nvpair_name(elem));
				dump_nvlist(value, indent + 4);
			}
			break;

		case DATA_TYPE_NVLIST_ARRAY:
			{
				nvlist_t **value;
				uint_t c, count;

				VERIFY(nvpair_value_nvlist_array(elem, &value,
				    &count) == 0);

				for (c = 0; c < count; c++) {
					(void) printf("%*s%s[%u]\n", indent, "",
					    nvpair_name(elem), c);
					dump_nvlist(value[c], indent + 8);
				}
			}
			break;

		default:

			(void) printf("bad config type %d for %s\n",
			    nvpair_type(elem), nvpair_name(elem));
		}
	}
}

/*
 * from zdb.c
 */
static void
dump_label(const char *dev)
{
	int fd;
	vdev_label_t label;
	char *buf = label.vl_vdev_phys.vp_nvlist;
	size_t buflen = sizeof (label.vl_vdev_phys.vp_nvlist);
	struct stat64 statbuf;
	uint64_t psize;
	int l;

	if ((fd = open64(dev, O_RDONLY)) < 0) {
		(void) printf("cannot open '%s': %s\n", dev, strerror(errno));
		exit(1);
	}

	if (fstat64(fd, &statbuf) != 0) {
		(void) printf("failed to stat '%s': %s\n", dev,
		    strerror(errno));
		exit(1);
	}

	psize = statbuf.st_size;
	psize = P2ALIGN(psize, (uint64_t)sizeof (vdev_label_t));

	for (l = 0; l < VDEV_LABELS; l++) {

		nvlist_t *config = NULL;

		(void) printf("--------------------------------------------\n");
		(void) printf("LABEL %d\n", l);
		(void) printf("--------------------------------------------\n");

		if (pread64(fd, &label, sizeof (label),
		    vdev_label_offset(psize, l, 0)) != sizeof (label)) {
			(void) printf("failed to read label %d\n", l);
			continue;
		}

		if (nvlist_unpack(buf, buflen, &config, 0) != 0) {
			(void) printf("failed to unpack label %d\n", l);
			continue;
		}
		dump_nvlist(config, 4);
		nvlist_free(config);
	}
}

/*ARGSUSED*/
static int
rawzfs_zlabel_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int error = 0;

	if (argc != 1)
		return (DCMD_USAGE);
	/* this is from the main routine in zdb.c */
	kernel_init(FREAD);
	mdb_printf("kernel_init returned %x\n", error);
	g_zfs = libzfs_init();
	ASSERT(g_zfs != NULL);

	/*
	 * Disable vdev caching.  If we don't do this, live pool traversal
	 * won't make progress because it will never see disk updates.
	 */
	zfs_vdev_cache_size = 0;
	if (strchr(argv->a_un.a_str, '/') != NULL) {
		dump_label(argv->a_un.a_str);
		libzfs_fini(g_zfs);
		kernel_fini();
		return (DCMD_OK);
	} else {
		libzfs_fini(g_zfs);
		kernel_fini();
		return (DCMD_USAGE);
	}
}

/*
 * from zdb.c
 */
static void
dump_uberblock(uberblock_t *ub)
{
	char blkbuf[BP_SPRINTF_LEN];
	time_t timestamp = ub->ub_timestamp;

	(void) mdb_printf("Uberblock\n\n");
	(void) mdb_printf("\tmagic = %016llx\n", (u_longlong_t)ub->ub_magic);
	(void) mdb_printf("\tversion = %llu\n", (u_longlong_t)ub->ub_version);
	(void) mdb_printf("\ttxg = %llu\n", (u_longlong_t)ub->ub_txg);
	(void) mdb_printf("\tguid_sum = %llu\n", (u_longlong_t)ub->ub_guid_sum);
	(void) mdb_printf("\ttimestamp = %llu UTC = %s",
		(u_longlong_t)ub->ub_timestamp, asctime(localtime(&timestamp)));
	sprintf_blkptr(blkbuf, &ub->ub_rootbp);
	(void) mdb_printf("\trootbp = %s\n", blkbuf);
	(void) mdb_printf("\n");
}



/*
 *  read the uberblock and display, from zdb.c
 *  TODO:
 *     handle exported/destroyed pools (can get from zdb.c)
 */

/*ARGSUSED*/
static int
rawzfs_ub_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	spa_t *spa;
	objset_t *os = NULL;
	int error;
	dsl_pool_t *dp;

	if (argc != 1) {
		return (DCMD_USAGE);
	}

	/* this is from the main routine in zdb.c */
	kernel_init(FREAD);
	g_zfs = libzfs_init();
	ASSERT(g_zfs != NULL);

	/*
	 * Disable vdev caching.  If we don't do this, live pool traversal
	 * won't make progress because it will never see disk updates.
	 */
	zfs_vdev_cache_size = 0;
#ifdef NOTNOW
	if (strchr(argv->a_un.a_str, '/') != NULL) {
			error = dmu_objset_open(argv->a_un.a_str, DMU_OST_ANY,
			    DS_MODE_USER | DS_MODE_READONLY, &os);
	} else {
			error = spa_open(argv->a_un.a_str, &spa, FTAG);
	}
#else
	error = spa_open(argv->a_un.a_str, &spa, FTAG);
#endif /*NOTNOW*/

	mdb_printf("spa_name = %s\n", spa->spa_name);
	mdb_printf("spa_uberblock = %lx", spa->spa_uberblock);
	mdb_printf("spa_config_txg = %lx\n", spa->spa_config_txg);
	mdb_printf("spa_root = %s\n", spa->spa_root);

	if (error)
		mdb_warn("failed to open %s\n", argv->a_un.a_str);
	else {
		dp  = spa_get_dsl(spa);
		spa_config_enter(spa, SCL_STATE, FTAG, RW_READER);
		dump_uberblock(&spa->spa_uberblock);
		spa_config_exit(spa, SCL_STATE, FTAG);
		spa_close(spa, FTAG);
	}

	libzfs_fini(g_zfs);
	kernel_fini();

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
  /*	{ "lzjbdcompress", NULL, "lzjb decompression for zfs meta data", lzjbdcompress }, */
  /*     	{ "blkptr", ":", "display blkptr on disk", rawzfs_blkptr_dcmd }, */
	{ "zprint", ":", "given blkptr, print data", rawzfs_zprint_dcmd },
	{ "ub", NULL, "display current uberblock", rawzfs_ub_dcmd },
	{ "zlabel", ":", "dump label", rawzfs_zlabel_dcmd },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "uberblock", "walk list of on disk uberblock structures",
		ub_walk_init, ub_walk_step, ub_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

libzfs_handle_t *g_zfs;

const mdb_modinfo_t *
_mdb_init(void)
{

	return (&modinfo);
}

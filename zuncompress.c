#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/metaslab_impl.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>
#include <sys/dbuf.h>
#include <sys/zil.h>
#include <sys/zil_impl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/dmu_traverse.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <sys/zfs_fuid.h>
#include <sys/arc.h>
#undef ZFS_MAXNAMELEN
#undef verify
#include <libzfs.h>
#include <sys/fcntl.h>
#include <umem.h>
#include <strings.h>

#define STARTOFFSET (0x400000)

int
main(int argc, char *argv[])
{
	int fd, i;
	uint64_t psize = 0, lsize = 0, offset = STARTOFFSET;
	char *sbuf;
	char *dbuf;
	char *ca = "lzjb";
	char *infile;
	int copt;
	enum zio_compress c;

	while ((copt = getopt(argc, argv, "l:p:c:o:")) != -1) {
		switch(copt) {
		case 'l':
			lsize = strtoull(optarg, &optarg, 16);
			if (lsize == 0) {
				fprintf(stderr, "Error: unknown lsize\n");
				exit(1);
			}
			break;

		case 'p':
			psize = strtoull(optarg, &optarg, 16);
			if (psize == 0) {
				fprintf(stderr, "Error: unknown psize\n");
				exit(1);
			}
			break;

		case 'c':
			ca = optarg;
			break;

		case 'o':
			offset += strtoull(optarg, &optarg, 16);
			break;

		case '?':
			fprintf(stderr, "Usage: %s -l lsize -p psize [-c compression_algorithm] [input_file]\n",
				argv[0]);
			exit(1);
		}
	}

	if (optind < argc) {
		infile = argv[optind];
		if ((fd = open(infile, O_RDONLY)) < 0) {
			perror("Cannot open input file\n");
			exit(1);
		}
	} else
		fd = 0;  /* stdin */

	if (lsize == 0 || psize == 0) {
		fprintf(stderr, "Usage: %s -l lsize -p psize [-c compression_algorithm] [input_file]\n",
			argv[0]);
		exit(1);
	}

	for (i = 0; i < ZIO_COMPRESS_FUNCTIONS; i++) {
		if (strncmp(ca, zio_compress_table[i].ci_name,
			    strlen(zio_compress_table[i].ci_name)) == 0)
			break;
	}

	if (i >= ZIO_COMPRESS_FUNCTIONS) {
		(void)fprintf(stderr, "***Unknown compression type: '%s'\n", ca);
		exit(1);
	}


	sbuf = malloc(psize);
	dbuf = malloc(lsize);

	if (sbuf == NULL || dbuf == NULL) {
		fprintf(stderr, "failed to allocate space for source/destination buffers\n");
		exit(1);
	}

	if (pread(fd, sbuf, psize, offset) != psize) {
		perror("error reading input file\n");
		exit(1);
	}

	if (zio_decompress_data(i, sbuf, dbuf, psize, lsize) != 0) {
		perror("decompress failed\n");
		exit(1);
	}

	write(1, dbuf, lsize);
	free(sbuf);
	free(dbuf);
	exit(0);
}



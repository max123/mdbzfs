mdbzfs
======

modified mdb for examining zfs on disk

This contains changes for usr/src/cmd/mdb/common/mdb/mdb_rawfile.c, usr/src/cmd/mdb/common/modules/zfs/zfs.c, and source for zuncompress.c and rawzfs.c
Also included are binaries:

     mdb - with changes to look at ZFS on disk
     zfs.so - slight change to be used with mdb
     rawzfs.so - new mdb dmod for the ::walk uberblock command
     zuncompress - uncompress data

To see these in use, see the Bruning Questions blog post at
http://www.joyent.com/blog/zfs-forensics-recovering-files-from-a-destroyed-zpool.

To build, start with http://wiki.smartos.org/display/DOC/Building+SmartOS+on+SmartOS
and follow all of the instructions there.  Then copy mdb_rawfile.c from here to
smartos-live/projects/illumos/usr/src/cmd/mdb/common/mdb/mdb_rawfile.c,
zfs.c from here to smartos-live/projects/illumos/usr/src/cmd/mdb/common/modules/zfs.c, and rawzfs.c to smartos-live/projects/illumos/usr/src/cmd/mdb/common/modules/rawzfs.c.  You may need to edit the mdb Makefile to get rawzfs.so to build, but it should be pretty straight forward.  To build zuncompress:
gcc -m64 -I ./smartos-live/projects/illumos/usr/src/uts/common/fs/zfs -lzfs -lzpool -o zuncompress zuncompress.c

This is very much a work in progress.  In its final form, I expect someone will
make a ZFS on disk target for mdb, and the hacks in mdb_rawfile.c can go away.  There are lots of dcmds and walkers that could be written that would be interesting.  For instance, object_id_#::dnodefind [-d dataset] [-p zpool].  But the best would be:  disk_address::zprint [-c compression_algorithm] datatype
Then there would be no need to use zuncompress, and you could do everything in 1 mdb session.

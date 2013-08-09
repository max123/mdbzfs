#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"@(#)Makefile.demo	1.1	99/11/19 SMI"

.KEEP_STATE:

all := TARGET = all
clean := TARGET = clean
clean.lint := TARGET = clean.lint
clobber := TARGET = clobber
lint := TARGET = lint

SUBDIRS :sh= [ `uname -p` = sparc ] && echo sparc sparcv9 || uname -p
TARGET =

all clean clean.lint clobber lint: $(SUBDIRS)

$(SUBDIRS): FRC
	$(MAKE) -f Makefile.$@ $(TARGET)

FRC:

#!/bin/ksh

## \file make.config.mk.sh Make "config.mk".  See comments in a makefile.

if [ x${GLIBCBUILD} == x -o x${GLIBC} == x ]; then
	echo "USAGE: env GLIBCBUILD=xxx GLIBC=xxx make.config.mk.sh"
	echo "It makes the include list from GLIBCBUILD/config.make."
	exit
fi

grep config-sysdirs ${GLIBCBUILD}/config.make \
    | sed -e "s|config-sysdirs = |INCS|" \
    -e "s| | -I${GLIBC}/|g" \
    -e "s|INCS|INCS =|" > config.mk

echo "INCS += -I${GLIBC}/include" >> config.mk
echo "INCS += -I${GLIBC}" >> config.mk
echo "INCS += -I${GLIBCBUILD}" >> config.mk
echo "SYMS = -include ${GLIBC}/include/libc-symbols.h" >> config.mk

echo "GLIBCBUILD = ${GLIBCBUILD}" >> config.mk
echo "GLIBC = ${GLIBC}" >> config.mk

# Makefile

# Compile this on a compute node; This makefile is for non-cross
# compiling.  It needs configuration information of ld.so.  First, it
# needs the include file settings.  Run "make.config.mk.sh" to make
# "config.mk".  The run makes a include list from the value of
# "config-sysdirs" in "GLIBCBUILD/config.make".  Second, it also needs
# "config.h" and "abi-versions.h" in "GLIBCBUILD".

-include config.mk

all: libkmrspawn.so

libkmrspawn.so: config.mk kmrld.c kmrhooks.c kmrspawn.c
	gcc -std=gnu99 -fPIC -O -g -fgnu89-inline -fmerge-all-constants \
	-DPIC -D_LIBC_REENTRANT -DSHARED -DNOT_IN_libc=1 \
	$(INCS) $(SYMS) -Wall -Wstrict-prototypes -c kmrld.c
	mpifcc -Xg -fopenmp -mt -std=gnu99 -fPIC -DPIC -c kmrhooks.c kmrspawn.c
	gcc -shared -Wl,-soname,libkmrspawn.so \
		-o libkmrspawn.so kmrld.o kmrhooks.o kmrspawn.o

config.mk:
	@echo "Run make.config.mk.sh to make config.mk"; exit 1

test::
	fccpx ${LPG} -Xg -fopenmp -mt -std=gnu99 -g -o testrun testrun.c -ldl
	fccpx ${LPG} -Xg -fopenmp -mt -std=gnu99 -g -o testtarget testtarget.c

ping::
	mpifccpx ${LPG} -o ping0 ping0.c -ldl
	mpifccpx ${LPG} -o ping1 ping1.c

testg::
	gcc -fopenmp -std=c99 -g -Wall -o testrun testrun.c -ldl
	gcc -fopenmp -std=c99 -g -Wall -o testtarget testtarget.c

pinge::
	mpifcc -o ping0 ping0.c -ldl
	mpifcc -o ping1 ping1.c

clean::
	rm -f a.out core.* *.o *.so testrun testtarget ping0 ping1

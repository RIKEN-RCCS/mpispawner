/* testrun.c (2016-04-07) */
/* Copyright (C) 2012-2016 RIKEN AICS */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <omp.h>
#include <assert.h>

#define TEST_RUN_WITH_THREADS 1

#if (TEST_RUN_WITH_THREADS > 0)

__thread int var_tls_a[10] = {100, 101, 102, 103, 104,
			      105, 106, 107, 108, 109};
void
foo(void)
{
    for (int i = 0; i < 10; i++) {
	var_tls_a[i] = (555000 + omp_get_thread_num());
    }
}

void
bar(void)
{
    for (int i = 0; i < 10; i++) {
	assert(var_tls_a[i] == (555000 + omp_get_thread_num()));
    }
}

#endif /*TEST_RUN_WITH_THREADS*/

int
main(int argc, char **argv, char **envp)
{
    if (argc == 1) {
	printf("USAGE a.out command...\n");
	exit(0);
    }

    /* Place the heap at a high address (enough for /bin/ls).
       (0x41b000+0x321c) */

#if 0
    void *obrk = sbrk(0);
    char *hlow = (char *)0x2300000;
    int cc = brk(hlow);
    assert(cc == 0);
    printf("brk()=%p\n", obrk); fflush(0);
#else
    void *obrk = sbrk(0);
    char *hlow = obrk;
#endif

#if 1
    /* REFER STDOUT */
    fprintf(stdout, "REFER STDOUT\n"); fflush(0);
    /* REFER STDERR */
    fprintf(stderr, "REFER STDERR\n"); fflush(0);
#endif

    if (0) {
	char pmap[80];
	snprintf(pmap, sizeof(pmap), "pmap -x %d", getpid());
	printf(">pmap\n"); fflush(0);
	int cc0 = system(pmap);
	if (cc0 != 0) {
	    perror("system(pmap)"); fflush(0);
	}
	printf("<pmap\n"); fflush(0);
    }

#if (TEST_RUN_WITH_THREADS > 0)

#pragma omp parallel
    {
	foo();
    }
#pragma omp parallel
    {
	/*printf("thno=%d\n", omp_get_thread_num()); fflush(0);*/
	/*nop*/;
    }
#pragma omp parallel
    {
	bar();
    }

#endif /*TEST_RUN_WITH_THREADS*/

    /* Load libkmrspawn.so. */

    void *m = dlopen("libkmrspawn.so", (RTLD_NOW|RTLD_GLOBAL));
    if (m == 0) {
	printf("dlopen(libkmrspawn.so): %s\n", dlerror());
	abort();
    }

    typedef void (*usoexecfn_t)(char **, char **, long, char *);
    usoexecfn_t usoexec = (usoexecfn_t)dlsym(m, "kmr_ld_usoexec");
    if (usoexec == 0) {
	printf("dlsym(kmr_ld_usoexec): %s\n", dlerror());
	abort();
    }

    typedef long (*getsizefn_t)(char *);
    getsizefn_t getsize = (getsizefn_t)dlsym(m, "kmr_ld_get_symbol_size");
    if (getsize == 0) {
	printf("dlsym(kmr_ld_get_symbol_size): %s\n", dlerror());
	abort();
    }

    /* Check kmr_ld_get_symbol_size(). */

    long sz = (*getsize)("printf");
    printf("size of symbol printf=%ld\n", sz);
    fflush(0);

    typedef void (*setprfn_t)(int, void (*)(int, char *, ...));
    setprfn_t setpr = (setprfn_t)dlsym(m, "kmr_ld_set_error_printer");
    if (setpr == 0) {
	printf("dlsym(kmr_ld_set_error_printer): %s\n", dlerror());
	abort();
    }

    /* Make verbose. */

    (*setpr)(3, 0);

    char **oldargv = argv;
    char **newargv = &argv[1];

    (*usoexec)(newargv, oldargv, 0x110, hlow);

    /* Never returns. */

    printf("usoexec returns\n");
    assert(0);
    return 0;
}

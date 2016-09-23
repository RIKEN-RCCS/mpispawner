/* testtarget.c (2016-04-07) */
/* Copyright (C) 2012-2016 RIKEN AICS */

/* A simplest target program to be execed by testexec.c. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <omp.h>
#include <assert.h>

#define TLS_TEST 1

#if (TLS_TEST == 1)
/* TLS with the same size as the old a.out. */
__thread int var_tls_b[10] = {200, 201, 202, 203, 204,
			      205, 206, 207, 208, 209};
#elif (TLS_TEST == 2)
/* (FAILS!) TLS with a larger size as the old a.out. */
__thread int var_tls_b[20] = {200, 201, 202, 203, 204,
			      205, 206, 207, 208, 209,
			      210, 211, 212, 213, 214,
			      215, 216, 217, 218, 219};
#else
/*nothing*/
#endif

#if (TLS_TEST > 0)

void
foo0(void)
{
    int bias = 200;
    if (omp_get_thread_num() == 0) {
	for (int i = 0; i < 10; i++) {
	    printf("var_tls_b[%d]=%d\n", i, var_tls_b[i]);
	}
	fflush(0);
    }
    for (int i = 0; i < 10; i++) {
	assert(var_tls_b[i] == (bias + i));
    }
}

void
foo1(void)
{
    for (int i = 0; i < 10; i++) {
	var_tls_b[i] = (1234 + omp_get_thread_num());
    }
}

void
bar(void)
{
    for (int i = 0; i < 10; i++) {
	assert(var_tls_b[i] == (1234 + omp_get_thread_num()));
    }
}

#endif /*TLS_TEST*/

int
main(int argc, char **argv, char **envp)
{
    printf("ECHOECHO\n");

#if 0
    extern int __libc_multiple_libcs;
#endif

#if 1
    printf("echoecho: stderr=%p &stderr=%p\n", stderr, &stderr);
#endif

#if 0
    errno = 0;
    perror("perror(NONE)");
    if (stderr->_mode != 0) {
	printf("AHO1\n");
    } else {
	printf("AHO2\n");
    }
#endif

#if (TLS_TEST == 1)
    printf("Test TLS with new-size <= old-size\n"); fflush(0);
#elif (TLS_TEST == 2)
    printf("Test TLS with new-size > old-size\n"); fflush(0);
#endif /*TLS_TEST*/

#if (TLS_TEST > 0)

#pragma omp parallel
    {
	foo0();
    }
#pragma omp parallel
    {
	foo1();
    }
#pragma omp parallel
    {
	bar();
    }

#endif /*TLS_TEST*/

    //_exit(0);
    exit(0);

    return 0;
}

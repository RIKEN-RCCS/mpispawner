/* ping0.c (2016-06-28) */

/* Simple Test.  USAGE: mpiexec -n 2 ./ping0 ./ping1.  It starts with
   ping0 on both rank0 and rank1, then switches to ping1 on rank1.  It
   does not finish MPI properly, because it uses _exit() instead of
   exit().  It uses _exit() because exit() is hooked to call the
   spawner service routine which is not usable in the ping test. */

#include <mpi.h>
#include <mpi-ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <assert.h>

int
main(int argc, char **argv)
{
    if (argc < 2) {
	printf("USAGE: ./ping0 ./ping1\n"); fflush(0);
	exit(0);
    }

    if (1) {
	char pmap[80];
	snprintf(pmap, sizeof(pmap), "pmap -x %d", getpid());
	system(pmap);
    }

    if (0) {
	void *obrk = sbrk(0);
	char *hlb = (char *)0x2300000;
	int cc = brk(hlb);
	if (cc != 0) {
	    perror("brk(hlb)");
	}
    }

    printf("loading libkmrspawn.so...\n"); fflush(0);
    void *m = dlopen("libkmrspawn.so", (RTLD_NOW|RTLD_GLOBAL));
    if (m == 0) {
	fprintf(stderr, "dlopen(libkmrspawn.so): %s\n", dlerror());
	abort();
    }
    typedef void (*execfn_t)(char **, void (*)(void), char **, long, char *);
    execfn_t usoexec = (execfn_t)dlsym(m, "kmr_ld_usoexec");
    if (usoexec == 0) {
	fprintf(stderr, "dlsym(kmr_ld_usoexec): %s\n", dlerror());
	abort();
    }

    typedef int (*hookfn_t)(void *);
    hookfn_t hookup = (hookfn_t)dlsym(m, "kmr_spawn_hookup");
    if (hookup == 0) {
	fprintf(stderr, "dlsym(kmr_spawn_hookup): %s\n", dlerror());
	abort();
    }
    char *hooks = malloc(1024);
    assert(hooks != 0);
    (*hookup)(hooks);

#if 0 /*GOMI*/
    if (0) {
	char **oldargv = argv;
	char **newargv = &argv[1];
	printf("USOEXEC...\n"); fflush(0);
	(*usoexec)(newargv, 0, oldargv, 0x110, 0);
	printf("USOEXEC RETURNS\n"); fflush(0);
	abort();
    }
#endif

    int nprocs, rank;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    assert(nprocs == 2);

    {
	/* comm->c_local_group->grp_proc_count; */
	void *c = MPI_COMM_WORLD;
	printf("comm=%p\n", c);
	void *g = *(void **)((char *)c + 0xa8);
	printf("group=%p\n", g);
	//int m = *(int *)((char *)g + 0x10);
	//printf("nprocs=%p\n", m);
	fflush(0);
    }

    printf("rank=%d/%d\n", rank, nprocs); fflush(0);
    MPI_Barrier(MPI_COMM_WORLD);

    if (rank == 0) {
	/* RUN BEFORE THREADS START. */
	char pmap[80];
	snprintf(pmap, sizeof(pmap), "pmap -x %d", getpid());
	int cc0 = system(pmap);
	if (cc0 != 0) {
	    perror("system(pmap)"); fflush(0);
	}
    }

    MPI_Barrier(MPI_COMM_WORLD);

    char name[MPI_MAX_PROCESSOR_NAME];
    char names[nprocs][MPI_MAX_PROCESSOR_NAME];
    int namelen;

    MPI_Get_processor_name(name, &namelen);
    MPI_Gather(name, sizeof(name), MPI_CHAR,
	       names, sizeof(name), MPI_CHAR,
	       0, MPI_COMM_WORLD);
    if (rank == 0) {
	for (int i = 0; i < nprocs; i++) {
	    printf("rank%d=%s\n", i, names[i]);
	}
	fflush(0);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    int n0 = 1000;
    long *data0 = malloc(sizeof(long) * n0);
    assert(data0 != 0);
    memset(data0, 0, (sizeof(long) * n0));

    {
	int n = n0;
	long *data = data0;
	int tag = 1001;
	long base = 5000000;
	if (rank == 0) {
	    for (int i = 0; i < n; i++) {
		data[i] = (base + i);
	    }
	    MPI_Send(data, n, MPI_LONG, 1, tag, MPI_COMM_WORLD);
	} else if (rank == 1) {
	    MPI_Recv(data, n, MPI_LONG, 0, tag, MPI_COMM_WORLD,
		     MPI_STATUS_IGNORE);
	    for (int i = 0; i < n; i++) {
		assert(data[i] == (base + i));
	    }
	} else {
	    /*nothing*/
	}
    }

    MPI_Barrier(MPI_COMM_WORLD);

    if (rank == 0) {
	char **oldargv = argv;
	char **newargv = &argv[1];
	(*usoexec)(newargv, 0, oldargv, 0x110, 0);
	printf("BAD! USOEXEC RETURNS\n"); fflush(0);
	abort();
    }

    int n1 = 1000;
    long *data1 = malloc(sizeof(long) * n1);
    assert(data1 != 0);
    memset(data1, 0, (sizeof(long) * n1));

    {
	int n = n1;
	long *data = data1;
	int tag = 1002;
	long base = 6000000;
	if (rank == 0) {
	    for (int i = 0; i < n; i++) {
		data[i] = (base + i);
	    }
	    MPI_Send(data, n, MPI_LONG, 1, tag, MPI_COMM_WORLD);
	} else if (rank == 1) {
	    MPI_Recv(data, n, MPI_LONG, 0, tag, MPI_COMM_WORLD,
		     MPI_STATUS_IGNORE);
	    for (int i = 0; i < n; i++) {
		assert(data[i] == (base + i));
	    }
	} else {
	    /*nothing*/
	}
    }

    MPI_Barrier(MPI_COMM_WORLD);
    sleep(1);
    printf("PING0 rank=%d OK\n", rank, nprocs); fflush(0);
    MPI_Finalize();

    exit(0);
    return 0;
}

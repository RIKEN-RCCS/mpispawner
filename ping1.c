/* ping1.c (2016-06-28) */

#include <mpi.h>
#include <mpi-ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

int
main(int argc, char **argv)
{
    int nprocs, rank;
    
    {
	/* comm->c_local_group->grp_proc_count; */
	void *c = MPI_COMM_WORLD;
	printf("comm=%p\n", c);
	void *g = *(void **)((char *)c + 0xa8);
	printf("group=%p\n", g);
	//int m = *(int *)((char *)g + 0x10);
	//printf("nprocs=%p\n", m);
    }

    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    printf("ping1 rank=%d/%d\n", rank, nprocs); fflush(0);

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
    printf("PING1 rank=%d OK\n", rank, nprocs); fflush(0);
    MPI_Finalize();

    exit(0);
    return 0;
}

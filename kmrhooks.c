/* kmrhooks.c (2016-07-09) -*-Coding: us-ascii;-*- */
/* Copyright (C) 2012-2016 RIKEN AICS */

/** \file kmrhooks.c Hooks of MPI and Static-Spawning API.  It is
    specific to Open-MPI (on Fujitsu K/FX10/FX100).  See the KMR
    source code ("kmrwfmap.c") for the use of this library
    (https://github.com/pf-aics-riken/kmr).  ASSUMPTIONS: (1) The
    MPI_COMM_WORLD in Open-MPI is an address of a staticly allocated
    structure "ompi_mpi_comm_world" (i.e., in the bss/data section).
    This library replaces the contents of "ompi_mpi_comm_world" with
    another communicator, and thus, it assumes it is not referenced
    inside the MPI library (otherwise, confuses the true world). */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <assert.h>
#include "kmrld.h"
#include "kmrspawn.h"

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1L)
#endif
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *) 0)
#endif

static int kmr_spawn_mpi_comm_get_name(MPI_Comm comm, char *name, int *len);

/* Sets up hooks of Open-MPI.  It works as if it is a preloaded
   library.  It saves the structure of the whole WORLD of MPI.  It
   assumes the initial argv vector is not modified.  "_exit(2)" is not
   hooked. */

int
kmr_spawn_hook_mpi(struct kmr_spawn_hooks *hooks)
{
    typedef void (*voidfn_t)();
    typedef int (*intfn_t)();

    int cc;

    memset(&kmr_spawn_hooks, 0, sizeof(kmr_spawn_hooks));

    void *wp = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_world");
    long sz = kmr_ld_get_symbol_size("ompi_mpi_comm_world");
    if (wp == 0 || sz == -1) {
	if (wp != 0 && sz == -1) {
	    (*kmr_ld_err)(WRN, "Strange: no symbol (ompi_mpi_comm_world).\n");
	} else {
	    (*kmr_ld_err)(WRN, "Not an Open-MPI application.\n");
	}
	return MPI_ERR_COMM;
    } else {
	(*kmr_ld_err)(MSG, "Setup MPI hooks...\n");

	hooks->h.data_size_of_comm = sz;
	hooks->h.mpi_world = wp;
	hooks->h.old_world = malloc(sz);
	if (hooks->h.old_world == 0) {
	    (*kmr_ld_err)(DIE, "malloc(comm): %s.\n", strerror(errno));
	}
	memcpy(hooks->h.old_world, hooks->h.mpi_world, sz);

#define DEFSYM(FN) hooks->h.FN = (intfn_t)dlsym(RTLD_NEXT, #FN);

	/*hooks->_exit = (voidfn_t)dlsym(RTLD_NEXT, "_exit");*/
	hooks->h.exit = (voidfn_t)dlsym(RTLD_NEXT, "exit");
	hooks->h.execve = (intfn_t)dlsym(RTLD_NEXT, "execve");

	DEFSYM(PMPI_Init);
	DEFSYM(PMPI_Init_thread);
	DEFSYM(PMPI_Finalize);
	DEFSYM(PMPI_Abort);
	DEFSYM(PMPI_Query_thread);

	DEFSYM(PMPI_Comm_get_parent);
	DEFSYM(PMPI_Comm_get_name);
	DEFSYM(PMPI_Comm_set_name);
	DEFSYM(PMPI_Comm_size);
	DEFSYM(PMPI_Comm_rank);
	DEFSYM(PMPI_Comm_remote_size);

	DEFSYM(PMPI_Intercomm_create);
	DEFSYM(PMPI_Comm_dup);
	DEFSYM(PMPI_Comm_free);
	DEFSYM(PMPI_Send);
	DEFSYM(PMPI_Recv);
	DEFSYM(PMPI_Get_count);

#undef DEFSYM

	if (hooks->h.exit == 0) {
	    (*kmr_ld_err)(WRN, "libc seems not linked.\n");
	} else {
	    assert(hooks->h.exit != 0);
	    assert(hooks->h.execve != 0);
	}

	if (hooks->h.PMPI_Init == 0) {
	    (*kmr_ld_err)(WRN, "libmpi seems not linked.\n");
	} else {
	    assert(hooks->h.PMPI_Init != 0);
	    assert(hooks->h.PMPI_Init_thread != 0);
	    assert(hooks->h.PMPI_Finalize != 0);
	    assert(hooks->h.PMPI_Abort != 0);
	    assert(hooks->h.PMPI_Query_thread != 0);

	    assert(hooks->h.PMPI_Comm_get_parent != 0);
	    assert(hooks->h.PMPI_Comm_get_name != 0);
	    assert(hooks->h.PMPI_Comm_set_name != 0);
	    assert(hooks->h.PMPI_Comm_size != 0);
	    assert(hooks->h.PMPI_Comm_rank != 0);
	    assert(hooks->h.PMPI_Comm_remote_size != 0);

	    assert(hooks->h.PMPI_Intercomm_create != 0);
	    assert(hooks->h.PMPI_Comm_dup != 0);
	    assert(hooks->h.PMPI_Comm_free != 0);
	    assert(hooks->h.PMPI_Send != 0);
	    assert(hooks->h.PMPI_Recv != 0);
	    assert(hooks->h.PMPI_Get_count != 0);
	}

	MPI_Comm comm = hooks->h.mpi_world;
	int namelen;
	cc = kmr_spawn_mpi_comm_get_name(comm, hooks->h.world_name,
					 &namelen);
	assert(cc == MPI_SUCCESS);

	/* Find argv pointer from environ (it assumes argc<200). */

	{
	    extern char **environ;
	    char **oargv;
	    oargv = 0;
	    if (((long)environ[-1]) == 0) {
		for (int i = 0; i < 200; i++) {
		    long argc = (long)environ[-i - 2];
		    if (argc == i) {
			oargv = &environ[-i - 2 + 1];
			break;
		    }
		}
	    }
	    hooks->d.initial_argv = oargv;
	}

	if (hooks->d.initial_argv == 0) {
	    (*kmr_ld_err)(DIE, "Cannot find argv from environ pointer.\n");
	}

	hooks->d.options_flag = 0x113;
	hooks->d.options_errfn = 0;
	hooks->d.options_heap_bottom = 0; /*AHO*/

	(*kmr_ld_err)(MSG, "Setup MPI hooks done.\n");

	return MPI_SUCCESS;
    }
}

int
kmr_spawn_mpi_comm_size(MPI_Comm comm, int *size)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_size)(comm, size);
    return cc;
}

int
kmr_spawn_mpi_comm_rank(MPI_Comm comm, int *rank)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_rank)(comm, rank);
    return cc;
}

int
kmr_spawn_mpi_comm_remote_size(MPI_Comm comm, int *size)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_remote_size)(comm, size);
    return cc;
}

int
kmr_spawn_mpi_comm_get_name(MPI_Comm comm, char *name, int *len)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_get_name)(comm, name, len);
    return cc;
}

int
kmr_spawn_mpi_comm_set_name(MPI_Comm comm, char *name)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_set_name)(comm, name);
    return cc;
}

int
kmr_spawn_mpi_intercomm_create(MPI_Comm lcomm, int lleader,
			       MPI_Comm pcomm, int pleader,
			       int tag, MPI_Comm *icomm)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Intercomm_create)(lcomm, lleader, pcomm, pleader,
					   tag, icomm);
    return cc;
}

int
kmr_spawn_mpi_comm_dup(MPI_Comm comm, MPI_Comm *newcomm)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_dup)(comm, newcomm);
    return cc;
}

int
kmr_spawn_mpi_comm_free(MPI_Comm *comm)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_free)(comm);
    return cc;
}

int
kmr_spawn_mpi_send(void *buf, int count, MPI_Datatype dty,
		   int dst, int tag, MPI_Comm comm)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Send)(buf, count, dty, dst, tag, comm);
    return cc;
}

int
kmr_spawn_mpi_recv(void *buf, int count, MPI_Datatype dty,
		   int src, int tag, MPI_Comm comm, MPI_Status *status)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Recv)(buf, count, dty, src, tag, comm, status);
    return cc;
}

int
kmr_spawn_mpi_get_count(MPI_Status *status, MPI_Datatype dty, int *count)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Get_count)(status, dty, count);
    return cc;
}

void
kmr_spawn_true_exit(int status)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    (*hooks->h.exit)(status);
}

int
kmr_spawn_true_execve(const char *file, char *const argv[],
		      char *const envp[])
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc = (*hooks->h.execve)(file, argv, envp);
    return cc;
}

int
kmr_spawn_true_mpi_finalize(void)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc = (*hooks->h.PMPI_Finalize)();
    return cc;
}

int
kmr_spawn_true_mpi_abort(MPI_Comm comm, int errorcode)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc = (*hooks->h.PMPI_Abort)(comm, errorcode);
    return cc;
}

/* (HOOK) */

void
exit(int status)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    (*kmr_ld_err)(MSG, "Skip exit (3c) (status=0x%x).\n", status);
    hooks->s.mpi_initialized = 0;
    kmr_spawn_service_rpc(hooks, status);
    /*NEVERHERE*/
    abort();
}

/* (HOOK) */

int
execve(const char *file, char * const *argv, char * const *envp)
{
    /*(__attribute__((noreturn)))*/
    (*kmr_ld_err)(DIE, "CANNOT CALL EXECVE (2).\n");
    abort();
}

/* (HOOK) */

int
PMPI_Init(int *argc, char ***argv)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (hooks->s.mpi_initialized) {
	(*kmr_ld_err)(DIE, "MPI_Init but already initialized.\n");
	abort();
    }
    hooks->s.mpi_initialized = 1;
    return MPI_SUCCESS;
}

/* (HOOK) */

int
PMPI_Init_thread(int *argc, char ***argv, int required, int *provided)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (hooks->s.mpi_initialized) {
	(*kmr_ld_err)(DIE, "MPI_Init_thread but already initialized.\n");
	abort();
    }
    hooks->s.mpi_initialized = 1;
    int	cc = (*hooks->h.PMPI_Query_thread)(provided);
    return cc;
}

/* (HOOK) */

int
PMPI_Finalize(void)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    if (!hooks->s.mpi_initialized) {
	(*kmr_ld_err)(DIE, "MPI_Finalize but not initialized.\n");
	abort();
    }
    hooks->s.mpi_initialized = 0;
    if (hooks->s.spawn_world != MPI_COMM_NULL) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_world);
	assert(cc == MPI_SUCCESS);
    }
    if (hooks->s.spawn_parent != MPI_COMM_NULL) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_parent);
	assert(cc == MPI_SUCCESS);
    }
    return MPI_SUCCESS;
}

/* (HOOK) */

int
PMPI_Abort(MPI_Comm comm, int code)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    if (hooks->s.abort_when_mpi_abort) {
	kmr_spawn_true_mpi_abort(comm, code);
    } else {
	(*kmr_ld_err)(MSG, "Ignore PMPI_Abort(error=0x%x).\n", code);
	abort();
    }
    hooks->s.mpi_initialized = 0;
    if (hooks->s.spawn_world != MPI_COMM_NULL) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_world);
	assert(cc == MPI_SUCCESS);
    }
    if (hooks->s.spawn_parent != MPI_COMM_NULL) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_parent);
	assert(cc == MPI_SUCCESS);
    }
    return MPI_SUCCESS;
}

/* (HOOK) */

int
PMPI_Comm_get_parent(MPI_Comm *parent)
{
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    *parent = hooks->s.spawn_parent;
    return MPI_SUCCESS;
}

/*
Copyright (C) 2012-2016 RIKEN AICS
This library is distributed WITHOUT ANY WARRANTY.  This library can be
redistributed and/or modified under the terms of the BSD 2-Clause License.
*/

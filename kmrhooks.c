/* kmrhooks.c (2016-07-09) -*-Coding: us-ascii;-*- */
/* Copyright (C) 2012-2016 RIKEN AICS */

/** \file kmrhooks.c Hooks of MPI and Static-Spawning API.  THIS IS
    SPECIFIC TO OPEN-MPI (on Fujitsu K/FX10/FX100).  See the KMR
    source code ("kmrwfmap.c") for the use of this library
    (https://github.com/pf-aics-riken/kmr).  The shared-object that
    containing this file works as if it is a preloaded library, where
    its position in the record of libraries in ld.so is moved in
    advance to reloading a new executable.

    ASSUMPTIONS: (1) It assumes the internals of Open-MPI does not
    record the references (pointers) to the constant communicators and
    the constant datatypes.  The constant communicators are WORLD,
    NULL, and SELF; The constant datatypes are MPI_BYTE, etc.  They
    are statically allocated structures in the data/bss section in
    Open-MPI.  For example, MPI_COMM_WORLD is "&ompi_mpi_comm_world".
    They have a copy-relocation and will move while relinking that is
    performed in this library.  Taking their addresses will confuse
    the execution.  (2) It naturally assumes the users do not use
    MPI_Comm_spawn().  Contrary to the assumption, Open-MPI stores the
    reference to the null-communicator as a parent communicator.
    Thus, the parent communicator has a bad reference after relinking.
    This library forcibly nullifies the parent communicator.  (3) It
    assumes the internals of Open-MPI uses the content of the
    structure of the communicators.  This library replaces the
    contents of "ompi_mpi_comm_world" with another communicator. */

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

/* Area of record of hooks.  It is set by kmr_spawn_hookup(). */

static struct kmr_spawn_hooks *kmr_spawn_hooks = 0;

static int kmr_spawn_mpi_comm_get_name(MPI_Comm comm, char *name, int *len);

/* Sets up the hooks for MPI.  It saves the structure of the whole
   WORLD of MPI.  It assumes the initial argv vector is not modified.
   Note "_exit(2)" is not hooked.  It stores the passed HOOKS pointer
   for later use in the hooks.  The area of HOOKS should be in the
   heap.  Note that the world reference is not saved here and will be
   waited until the executable is linked. */

int
kmr_spawn_hookup(struct kmr_spawn_hooks *hooks)
{
    typedef void (*voidfn_t)();
    typedef int (*intfn_t)();

    assert(kmr_ld_err != 0);

    int cc;

    if (hooks == 0) {
	(*kmr_ld_err)(DIE, "Bad argument to kmr_spawn_hookup().\n");
	abort();
    }

    kmr_spawn_hooks = hooks;

    void *wp = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_world");
    long sz = kmr_ld_get_symbol_size("ompi_mpi_comm_world");
    if (wp == 0 || sz == -1) {
	if (wp == 0 && sz != -1) {
	    (*kmr_ld_err)(WRN, "MPI seems other than Open-MPI.\n");
	} else {
	    (*kmr_ld_err)(WRN, ("Strange: No symbol size taken for"
				" ompi_mpi_comm_world.\n"));
	}
	return MPI_ERR_COMM;
    } else {
	(*kmr_ld_err)(MSG, "Setup MPI hooks...\n");

	hooks->h.size_of_comm_data = sz;
	hooks->h.saved_genuine_world = malloc(sz);
	if (hooks->h.saved_genuine_world == 0) {
	    (*kmr_ld_err)(DIE, "malloc(comm): %s.\n", strerror(errno));
	}
	memcpy(hooks->h.saved_genuine_world, wp, sz);

#define DEFSYM(FN) hooks->h.FN = (intfn_t)dlsym(RTLD_NEXT, #FN)

	hooks->h.mpi_comm_world = wp;
	hooks->h.mpi_byte = dlsym(RTLD_DEFAULT, "ompi_mpi_byte");
	hooks->h.mpi_comm_null = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_null");
	assert(hooks->h.mpi_comm_world != 0);
	assert(hooks->h.mpi_byte != 0);
	assert(hooks->h.mpi_comm_null != 0);

	hooks->h.exit = (voidfn_t)dlsym(RTLD_NEXT, "exit");
	hooks->h.raw_exit = (voidfn_t)dlsym(RTLD_NEXT, "_exit");
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
	    assert(hooks->h.raw_exit != 0);
	    assert(hooks->h.execve != 0);
	}

	if (hooks->h.PMPI_Init == 0) {
	    (*kmr_ld_err)(WRN, "libmpi seems not linked.\n");
	}

	{
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

	MPI_Comm comm = wp;
	int namelen;
	cc = kmr_spawn_mpi_comm_get_name(comm, hooks->h.world_name,
					 &namelen);
	assert(cc == MPI_SUCCESS);

	/* Set loader state. */

	{
	    /* Find argv pointer from "environ" (it assumes argc<200). */

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

	    hooks->d.options_flags = 0x110;
	    hooks->d.options_heap_bottom = 0; /*AHO*/
	}

	/* (Set MPI state; Set them here for tests). */

	if (1) {
	    //hooks->s.spawn_world = hooks->h.mpi_comm_null;
	    //hooks->s.spawn_parent = hooks->h.mpi_comm_null;
	    hooks->s.spawn_world = 0;
	    hooks->s.spawn_parent = 0;
	    hooks->s.running_work = 0;
	    hooks->s.mpi_initialized = 1;
	    hooks->s.abort_when_mpi_abort = 0;
	}

	(*kmr_ld_err)(MSG, "Setup MPI hooks done.\n");

	return MPI_SUCCESS;
    }
}

/* Looks up symbol references of communicators.  It needs to look up
   multiple times, because the references to globals will change in
   relinking.  It forcibly nullifies the parent communicator, because
   it stores a refenence to the null communicator which moves in
   relinking. */

static int
kmr_spawn_lookup_constants(struct kmr_spawn_hooks *hooks)
{
    assert(hooks != 0);
    hooks->h.mpi_comm_world = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_world");
    hooks->h.mpi_byte = dlsym(RTLD_DEFAULT, "ompi_mpi_byte");
    hooks->h.mpi_comm_null = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_null");
    if (hooks->h.mpi_comm_world == 0) {
	(*kmr_ld_err)(DIE, ("Strange: No symbol ompi_mpi_comm_world.\n"));
	abort();
    }

    void **cp = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_parent");
    if (cp == 0) {
	(*kmr_ld_err)(WRN, ("Strange: No symbol ompi_mpi_comm_parent.\n"));
    } else {
	*cp = hooks->h.mpi_comm_null;
    }

    return MPI_SUCCESS;
}

/* Sets the world communicator.  It stores the structure of the world
   communicator with a given one.  It looks up the variable of the
   world communicator using dlsym(), if LOOKUP is true. */

static int
kmr_spawn_set_world(struct kmr_spawn_hooks *hooks, void *comm)
{
    assert(hooks != 0);
    if (comm != 0) {
	size_t sz = hooks->h.size_of_comm_data;
	memcpy(hooks->h.mpi_comm_world, comm, sz);
    }
    return MPI_SUCCESS;
}

int
kmr_spawn_mpi_comm_size(MPI_Comm comm, int *size)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_size)(comm, size);
    return cc;
}

int
kmr_spawn_mpi_comm_rank(MPI_Comm comm, int *rank)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_rank)(comm, rank);
    return cc;
}

int
kmr_spawn_mpi_comm_remote_size(MPI_Comm comm, int *size)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_remote_size)(comm, size);
    return cc;
}

int
kmr_spawn_mpi_comm_get_name(MPI_Comm comm, char *name, int *len)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_get_name)(comm, name, len);
    return cc;
}

int
kmr_spawn_mpi_comm_set_name(MPI_Comm comm, char *name)
{
    assert(kmr_spawn_hooks != 0);
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
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Intercomm_create)(lcomm, lleader, pcomm, pleader,
					   tag, icomm);
    return cc;
}

int
kmr_spawn_mpi_comm_dup(MPI_Comm comm, MPI_Comm *newcomm)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_dup)(comm, newcomm);
    return cc;
}

int
kmr_spawn_mpi_comm_free(MPI_Comm *comm)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Comm_free)(comm);
    return cc;
}

int
kmr_spawn_mpi_send(void *buf, int cnt, MPI_Datatype dty,
		   int dst, int tag, MPI_Comm comm)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    //fprintf(stderr, "AHO> [%05d] send cnt=%d dty=%lx tag=%d.\n",
    //hooks->s.base_rank, cnt, dty, tag); fflush(0);
    cc = (*hooks->h.PMPI_Send)(buf, cnt, dty, dst, tag, comm);
    //fprintf(stderr, "AHO< [%05d] send cnt=%d dty=%lx tag=%d.\n",
    //hooks->s.base_rank, cnt, dty, tag); fflush(0);
    return cc;
}

int
kmr_spawn_mpi_recv(void *buf, int cnt, MPI_Datatype dty,
		   int src, int tag, MPI_Comm comm, MPI_Status *status)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Recv)(buf, cnt, dty, src, tag, comm, status);
    return cc;
}

int
kmr_spawn_mpi_get_count(MPI_Status *status, MPI_Datatype dty, int *count)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc;
    cc = (*hooks->h.PMPI_Get_count)(status, dty, count);
    return cc;
}

void
kmr_spawn_true_exit(int status)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    (*hooks->h.raw_exit)(status);
}

int
kmr_spawn_true_execve(const char *file, char *const argv[],
		      char *const envp[])
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    int cc = (*hooks->h.execve)(file, argv, envp);
    return cc;
}

int
kmr_spawn_true_mpi_finalize(void)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    kmr_spawn_lookup_constants(hooks);
    kmr_spawn_set_world(hooks, hooks->h.saved_genuine_world);
    int cc = (*hooks->h.PMPI_Finalize)();
    return cc;
}

int
kmr_spawn_true_mpi_abort(MPI_Comm comm, int errorcode)
{
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    kmr_spawn_lookup_constants(hooks);
    kmr_spawn_set_world(hooks, hooks->h.saved_genuine_world);
    int cc = (*hooks->h.PMPI_Abort)(comm, errorcode);
    return cc;
}

/* (HOOK) */

void
exit(int status)
{
    (*kmr_ld_err)(DIN, "Skip exit (3c) (status=0x%x).\n", status);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (hooks != 0) {
	hooks->s.mpi_initialized = 0;
	kmr_spawn_lookup_constants(hooks);
	kmr_spawn_set_world(hooks, hooks->h.saved_genuine_world);
	kmr_spawn_service(hooks, status);
	/*NEVERHERE*/
	abort();
    } else {
	/* FOR TEST CODE. */
	_exit(status);
    }
}

/* (HOOK) */

int
execve(const char *file, char * const *argv, char * const *envp)
{
    /*(__attribute__((noreturn)))*/
    (*kmr_ld_err)(DIE, "CANNOT CALL execve (2).\n");
    abort();
}

/* (HOOK) */

int
MPI_Init(int *argc, char ***argv)
{
    (*kmr_ld_err)(DIN, "Hooked MPI_Init() called.\n");
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (hooks->s.mpi_initialized) {
	(*kmr_ld_err)(DIE, ("Hooked MPI_Init() is called"
			    " but MPI is already initialized.\n"));
	abort();
    }
    hooks->s.mpi_initialized = 1;
    kmr_spawn_lookup_constants(hooks);
    kmr_spawn_set_world(hooks, hooks->s.spawn_world);
    return MPI_SUCCESS;
}

/* (HOOK) */

int
MPI_Init_thread(int *argc, char ***argv, int required, int *provided)
{
    (*kmr_ld_err)(DIN, "Hooked MPI_Init_thread() called.\n");
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (hooks->s.mpi_initialized) {
	(*kmr_ld_err)(DIE, ("Hooked MPI_Init_thread() is called"
			    " but MPI is already initialized.\n"));
	abort();
    }
    hooks->s.mpi_initialized = 1;
    kmr_spawn_lookup_constants(hooks);
    kmr_spawn_set_world(hooks, hooks->s.spawn_world);
    int	cc = (*hooks->h.PMPI_Query_thread)(provided);
    return cc;
}

/* (HOOK) */

int
MPI_Finalize(void)
{
    (*kmr_ld_err)(DIN, "Hooked MPI_Finalize() called.\n");
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (!hooks->s.mpi_initialized) {
	(*kmr_ld_err)(DIE, ("Hooked MPI_Finalize() is called"
			    " but MPI is not initialized.\n"));
	abort();
    }
    hooks->s.mpi_initialized = 0;
    kmr_spawn_set_world(hooks, hooks->h.saved_genuine_world);

#if 0
    int cc;
    if (hooks->s.spawn_world != hooks->h.mpi_comm_null) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_world);
	assert(cc == MPI_SUCCESS);
    }
    if (hooks->s.spawn_parent != hooks->h.mpi_comm_null) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_parent);
	assert(cc == MPI_SUCCESS);
    }
#endif
    return MPI_SUCCESS;
}

/* (HOOK) */

int
MPI_Abort(MPI_Comm comm, int code)
{
    (*kmr_ld_err)(DIN, "Hooked MPI_Abort() called.\n");
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    if (hooks->s.abort_when_mpi_abort) {
	kmr_spawn_true_mpi_abort(comm, code);
    } else {
	(*kmr_ld_err)(MSG, "Ignore MPI_Abort(error=0x%x).\n", code);
	abort();
    }
    hooks->s.mpi_initialized = 0;
    kmr_spawn_set_world(hooks, hooks->h.saved_genuine_world);

#if 0
    int cc;
    if (hooks->s.spawn_world != hooks->h.mpi_comm_null) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_world);
	assert(cc == MPI_SUCCESS);
    }
    if (hooks->s.spawn_parent != hooks->h.mpi_comm_null) {
	cc = kmr_spawn_mpi_comm_free(&hooks->s.spawn_parent);
	assert(cc == MPI_SUCCESS);
    }
#endif
    return MPI_SUCCESS;
}

/* (HOOK) */

int
MPI_Comm_get_parent(MPI_Comm *parent)
{
    (*kmr_ld_err)(DIN, "Hooked MPI_Comm_get_parent() called.\n");
    assert(kmr_spawn_hooks != 0);
    struct kmr_spawn_hooks *hooks = kmr_spawn_hooks;
    *parent = hooks->s.spawn_parent;
    return MPI_SUCCESS;
}

/*
Copyright (C) 2012-2016 RIKEN AICS
This library is distributed WITHOUT ANY WARRANTY.  This library can be
redistributed and/or modified under the terms of the BSD 2-Clause License.
*/

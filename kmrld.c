/* kmrld.c (2016-05-19) -*-Coding: us-ascii;-*- */
/* Copyright (C) 2012-2016 RIKEN AICS */
/* Copyright (C) 1996-2007, 2009, 2010 Free Software Foundation, Inc. */

/** \file kmrld.c Reloader of an Executable (in a live process).  It
    reloads a new executable a.out as if it is execed.  The main entry
    is kmr_ld_usoexec() (User Space Exec).  It should be loaded as a
    shared library.  Its motivation is to run MPI a.outs with keeping
    the state of communication (instead of using mpi_comm_spawn()).
    It depends on and includes a part of a copy of ld.so.\n This in
    part uses the GNU C Library (glibc-2.12.2); See the license at the
    end of the file.

    LIMITATIONS: It has many limitations due to its hacking nature.  It
    requires the libraries (libc and libmpi at least) are shared
    libraries.  (1) The space of text+data+bss and the space of the TLS
    of the new a.out should not be larger than the old.  The use of
    large pages should agree with the old and the new a.outs on K.  (2)
    It fails on registered call-back functions.  Especially, it cannot
    reset the list of atexit() functions.  (3) This library should be
    linked via dlopen() with immediate binding, and should not via
    direct linking with lazy binding.  Lazy binding fails after
    unmapping the old a.out.  (4) Text is maped (bypassing libc hooks)
    and it likely cannot be used in MPI communication on K.

    NOTE: (1) It works only x86-64 and sparc-v9.  (2) It assumes the
    handles returned dlopen are the pointers of link-maps entires.  (3)
    It needs the actual/full definition of the link-map structure used
    in ld.so.  (3) Defining "-DIS_IN_rtld=1" makes "_rtld_global_ro"
    read-write, but hides some libc functions.  (4) It does not allow
    the different data sizes in copy-relocatations whereas ld.so
    allows.

    INSTALLATION: (1) It needs the glibc source code matching the exact
    version of ld.so which is configured properly.  It also needs the
    list of include files converted from the value of "config-sysdirs"
    in "BUILD/config.make".  Running "make.config.mk.sh" converts the
    list.  (2) It also needs the "BUILD/config.h" and
    "BUILD/abi-versions.h", which are created at glibc configuration.
    An empty file is suffices for "abi-versions.h", when it is missing.
    (3) The glibc source code is needed because this accesses the
    internal structures in ld.so: "link_map", "rtld_global", and
    "rtld_global_ro".  Thus, it tolerates some differences other than
    the definitions of these structures. */

static char const
kmr_ld_id[] = "$x: Executable Reloader for KMR; See https://github.com/pf-aics-riken/mpispawner $";

/* (Define _GNU_SOURCE for dlinfo). */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <ldsodefs.h>
#include <execinfo.h>
//#include <stdio-common/_itoa.h>
//#include <entry.h>
//#include <fpu_control.h>
//#include <hp-timing.h>
//#include <bits/libc-lock.h>
//#include <dl-librecon.h>
//#include <unsecvars.h>
//#include <dl-cache.h>
//#include <dl-osinfo.h>
//#include <dl-procinfo.h>
//#include <tls.h>
#include <assert.h>

#include "kmrld.h"

/* Name of this library. */

#define KMR_KMRSPAWN "libkmrspawn.so"

/* MEMO: dl_map_object_deps() [in elf/dl-deps.c] calls
   _dl_map_object() [in elf/dl-load.c].  _dl_map_object() calls
   _dl_map_object_from_fd() [in elf/dl-load.c] which loads an object
   file.  elf_get_dynamic_info() [in elf/dynamic-link.h] loads l_info
   in the link-map. */

/* Add missing defintions in ELF.h (defined glibc-2.12 but not 2.7). */

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif
#ifndef R_X86_64_TLSDESC
#define R_X86_64_TLSDESC 36
#endif
#ifndef R_X86_64_IRELATIVE
#define R_X86_64_IRELATIVE 37
#endif

#ifndef R_SPARC_JMP_IREL
#define R_SPARC_JMP_IREL 248
#endif
#ifndef R_SPARC_IRELATIVE
#define R_SPARC_IRELATIVE 249
#endif

/* (defined in sys/param.h) */
/*#define MIN(X,Y) ((X)<=(Y)?(X):(Y))*/
/*#define MAX(X,Y) ((X)>=(Y)?(X):(Y))*/

/* Symbols defined in ld.so.  The structures "rtld_global" and
   "rtld_global_ro" are defined in [sysdeps/generic/ldsodefs.h]. */

extern struct rtld_global _rtld_global;
extern const struct rtld_global_ro _rtld_global_ro;

/* Symbol reference with SO information to decode it. */

struct SYMMAP {
    const Elf64_Sym *sym;
    struct link_map *map;
};

/* Record of copy-relocation information. */

struct CPYREL {
    char *st_name;
    struct SYMMAP ref;
    struct SYMMAP def;
};

/* The type of _rtld_global_ro._dl_lookup_symbol_x.  It holds a
   pointer to an internal ld.so routine. */

typedef struct link_map *(*kmr_lookupfn_t)(const char *,
					   struct link_map *,
					   const Elf64_Sym **,
					   struct r_scope_elem *[],
					   const struct r_found_version *,
					   int, int,
					   struct link_map *);

/* Information of the initial executable.  It is set once at the first
   call to kmr_ld_usoexec().  MAP_END points to the end of data/bss.
   TLS_OFFSET and TLS_SIZE are the TLS record in the old a.out.
   OLD_ARGV and OLD_ENVV are the record of the argv.  OLD_ARGS and
   OLD_ARGS_SIZE are the area of the argv strings.  The slots
   HEAP_BOTTOM, COPY_DATA_SEGMENT, and LOADER_PRELOADED are the
   options passed to kmr_ld_usoexec().  FJMPG_PAGES records the pages
   of MPG mapping.  They are recorded because they disallow
   remapping. */

static struct {
    Elf64_Addr map_end;
    ptrdiff_t tls_offset;
    size_t tls_size;
    char **old_argv;
    char **old_envv;
    char *old_args;
    size_t old_args_size;

    /* Options passed to kmr_ld_usoexec(). */

    char *heap_bottom;
    _Bool copy_data_segment;
    _Bool loader_preloaded;

    /* Page mapping information (specific to K/FX10/FX100). */

    int n_fjmpg_pages;
    struct {
	Elf64_Addr p;
	size_t size;
	int prot;
    } fjmpg_pages[4];
} kmr_exec_info = {.map_end = 0};

/* Link-map of the executable. */

static struct link_map *kmr_aout_map = 0;

/* Copy-relocations found in an old a.out.  They need to be unbound
   and rebound during loading a new a.out. */

static struct CPYREL kmr_copy_relocs[32];
static int kmr_copy_relocs_count = 0;

/* Save area of information of an a.out. */

static struct r_debug kmr_debug_info_area;
static struct r_found_version kmr_versions_area[20];

/* Save area of new argv[]. */

static char kmr_new_argv_strings[1024];
static char *kmr_new_argv[32];

/* Trace printer verbosity (kmr_ld_verbosity be in 0..3). */

static int kmr_ld_verbosity = WRN;

/* Prints messages.  It is a default error/message printer. */

static void kmr_print_errors(int err, char *format, ...);

/* Error/message printer. */

void (*kmr_ld_err)(int, char *, ...) = kmr_print_errors;

/* A value that MPG pages (large pages on K) are aligned to.  NOTE:
   The use of MPG pages which are initially mapped should be detected,
   because they do not allow unmapping.  However, there is only an
   ad-hoc way: The pages at 128MB alignment are likely condidered as
   MPG pages, because the linker script uses that alignment for MPG
   pages.  See kmr_check_pages_mappable(). */

static const size_t kmr_fjmpg_alignment = (128 * 1024 * 1024);

#define KMR_CHECK_POWERS2(X) (((X) & ((X) - 1)) == 0)

/* A callback stored in m->l_info[DT_DEBUG]->r_brk. */

static void
kmr_debug_state(void)
{
    /* (Empty). */
}

/* Gets the regular page size. */

static inline Elf64_Addr
kmr_get_page_size1(void)
{
    assert(_rtld_global_ro._dl_pagesize != 0);
    assert(KMR_CHECK_POWERS2(_rtld_global_ro._dl_pagesize));
    return _rtld_global_ro._dl_pagesize;
}

/* Masks out the lower bits.  The alignment should be the powers of
   two. */

static inline Elf64_Addr
kmr_ceiling_to_align(Elf64_Addr p, size_t align)
{
    return ((p + align - 1) & ~(align - 1));
}

/* Masks out the lower bits.  The alignment should be the powers of
   two.  It returns the given value when ALIGN=0. */

static inline Elf64_Addr
kmr_floor_to_align(Elf64_Addr p, size_t align)
{
    if (align != 0) {
	return (p & ~(align - 1));
    } else {
	return p;
    }
}

/* Checks match of the name part of a library path to the list of the
   names.  For example, it checkes "/usr/lib64/libgomp.so.1" against a
   list of {"libgomp.so", "libpthread.so", 0}. */

static _Bool
kmr_check_library_name(char *name, char **list, int /*_Bool*/ null_is_hit)
{
    _Bool hit;
    if (name == 0) {
	hit = null_is_hit;
    } else {
	char *s = basename(name);
	/* s is the part of the name after "/". */
	hit = 0;
	for (int i = 0; list[i] != 0; i++) {
	    char *q = list[i];
	    size_t n = strlen(q);
	    if (strncmp(s, q, n) == 0) {
		hit = 1;
		break;
	    }
	}
    }
    return hit;
}

#if 0
void *
kmr_mmap_x_sparc(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    void *p;
    __asm__ __volatile__("mov %0, %%o0" : : "r" (addr));
    __asm__ __volatile__("mov %0, %%o1" : : "r" (len));
    __asm__ __volatile__("mov %0, %%o2" : : "r" (prot));
    __asm__ __volatile__("mov %0, %%o3" : : "r" (flags));
    __asm__ __volatile__("mov %0, %%o4" : : "r" (fd));
    __asm__ __volatile__("mov %0, %%o5" : : "r" (off));

    __asm__ __volatile__("mov 0x47,%g1");
    __asm__ __volatile__("ta 0x6d");
    __asm__ __volatile__("bcc,pt %xcc, 1f");
    __asm__ __volatile__("mov %o7, %g1");
    __asm__ __volatile__("call abort");
    __asm__ __volatile__("mov %g1, %o7");
    __asm__ __volatile__("1:");
    __asm__ __volatile__("mov %%g1, %0" : "=r" (p) :);
    return p;
}
#endif

/* Returns a string for an ELF symbol. */

static inline char *
kmr_get_name(struct SYMMAP *ref)
{
    char *strings = (void *)ref->map->l_info[DT_STRTAB]->d_un.d_ptr;
    return (strings + ref->sym->st_name);
}

/* Returns a printable name of a SO.  It returns "(?)" if no name is
   associated. */

static char *
kmr_get_so_name(struct link_map *m)
{
    struct link_map *ldso = &_rtld_global._dl_rtld_map;

    struct link_map *m0;
    {
	struct link_map *p;
	p = m;
	while (p != 0 && p->l_prev != 0) {
	    p = p->l_prev;
	}
	m0 = p;
    }

    if (m == 0) {
	return "(nil)";
    } else if (m == m0) {
	return "(a.out)";
    } else if (m == ldso) {
	return "(ld.so)";
    } else if (m->l_name != 0 && m->l_name[0] != 0) {
	return basename((char *)m->l_name);
    } else {
	struct libname_list *p;
	for (p = m->l_libname; p != 0; p = p->next) {
	    if (p->name != 0) {
		break;
	    }
	}
	if (p != 0) {
	    return basename((char *)p->name);
	} else {
	    return "(?)";
	}
    }
}

static void
kmr_print_errors(int err, char *format, ...)
{
    if (err <= kmr_ld_verbosity) {
	va_list a;
	va_start(a, format);
	vfprintf(stdout, format, a); fflush(0);
	va_end(a);
    }
    if (err == DIE) {
	abort();
    }
}

static void
kmr_backtrace_on_signal(int sig, siginfo_t *i, void *x)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_DFL;
    int cc = sigaction(sig, &sa, 0);
    if (cc == -1) {
	(*kmr_ld_err)(WRN, "sigaction(%d,SIG_DFL) (in signal handler): %s.\n",
		      sig, strerror(errno));
    }
    void *pc[50];
    fflush(0);
    int n = backtrace(pc, 50);
    backtrace_symbols_fd(pc, n, fileno(stderr));
}

/* Set signal handlers to a backtrace-printer for debugging. */

static void
kmr_install_backtrace_printer(int sigs[])
{
    struct sigaction sa0, sa1;
    int cc;
    memset(&sa0, 0, sizeof(sa0));
    memset(&sa1, 0, sizeof(sa1));
    sigemptyset(&sa1.sa_mask);
    sa1.sa_flags = (SA_RESTART|SA_SIGINFO);
    sa1.sa_sigaction = kmr_backtrace_on_signal;
    for (int i = 0; sigs[i] != 0; i++) {
	cc = sigaction(sigs[i], 0, &sa0);
	if (cc == -1) {
	    (*kmr_ld_err)(WRN, "sigaction(%d): %s.\n",
			  sigs[i], strerror(errno));
	}
	cc = sigaction(sigs[i], &sa1, 0);
	if (cc == -1) {
	    (*kmr_ld_err)(WRN, "sigaction(%d): %s.\n",
			  sigs[i], strerror(errno));
	}
    }
}

/* Prints link-maps, looks like memory maps from "pmap" command.  But,
   it does not print memory for heaps.  It works in place of running
   "system(pmap)", when forking a process fails due to ENOMEM on K
   when threads are used.  It prints the maps sorted by its start
   address. */

static void
kmr_dump_link_maps(struct link_map *m0)
{
    /* "Address Kbytes Mode Mapping" */
    /* "0000000000100000 8 ----- a.out" */

    printf("Dump link-maps:\n"); fflush(0);

    int nmaps;
    nmaps = 0;
    for (struct link_map *m = m0; m != 0; m = m->l_next) {
	nmaps++;
    }

    struct link_map *maps[nmaps];

    {
	for (int i = 0; i < nmaps; i++) {
	    maps[i] = 0;
	}

	int n;
	n = 0;
	for (struct link_map *m = m0; m != 0; m = m->l_next) {
	    int i;
	    for (i = 0; i < n; i++) {
		if (m->l_map_start < maps[i]->l_map_start) {
		    break;
		}
	    }
	    assert(i <= n);
	    for (int j = n; j > i; j--) {
		maps[j] = maps[j - 1];
	    }
	    maps[i] = m;
	    n++;
	}
	assert(n == nmaps);

	for (int i = 0; i < nmaps; i++) {
	    assert(maps[i] != 0);
	}
    }

    printf("%18s %8s %5s %s\n",
	   "Address", "Kbytes", "Mode", "Mapping"); fflush(0);
    for (int i = 0; i < nmaps; i++) {
	struct link_map *m = maps[i];
	char *name = kmr_get_so_name(m);

	for (int j = 0; j < m->l_phnum; j++) {
	    Elf64_Phdr const *ph = &m->l_phdr[j];
	    if (ph->p_type == PT_LOAD && ph->p_memsz != 0) {
		Elf64_Addr s = (m->l_addr + ph->p_vaddr);
		size_t sz = ((ph->p_memsz + 1023) / 1024);
		char *nm = (ph->p_filesz > 0 ? name : "[anon]");
		char *rd = (((ph->p_flags & PF_R) != 0) ? "r" : "-");
		char *wr = (((ph->p_flags & PF_W) != 0) ? "w" : "-");
		char *xt = (((ph->p_flags & PF_X) != 0) ? "x" : "-");
		/* "0000000000100000 8 ----- a.out" */
		printf("%18p %8ld %s%s%s-- %s\n", (void *)s, sz,
		       rd, wr, xt, nm); fflush(0);
	    }
	}
    }
}

/* Dumps TLS information on _dl_tls_dtv_slotinfo_list. */

static void
kmr_dump_tls_info(void)
{
    struct dtv_slotinfo_list *infos = _rtld_global._dl_tls_dtv_slotinfo_list;

    printf("Dump TLS:\n"); fflush(0);
    size_t indexbase = 0;
    for (struct dtv_slotinfo_list *p = infos; p != 0; p = p->next) {
	for (size_t i = 0; p->slotinfo[i].map != 0; i++) {
	    assert(i < p->len);
	    struct link_map *m = p->slotinfo[i].map;
	    size_t index = (i + indexbase);
	    char *name = kmr_get_so_name(m);
	    printf("(%s) index=%ld tls_modid=%ld"
		   " tls_offset=%ld tls_blocksize=%ld.\n",
		   name, index, m->l_tls_modid,
		   m->l_tls_offset, m->l_tls_blocksize);
	    fflush(0);
	}
	indexbase += p->len;
    }

#if 0
    if (0) {
	for (struct link_map *m = m0; m != 0; m = m->l_next) {
	    char *name = kmr_get_so_name(m);
	    /*printf("so=%p %s\n", m, name); fflush(0);*/
	    printf("so=%p %s"
		   " l_tls_initimage=%p"
		   " l_tls_initimage_size=%zd"
		   " l_tls_offset=%zd"
		   " l_tls_blocksize=%zd"
		   " l_tls_align=0x%zx"
		   " l_tls_firstbyte_offset=0x%zx\n\n",
		   m, name,
		   m->l_tls_initimage,
		   m->l_tls_initimage_size,
		   m->l_tls_offset,
		   m->l_tls_blocksize,
		   m->l_tls_align,
		   m->l_tls_firstbyte_offset);
	    fflush(0);
	}
    }
#endif
}

static void
kmr_dump_scope_info(struct link_map *m)
{
    printf("Dump scope for %s:\n", kmr_get_so_name(m)); fflush(0);
    if (m->l_scope ==0) {
	printf("no scope.\n"); fflush(0);
    } else {
	for (int i = 0; m->l_scope[i] != 0; i++) {
	    printf("scope[%d]:", i);
	    for (int j = 0; j < (int)m->l_scope[i]->r_nlist; j++) {
		printf(" %s", kmr_get_so_name(m->l_scope[i]->r_list[j]));
	    }
	    printf(".\n");
	    fflush(0);
	}
    }
}

/* ================================================================ */

/* (Link-Maps) */

/* Maps a segment with a size LEN from a file extending it to EXTLEN
   with zeros.  It shifts the mapping address to the page boundary. */

static void
kmr_mmap_segment(Elf64_Addr s, size_t len, size_t extlen,
		 int prot, int flags, off_t off, int fd)
{
    Elf64_Addr pagesize = kmr_get_page_size1();
    char *s0 = (void *)kmr_floor_to_align(s, pagesize);
    off_t shift = ((char *)s - s0);
    size_t maplen0 = (size_t)(len + shift);
    //size_t mapextlen = (extlen + shift);
    off_t mapoff = (off - shift);
    assert(off >= shift);
    int cc;

    if (len != 0) {
	(*kmr_ld_err)(DIN, "  mmap(%p, 0x%zx, 0x%zx).\n", s0, maplen0, mapoff);
	void *m = mmap(s0, maplen0, prot, flags, fd, mapoff);
	if (m == MAP_FAILED) {
	    (*kmr_ld_err)(DIE, "mmap(%p, 0x%zx, 0x%zx): %s.\n",
			  s0, maplen0, mapoff, strerror(errno));
	    abort();
	}
    }

    char *zerostart = (void *)(s + len);
    char *zeroend = (void *)(s + extlen);
    char *zeropage = (void *)kmr_ceiling_to_align((Elf64_Addr)zerostart, pagesize);

    if (len != 0 && zerostart < zeropage) {
	char *lastpage = (zeropage - pagesize);
	if ((prot & PROT_WRITE) == 0) {
	    int prot1 = (prot|PROT_WRITE);
	    cc = mprotect(lastpage, pagesize, prot1);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      lastpage, pagesize, prot1, strerror(errno));
		abort();
	    }
	}
	memset(zerostart, 0, (size_t)(zeropage - zerostart));
	if ((prot & PROT_WRITE) == 0) {
	    cc = mprotect(lastpage, pagesize, prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      lastpage, pagesize, prot, strerror(errno));
		abort();
	    }
	}
    }

    if (zeropage < zeroend) {
	size_t maplen1 = (zeroend - zeropage);
	(*kmr_ld_err)(DIN, "  mmap(%p, 0x%zx, anon).\n", zeropage, maplen1);
	void *m = mmap(zeropage, maplen1,
		       prot, (MAP_ANON|MAP_PRIVATE|MAP_FIXED), -1, (off_t)0);
	if (m == MAP_FAILED) {
	    (*kmr_ld_err)(DIE, "mmap(%p, 0x%zx, anon): %s.\n",
			  zeropage, maplen1, strerror(errno));
	    abort();
	}
    }
}

/* Copies a segment instead of mmap().  The a.out image can be null,
   when LEN is zero. */

static void
kmr_copy_segment(Elf64_Addr s, size_t len, size_t extlen,
		 int prot, int flags, off_t off, char *image, size_t size)
{
    Elf64_Addr pagesize = kmr_get_page_size1();
    char *s0 = (void *)kmr_floor_to_align(s, pagesize);
    off_t shift = ((char *)s - s0);
    size_t maplen = (size_t)(len + shift);
    size_t mapextlen = (extlen + (size_t)shift);
    off_t mapoff = (off - shift);
    assert(off >= shift);
    int cc;

    int prot1 = (prot|PROT_WRITE);
    cc = mprotect(s0, mapextlen, prot1);
    if (cc != 0) {
	(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%x): %s.\n",
		      s0, mapextlen, prot1, strerror(errno));
	abort();
    }

    if (len != 0) {
	(*kmr_ld_err)(DIN, "  memcpy(%p, _, 0x%zx).\n", s0, maplen);
	memcpy(s0, (image + mapoff), maplen);
    }

    char *zerostart = (void *)(s + len);
    size_t zerolen = (extlen - len);

    if (zerolen > 0) {
	(*kmr_ld_err)(DIN, "  memset(%p, 0, 0x%zx).\n", zerostart, zerolen);
	memset(zerostart, 0, zerolen);
    }

    cc = mprotect(s0, mapextlen, prot);
    if (cc != 0) {
	(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%x): %s.\n",
		      s0, mapextlen, prot, strerror(errno));
	abort();
    }
}

static Elf64_Sym *kmr_lookup_in_so_gnu(struct link_map *m, char *name);
static Elf64_Sym *kmr_lookup_in_so_sysv(struct link_map *m, char *name);

/* Looks up a symbol in the SO (slowly).  It is used to look up in
   ld.so instead of using _dl_lookup_symbol_x(), because ld.so has an
   empty scope.  It uses the gnu-hash when (m->l_gnu_bitmask!=0) or
   the sysv-hash otherwise. */

static Elf64_Sym *
kmr_lookup_in_so(struct link_map *m, char *name)
{
    Elf64_Sym *s;
    if (m->l_gnu_bitmask != 0) {
	s = kmr_lookup_in_so_gnu(m, name);
    } else {
	s = kmr_lookup_in_so_sysv(m, name);
    }
    return s;
}

static Elf64_Sym *
kmr_lookup_in_so_gnu(struct link_map *m, char *name)
{
    assert(m->l_gnu_bitmask != 0);

    Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
    char *strings = (void *)m->l_info[DT_STRTAB]->d_un.d_ptr;

    Elf64_Sym *sym = 0;
    for (Elf_Symndx bucket = 0; bucket < m->l_nbuckets; bucket++) {
	Elf32_Word symbase = m->l_gnu_buckets[bucket];
	if (symbase != 0) {
	    for (int symidx = symbase; 1; symidx++) {
		Elf64_Sym *sym0 = &symtab[symidx];
		unsigned int t = ELF64_ST_TYPE(sym0->st_info);
		if (t == STT_NOTYPE) {
		    /*printf("sym=%s (NOTYPE)\n", (strings + sym0->st_name));*/
		} else if ((t == STT_OBJECT) || (t == STT_FUNC)) {
		    char *s = (strings + sym0->st_name);
		    if (strcmp(s, name) == 0) {
			sym = sym0;
			break;
		    }
		} else if ((t == STT_COMMON) || (t == STT_TLS)
			   || (t == STT_GNU_IFUNC)) {
		    /*printf("sym=%s (?)\n", (strings + sym0->st_name));*/
		} else {
		    /*printf("sym=? %x\n", t);*/
		}
		if ((m->l_gnu_chain_zero[symidx] & 1U) != 0) {
		    break;
		}
	    }
	    if (sym != 0) {
		break;
	    }
	}
    }
    return sym;
}

static Elf64_Sym *
kmr_lookup_in_so_sysv(struct link_map *m, char *name)
{
    assert(m->l_gnu_bitmask == 0);

    Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
    char *strings = (void *)m->l_info[DT_STRTAB]->d_un.d_ptr;

    Elf64_Sym *sym = 0;
    for (Elf_Symndx bucket = 0; bucket < m->l_nbuckets; bucket++) {
	Elf_Symndx symndx0 = m->l_buckets[bucket];
	for (Elf_Symndx i = symndx0; i != STN_UNDEF; i = m->l_chain[i]) {
	    Elf64_Sym *sym0 = &symtab[i];
	    unsigned int t = ELF64_ST_TYPE(sym0->st_info);
	    if (t == STT_NOTYPE) {
		/*printf("sym=%s (NOTYPE)\n", (strings + sym0->st_name));*/
	    } else if ((t == STT_OBJECT) || (t == STT_FUNC)) {
		char *s = (strings + sym0->st_name);
		if (strcmp(s, name) == 0) {
		    sym = sym0;
		    break;
		}
	    } else if ((t == STT_COMMON) || (t == STT_TLS)
		       || (t == STT_GNU_IFUNC)) {
		/*printf("sym=%s (?)\n", (strings + sym0->st_name));*/
	    } else {
		/*printf("sym=? %x\n", t);*/
	    }
	}
	if (sym != 0) {
	    break;
	}
    }
    return sym;
}

/* Checks the matching of header files (used for compiling this file)
   against the version of the loaded ld.so. */

static void
kmr_check_structure_sizes_in_loaded_ldso(struct link_map *m0)
{
    /* Check the slot "_dl_rtld_map" (in the header file) in
       "_rtld_global" properly points to some link-map entry. */

    struct link_map *ldso = &_rtld_global._dl_rtld_map;
    struct link_map *p;
    p = m0;
    while (p != 0) {
	if (p == ldso) {
	    break;
	}
	p = p->l_next;
    }
    assert(p != 0);

    /* Check the sizes of "_rtld_global" and "_rtld_global_ro". */

    const Elf64_Sym *s0 = kmr_lookup_in_so(ldso, "_rtld_global");
    assert((*s0).st_size == sizeof(_rtld_global));

    const Elf64_Sym *s1 = kmr_lookup_in_so(ldso, "_rtld_global_ro");
    assert((*s1).st_size == sizeof(_rtld_global_ro));
}

/* Converts protection bits from ones of ELF to mmap(). */

static inline int
kmr_prot_from_header(Elf64_Word flags) {
    int prot;
    prot = PROT_READ;
    if ((flags & PF_W) != 0) {
	prot |= PROT_WRITE;
    }
    if ((flags & PF_X) != 0) {
	prot |= PROT_EXEC;
    }
    return prot;
}

/* Returns true when the address range does not overlap with the pages
   known to fail to mmap()/munmap().  The initially mapped data/bss
   pages (registered pages to TOFU-NIC and large pages) fail to
   mmap()/munmap() on K.  It excludes text pages, and they are always
   mmapped.  It checks if the given range [s:s+len) NOT overlaps the
   recorded range. */

static _Bool
kmr_check_pages_mappable(Elf64_Addr s, size_t len)
{
    if (!kmr_exec_info.copy_data_segment) {
	return 1;
    } else {
	Elf64_Addr s0 = s;
	Elf64_Addr e0 = (s + len);
	_Bool overlaps = 0;
	for (int i = 0; i < kmr_exec_info.n_fjmpg_pages; i++) {
	    Elf64_Addr s1 = kmr_exec_info.fjmpg_pages[i].p;
	    Elf64_Addr e1 = (s + kmr_exec_info.fjmpg_pages[i].size);
	    if (!((e1 <= s0) || (e0 <= s1))) {
		overlaps = 1;
		break;
	    }
	}
	return (!overlaps);
    }
}

/* Records mapped pages (See kmr_check_pages_mappable()). */

static void
kmr_record_fjmpg_pages(struct link_map *m0)
{
    Elf64_Phdr const *phdrs = m0->l_phdr;
    Elf64_Addr addr = m0->l_addr;
    Elf64_Addr pagesize = kmr_get_page_size1();

    for (int i = 0; i < m0->l_phnum; i++) {
	Elf64_Phdr const *ph = &phdrs[i];

	if (ph->p_type == PT_LOAD && ph->p_memsz != 0) {
	    assert(ph->p_filesz <= ph->p_memsz);
	    assert(((ph->p_vaddr - ph->p_offset) & (ph->p_align - 1)) == 0);
	    Elf64_Addr s = (addr + ph->p_vaddr);
	    size_t len = ph->p_memsz;
	    int prot = kmr_prot_from_header(ph->p_flags);

	    char *s0 = (void *)kmr_floor_to_align(s, pagesize);
	    size_t shift = ((char *)s - s0);
	    size_t maplen = (len + shift);
	    size_t size = kmr_ceiling_to_align(maplen, pagesize);

	    if (((intptr_t)s0 & (kmr_fjmpg_alignment - 1)) == 0) {
		(*kmr_ld_err)(DIN, ("Record mpg-mapped page %p,"
				    " size=0x%zx, prot=0x%x.\n"),
			      (void *)s0, size, prot);
		int N = (sizeof(kmr_exec_info.fjmpg_pages)
			 /sizeof(kmr_exec_info.fjmpg_pages[0]));
		if (kmr_exec_info.n_fjmpg_pages >= N) {
		    (*kmr_ld_err)(DIE, "Many pages are mpg-mapped.\n");
		    abort();
		}
		int j = kmr_exec_info.n_fjmpg_pages;
		kmr_exec_info.fjmpg_pages[j].p = (Elf64_Addr)s0;
		kmr_exec_info.fjmpg_pages[j].size = size;
		kmr_exec_info.fjmpg_pages[j].prot = prot;
		kmr_exec_info.n_fjmpg_pages++;
	    }
	}
    }
}

/* Unmaps the all PT_LOAD entries of the old a.out. */

static void
kmr_unmap_old_aout(Elf64_Addr addr, Elf64_Phdr *phdrs, int phnum)
{
    Elf64_Addr pagesize = kmr_get_page_size1();
    int cc;

    for (int i = 0; i < phnum; i++) {
	Elf64_Phdr const *ph = &phdrs[i];

	if (ph->p_type == PT_LOAD && ph->p_memsz != 0) {
	    assert(ph->p_filesz <= ph->p_memsz);
	    assert(((ph->p_vaddr - ph->p_offset) & (ph->p_align - 1)) == 0);
	    Elf64_Addr s = (addr + ph->p_vaddr);
	    char *s0 = (void *)kmr_floor_to_align(s, pagesize);
	    size_t shift = ((char *)s - s0);
	    size_t len = ph->p_memsz;
	    size_t maplen = (len + shift);
	    if (kmr_check_pages_mappable(s, len)) {
		(*kmr_ld_err)(DIN, "  munmap(%p, 0x%zx).\n", s0, maplen);
		cc = munmap(s0, maplen);
		if (cc != 0) {
		    (*kmr_ld_err)(DIE, "munmap(%p, 0x%zx): %s.\n",
				  s0, maplen, strerror(errno));
		    abort();
		}
	    } else {
		int prot = kmr_prot_from_header(ph->p_flags);
		kmr_copy_segment((Elf64_Addr)s0, (size_t)0, maplen,
				 prot, 0, (off_t)0, 0, (size_t)0);
	    }
	}
    }
}

/* Maps the new a.out.  It mimics [_dl_map_object_from_fd() in
   elf/dl-load.c]. */

static void
kmr_remap_new_aout(struct link_map *m0, char *image, size_t size, int fd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(image + ehdr->e_phoff);
    Elf64_Addr addr = 0;

    /* Map text and data (program) sections. */

    for (int i = 0; i < ehdr->e_phnum; i++) {
	Elf64_Phdr *ph = &phdrs[i];

	if (ph->p_type == PT_LOAD && ph->p_memsz != 0) {
	    assert(ph->p_filesz <= ph->p_memsz);
	    /*assert(ph->p_paddr == 0);*/

	    Elf64_Addr s = (addr + ph->p_vaddr);
	    size_t fsz = ph->p_filesz;
	    size_t msz = ph->p_memsz;
	    off_t off = ph->p_offset;
	    int prot = kmr_prot_from_header(ph->p_flags);
	    int flags = (MAP_FIXED|MAP_PRIVATE);
	    if (kmr_check_pages_mappable(s, msz)) {
		kmr_mmap_segment(s, fsz, msz, prot, flags, off, fd);
	    } else {
		kmr_copy_segment(s, fsz, msz, prot, flags, off, image, size);
	    }
	}
    }
}

static struct link_map *
kmr_find_named_so(struct link_map *m0, char *s)
{
    struct link_map *p;
    p = m0->l_next;
    while (p != 0) {
	struct libname_list *n;
	n = p->l_libname;
	while (n != 0) {
	    if (strcmp(s, n->name) == 0) {
		break;
	    }
	    n = n->next;
	}
	if (n != 0) {
	    break;
	}
	p = p->l_next;
    }
    return p;
}

/* Loads the needed libraries of the new a.out.  Note they are loaded
   for the old a.out (at an early stage).  It is because it needs to
   load the libraries before relocating the new a.out, and it seems
   undesirable to load them for the not-relocated a.out.  The loaded
   ones are inserted to the search list on the old a.out
   (m0->l_searchlist) by dlopen().  [_dl_map_object_deps() in
   elf/dl-deps.c].  NOTE ON K: The tag value at the N-th entry
   (specified by the size) is not the end of the list (on K with
   glibc-2.7). */

static void
kmr_load_needed_so(char *image, size_t size, struct link_map *m0)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
    //Elf64_Phdr *phdrs = (Elf64_Phdr *)(image + ehdr->e_phoff);
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(image + ehdr->e_shoff);

    char *needs[100];
    int nneeds = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
	Elf64_Shdr *sh = &shdrs[i];
	if (sh->sh_type == SHT_DYNAMIC) {
	    assert(sh->sh_entsize == sizeof(Elf64_Dyn));
	    int n = (sh->sh_size / sizeof(Elf64_Dyn));
	    Elf64_Dyn *ents = (Elf64_Dyn *)(image + sh->sh_offset);
	    char *strings = image + shdrs[sh->sh_link].sh_offset;
	    /*assert(ents[n].d_tag == 0);*/
	    int endpos;
	    endpos = (n + 1);
	    for (int j = 0; j < (n + 1); j++) {
		switch (ents[j].d_tag) {
		case DT_NULL:
		    endpos = j;
		    break;

		case DT_NEEDED: {
		    char *s = (strings + ents[j].d_un.d_val);
		    struct link_map *p = kmr_find_named_so(m0, s);
#if 0
		    struct link_map *p;
		    p = m0->l_next;
		    while (p != 0) {
			struct libname_list *n;
			n = p->l_libname;
			while (n != 0) {
			    if (strcmp(s, n->name) == 0) {
				break;
			    }
			    n = n->next;
			}
			if (n != 0) {
			    break;
			}
			p = p->l_next;
		    }
#endif
		    if (p != 0) {
			(*kmr_ld_err)(DIN, "  %s (already loaded).\n", s);
		    } else {
			/*printf("so=%s needed.\n", s);*/
			assert(nneeds < (int)(sizeof(needs)/sizeof(needs[0])));
			needs[nneeds] = s;
			nneeds++;
		    }
		    break;
		}

		case DT_AUXILIARY:
		case DT_FILTER: {
		    (*kmr_ld_err)(WRN, "DT_AUXILIARY/DT_FILTER enties"
				  " are ignored.\n");
		    break;
		}

		default:
		    /* case DT_FLAGS: abort();*/
		    /* (Ignore others). */
		    break;
		}
	    }
	    assert(endpos <= n);
	}
    }

    /* Load needed, and set dependency as required by a.out. */

    for (int i = 0; i < nneeds; i++) {
	(*kmr_ld_err)(DIN, "  %s loading...\n", needs[i]); fflush(0);
	struct link_map *m = dlopen(needs[i], (RTLD_NOW|RTLD_GLOBAL));
	if (m == 0) {
	    (*kmr_ld_err)(DIE, "dlopen(%s): %s.\n", needs[i], dlerror());
	    abort();
	}
	assert(m->l_loader == 0);
	m->l_loader = m0;
    }
}

/* Changes the a.out name in a core-dump.  Core dumper takes the name
   from the user space at the argv[0].  It sets argv[0] with the name,
   and filling the remaining space with a blank character.  The name
   length is limited to the original argv size.  The arguments are
   argv[0] (ARGS) and the size (SZ) of the argv strings. NOTE:
   prctl(PR_SET_NAME) nor setproctitle() does not work. */

static void
kmr_change_aout_name(char *args, size_t sz, char *name)
{
    //char *args = argv[0];
    //char *arge = envv[0];
    //size_t sz = (size_t)(arge - args);

    if (sz > (size_t)((256 * 1024) * 4)) {
	/* The area for argv is strangely too large. */
	(*kmr_ld_err)(DIE, "Area for argv is strange: (start=%p size=%p).\n",
		      args, sz);
    }

    memset(args, 0, sz);
    snprintf(args, sz, name);
    args[sz - 1] = 0;

    if ((sz - 1) < strlen(name)) {
	(*kmr_ld_err)(WRN, "Cannot replace the command name,"
		      " truncated (%s).\n", name);
    }
}

/* Resets the link-map filling with fake data for unmapping the old
   a.out. */

static void
kmr_reset_link_map(struct link_map *m0, char *image, size_t size)
{
    const Elf64_Addr ADDRMAX = 0x7fffffffffffffffUL;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(image + ehdr->e_phoff);

    //struct link_map *ldso = &_rtld_global._dl_rtld_map;

    //abort();

    m0->l_phdr = phdrs;
    m0->l_phnum = ehdr->e_phnum;
    m0->l_entry = ehdr->e_entry; /*(*user_entry)*/
    m0->l_map_start = (Elf64_Addr)ADDRMAX;
    m0->l_map_end = 0;
    m0->l_text_end = 0;
    m0->l_direct_opencount = 1;

    m0->l_relro_addr = 0;
    m0->l_relro_size = 0;

    m0->l_tls_modid = 1;
    m0->l_tls_offset = 0;
    m0->l_tls_blocksize = 0;
    m0->l_tls_align = 0;
    m0->l_tls_firstbyte_offset = 0;
    m0->l_tls_initimage = 0;
    m0->l_tls_initimage_size = 0;
    /*(ph->p_vaddr != 0)*/

    /* Assume it is already on the namespace-list. */

    /*_dl_add_to_namespace_list(m0, LM_ID_BASE);*/
    assert(m0->l_serial == 0);

    for (int i = 0; i < ehdr->e_phnum; i++) {
	Elf64_Phdr *ph = &phdrs[i];
	switch (ph->p_type) {
	case PT_INTERP:
	    break;

	case PT_PHDR:
	    m0->l_addr = (Elf64_Addr)phdrs - ph->p_vaddr;
	    break;

	case PT_DYNAMIC:
	    m0->l_ld = (void *)m0->l_addr + ph->p_vaddr;
	    break;

	case PT_LOAD: {
	    Elf64_Addr pagesize = kmr_get_page_size1();
	    Elf64_Addr s = (m0->l_addr + ph->p_vaddr);
	    Elf64_Addr s0 = kmr_floor_to_align(s, pagesize);
	    Elf64_Addr e = (s + ph->p_memsz);
	    m0->l_map_start = MIN(m0->l_map_start, s0);
	    m0->l_map_end = MAX(m0->l_map_end, e);
	    if ((ph->p_flags & PF_X) != 0) {
		m0->l_text_end = MAX(m0->l_text_end, e);
	    }
	    break;
	}

	case PT_TLS:
	    /*printf("See PT_TLS in PHDR.\n"); fflush(0);*/
	    break;

	case PT_GNU_STACK:
	    /*printf("See PT_GNU_STACK in PHDR.\n"); fflush(0);*/
	    break;

	case PT_GNU_RELRO:
	    /*printf("See PT_GNU_RELRO in PHDR.\n"); fflush(0);*/
	    break;
	}
    }

    if (m0->l_map_end == 0) {
	m0->l_map_end = (Elf64_Addr)ADDRMAX;
    }
    if (m0->l_text_end == 0) {
	m0->l_text_end = (Elf64_Addr)ADDRMAX;
    }
}

/* [ADDRIDX() in sysdeps/x86_64/dl-tlsdesc.h].  */

#define ADDRIDX(tag) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM \
		      + DT_EXTRANUM + DT_VALNUM + DT_ADDRTAGIDX(tag))

/* [VERSYMIDX() in elf/do-rel.h]. */

#define VERSYMIDX(tag) (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(tag))

static inline void
kmr_adjust_dyn_info(int /*Elf64_Xword*/ tag, Elf64_Dyn **info, Elf64_Addr addr)
{
    if (info[tag] != 0) {
	info[tag]->d_un.d_ptr += addr;
    }
}

static void kmr_setup_dynamic_info(struct link_map *m);
static void kmr_setup_versions_info(struct link_map *m);
static void kmr_setup_hashtable(struct link_map *m);

/*(l_addr)*/
/*l_name*/
/*(l_ld)*/
/*=(l_next,l_prev)*/
/*=(l_real)*/
/*l_ns*/
/*l_libname*/
/*(l_info)*/
/*(l_phdr)*/
/*(l_entry)*/
/*(l_phnum)*/
/*(l_ldnum)*/
/*=l_searchlist*/
/*=l_symbolic_searchlist*/
/*=l_loader*/
/*=l_versions*/
/*=l_nversions*/
/*(hashtable-related)*/
/*!(l_direct_opencount)*/
/*!l_contiguous*/
/*l_versyms(?)*/
/*l_origin(?)*/
/*!l_dev,l_ino*/
/*!l_lookup_cache*/
/*(tls-related)*/

/* Modifies the main link-map for the new a.out.  It mimics the first
   part of dl_main().  [dl_main() in elf/rtld.c]. */

static void
kmr_setup_link_map(struct link_map *m0, char *image, size_t size)
{
    const Elf64_Addr ADDRMAX = 0x7fffffffffffffffUL;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(image + ehdr->e_phoff);
    struct link_map *ldso = &_rtld_global._dl_rtld_map;
    Elf64_Addr pagesize = kmr_get_page_size1();

    /* Clear the field values (for checks later). */

    m0->l_addr = 0;
    m0->l_ld = 0;
    memset(m0->l_info, 0, sizeof(m0->l_info));
    m0->l_phdr = 0;

    /* (l_versions of a.out is not malloced). */

    m0->l_versions = 0;
    m0->l_versyms = 0;

    m0->l_entry = ehdr->e_entry; /*(*user_entry)*/
    m0->l_map_start = (Elf64_Addr)ADDRMAX;
    m0->l_map_end = 0;
    m0->l_text_end = 0;
    m0->l_direct_opencount = 1;

    memset(&m0->l_lookup_cache, 0, sizeof(m0->l_lookup_cache));

    m0->l_info[DT_DEBUG] = 0;

    _rtld_global._dl_stack_flags = 0;

    /* (Some old field values are untouched). */

    /* Assume it is already on the namespace-list. */

    /* (_dl_add_to_namespace_list(m0, LM_ID_BASE)) */
    assert(m0->l_serial == 0);

    for (int i = 0; i < ehdr->e_phnum; i++) {
	Elf64_Phdr *ph = &phdrs[i];
	switch (ph->p_type) {
	case PT_INTERP: {
	    char *interp0 = (char *)(m0->l_addr + ph->p_vaddr);
	    char *interp = basename(interp0);
	    struct libname_list *n;
	    n = ldso->l_libname;
	    while (n != 0) {
		/*printf("Compare interp (%s %s).\n", interp, n->name);*/
		if (strcmp(interp, n->name) == 0) {
		    break;
		}
		n = n->next;
	    }
	    if (n == 0) {
		(*kmr_ld_err)(WRN, "New a.out uses a different interp"
			      " (new=%s).\n", interp);
	    }
	    break;
	}

	case PT_PHDR:
	    assert(m0->l_phdr == 0);
	    m0->l_phdr = (void *)ph->p_vaddr;
	    /*m0->l_addr = (Elf64_Addr)phdrs - ph->p_vaddr;*/
	    m0->l_phnum = ehdr->e_phnum;
	    break;

	case PT_DYNAMIC:
	    assert(m0->l_ld == 0);
	    m0->l_ld = (void *)ph->p_vaddr;
	    /*m0->l_ld = (void *)(m0->l_addr + ph->p_vaddr);*/
	    m0->l_ldnum = (ph->p_memsz / sizeof(Elf64_Dyn));
	    break;

	case PT_LOAD: {
	    assert(m0->l_addr == 0);
	    assert(ph->p_filesz <= ph->p_memsz);
	    assert(((ph->p_vaddr - ph->p_offset) & (ph->p_align - 1)) == 0);
	    Elf64_Addr s = (m0->l_addr + ph->p_vaddr);
	    Elf64_Addr s0 = kmr_floor_to_align(s, pagesize);
	    Elf64_Addr e = (s + ph->p_memsz);
	    m0->l_map_start = MIN(m0->l_map_start, s0);
	    m0->l_map_end = MAX(m0->l_map_end, e);
	    if ((ph->p_flags & PF_X) != 0) {
		m0->l_text_end = MAX(m0->l_text_end, e);
	    }
	    break;
	}

	case PT_TLS: {
	    /*printf("See PT_TLS in PHDR.\n"); fflush(0);*/
	    if (ph->p_memsz > 0) {
		m0->l_tls_modid = 1;
		m0->l_tls_blocksize = ph->p_memsz;
		m0->l_tls_align = ph->p_align;
		m0->l_tls_firstbyte_offset = (ph->p_vaddr & (ph->p_align - 1));
		/*GL(dl_tls_max_dtv_idx) = 1;*/
		/*m0->l_tls_initimage = (void *)ph->p_vaddr;*/
		/* (PT_PHDR has already been seen). */
		if (ph->p_vaddr != 0) {
		    m0->l_tls_initimage = (void *)(m0->l_addr + ph->p_vaddr);
		} else {
		    m0->l_tls_initimage = 0;
		}
		m0->l_tls_initimage_size = ph->p_filesz;
	    }
	    break;
	}

	case PT_GNU_STACK:
	    (*kmr_ld_err)(DIN, "  Ignore PT_GNU_STACK in PHDR.\n");
	    _rtld_global._dl_stack_flags = ph->p_flags;
	    break;

	case PT_GNU_RELRO:
	    /*printf("See PT_GNU_RELRO in PHDR.\n"); fflush(0);*/
	    m0->l_relro_addr = ph->p_vaddr;
	    m0->l_relro_size = ph->p_memsz;
	    break;

	default:
	    break;
	}
    }

    assert(m0->l_phdr != 0 && m0->l_ld != 0);

    if (m0->l_map_end == 0) {
	m0->l_map_end = (Elf64_Addr)ADDRMAX;
    }
    if (m0->l_text_end == 0) {
	m0->l_text_end = (Elf64_Addr)ADDRMAX;
    }

    /*assert(m0->l_info[DT_SONAME] != 0);*/

    m0->l_relocated = 0;

    /* (elf_get_dynamic_info()) */

    kmr_setup_dynamic_info(m0);
    assert(m0->l_info[DT_SYMTAB] != 0);

    /* (_dl_setup_hashtable()) */

    kmr_setup_hashtable(m0);

    /* (_dl_init_paths()) */
    /* (_dl_debug_initialize()) */

    /*printf("m0->l_info[DT_DEBUG]=%p\n", m0->l_info[DT_DEBUG]); fflush(0);*/

    if (/*isa == EM_X86_64*/ 1) {
	if (m0->l_info[DT_DEBUG] != 0) {
	    assert(m0->l_info[DT_DEBUG]->d_un.d_ptr == 0);
	    struct r_debug *g = (void *)&kmr_debug_info_area;
	    m0->l_info[DT_DEBUG]->d_un.d_ptr = (intptr_t)g;
	    g->r_version = 1;
	    g->r_ldbase = 0;
	    g->r_map = (void *)_rtld_global._dl_ns[LM_ID_BASE]._ns_loaded;
	    g->r_state = RT_CONSISTENT;
	    g->r_brk = (intptr_t)(void *)kmr_debug_state;
	}
    }

    /* (_dl_map_object_deps()) */

    /* (_dl_receive_error(,version_check_doit,)) */

    kmr_setup_versions_info(m0);

#if 0
    bool was_tls_init_tp_called = tls_init_tp_called;
    void *tcbp = 0;
    if (tcbp == 0) {
	tcbp = init_tls();
    }
#endif

    /* security_init() */

#if 0
    if (m0->l_info[ADDRIDX(DT_GNU_LIBLIST)] != 0
	&& _rtld_global._dl_profile == 0
	&& !_rtld_global._dl_dynamic_weak) {
    }
#endif

    assert(_rtld_global._dl_ns[LM_ID_BASE]._ns_main_searchlist
	   == &m0->l_searchlist);

    /*assert(memcmp_slow(&_rtld_global_ro._dl_initial_searchlist,
      _rtld_global._dl_ns[LM_ID_BASE]._ns_main_searchlist,
      sizeof(struct r_scope_elem)) == 0);*/

    /* FALSE VALUE */
    m0->l_contiguous = 1;
}

/* Adjusts the loaded values of ELF dynamic.  [elf_get_dynamic_info()
   in elf/dynamic-link.h]. */

static void
kmr_setup_dynamic_info(struct link_map *m)
{
    assert(m->l_ld != 0);

    Elf64_Dyn **info = m->l_info;
    for (int i = 0; m->l_ld[i].d_tag != DT_NULL; i++) {
	Elf64_Dyn *d = &m->l_ld[i];
	Elf64_Xword tag = d->d_tag;

	assert(tag != DT_VERDEF && tag != DT_VERDEFNUM);
	if (tag < DT_NUM) {
	    info[tag] = d;
	    if (tag == DT_DEBUG) {
		/*printf("See DT_DEBUG in l_ld (%p).\n", d); fflush(0);*/
	    }
	} else if (DT_LOPROC <= tag
		   && tag < DT_LOPROC + DT_THISPROCNUM) {
	    info[tag - DT_LOPROC + DT_NUM] = d;
	} else if (DT_VERSIONTAGIDX(tag) < DT_VERSIONTAGNUM) {
	    info[VERSYMIDX(tag)] = d;
	    if (tag == DT_VERSYM) {
		/*printf("See DT_VERSYM in l_ld.\n"); fflush(0);*/
	    }
	    if (tag == DT_VERNEED) {
		/*printf("See DT_VERNEED in l_ld.\n"); fflush(0);*/
	    }
	    if (tag == DT_VERNEEDNUM) {
		/*printf("See DT_VERNEEDNUM in l_ld.\n"); fflush(0);*/
	    }
	} else if (DT_EXTRATAGIDX(tag) < DT_EXTRANUM) {
	    long off3 = (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM);
	    info[DT_EXTRATAGIDX(tag) + off3] = d;
	} else if (DT_VALTAGIDX(tag) < DT_VALNUM) {
	    long off4 = (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
			 + DT_EXTRANUM);
	    info[DT_VALTAGIDX(tag) + off4] = d;
	} else if (DT_ADDRTAGIDX(tag) < DT_ADDRNUM) {
	    long off5 = (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
			 + DT_EXTRANUM + DT_VALNUM);
	    info[DT_ADDRTAGIDX(tag) + off5] = d;
	}
    }

    if (m->l_addr != 0) {
	Elf64_Addr addr = m->l_addr;
	int off5 = (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		    + DT_EXTRANUM + DT_VALNUM);
	kmr_adjust_dyn_info(DT_HASH, info, addr);
	kmr_adjust_dyn_info(DT_PLTGOT, info, addr);
	kmr_adjust_dyn_info(DT_STRTAB, info, addr);
	kmr_adjust_dyn_info(DT_SYMTAB, info, addr);
	kmr_adjust_dyn_info(DT_RELA, info, addr);
	kmr_adjust_dyn_info(DT_REL, info, addr);
	kmr_adjust_dyn_info(DT_JMPREL, info, addr);
	kmr_adjust_dyn_info(VERSYMIDX(DT_VERSYM), info, addr);
	kmr_adjust_dyn_info((DT_ADDRTAGIDX(DT_GNU_HASH) + off5), info, addr);
    }
    if (info[DT_RELA] != 0) {
	assert(info[DT_RELAENT]->d_un.d_val == sizeof(Elf64_Rela));
    }
    if (info[DT_REL] != 0) {
	assert(info[DT_RELENT]->d_un.d_val == sizeof(Elf64_Rel));
    }
    if (info[DT_PLTREL] != 0) {
	assert(info[DT_PLTREL]->d_un.d_val == DT_RELA
	       || info[DT_PLTREL]->d_un.d_val == DT_REL);
    }
    if (info[DT_FLAGS] != 0) {
	m->l_flags = info[DT_FLAGS]->d_un.d_val;
	if ((m->l_flags & DF_SYMBOLIC) != 0) {
	    info[DT_SYMBOLIC] = info[DT_FLAGS];
	}
	if ((m->l_flags & DF_TEXTREL) != 0) {
	    info[DT_TEXTREL] = info[DT_FLAGS];
	}
	if ((m->l_flags & DF_BIND_NOW) != 0) {
	    info[DT_BIND_NOW] = info[DT_FLAGS];
	}
    }
    if (info[VERSYMIDX(DT_FLAGS_1)] != 0) {
	m->l_flags_1 = info[VERSYMIDX(DT_FLAGS_1)]->d_un.d_val;
	if ((m->l_flags_1 & DF_1_NOW) != 0) {
	    info[DT_BIND_NOW] = info[VERSYMIDX(DT_FLAGS_1)];
	}
    }
    if (info[DT_RUNPATH] != 0) {
	info[DT_RPATH] = 0;
    }
}

/* Adjusts the loaded values version information.
   [_dl_check_map_versions() in elf/dl-version.c]. */

static void
kmr_setup_versions_info(struct link_map *m)
{
#define VN_NEXT(E) \
    ((E)->vn_next == 0 ? 0 : (void *)((char *)(E) + (E)->vn_next))
#define VNA_NEXT(A) \
    ((A)->vna_next == 0 ? 0 : (void *)((char *)(A) + (A)->vna_next))

    if (m->l_info[VERSYMIDX(DT_VERSYM)] != 0) {
	m->l_versyms = (void *)m->l_info[VERSYMIDX(DT_VERSYM)]->d_un.d_ptr;
    }

    if (m->l_info[VERSYMIDX(DT_VERNEED)] != 0) {
	Elf64_Dyn *d = m->l_info[VERSYMIDX(DT_VERNEED)];
	assert(m->l_info[DT_STRTAB] != 0);
	char *strings = (void *)m->l_info[DT_STRTAB]->d_un.d_ptr;
	Elf64_Verneed *need = (void *)(m->l_addr + d->d_un.d_ptr);

	unsigned int nversions = 0;
	if (m->l_info[VERSYMIDX(DT_VERNEEDNUM)] != 0) {
	    nversions = m->l_info[VERSYMIDX(DT_VERNEEDNUM)]->d_un.d_val;
	} else {
	    for (Elf64_Verneed *e = need; e != 0; e = VN_NEXT(e)) {
		Elf64_Vernaux *naux = (void *)((char *)e + e->vn_aux);
		for (Elf64_Vernaux *a = naux; a != 0; a = VNA_NEXT(a)) {
		    Elf64_Half i = (a->vna_other & 0x7fff);
		    nversions = MAX(nversions, (unsigned int)(i + 1));
		}
	    }
	}
	assert(nversions <= sizeof(kmr_versions_area)/sizeof(kmr_versions_area[0]));
	m->l_versions = kmr_versions_area;
	m->l_nversions = nversions;

	for (Elf64_Verneed *e = need; e != 0; e = VN_NEXT(e)) {
	    Elf64_Vernaux *naux = (void *)((char *)e + e->vn_aux);
	    for (Elf64_Vernaux *a = naux; a != 0; a = VNA_NEXT(a)) {
		Elf64_Half i = (a->vna_other & 0x7fff);
		if (i < m->l_nversions) {
		    m->l_versions[i].hash = a->vna_hash;
		    m->l_versions[i].hidden = a->vna_other & 0x8000;
		    m->l_versions[i].name = &strings[a->vna_name];
		    m->l_versions[i].filename = &strings[e->vn_file];
		}
	    }
	}
    }
}

static void
kmr_setup_hashtable(struct link_map *m)
{
    long off = (DT_ADDRTAGIDX(DT_GNU_HASH)
		+ DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		+ DT_EXTRANUM + DT_VALNUM);
    if (m->l_info[off] != 0) {
	Elf32_Word *hash = (void *)(m->l_info[off]->d_un.d_ptr);
	m->l_nbuckets = hash[0];
	Elf32_Word symbias = hash[1];
	Elf32_Word bitmask = hash[2];
	assert(KMR_CHECK_POWERS2(bitmask));
	m->l_gnu_shift = hash[3];
	m->l_gnu_bitmask_idxbits = bitmask - 1;
	m->l_gnu_bitmask = (Elf64_Addr *)&hash[4];
	m->l_gnu_buckets = (hash + 4 + (64 / 32 * bitmask));
	m->l_gnu_chain_zero = (hash + 4 + (64 / 32 * bitmask)
			       + m->l_nbuckets - symbias);
    } else if (m->l_info[DT_HASH] != 0) {
	Elf_Symndx *hash = (void *)m->l_info[DT_HASH]->d_un.d_ptr;
	m->l_nbuckets = hash[0];
	/*Elf_Symndx nchain = hash[1];*/
	m->l_buckets = hash + 2;
	m->l_chain = (hash + 2 + m->l_nbuckets);
    }
}

/* ================================================================ */

/* (Binding/Relocation) */

/* NOTE: X86-64 uses relocation information ELF64_R_SYM(info) and
   ELF64_R_TYPE(info), but SPARC uses others ELF64_R_TYPE_DATA(info)
   and ELF64_R_TYPE_ID(info). */

#define ELF64_R_TYPE_DATA(INFO) ((INFO) >> 8)

/* [struct tlsdesc defined in sysdeps/x86_64/dl-tlsdesc.h].  */

struct tlsdesc_x86_64 {
    ptrdiff_t (*entry)(struct tlsdesc_x86_64 *on_rax);
    void *arg;
};

/* Array handle for passing both Elf64_Rela and Elf64_Rel.  AZ is
   either DT_RELA or DT_REL, indicating the meaning of the union. */

struct RELAZ {
    int az;
    union {
	Elf64_Rela *a;
	Elf64_Rel *z;
    } u;
};

/* Specifier of the start point searching for the definition of the
   symbols in the relocations.  It tells to include the definition in
   the a.out or not.  It holds the value of the 4th argument to
   kmr_relocate_so(). */

static struct link_map *kmr_relocation_binder;

/* Copies Elf64_Rel/Elf64_Rela at an index I as Elf64_Rela (with
   r_addend=0 for Elf64_Rel) using the buffer RA. */

static Elf64_Rela *
kmr_aref_relaz(struct RELAZ reloc, int i, Elf64_Rela *ra)
{
    if (reloc.az == DT_RELA) {
	return &(reloc.u.a)[i];
    } else if (reloc.az == DT_REL) {
	Elf64_Rel *z = &(reloc.u.z)[i];
	ra->r_offset = z->r_offset;
	ra->r_info = z->r_info;
	ra->r_addend = 0;
	return ra;
    } else {
	assert(reloc.az == DT_RELA || reloc.az == DT_REL);
	return 0;
    }
}

static void kmr_relocate_elf_dynamic(int isa, struct link_map *m,
				     struct RELAZ reloc, int nreloc,
				     void (*fn)(int isa, struct link_map *m,
						Elf64_Rela *r, Elf64_Addr *slot));
static void kmr_bind_elf_lazy_machine(int isa, struct link_map *m,
				      Elf64_Rela *reloc, Elf64_Addr *slot);
static void kmr_bind_elf_machine(int isa, struct link_map *m,
				 Elf64_Rela *reloc, Elf64_Addr *slot);

/* Looks over all relocation entries in the link-map and calls a
   binder function FN on them.  It takes as FN
   kmr_bind_elf_lazy_machine() or kmr_bind_elf_machine().
   [_dl_relocate_object() in elf/dl-reloc.c]. */

static void
kmr_relocate_so(int isa, struct link_map *m,
		void (*fn)(int isa, struct link_map *m,
			   Elf64_Rela *r, Elf64_Addr *slot),
		struct link_map *binder)
{
    kmr_relocation_binder = binder;

    if (m->l_info[DT_TEXTREL] != 0) {
	(*kmr_ld_err)(DIN, "  Ignore DT_TEXTREL.\n");
    }

    /* [ELF_DYNAMIC_RELOCATE() in elf/dynamic-link.h] */

    /*elf_machine_runtime_setup(m, lazy, 0);*/
    /* [elf_machine_runtime_setup() in sysdeps/x86_64/dl-machine.h]. */

    /* [_ELF_DYNAMIC_DO_RELOC() in elf/dynamic-link.h]. */

    Elf64_Rela *rela[2] = {0, 0};
    Elf64_Rel *relz[2] = {0, 0};

    if (m->l_info[DT_RELA] != 0) {
	Elf64_Rela *start = (void *)m->l_info[DT_RELA]->d_un.d_ptr;
	Elf64_Addr size = m->l_info[DT_RELASZ]->d_un.d_val;
	Elf64_Rela *end = (void *)((char *)start + size);
	int n = (end - start);
	struct RELAZ reloc = {.az = DT_RELA, .u.a = start};
	/*printf("relocate (RELA n=%d)...\n", n); fflush(0);*/
	kmr_relocate_elf_dynamic(isa, m, reloc, n, fn);
	rela[0] = start;
	rela[1] = end;
    }
    if (m->l_info[DT_REL] != 0) {
	Elf64_Rel *start = (void *)m->l_info[DT_REL]->d_un.d_ptr;
	Elf64_Addr size = m->l_info[DT_RELSZ]->d_un.d_val;
	Elf64_Rel *end = (void *)((char *)start + size);
	int n = (end - start);
	struct RELAZ reloc = {.az = DT_REL, .u.z = start};
	/*printf("relocate (REL n=%d)...\n", n); fflush(0);*/
	kmr_relocate_elf_dynamic(isa, m, reloc, n, fn);
	relz[0] = start;
	relz[1] = end;
    }

    /* Check the range of DT_PLTREL which may overlap with
       DT_RELA/DT_REL.  It cannot handle partial overlaps.  See the
       comment referring to SPARC in [elf/dynamic-link.h]. */

    if (m->l_info[DT_PLTREL] != 0
	&& m->l_info[DT_PLTREL]->d_un.d_val == DT_RELA) {
	Elf64_Rela *start = (void *)m->l_info[DT_JMPREL]->d_un.d_ptr;
	Elf64_Addr size = m->l_info[DT_PLTRELSZ]->d_un.d_val;
	Elf64_Rela *end = (void *)((char *)start + size);
	if (!(rela[0] <= start && end <= rela[1])) {
	    assert(rela[1] <= start || end <= rela[0]);
	    int n = (end - start);
	    struct RELAZ reloc = {.az = DT_RELA, .u.a = start};
	    /*printf("relocate (PLT RELA n=%d)...\n", n); fflush(0);*/
	    kmr_relocate_elf_dynamic(isa, m, reloc, n, fn);
	}
    }
    if (m->l_info[DT_PLTREL] != 0
	&& m->l_info[DT_PLTREL]->d_un.d_val == DT_REL) {
	Elf64_Rel *start = (void *)m->l_info[DT_JMPREL]->d_un.d_ptr;
	Elf64_Addr size = m->l_info[DT_PLTRELSZ]->d_un.d_val;
	Elf64_Rel *end = (void *)((char *)start + size);
	if (!(relz[0] <= start && end <= relz[1])) {
	    assert(relz[1] <= start || end <= relz[0]);
	    int n = (end - start);
	    struct RELAZ reloc = {.az = DT_REL, .u.z = start};
	    /*printf("relocate (PLT REL n=%d)...\n", n); fflush(0);*/
	    kmr_relocate_elf_dynamic(isa, m, reloc, n, fn);
	}
    }
}

/* Returns the relocation features: 0, PLT, COPY.  See the comment on
   ELF_RTYPE_CLASS_PLT/COPY in [sysdeps/generic/ldsodefs.h]. */

static int
kmr_get_relocation_class(int isa, unsigned long relty)
{
    if (isa == EM_X86_64) {
	/* [sysdeps/x86_64/dl-machine.h] */
	switch (relty) {
	case R_X86_64_JUMP_SLOT:
	case R_X86_64_DTPMOD64:
	case R_X86_64_DTPOFF64:
	case R_X86_64_TPOFF64:
	case R_X86_64_TLSDESC:
	    return ELF_RTYPE_CLASS_PLT;
	case R_X86_64_COPY:
	    return ELF_RTYPE_CLASS_COPY;
	default:
	    return 0;
	}
    } else if (isa == EM_SPARCV9) {
	/* [sysdeps/sparc/sparc64/dl-machine.h]. */
	if (relty == R_SPARC_JMP_SLOT) {
	    return ELF_RTYPE_CLASS_PLT;
	} else if (R_SPARC_TLS_GD_HI22 <= relty
		   && relty <= R_SPARC_TLS_TPOFF64) {
	    return ELF_RTYPE_CLASS_PLT;
	} else if (relty == R_SPARC_COPY) {
	    return ELF_RTYPE_CLASS_COPY;
	} else {
	    return 0;
	}
    } else {
	assert(isa == EM_X86_64 || isa == EM_SPARCV9);
	return 0;
    }
}

static inline struct r_found_version *
kmr_get_symbol_version(struct SYMMAP *ref, Elf64_Rela *r)
{
    int VERS = VERSYMIDX(DT_VERSYM);
    struct link_map *m = ref->map;
    struct r_found_version *version;
    if (m->l_info[VERS] != 0) {
	Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
	unsigned long index = (ref->sym - symtab);
	assert(ELF64_R_SYM(r->r_info) == index);
	Elf64_Half *vv = (void *)(m->l_info[VERS]->d_un.d_ptr);
	Elf64_Half n = (vv[index] & 0x7fff);
	struct r_found_version *v = &m->l_versions[n];
	version = ((v != 0 && v->hash != 0) ? v : 0);
    } else {
	version = 0;
    }
    return version;
}

/* Returns a defining library.  It returns a null-pair when not found.
   [RESOLVE_MAP() in elf/dl-reloc.c]. */

static struct SYMMAP
kmr_resolve_map(int isa, struct SYMMAP *ref, Elf64_Rela *r, struct link_map *m)
{
    kmr_lookupfn_t lookup = _rtld_global_ro._dl_lookup_symbol_x;

    struct SYMMAP def;
    if (ELF64_ST_BIND(ref->sym->st_info) == STB_LOCAL) {
	def = *ref;
    } else {
	unsigned long relty = ELF64_R_TYPE(r->r_info);
	char *name = kmr_get_name(ref);

	struct r_found_version *version = kmr_get_symbol_version(ref, r);
	int tc = kmr_get_relocation_class(isa, relty);

	def.sym = ref->sym;
	def.map = (*lookup)(name, m, &def.sym,
			    m->l_scope, version, tc,
			    DL_LOOKUP_ADD_DEPENDENCY, 0);
	if (kmr_ld_verbosity >= DIN) {
	    (*kmr_ld_err)(DIN, "  Lookup_symbol (%s) ref=%s, def=%s\n",
			  name, kmr_get_so_name(m), kmr_get_so_name(def.map));
	}
    }
    return def;
}

/* [elf_dynamic_do_rel() and elf_dynamic_do_rela() in elf/do-rel.h]. */

static void
kmr_relocate_elf_dynamic(int isa, struct link_map *m,
			 struct RELAZ reloc, int nreloc,
			 void (*fn)(int isa, struct link_map *m,
				    Elf64_Rela *r, Elf64_Addr *slot))
{
    assert(reloc.az == DT_RELA || reloc.az == DT_REL);

    for (int i = 0; i < nreloc; i++) {
	Elf64_Rela ra;
	Elf64_Rela *r = kmr_aref_relaz(reloc, i, &ra);
	Elf64_Addr *slot = (void *)(m->l_addr + r->r_offset);
	/* Call kmr_bind_elf_lazy_machine() or kmr_bind_elf_machine(). */
	(*fn)(isa, m, r, slot);
    }
}

static inline Elf64_Addr
kmr_get_symbol_value(struct SYMMAP *def, Elf64_Sxword addend)
{
    Elf64_Addr value;
    if (def->sym == 0) {
	value = 0;
    } else {
	Elf64_Addr v0 = (def->map->l_addr + def->sym->st_value);
	if ((def->sym->st_shndx != SHN_UNDEF)
	    && (ELF64_ST_TYPE(def->sym->st_info) == STT_GNU_IFUNC)) {
	    value = (*(Elf64_Addr (*)(void))v0)();
	} else {
	    value = v0;
	}
    }
    return (value + addend);
}

static void kmr_bind_elf_lazy_x86(int isa, struct link_map *m,
				  Elf64_Rela *r, Elf64_Addr *slot);
static void kmr_bind_elf_lazy_sparc(int isa, struct link_map *m,
				    Elf64_Rela *r, Elf64_Addr *slot);

/* Binds the SLOT location for relocation.  It takes the Elf64_Rela
   structure for both DT_RELA and DT_REL cases, with r_addend=0 for
   DT_REL.  [elf_machine_lazy_rel() in sysdeps/xxx/dl-machine.h]. */

static void
kmr_bind_elf_lazy_machine(int isa, struct link_map *m,
			  Elf64_Rela *r, Elf64_Addr *slot)
{
    if (isa == EM_X86_64) {
	kmr_bind_elf_lazy_x86(isa, m, r, slot);
    } else if (isa == EM_SPARCV9) {
	kmr_bind_elf_lazy_sparc(isa, m, r, slot);
    } else {
	assert(isa == EM_X86_64 || isa == EM_SPARCV9);
    }
}

/* (Note this needs conditional compilation because m->l_mach is
   machine dependent). */

static void
kmr_bind_elf_lazy_x86(int isa, struct link_map *m,
		      Elf64_Rela *r, Elf64_Addr *slot)
{
#ifdef __x86_64__
    unsigned long relty = ELF64_R_TYPE(r->r_info);
    assert(isa == EM_X86_64);

    /* Check for unexpected PLT relocation type.  */

    switch (relty) {
    case R_X86_64_JUMP_SLOT: {
	if (m->l_mach.plt == 0) {
	    *slot += m->l_addr;
	} else {
	    long off = (((Elf64_Addr)slot) - m->l_mach.gotplt);
	    *slot = (m->l_mach.plt + (off * 2));
	}
	break;
    }

    case R_X86_64_TLSDESC: {
	struct tlsdesc_x86_64 *td = (void *)slot;
	long off = m->l_info[ADDRIDX(DT_TLSDESC_PLT)]->d_un.d_ptr;
	td->arg = (void *)r;
	td->entry = (void *)(m->l_addr + off);
	break;
    }

    case R_X86_64_IRELATIVE: {
	Elf64_Addr value0 = (m->l_addr + r->r_addend);
	Elf64_Addr value1 = (*(Elf64_Addr (*)(void))value0)();
	*slot = value1;
	break;
    }

    default:
	assert(0);
	break;
    }
#else
    (*kmr_ld_err)(DIE, "(configuration error).\n");
    abort();
#endif /*__x86_64__*/
}

static void
kmr_bind_elf_lazy_sparc(int isa, struct link_map *m,
			Elf64_Rela *r, Elf64_Addr *slot)
{
    (*kmr_ld_err)(DIE, "Bad call; should be unused (internal).\n");
    abort();
}

static void kmr_bind_elf_x86(int isa, struct link_map *m,
			     Elf64_Rela *r, Elf64_Addr *slot);
static void kmr_bind_elf_sparc(int isa, struct link_map *m,
			       Elf64_Rela *r, Elf64_Addr *slot);

/* Binds the SLOT location for relocation.  It takes the Elf64_Rela
   structure for both DT_REL and DT_RELA, with r_addend=0 for DT_REL.
   [elf_machine_rel() in sysdeps/xxx/dl-machine.h]. */

static void
kmr_bind_elf_machine(int isa, struct link_map *m,
		     Elf64_Rela *r, Elf64_Addr *slot)
{
    if (isa == EM_X86_64) {
	kmr_bind_elf_x86(isa, m, r, slot);
    } else if (isa == EM_SPARCV9) {
	kmr_bind_elf_sparc(isa, m, r, slot);
    } else {
	assert(isa == EM_X86_64 || isa == EM_SPARCV9);
    }
}

static void
kmr_bind_elf_x86(int isa, struct link_map *m,
		 Elf64_Rela *r, Elf64_Addr *slot)
{
    assert(isa == EM_X86_64);

    Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
    Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];
    struct SYMMAP ref = {.map = m, .sym = sym};
    char *name = kmr_get_name(&ref);
    unsigned long relty = ELF64_R_TYPE(r->r_info);

    /* [sysdeps/x86_64/dl-machine.h]. */

    switch (relty) {
    case R_X86_64_NONE:
	break;

    case R_X86_64_RELATIVE: {
	*slot = ref.map->l_addr + r->r_addend;
	break;
    }

    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	*slot = value;
	break;
    }

    case R_X86_64_DTPMOD64: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	if (def.map != 0) {
	    *slot = def.map->l_tls_modid;
	}
	break;
    }

    case R_X86_64_DTPOFF64: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	if (def.sym != 0) {
	    *slot = def.sym->st_value + r->r_addend;
	}
	break;
    }

    case R_X86_64_TLSDESC: {
	assert(0);
#if 0 /*AHO*/
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	struct tlsdesc_x86_64 *td = (void *)slot;
	if (def.sym == 0) {
	    td->arg = (void*)r->r_addend;
	    td->entry = _dl_tlsdesc_undefweak;
	} else {
	    if (!TRY_STATIC_TLS(ref.map, def.map)) {
		td->arg = _dl_make_tlsdesc_dynamic
		    (def.map, def.sym->st_value + r->r_addend);
		td->entry = _dl_tlsdesc_dynamic;
	    } else {
		td->arg = (def.sym->st_value - def.map->l_tls_offset
			   + r->r_addend);
		td->entry = _dl_tlsdesc_return;
	    }
	}
#endif
	break;
    }

    case R_X86_64_TPOFF64: {
	assert(0);
#if 0 /*AHO*/
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	if (def.sym != 0) {
	    CHECK_STATIC_TLS(ref.map, def.map);
	    *slot = (def.sym->st_value + r->r_addend
		     - def.map->l_tls_offset);
	}
#endif
	break;
    }

    case R_X86_64_64: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	*slot = value;
	break;
    }

    case R_X86_64_32: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *addr = (void *)slot;
	*addr = value;
	if (value > UINT_MAX) {
	    (*kmr_ld_err)(WRN, "Symbol '%s' causes overflow"
			  " in R_X86_64_32 relocation.\n", name);
	}
	break;
    }

    case R_X86_64_PC32: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *addr = (void *)slot;
	Elf64_Addr value1 = (value - (Elf64_Addr)slot);
	*addr = value1;
	if (value1 != (unsigned int)value1) {
	    (*kmr_ld_err)(WRN, "Symbol '%s' causes overflow"
			  " in R_X86_64_PC32 relocation.\n", name);
	}
	break;
    }

    case R_X86_64_COPY: {
	/*printf("R_X86_64_COPY (%s).\n", name); fflush(0);*/
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	if (def.sym != 0) {
	    Elf64_Addr value = kmr_get_symbol_value(&def, (Elf64_Sxword)0);
	    if (def.sym->st_size != ref.sym->st_size) {
		(*kmr_ld_err)(WRN, "Symbol '%s' (copy-relocation)"
			      " has different sizes.\n", name);
	    }
	    size_t sz = MIN(def.sym->st_size, ref.sym->st_size);
	    memcpy(slot, (void *)value, sz);
	    (*kmr_ld_err)(DIN, "  R_COPY (%s) memcpy(%p, %p, %ld).\n",
			  name, slot, (void *)value, sz); fflush(0);
	}
	break;
    }

    case R_X86_64_IRELATIVE: {
	Elf64_Addr value0 = ref.map->l_addr + r->r_addend;
	Elf64_Addr value1 = (*(Elf64_Addr (*)(void))value0)();
	*slot = value1;
	break;
    }

    default:
	(*kmr_ld_err)(DIE, "Unknown relocation information (%d).\n", relty);
	abort();
	break;
    }
}

/* Sets PLT entry.  [sparc64_fixup_plt() in
   sysdeps/sparc/sparc64/dl-plt.h]. */

static inline void
kmr_bind_plt_sparc(struct link_map *m, const Elf64_Rela *r,
		   Elf64_Addr *slot, Elf64_Addr value,
		   int /*_Bool*/ plt32768, int t)
{
#ifdef __sparc__
    unsigned int *insns0 = (unsigned int *)slot;
    Elf64_Addr addr = (Elf64_Addr)slot + ((t + 1) * 4);

    Elf64_Sxword disp0 = (value - (Elf64_Addr)slot);
    if (plt32768) {
	/* PLT32768 and higher entries; Set PLTP entry.  */

	*slot = (value - m->l_addr);
    } else if (-0x100000 <= disp0 && disp0 < 0x100000) {
	/* PLT102 (with nearer destination). */

	/* "ba,a,pt %icc" */

	insns0[0] = (0x30480000  | ((disp0 >> 2) & 0x07ffff));
	__asm__ __volatile__("flush %0" : : "r" (insns0));
    } else if (-0x800000 <= disp0 && disp0 < 0x800000) {
	/* PLT102 (with nearer destination). */

	/* "ba,a" */

	insns0[0] = (0x30800000 | ((disp0 >> 2) & 0x3fffff));
	__asm__ __volatile__("flush %0" : : "r" (insns0));
    } else if ((value >> 32) == 0) {
	/* PLT102 (with a target within 32 bits). */

	/* "sethi %hi(target), %g1" */
	/* "jmpl %g1 + %lo(target), %g0" */

	unsigned int *insns1 = (insns0 + t);
	insns1[1] = (0x81c06000 | (value & 0x3ff));
	__asm__ __volatile__("flush %0 + 4" : : "r" (insns1));
	insns1[0] = (0x03000000 | (unsigned int)(value >> 10));
	__asm__ __volatile__("flush %0" : : "r" (insns1));
    } else if ((addr > value && ((addr - value) >> 31) == 0)
	       || (value > addr && ((value - addr) >> 31) == 0)) {
	/* PLT101 */
	/* "mov %o7, %g1" */
	/* "call disp1" */
	/* "mov %g1, %o7" */

	unsigned int disp1;
	if (addr > value) {
	    disp1 = (0 - (addr - value));
	} else {
	    disp1 = (value - addr);
	}
	unsigned int *insns1 = (insns0 + t);
	insns1[2] = 0x9e100001;
	__asm__ __volatile__("flush %0 + 8" : : "r" (insns1));
	insns1[1] = (0x40000000 | (disp1 >> 2));
	__asm__ __volatile__("flush %0 + 4" : : "r" (insns1));
	insns1[0] = 0x8210000f;
	__asm__ __volatile__("flush %0" : : "r" (insns1));
    } else {
	/* PLT103 */

	unsigned int high32 = (value >> 32);
	unsigned int low32 = (unsigned int)value;

	unsigned int *insns1 = (insns0 + t);
	if ((high32 & 0x3ff) != 0) {
	    /* "sethi %hh(value), %g1" */
	    /* "sethi %lm(value), %g5" */
	    /* "or %g1, %hm(value), %g1" */
	    /* "or %g5, %lo(value), %g5" */
	    /* "sllx %g1, 32, %g1" */
	    /* "jmpl %g1 + %g5, %g0" */
	    /* "nop"  */

	    insns1[5] = 0x81c04005;
	    __asm__ __volatile__("flush %0 + 20" : : "r" (insns1));
	    insns1[4] = 0x83287020;
	    __asm__ __volatile__("flush %0 + 16" : : "r" (insns1));
	    insns1[3] = (0x8a116000 | (low32 & 0x3ff));
	    __asm__ __volatile__("flush %0 + 12" : : "r" (insns1));
	    insns1[2] = (0x82106000 | (high32 & 0x3ff));
	    __asm__ __volatile__("flush %0 + 8" : : "r" (insns1));
	    insns1[1] = (0x0b000000 | (low32 >> 10));
	    __asm__ __volatile__("flush %0 + 4" : : "r" (insns1));
	    insns1[0] = (0x03000000 | (high32 >> 10));
	    __asm__ __volatile__("flush %0" : : "r" (insns1));
	} else {
	    /* "sethi %hh(value), %g1" */
	    /* "sethi %lm(value), %g5" */
	    /* "sllx %g1, 32, %g1" */
	    /* "or %g5, %lo(value), %g5" */
	    /* "jmpl %g1 + %g5, %g0" */
	    /* "nop" */

	    insns1[4] = 0x81c04005;
	    __asm__ __volatile__("flush %0 + 16" : : "r" (insns1));
	    insns1[3] = (0x8a116000 | (low32 & 0x3ff));
	    __asm__ __volatile__("flush %0 + 12" : : "r" (insns1));
	    insns1[2] = 0x83287020;
	    __asm__ __volatile__("flush %0 + 8" : : "r" (insns1));
	    insns1[1] = (0x0b000000 | (low32 >> 10));
	    __asm__ __volatile__("flush %0 + 4" : : "r" (insns1));
	    insns1[0] = 0x03000000 | (high32 >> 10);
	    __asm__ __volatile__("flush %0" : : "r" (insns1));
	}
    }
#else
    (*kmr_ld_err)(DIE, "(configuration error).\n");
    abort();
#endif /*__sparc__*/
}

/* [elf_machine_rela() in sysdeps/sparc/sparc64/dl-machine.h]. */

static void
kmr_bind_elf_sparc(int isa, struct link_map *m,
		   Elf64_Rela *r, Elf64_Addr *slot)
{
    assert(isa == EM_SPARCV9);

    Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
    Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];
    struct SYMMAP ref = {.map = m, .sym = sym};
    char *name = kmr_get_name(&ref);
    unsigned long relty = ELF64_R_TYPE(r->r_info);

    struct link_map *ldso = &_rtld_global._dl_rtld_map;

    switch (relty) {

    case R_SPARC_NONE:
	break;

    case R_SPARC_RELATIVE: {
	if (m != ldso) {
	    *slot += (m->l_addr + r->r_addend);
	}
	break;
    }

    case R_SPARC_COPY: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	if (def.sym != 0) {
	    Elf64_Addr value = kmr_get_symbol_value(&def, (Elf64_Sxword)0);
	    if (def.sym->st_size != ref.sym->st_size) {
		(*kmr_ld_err)(WRN, "Symbol '%s' (copy-relocation)"
			      " has different sizes.\n", name);
	    }
	    size_t sz = MIN(def.sym->st_size, ref.sym->st_size);
	    memcpy(slot, (void *)value, sz);
	    (*kmr_ld_err)(DIN, "  R_COPY (%s) memcpy(%p, %p, %ld).\n",
			  name, slot, (void *)value, sz); fflush(0);
	}
	break;
    }

    case R_SPARC_64:
    case R_SPARC_GLOB_DAT: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	*slot = value;
	break;
    }

    case R_SPARC_IRELATIVE: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value0 = kmr_get_symbol_value(&def, r->r_addend);
	Elf64_Addr value1 = (*(Elf64_Addr (*)(void))value0)();
	*slot = value1;
	break;
    }

    case R_SPARC_JMP_IREL:
    case R_SPARC_JMP_SLOT: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value0 = kmr_get_symbol_value(&def, r->r_addend);
	Elf64_Addr value1;
	if (relty == R_SPARC_JMP_IREL) {
	    value1 = (*(Elf64_Addr (*)(void))value0)();
	} else {
	    value1 = value0;
	}
	kmr_bind_plt_sparc(m, r, slot, value1, (r->r_addend != 0), 0);
	break;
    }

    case R_SPARC_TLS_DTPMOD64:
	assert(0);
	break;

    case R_SPARC_TLS_DTPOFF64:
	assert(0);
	break;

    case R_SPARC_TLS_TPOFF64:
	assert(0);
	break;

    case R_SPARC_TLS_LE_HIX22:
    case R_SPARC_TLS_LE_LOX10: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	if (def.sym != 0) {
	    /*CHECK_STATIC_TLS(m, def.map);*/
	    assert(def.map->l_tls_offset != 0);
	    Elf64_Addr value = (def.sym->st_value - def.map->l_tls_offset
				+ r->r_addend);
	    if (relty == R_SPARC_TLS_LE_HIX22) {
		unsigned int *p = (unsigned int *)slot;
		*p = ((*p & 0xffc00000) | (((~value) >> 10) & 0x3fffff));
	    } else {
		unsigned int *p = (unsigned int *)slot;
		*p = ((*p & 0xffffe000) | (value & 0x3ff) | 0x1c00);
	    }
	}
	break;
    }

    case R_SPARC_8: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	char *p = (char *)slot;
	*p = value;
	break;
    }

    case R_SPARC_16: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	short *p = (short *)slot;
	*p = value;
	break;
    }

    case R_SPARC_32: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = value;
	break;
    }

    case R_SPARC_DISP8: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	char *p = (char *)slot;
	*p = (value - (Elf64_Addr)slot);
	break;
    }

    case R_SPARC_DISP16: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	short *p = (short *)slot;
	*p = (value - (Elf64_Addr)slot);
	break;
    }

    case R_SPARC_DISP32: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = (value - (Elf64_Addr)slot);
	break;
    }

    case R_SPARC_WDISP30: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & 0xc0000000)
	      | (((value - (Elf64_Addr)slot) >> 2) & 0x3fffffff));
	break;
    }

	/* (MEDLOW code model relocations). */

    case R_SPARC_LO10: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & ~0x3ff) | (value & 0x3ff));
	break;
    }

    case R_SPARC_HI22: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & 0xffc00000) | ((value >> 10) & 0x3fffff));
	break;
    }

    case R_SPARC_OLO10: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	Elf64_Xword rdata = ELF64_R_TYPE_DATA(r->r_info);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & ~0x1fff) | (((value & 0x3ff) + rdata) & 0x1fff));
	break;
    }

	/* (MEDMID code model relocations). */

    case R_SPARC_H44: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & 0xffc00000) | ((value >> 22) & 0x3fffff));
	break;
    }

    case R_SPARC_M44: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & ~0x3ff) | ((value >> 12) & 0x3ff));
	break;
    }

    case R_SPARC_L44: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & ~0xfff) | (value & 0xfff));
	break;
    }

	/* (MEDANY code model relocations). */

    case R_SPARC_HH22: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & 0xffc00000) | (value >> 42));
	break;
    }

    case R_SPARC_HM10: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & ~0x3ff) | ((value >> 32) & 0x3ff));
	break;
    }

    case R_SPARC_LM22: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned int *p = (unsigned int *)slot;
	*p = ((*p & 0xffc00000) | ((value >> 10) & 0x003fffff));
	break;
    }

    case R_SPARC_UA16: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned char *v = (unsigned char *)slot;
	v[0] = (value >> 8);
	v[1] = value;
	break;
    }

    case R_SPARC_UA32: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	unsigned char *v = (unsigned char *)slot;
	v[0] = (value >> 24);
	v[1] = (value >> 16);
	v[2] = (value >> 8);
	v[3] = value;
	break;
    }

    case R_SPARC_UA64: {
	struct SYMMAP def = kmr_resolve_map(isa, &ref, r, m);
	Elf64_Addr value = kmr_get_symbol_value(&def, r->r_addend);
	if (((long)slot & 3) == 0) {
	    unsigned int *v = (unsigned int *)slot;
	    v[0] = (value >> 32);
	    v[1] = value;
	} else {
	    unsigned char *v = (unsigned char *)slot;
	    v[0] = (value >> 56);
	    v[1] = (value >> 48);
	    v[2] = (value >> 40);
	    v[3] = (value >> 32);
	    v[4] = (value >> 24);
	    v[5] = (value >> 16);
	    v[6] = (value >> 8);
	    v[7] = value;
	}
	break;
    }

    default:
	(*kmr_ld_err)(DIE, "Unknown relocation information (%d).\n", relty);
	abort();
	break;
    }
}

/* Finds the copy-relocations and records them.  It is called in two
   ways, unbinding and rebinding.  It reverse-copies the content to
   the original definition for unbinding.  It works as unbinding when
   kmr_relocation_binder=0, and rebinding when
   kmr_relocation_binder!=0.  See kmr_bind_elf_machine() for
   relocation information. */

static void
kmr_find_copy_relocations(int isa, struct link_map *m,
			  Elf64_Rela *r, Elf64_Addr *slot)
{
    assert(isa == EM_X86_64 || isa == EM_SPARCV9);

    unsigned long relty = ELF64_R_TYPE(r->r_info);

    if (relty == R_X86_64_COPY || relty == R_SPARC_COPY) {
	Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
	Elf64_Sym *sym0 = &symtab[ELF64_R_SYM(r->r_info)];
	struct SYMMAP ref = {.map = m, .sym = sym0};
	char *name = kmr_get_name(&ref);

	int n = (sizeof(kmr_copy_relocs) / sizeof(kmr_copy_relocs[0]));
	assert(kmr_copy_relocs_count < n);
	struct SYMMAP def;
	if (kmr_relocation_binder == 0) {
	    def = kmr_resolve_map(isa, &ref, r, m);
	} else {
	    /* IN REBINDING, DEFINITION SHOULD BE IN THE A.OUT. */
	    Elf64_Sym *sym1 = kmr_lookup_in_so(kmr_relocation_binder, name);
	    def.sym = sym1;
	    def.map = kmr_relocation_binder;
	}
	(*kmr_ld_err)(DIN, "  Find R_COPY (%s) ref=%s, def=%s.\n",
		      name, kmr_get_so_name(ref.map),
		      kmr_get_so_name(def.map));
	if (def.sym == 0) {
	    (*kmr_ld_err)(WRN, "Find copy-relocation from unknown (%s).\n",
			  name);
	}
	kmr_copy_relocs[kmr_copy_relocs_count].st_name = name;
	kmr_copy_relocs[kmr_copy_relocs_count].ref = ref;
	kmr_copy_relocs[kmr_copy_relocs_count].def = def;
	kmr_copy_relocs_count++;

	if (kmr_relocation_binder == 0 && def.sym != 0) {
	    /* Move content when unbinding. */
	    assert(def.sym->st_size == ref.sym->st_size);
	    Elf64_Addr value = kmr_get_symbol_value(&def, (Elf64_Sxword)0);
	    size_t sz = MIN(def.sym->st_size, ref.sym->st_size);
	    memcpy((void *)value, slot, sz);
	    (*kmr_ld_err)(DIN, "  R_COPY (%s) memcpy(%p, %p, %ld).\n",
			  name, (void *)value, slot, sz); fflush(0);
	}
    } else {
	/* (Ignore). */
    }
}

static void kmr_relocate_copy_relocation_x86(int isa, struct link_map *m,
					     Elf64_Rela *r, Elf64_Addr *slot,
					     struct CPYREL *reloc);
static void kmr_relocate_copy_relocation_sparc(int isa, struct link_map *m,
					       Elf64_Rela *r, Elf64_Addr *slot,
					       struct CPYREL *reloc);

/* Relocates (binds or unbinds) a copy-relocation to the definition in
   the a.out or in SO. */

static void
kmr_rebind_copy_relocations(int isa, struct link_map *m,
			    Elf64_Rela *r, Elf64_Addr *slot)
{
    Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;
    Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];
    struct SYMMAP ref = {.map = m, .sym = sym};
    char *name = kmr_get_name(&ref);

    for (int i = 0; i < kmr_copy_relocs_count; i++) {
	if (strcmp(name, kmr_copy_relocs[i].st_name) == 0) {
	    if (isa == EM_X86_64) {
		kmr_relocate_copy_relocation_x86(isa, m, r, slot, &kmr_copy_relocs[i]);
	    } else if (isa == EM_SPARCV9) {
		kmr_relocate_copy_relocation_sparc(isa, m, r, slot, &kmr_copy_relocs[i]);
	    }
	    break;
	}
    }
}

static void
kmr_relocate_copy_relocation_x86(int isa, struct link_map *m,
				 Elf64_Rela *r, Elf64_Addr *slot,
				 struct CPYREL *reloc)
{
    assert(isa == EM_X86_64);

    int cc;

    /*Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;*/
    /*Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];*/
    /*struct r_found_version *version = kmr_get_symbol_version(m, r);*/
    unsigned long relty = ELF64_R_TYPE(r->r_info);

    switch (relty) {
    case R_X86_64_NONE:
	assert(0);
	break;

    case R_X86_64_RELATIVE:
	assert(0);
	break;

    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT: {
	(*kmr_ld_err)(DIN, "  Rebind R_COPY (%s) ref=%s, def=%s.\n",
		      reloc->st_name, kmr_get_so_name(m),
		      kmr_get_so_name(reloc->def.map));
	Elf64_Addr pagesize = kmr_get_page_size1();
	Elf64_Addr s = (m->l_addr + m->l_relro_addr);
	Elf64_Addr e = (s + m->l_relro_size);
	_Bool ro = (s <= (Elf64_Addr)slot && (Elf64_Addr)slot < e);
	Elf64_Addr s0 = kmr_floor_to_align(s, pagesize);
	if (ro) {
	    int prot = (PROT_READ|PROT_WRITE);
	    cc = mprotect((void *)s0, (e - s0), prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      (void *)s0, (e - s0), prot, strerror(errno));
		abort();
	    }
	}
	Elf64_Addr value = kmr_get_symbol_value(&reloc->def, r->r_addend);
	*slot = value;
	if (ro) {
	    int prot = PROT_READ;
	    cc = mprotect((void *)s0, (e - s0), prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      (void *)s0, (e - s0), prot, strerror(errno));
		abort();
	    }
	}
	break;
    }

    case R_X86_64_DTPMOD64:
	assert(0);
	break;

    case R_X86_64_DTPOFF64:
	assert(0);
	break;

    case R_X86_64_TLSDESC:
	assert(0);
	break;

    case R_X86_64_TPOFF64:
	assert(0);
	break;

    case R_X86_64_64:
	assert(0);
	break;

    case R_X86_64_32:
	assert(0);
	break;

    case R_X86_64_PC32:
	assert(0);
	break;

    case R_X86_64_COPY:
	assert(0);
	break;

    case R_X86_64_IRELATIVE:
	assert(0);
	break;

    default:
	assert(0);
	break;
    }
}

static void
kmr_relocate_copy_relocation_sparc(int isa, struct link_map *m,
				   Elf64_Rela *r, Elf64_Addr *slot,
				   struct CPYREL *reloc)
{
    assert(isa == EM_SPARCV9);

    int cc;

    /*Elf64_Sym *symtab = (void *)m->l_info[DT_SYMTAB]->d_un.d_ptr;*/
    /*Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];*/
    /*char *strings = (void *)m->l_info[DT_STRTAB]->d_un.d_ptr;*/
    /*char *name = (strings + sym->st_name);*/
    /*printf("name=%s (%d).\n", name, (int)relty); fflush(0);*/
    /*struct SYMMAP ref = {.map = m, .sym = sym};*/
    unsigned long relty = ELF64_R_TYPE(r->r_info);

    /*struct link_map *ldso = &_rtld_global._dl_rtld_map;*/

    switch (relty) {

    case R_SPARC_NONE:
	assert(0);
	break;

    case R_SPARC_RELATIVE:
	assert(0);
	break;

    case R_SPARC_COPY:
	assert(0);
	break;

    case R_SPARC_64:
    case R_SPARC_GLOB_DAT: {
	(*kmr_ld_err)(DIN, "  Rebind R_COPY (%s) ref=%s, def=%s.\n",
		      reloc->st_name, kmr_get_so_name(m),
		      kmr_get_so_name(reloc->def.map));
	Elf64_Addr pagesize = kmr_get_page_size1();
	Elf64_Addr s = (m->l_addr + m->l_relro_addr);
	Elf64_Addr e = (s + m->l_relro_size);
	_Bool ro = (s <= (Elf64_Addr)slot && (Elf64_Addr)slot < e);
	Elf64_Addr s0 = kmr_floor_to_align(s, pagesize);
	if (ro) {
	    int prot = (PROT_READ|PROT_WRITE);
	    cc = mprotect((void *)s0, (e - s0), prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			   (void *)s0, (e - s0), prot, strerror(errno));
		abort();
	    }
	}
	Elf64_Addr value = kmr_get_symbol_value(&reloc->def, r->r_addend);
	*slot = value;
	if (ro) {
	    int prot = PROT_READ;
	    cc = mprotect((void *)s0, (e - s0), prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      (void *)s0, (e - s0), prot, strerror(errno));
		abort();
	    }
	}
	break;
    }

    case R_SPARC_IRELATIVE:
	assert(0);
	break;

    case R_SPARC_JMP_IREL:
	assert(0);
	break;

    case R_SPARC_JMP_SLOT: {
	(*kmr_ld_err)(DIN, "  Rebind R_COPY (%s) ref=%s, def=%s.\n",
		      reloc->st_name, kmr_get_so_name(m),
		      kmr_get_so_name(reloc->def.map));
	Elf64_Addr pagesize = kmr_get_page_size1();
	Elf64_Addr s = (m->l_addr + m->l_relro_addr);
	Elf64_Addr e = (s + m->l_relro_size);
	_Bool ro = (s <= (Elf64_Addr)slot && (Elf64_Addr)slot < e);
	Elf64_Addr s0 = kmr_floor_to_align(s, pagesize);
	if (ro) {
	    int prot = (PROT_READ|PROT_WRITE);
	    cc = mprotect((void *)s0, (e - s0), prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      (void *)s0, (e - s0), prot, strerror(errno));
		abort();
	    }
	}
	Elf64_Addr value = kmr_get_symbol_value(&reloc->def, r->r_addend);
	kmr_bind_plt_sparc(m, r, slot, value, (r->r_addend != 0), 0);
	if (ro) {
	    int prot = PROT_READ;
	    cc = mprotect((void *)s0, (e - s0), prot);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "mprotect(%p, 0x%zx, 0x%z): %s.\n",
			      (void *)s0, (e - s0), prot, strerror(errno));
		abort();
	    }
	}
	break;
    }

    case R_SPARC_TLS_DTPMOD64:
	assert(0);
	break;

    case R_SPARC_TLS_DTPOFF64:
	assert(0);
	break;

    case R_SPARC_TLS_TPOFF64:
	assert(0);
	break;

    case R_SPARC_TLS_LE_HIX22:
    case R_SPARC_TLS_LE_LOX10:
	assert(0);
	break;

    case R_SPARC_8:
	assert(0);
	break;

    case R_SPARC_16:
	assert(0);
	break;

    case R_SPARC_32:
	assert(0);
	break;

    case R_SPARC_DISP8:
	assert(0);
	break;

    case R_SPARC_DISP16:
	assert(0);
	break;

    case R_SPARC_DISP32:
	assert(0);
	break;

    case R_SPARC_WDISP30:
	assert(0);
	break;

	/* (MEDLOW code model relocations). */

    case R_SPARC_LO10:
	assert(0);
	break;

    case R_SPARC_HI22:
	assert(0);
	break;

    case R_SPARC_OLO10:
	assert(0);
	break;

	/* (MEDMID code model relocations). */

    case R_SPARC_H44:
	assert(0);
	break;

    case R_SPARC_M44:
	assert(0);
	break;

    case R_SPARC_L44:
	assert(0);
	break;

	/* (MEDANY code model relocations). */

    case R_SPARC_HH22:
	assert(0);
	break;

    case R_SPARC_HM10:
	assert(0);
	break;

    case R_SPARC_LM22:
	assert(0);
	break;

    case R_SPARC_UA16:
	assert(0);
	break;

    case R_SPARC_UA32:
	assert(0);
	break;

    case R_SPARC_UA64:
	assert(0);
	break;

    default:
	(*kmr_ld_err)(DIE, "Unknown relocation information (%d).\n", relty);
	abort();
	break;
    }
}

/* ================================================================ */

/* (TLS) */

/* MEMO: (1) The list "_rtld_global.dl_tls_dtv_slotinfo_list" has
   link-maps with non-zero l_tls_blocksize.  The toplevel is a linked
   list and each element (.slotinfo[i]) holds some (.len) entries.
   (The total is dl_tls_max_dtv_idx entries).  (2) The values of
   functions slots:
   _rtld_global._dl_init_static_tls=<__pthread_init_static_tls>
   _rtld_global._dl_wait_lookup_done=<__wait_lookup_done>. */

/* Adjusts TLS offsets.  Note the a.out needs TLS be located at the
   first position.  See [init_tls() in elf/rtld.c], [_dl_open_worker()
   in elf/dl-open.c], and [_dl_try_allocate_static_tls() in
   elf/dl-reloc.c].  The first part checks the offsets, like
   [_dl_determine_tlsoffset() in elf/dl-tls.c].  See also
   [_dl_allocate_tls_init() in elf/dl-tls.c].  The TLS offsets are
   positive, although the actual offsets are negative as they are
   placed in front of the TCB.  The second part calls thread
   initializer __pthread_init_static_tls(), which copies TLS initial
   values.  __pthread_init_static_tls() is defined in
   [nptl/allocatestack.c].  It is set to
   _rtld_global._dl_init_static_tls in [nptl/nptl-init.c].  It skips
   [_dl_update_slotinfo() in elf/dl-tls.c].  ASSUMPTIONS: (1) It
   assumes the TLS layout is TLS_TCB_AT_TP.  (2) It assumes the ELF
   PT_TLS content is aligned (p_vaddr to p_align) and
   l_tls_firstbyte_offset is zero.  NOTE: (1) The first entry of
   _dl_tls_dtv_slotinfo_list is a duplicate of the second, and thus,
   is skipped. */

static void
kmr_reset_tls_space(struct link_map *m0, char **skipreset)
{
    //#if (!defined(TLS_TCB_AT_TP) || !TLS_TCB_AT_TP)
    //#error "Assume TLS layout TLS_TCB_AT_TP"
    //#endif

    if (0) {
	printf("tls_static_size=%ld tls_static_used=%ld\n",
	       _rtld_global._dl_tls_static_size,
	       _rtld_global._dl_tls_static_used); fflush(0);
    }

    assert(m0->l_tls_align == 0 || m0->l_tls_firstbyte_offset == 0);

    /* Calculate a TLS offset of the new a.out. */

    size_t size = m0->l_tls_blocksize;
    if (size <= kmr_exec_info.tls_size) {
	/* (TLS fits in the old space). */
	(*kmr_ld_err)(MSG, "TLS fits in the old space.\n");
	m0->l_tls_offset = kmr_exec_info.tls_offset;
    } else {
	(*kmr_ld_err)(DIE, "TLS does not fix in the old space.\n");
	abort();
    }

    /* Reinitialize the TLS (filling the values) of the existing
       threads by calling __pthread_init_static_tls(). */

    assert(_rtld_global._dl_tls_dtv_slotinfo_list != 0);
    struct dtv_slotinfo_list *infos = _rtld_global._dl_tls_dtv_slotinfo_list;

    if (skipreset == 0) {
	if (m0->l_tls_blocksize > 0) {
	    (*kmr_ld_err)(MSG, "Reset TLS of a.out.\n");
	    (*_rtld_global._dl_init_static_tls)(m0);
	}
    } else {
	size_t indexbase;
	indexbase = 0;
	for (struct dtv_slotinfo_list *p = infos; p != 0; p = p->next) {
	    for (size_t i = 0; p->slotinfo[i].map != 0; i++) {
		assert (i < p->len);
		struct link_map *m = p->slotinfo[i].map;
		size_t index = (i + indexbase);
		if (index != m->l_tls_modid) {
		    /* (Skip the first entry). */
		    assert(i == 0);
		} else {
		    _Bool skip = kmr_check_library_name(m->l_name, skipreset, 0);
		    if (!skip && m->l_tls_blocksize > 0) {
			/* Skip _dl_add_to_slotinfo(m). */
			/* Skip _dl_update_slotinfo(m->l_tls_modid). */
			(*kmr_ld_err)(MSG, "Reset TLS of SO.\n");
			(*_rtld_global._dl_init_static_tls)(m);
		    }
		}
	    }
	    indexbase += p->len;
	}
    }
}

/* ================================================================ */

/* (Main Part) */

static int kmr_make_preloaded(struct link_map *m0);
static void kmr_restart_x86(int isa, void *entrypoint, char **argv);
static void kmr_restart_sparc(int isa, void *entrypoint, char **argv);

/* Sets the error/warning/message printer.  LEVEL is 0 to 3.  PRINTER
   can be a null. */

void
kmr_ld_set_error_printer(int level, void (*printer)(int, char *, ...))
{
    assert(0 <= level && level <= DIN);
    kmr_ld_err = ((printer != 0) ?  printer : kmr_print_errors);
    kmr_ld_verbosity = level;
}

/* Returns the size of the symbol, or returns -1 when not found.  It
   first tests the existence of the symbol by dlsym(), because
   _dl_lookup_symbol_x() aborts inside. */

long
kmr_ld_get_symbol_size(char *name)
{
    kmr_lookupfn_t lookup = _rtld_global_ro._dl_lookup_symbol_x;

    int cc;

    void *p = dlsym(RTLD_DEFAULT, name);
    if (p == 0) {
	return -1;
    } else {
	struct link_map *m0 = 0;

	{
	    void *ma = dlopen(0, (RTLD_NOW|RTLD_GLOBAL|RTLD_NOLOAD));
	    if (ma == 0) {
		(*kmr_ld_err)(DIE, "dlopen(0): %s.\n", dlerror());
		abort();
	    }
	    cc = dlinfo(ma, RTLD_DI_LINKMAP, &m0);
	    if (cc == -1) {
		(*kmr_ld_err)(DIE, "dlinfo(a.out): %s.\n", dlerror());
		abort();
	    }
	    cc = dlclose(ma);
	    if (cc != 0) {
		(*kmr_ld_err)(DIE, "dlclose(0): %s.\n", dlerror());
		abort();
	    }
	}

	const Elf64_Sym *s = 0;
	struct link_map *m = (*lookup)(name, m0, &s,
				       m0->l_scope, 0, 0,
				       DL_LOOKUP_ADD_DEPENDENCY, 0);
	if (m != 0) {
	    return (*s).st_size;
	} else {
	    return -1;
	}
    }
}

/* Restart a new a.out with an ARGV vector.  It is like execve() but
   "path" is argv[0] and "envp" is implicit.  The arguments except
   ARGV are only effective at the first call.  They can be zero for
   later calls.  OLDARGV is an original argv pointer which is used to
   replace the command line strings visible in core dumps.  FLAGS are
   bits.  The 0x10 bit indicates to use memcpy() the data segment
   instead of mmap().  The 0x100 bit indicates to make this library as
   preloaded.  HEAPBOTTOM specifies the lower bound of heaps. */

void
kmr_ld_usoexec(char **argv, char **oldargv, long flags, char *heapbottom)
{
    int cc;

    if (kmr_exec_info.map_end == 0) {
	/* Do it once. */

	int oldargc = (long)oldargv[-1];
	if (oldargv[oldargc] != 0) {
	    (*kmr_ld_err)(DIE, "Bad format in old argv (argv=%p).\n",
			  oldargv);
	    abort();
	}
	char **oldenvv = &oldargv[oldargc + 1];
	if (oldenvv != environ) {
	    (*kmr_ld_err)(DIE,
			  ("Bad format in old argv, mismatch with environ"
			   " (argv=%p, envv=%p, environ=%p).\n"),
			  oldargv, oldenvv, environ);
	    abort();
	}

	kmr_exec_info.old_argv = oldargv;
	kmr_exec_info.old_envv = oldenvv;
	kmr_exec_info.old_args = oldargv[0];
	kmr_exec_info.old_args_size = (oldenvv[0] - oldargv[0]);

	kmr_exec_info.heap_bottom = heapbottom;

	_Bool copy_data_segment = ((flags & 0x10) != 0);
	_Bool loader_preloaded = ((flags & 0x100) != 0);
	kmr_exec_info.copy_data_segment = copy_data_segment;
	kmr_exec_info.loader_preloaded = loader_preloaded;
    }

    if (kmr_ld_verbosity >= WRN) {
	int sigs[] = {SIGSEGV, SIGILL, 0};
	kmr_install_backtrace_printer(sigs);
    }

    /* Check the ISA of the running machine. */

    int isa;

    {
	struct utsname u;
	cc = uname(&u);
	assert(cc == 0);
	if (strcmp("x86_64", u.machine) == 0) {
	    isa = EM_X86_64;
	} else if (strcmp("s64fx", u.machine) == 0) {
	    isa = EM_SPARCV9;
	} else if (strcmp("sun4u", u.machine) == 0) {
	    isa = EM_SPARCV9;
	} else {
	    isa = 0;
	    (*kmr_ld_err)(DIE, "Bad machine, unsupported: %s.\n", u.machine);
	    abort();
	}
	assert(isa != 0);
    }

    /* Copy arguments in case they are in text/data. */

    int new_argc;

    {
	int argslimit = ((sizeof(kmr_new_argv) / sizeof(kmr_new_argv[0])) - 1);
	new_argc = 0;
	for (int i = 0; i < argslimit; i++) {
	    if (argv[i] == 0) {
		new_argc = i;
		break;
	    }
	}
	if (new_argc == 0) {
	    (*kmr_ld_err)(DIE, "Bad argv, none or too many.\n");
	    abort();
	}
	assert(new_argc != 0 && new_argc <= argslimit);

	char *strslimit = &kmr_new_argv_strings[sizeof(kmr_new_argv_strings)];
	char *p;
	p = kmr_new_argv_strings;
	for (int i = 0; i < new_argc; i++) {
	    int n = strlen(argv[i]);
	    if ((p + n + 1) >= strslimit) {
		(*kmr_ld_err)(DIE, "Bad argv, strings not fit in buffer.\n");
		abort();
	    }
	    memcpy(p, argv[i], (size_t)(n + 1));
	    kmr_new_argv[i] = p;
	    p += (n + 1);
	}
	kmr_new_argv[new_argc] = 0;
    }

    char *name = kmr_new_argv[0];

    if (kmr_ld_verbosity >= MSG) {
	(*kmr_ld_err)(MSG, "Reload: executable=%s, nommap=%d, preload=%d.\n",
		      name,
		      kmr_exec_info.copy_data_segment,
		      kmr_exec_info.loader_preloaded);
    }

    /*if (kmr_ld_verbosity >= DIN) {kmr_dump_tls_info();}*/

    //(*kmr_ld_err)(MSG, "pagesize=%d.\n", kmr_get_page_size1());
    //printf("sizeof(struct link_map)=%ld\n", sizeof(struct link_map));
    //printf("sizeof(_rtld_global)=%ld\n", sizeof(_rtld_global));
    //printf("sizeof(_rtld_global_ro)=%ld\n", sizeof(_rtld_global_ro));

    /* Open the target a.out, and check the ELF marker. */

    _Bool image_malloced = 1;
    char *image;
    size_t size;
    int fd;
    struct stat statv;

    {
	cc = stat(name, &statv);
	if (cc == -1) {
	    (*kmr_ld_err)(DIE, "stat(%s): %s.\n", name, strerror(errno));
	    abort();
	}
	size = statv.st_size;

	fd = open(name, O_RDONLY);
	if (fd == -1) {
	    (*kmr_ld_err)(DIE, "open(%s): %s.\n", name, strerror(errno));
	    abort();
	}

	if (image_malloced) {
	    image = malloc(size);
	    assert(image != 0);
	    size_t off = 0;
	    while (off < size) {
		size_t BUF = (8 * 1024);
		ssize_t cx = read(fd, (image + off), MIN((size - off), BUF));
		if (cx == -1) {
		    (*kmr_ld_err)(DIE, "read(%s): %s.\n", name,
				  strerror(errno));
		    abort();
		}
		off += cx;
	    }
	    (*kmr_ld_err)(DIN, "image(malloc)=%p.\n", image);
	} else {
	    image = mmap(0, size, (PROT_READ), (MAP_PRIVATE), fd, (off_t)0);
	    if (image == MAP_FAILED) {
		(*kmr_ld_err)(DIE, "mmap(%s): %s", name, strerror(errno));
		abort();
	    }
	    (*kmr_ld_err)(DIN, "image(mmap)=%p.\n", image);
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
	assert(ehdr->e_ident[0] == ELFMAG0
	       && ehdr->e_ident[1] == ELFMAG1
	       && ehdr->e_ident[2] == ELFMAG2
	       && ehdr->e_ident[3] == ELFMAG3);
	assert(ehdr->e_ident[EI_CLASS] == ELFCLASS64);
	assert(ehdr->e_type == ET_EXEC);
    }

    /* Find the link-map entry for the old a.out.  It assumes the
       first entry is the old a.out (it has no name). */

    struct link_map *m0old;

    {
	void *ma = dlopen(0, (RTLD_NOW|RTLD_GLOBAL|RTLD_NOLOAD));
	if (ma == 0) {
	    (*kmr_ld_err)(DIE, "dlopen(0): %s.\n", dlerror());
	    abort();
	}
	cc = dlinfo(ma, RTLD_DI_LINKMAP, &m0old);
	if (cc == -1) {
	    (*kmr_ld_err)(DIE, "dlinfo(a.out): %s.\n", dlerror());
	    abort();
	}
	/* Ascertain dl-handles are link-map entries. */
	assert(m0old != 0 && ma == m0old);
	assert(m0old->l_prev == 0 && m0old->l_next != 0);
	assert(m0old->l_type == lt_executable);

	cc = dlclose(ma);
	if (cc != 0) {
	    (*kmr_ld_err)(DIE, "dlclose(0): %s.\n", dlerror());
	    abort();
	}
    }

    assert(m0old != 0);
    kmr_aout_map = m0old;

    if (kmr_ld_verbosity >= DIN) {kmr_dump_link_maps(m0old);}

    kmr_check_structure_sizes_in_loaded_ldso(m0old);

    (*kmr_ld_err)(MSG, "Load the needed so...\n");
    kmr_load_needed_so(image, size, m0old);
    (*kmr_ld_err)(MSG, "Load the needed so done.\n");

    /* Save settings of the initial call. */

    if (kmr_exec_info.map_end == 0) {
	/* Do it once. */

	kmr_exec_info.map_end = MAX(m0old->l_map_end,
				    (Elf64_Addr)kmr_exec_info.heap_bottom);
	assert(kmr_exec_info.map_end != 0);

	kmr_exec_info.tls_offset = m0old->l_tls_offset;
	kmr_exec_info.tls_size = m0old->l_tls_blocksize;
	if (kmr_exec_info.copy_data_segment) {
	    kmr_record_fjmpg_pages(m0old);
	}
	if (kmr_exec_info.loader_preloaded) {
	    char *libname = KMR_KMRSPAWN;
    	    (*kmr_ld_err)(MSG, "Change scope for %s...\n", libname);
	    kmr_make_preloaded(m0old);
	    (*kmr_ld_err)(MSG, "Change scope for %s done\n", libname);
	}
	assert(kmr_exec_info.map_end != 0);
    }

    if (kmr_ld_verbosity >= DIN) {kmr_dump_link_maps(m0old);}

    /* Reset the error printer, which will become unusable. */

    if ((void *)kmr_ld_err < (void *)kmr_exec_info.map_end) {
	(*kmr_ld_err)(WRN, "Reset the error function; given one unusable.\n");
	kmr_ld_err = kmr_print_errors;
    }

    /* Block all signals. */

    sigset_t sigsetsave;

    {
	int thrusigs[] = {SIGKILL, SIGSTOP, SIGBUS, SIGFPE, SIGILL,
			  SIGSEGV, SIGHUP, SIGINT, SIGQUIT, SIGABRT,
			  SIGTERM, SIGXCPU, SIGXFSZ, SIGPROF, SIGPWR,
			  SIGSYS,
#ifdef SIGSTKFLT
			  SIGSTKFLT,
#endif
			  0};
	sigset_t ss;
	sigfillset(&ss);
	for (int i = 0; thrusigs[i] != 0; i++) {
	    sigdelset(&ss, thrusigs[i]);
	}
	/*(sigprocmask)*/
	cc = pthread_sigmask(SIG_BLOCK, &ss, &sigsetsave);
	if (cc != 0) {
	    (*kmr_ld_err)(WRN, "pthread_sigmask(): %s", strerror(cc));
	}
    }

    {
	(*kmr_ld_err)(MSG, "Unbind the old copy-relocations...\n");
	kmr_copy_relocs_count = 0;
	kmr_relocate_so(isa, m0old, kmr_find_copy_relocations, 0);
	if (kmr_copy_relocs_count > 0) {
	    for (struct link_map *p = m0old->l_next; p != 0; p = p->l_next) {
		kmr_relocate_so(isa, p, kmr_rebind_copy_relocations, 0);
	    }
	}
	(*kmr_ld_err)(MSG, "Unbind the old copy-relocations done.\n");
    }

    /* Replace the a.out image. */

    struct link_map *m0new;

    {
	struct link_map *m0 = m0old;

	(*kmr_ld_err)(DIN, "Put the new command name (%s).\n", name);
	kmr_change_aout_name(kmr_exec_info.old_args,
			     kmr_exec_info.old_args_size,
			     name);

	/* Save the old PHDR for unmapping the old a.out. */

	Elf64_Addr oaddr = m0old->l_addr;
	int ophnum = m0old->l_phnum;
	Elf64_Phdr ophdrs[ophnum];
	memcpy(ophdrs, m0old->l_phdr, (sizeof(Elf64_Phdr) * ophnum));

	(*kmr_ld_err)(MSG, "Reset the old link-map...\n");
	kmr_reset_link_map(m0, image, size);
	(*kmr_ld_err)(MSG, "Reset the old link-map done.\n");
	(*kmr_ld_err)(MSG, "Unmap the old a.out...\n");
	kmr_unmap_old_aout(oaddr, ophdrs, ophnum);
	(*kmr_ld_err)(MSG, "Unmap the old a.out done.\n");

	if (0) {
	    char pmap[80];
	    snprintf(pmap, sizeof(pmap), "pmap -x %d", getpid());
	    system(pmap);
	}

	(*kmr_ld_err)(MSG, "Remap the new a.out...\n");
	kmr_remap_new_aout(m0, image, size, fd);
	(*kmr_ld_err)(MSG, "Remap the new a.out done.\n");
	(*kmr_ld_err)(MSG, "Setup the new link-map...\n");
	kmr_setup_link_map(m0, image, size);
	(*kmr_ld_err)(MSG, "Setup the new link-map done.\n");

	m0->l_dev = statv.st_dev;
	m0->l_ino = statv.st_ino;
	m0->l_name = name;

	m0new = m0old;
	m0old = 0;
    }

    if (kmr_ld_verbosity >= DIN) {kmr_dump_link_maps(m0new);}

    if (kmr_exec_info.map_end < m0new->l_map_end) {
	(*kmr_ld_err)(DIE,
		      ("New a.out has text+data+bss larger than the old"
		       " (old-end=%p new-end=%p); heap will be corrupted.\n"),
		      kmr_exec_info.map_end, m0new->l_map_end);
	abort();
    }

    {
	(*kmr_ld_err)(MSG, "Relocate the new a.out...\n");
	kmr_relocate_so(isa, m0new, kmr_bind_elf_machine, 0);
	(*kmr_ld_err)(MSG, "Relocate the new a.out done.\n");

	(*kmr_ld_err)(MSG, "Rebind the new copy-relocations...\n");
	kmr_copy_relocs_count = 0;
	kmr_relocate_so(isa, m0new, kmr_find_copy_relocations, m0new);
	if (kmr_copy_relocs_count > 0) {
	    for (struct link_map *p = m0new->l_next; p != 0; p = p->l_next) {
		kmr_relocate_so(isa, p, kmr_rebind_copy_relocations, m0new);
	    }
	}
	(*kmr_ld_err)(MSG, "Rebind the new copy-relocations done.\n");
    }

    kmr_reset_tls_space(m0new, 0);

    if (image_malloced) {
	free(image);
    } else {
	cc = munmap(image, size);
	if (cc != 0) {
	    (*kmr_ld_err)(DIE, "munmap(): %s", strerror(errno));
	    abort();
	}
	assert(cc == 0);
    }

    cc = close(fd);
    assert(cc == 0);

    if (kmr_ld_verbosity >= MSG) {
	(*kmr_ld_err)(MSG, "Reloaded the new executable.\n");
    }

    assert(kmr_aout_map == m0new);

    /* Set up for the new a.out (unblock blocked signals, close files,
       and maybe run Boehm GC to reclaim unfreed memory. */

    {
	/*(sigprocmask)*/
	cc = pthread_sigmask(SIG_BLOCK, &sigsetsave, 0);
	if (cc != 0) {
	    (*kmr_ld_err)(WRN, "pthread_sigmask(): %s", strerror(cc));
	}

#if 0 /*GOMI*/
	if (kmr_exec_info.loader_preloaded) {
	    void (*fn)(void) = (void (*)(void))dlsym(RTLD_DEFAULT,
						     "kmr_ld_setup_hooks");
	    if (fn != 0) {
		(*fn)();
	    }
	}
#endif
    }

    /* Prepare arguments, and then start. */

    {
	void *entrypoint = (void *)m0new->l_entry;

	/* Check the stack top-end is far enough to run this frame. */

	volatile char s[8];
	volatile char *sp = s;
	assert(((char *)kmr_exec_info.old_argv - sp) > 100);

	/* Layout arguments at immediately before the old ENVP. */

	char **envv = kmr_exec_info.old_envv;
	char **argvstack = &envv[-(new_argc + 1)];
	for (int i = 0; i < new_argc; i++) {
	    argvstack[i] = kmr_new_argv[i];
	}
	argvstack[new_argc] = 0;
	long *iargv = (long *)argvstack;
	iargv[-1] = new_argc;

	if (kmr_ld_verbosity >= DIN) {
	    printf("  argc=%ld\n", (long)argvstack[-1]);
	    for (int i = 0; i < (new_argc + 1); i++) {
		printf("  argv[%d]=%s\n", i, argvstack[i]);
	    }
	}

	(*kmr_ld_err)(MSG, "Start at entry=%p.\n", entrypoint);

	if (isa == EM_X86_64) {
	    kmr_restart_x86(isa, entrypoint, argvstack);
	} else if (isa == EM_SPARCV9) {
	    kmr_restart_sparc(isa, entrypoint, argvstack);
	} else {
	    assert(isa == EM_X86_64 || isa == EM_SPARCV9);
	}
    }
}

/* Moves this SO ("libkmrspawn.so") to the front of the scope (next to
   an a.out).  It is used to make MPI hooks work as preloaded.  It
   changes the order of scope entries. */

static int
kmr_make_preloaded(struct link_map *m0)
{
    char *name = KMR_KMRSPAWN;
    if (m0->l_scope == 0) {
	(*kmr_ld_err)(WRN, "No scope information for a.out.\n");
	return -1;
    }
    struct link_map *m1 = kmr_find_named_so(m0, name);
    if (m1 == 0) {
	(*kmr_ld_err)(WRN, "SO not found (%s).\n", name);
	return -1;
    }
    struct r_scope_elem *lscope = m0->l_scope[0];
    unsigned int n = lscope->r_nlist;
    struct link_map **scope = lscope->r_list;
    if (!(scope != 0 && n > 1 && scope[0]->l_real == m0)) {
	(*kmr_ld_err)(WRN, "Scope information strange.\n");
	return -1;
    }
    int pos;
    pos = 0;
    for (int i = 1; i < (int)n; i++) {
	struct link_map *m = scope[i];
	if (m == m1) {
	    pos = i;
	    break;
	}
    }
    if (pos == 0) {
	(*kmr_ld_err)(WRN, "SO not in scope (%s).\n", name);
	return -1;
    }
    for (int i = pos; i >= 2; i--) {
	scope[i] = scope[i - 1];
    }
    scope[1] = m1;
    return 0;
}

/* STACK AT _START() */
/* (0,0):aux */
/* auxv[m]:aux */
/* 0:ptr */
/* envv[n]:ptr */
/* 0:ptr */
/* argv[argc]:ptr */
/* argc:int */

/* Starts from an entry point as specified by the SYSV ABI. */

static void
kmr_restart_x86(int isa, void *entrypoint, char **argv)
{
#ifdef __x86_64__
    void *ep = entrypoint;
    void *sp = (argv - 1);
    __asm__ __volatile__("mov $0, %rdx");
    __asm__ __volatile__("mov %0, %%rsp" : : "r" (sp));
    __asm__ __volatile__("mov %0, %%rax" : : "r" (ep));
    __asm__ __volatile__("jmp *%rax");
    __asm__ __volatile__("hlt");
#endif /*__x86_64__*/
    (*kmr_ld_err)(DIE, "(configuration error).\n");
    abort();
}

/* Starts from an entry point as specified by the SYSV ABI.  See
   "SYSTEM V APPLICATION BINARY INTERFACE SPARC Version 9 Processor
   Supplement" (May 17, 1996).  "Figure 3-32: Initial Process
   Stack". */

static void
kmr_restart_sparc(int isa, void *entrypoint, char **argv)
{
#ifdef __sparc__
    void *ep = (char *)entrypoint;
    void *sp = (char *)(argv - 1) - (16 * 8) - 0x7ff;
    __asm__ __volatile__("mov %0, %%sp" : : "r" (sp));
    __asm__ __volatile__("mov %0, %%l0" : : "r" (ep));
    __asm__ __volatile__("mov %g0, %g2");
    __asm__ __volatile__("mov %g0, %g3");
    __asm__ __volatile__("mov %g0, %g4");
    __asm__ __volatile__("mov %g0, %g1");
    __asm__ __volatile__("mov %g0, %fp");
    __asm__ __volatile__("jmp %l0");
    __asm__ __volatile__("nop");
    __asm__ __volatile__("illtrap 0");
#endif /*__sparc__*/
    (*kmr_ld_err)(DIE, "(configuration error).\n");
    abort();
}

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

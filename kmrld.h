/* kmrld.h (2016-07-09) -*-Coding: us-ascii;-*- */
/* Copyright (C) 2012-2016 RIKEN AICS */
/* Copyright (C) 1996-2007, 2009, 2010 Free Software Foundation, Inc. */

/** \file kmrld.h Interface to the routines defined in "kmrld.c". */

/* Verbosity of the error/message printer.  Smaller numbers are more
   sever.  The default error printer aborts at DIE.  DIN is for
   debugging of the library.  */

enum {
    DIE = 0,
    WRN = 1,
    MSG = 2,
    DIN = 3,
};

extern void kmr_ld_usoexec(char **argv, void (*lastfixing)(void),
			   char **oldargv, long flags, char *heapbottom);
extern long kmr_ld_get_symbol_size(char *symbol);
extern void kmr_ld_set_error_printer(int level,
				     void (*printfn)(int, char *, ...));
extern void (*kmr_ld_err)(int, char *, ...);

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

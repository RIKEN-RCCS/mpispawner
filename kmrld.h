/* kmrld.h (2016-07-09) -*-Coding: us-ascii;-*- */
/* Copyright (C) 2012-2016 RIKEN AICS */
/* Copyright (C) 1996-2007, 2009, 2010 Free Software Foundation, Inc. */

/** \file kmrld.h Interface defined in "kmrld.c". */

enum {
    DIE = 0,
    ERR = 1,
    WRN = 2,
    MSG = 3
};

extern void kmr_ld_usoexec(char **argv, char **oldargv, long flags,
			   void (*errfn)(int, char *, ...),
			   char *heapbottom);
extern long kmr_ld_get_symbol_size(char *symbol);
extern void (*kmr_ld_err)(int, char *, ...);

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

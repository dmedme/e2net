#
# Mip.solar - Traffic Generator components for SUN SOLARIS 2.3
#
# Copyright (c) E3 Systems 1995. All Rights Reserved.
# @(#) $Name$ $Id$
#
# Executable is ipdrive
#
# System V.4
#
CC=rcc
CFLAGS=-g -DPATH_AT -DSCO -DNOSTDIO -DM_UNIX -DATT -I. -I .. -I../../e2common
LIBS=../../e2common/comlib.a -lsocket -lcurses -ltermlib -lm
RANLIB = ar ts
#
all: ipdanal ipdrive
	@echo 'E2 Traffic Generator make finished'
#*************************************************************************
# Non-product-specific utilities
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
ipdanal: ipdanal.o ipdinrec.o ../../e2common/comlib.a
	$(CC) $(CFLAGS) -o ipdanal ipdanal.o ipdinrec.o $(LIBS)

ipdrive: ipdrive.o ipdinrec.o ../pathatlib.a ../../e2common/comlib.a
	$(CC) $(CFLAGS) -o ipdrive ipdrive.o ipdinrec.o ../pathatlib.a $(LIBS)

ipdanal.o: ipdanal.c ipdrive.h 
	$(CC) $(CFLAGS) -c ipdanal.c

ipdrive.o: ipdrive.c ipdrive.h 
	$(CC) $(CFLAGS) -c ipdrive.c

ipdinrec.o: ipdinrec.c ipdrive.h 
	$(CC) $(CFLAGS) -c ipdinrec.c


#
#  udbctest.mk
#
#  $Id: udbctest.mk,v 1.6 1995/06/17 03:53:12 openlink Exp $
#
#  Makefile for the UDBC test program
#
#  (C)Copyright 1993, 1994, 1995 OpenLink Software.
#  All Rights Reserved.
#
#  The copyright above and this notice must be preserved in all
#  copies of this source code.  The copyright above does not
#  evidence any actual or intended publication of this source code.
#
#  This is unpublished proprietary trade secret of OpenLink Software.
#  This source code may not be copied, disclosed, distributed, demonstrated
#  or licensed except as authorized by OpenLink Software.
#

#### Generic
#LIBS		= ../lib/libudbc.a ../lib/librpc.a
#### SCO Unix
#LIBS		= ../lib/libudbc.a ../lib/librpc.a -lsocket
#### OSF-1
#LIBS		= ../lib/libudbc.so
#### Solaris
LIBS= /export/home/dme/path/pathatlib.a /export/home/dme/e2common/comlib.a ../lib/libudbc.a ../lib/librpc.a -lnsl -lsocket
#### Linux
#LIBS		= ../lib/libudbc.sa
CFLAGS=-g -I../include -I. -I/export/home/dme/path -I/export/home/dme/e2common -DPATH_AT -DSOLAR -DV4 -DICL
opldrive: opldrive.c
	cc $(CFLAGS) -o opldrive opldrive.c $(LIBS)

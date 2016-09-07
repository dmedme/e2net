# makefile
#	SCCS ID: %W% %G%
##########################################################################
# The compilation stuff
##########################################################################
#
# Microsoft NT.4
#
LIBDIR=/cygnus/cygwin-b20/H-i586-cygwin32/lib
INCS=-I. -I../sqldrive -I../native/e2comnt -I../perfdb -I/oracle/v80/oci80 -I/cygnus/cygwin-b20/H-i586-cygwin32/i586-cygwin32/include/mingw32
LIBS=../perfdb/perf.a ../native/e2comnt/comlib.a -lwsock32 -lkernel32 -luser32 -lcrtdll
CFLAGS=-DWE_KNOW -DPOSIX -g -I. $(INCS) -DNOBPF_H -DNOETHER_H -DNOTCP_H -DNOIP_H -DNOIP_ICMP_H -DAT -DNT4 -DMINGW32 -L$(LIBDIR) -L/cygnus/cygwin-b20/H-i586-cygwin32/lib/gcc-lib/i586-cygwin32/egcs-2.91.57  -fwritable-strings -mno-cygwin
LDFLAGS=$(LIBS)
CLIBS=$(LIBS)
RANLIB = ar ts
VCC = gcc
CC = gcc
XPGCC = gcc
YACC=byacc
LEX=flex -l
##########################################################################
# The executables that are built
##########################################################################
# Makefile for snoopfix
all: ccsmul ccsdbg genconv aixdump2snp sqlmul sqldbg snoopfix eqsnf2snp codamul coddump llctrace2snp
	@echo All done
genconv: genconv.c e2net.o e2net.h
	$(CC) $(CFLAGS) -o genconv genconv.c e2net.o $(CLIBS)
dumpconv: genconv.c e2net.o e2net.h
	$(CC) $(CFLAGS) -o dumpconv -DDUMP genconv.c e2net.o $(CLIBS)
resum: resum.c e2net.o novell.o e2net.h
	$(CC) $(CFLAGS) -o resum resum.c e2net.o novell.o $(CLIBS)
aixdump2snp: aixdump2snp.c
	$(CC) $(CFLAGS) -o aixdump2snp aixdump2snp.c $(CLIBS)
llctrace2snp: llctrace2snp.c
	$(CC) $(CFLAGS) -o llctrace2snp llctrace2snp.c $(CLIBS)
eqsnf2snp: eqsnf2snp.c
	$(CC) $(CFLAGS) -o eqsnf2snp eqsnf2snp.c $(CLIBS)
mdis2snp: mdis2snp.c
	$(CC) $(CFLAGS) -o mdis2snp mdis2snp.c $(CLIBS)
coddrive: coddrive.c coddrive.h e2net.h e2net.o
	$(CC) $(CFLAGS) -o coddrive coddrive.c -DPATH_AT $(CLIBS)
coddump: coddump.c coddrive.h e2net.h
	$(CC) $(CFLAGS) -o coddump coddump.c -DPATH_AT $(CLIBS)
dmmul: genconv.c novell.h e2net.h e2net.o dmlib.o
	$(CC) $(CFLAGS) -DVERBOSE -DREC_PROT1=dm_app_recognise -o dmmul genconv.c dmlib.o e2net.c $(CLIBS)
codamul: genconv.c novell.h e2net.h e2net.o codextlib.o
	$(CC) $(CFLAGS) -DREC_PROT1=cod_app_recognise -o codamul genconv.c codextlib.o e2net.o $(CLIBS)
ccsmul: genconv.c novell.h e2net.h e2net.o ccsextlib.o
	$(CC) $(CFLAGS) -DREC_PROT1=ccs_app_recognise -o ccsmul genconv.c ccsextlib.o e2net.o $(CLIBS)
ccsdbg: genconv.c novell.h e2net.h e2net.o ccsextlib.c
	$(CC) $(CFLAGS) -DDEBUG -DREC_PROT1=ccs_app_recognise -o ccsdbg genconv.c ccsextlib.c e2net.o $(CLIBS)
trafmul: genconv.c novell.h e2net.h e2net.o trafextlib.o
	$(CC) $(CFLAGS) -DREC_PROT1=traf_app_recognise -o trafmul genconv.c trafextlib.o e2net.o $(CLIBS)
sqlmul: genconv.c novell.h e2net.h e2net.o sqlextlib.o pathextlib.o
	$(CC) $(CFLAGS) -DREC_PROT1=ora_app_recognise -DREC_PROT2=telnet_app_recognise -o sqlmul genconv.c sqlextlib.o pathextlib.o e2net.o malloc.o $(CLIBS)
sybmul: genconv.c novell.h e2net.h e2net.o sybextlib.o pathextlib.o
	$(CC) $(CFLAGS) -DREC_PROT1=syb_app_recognise -DREC_PROT2=telnet_app_recognise -o sybmul genconv.c sybextlib.o pathextlib.o e2net.o $(CLIBS)
pathmul: genconv.c novell.h e2net.h e2net.o pathextlib.o
	$(CC) $(CFLAGS) -DREC_PROT1=telnet_app_recognise -o pathmul genconv.c pathextlib.o e2net.o $(CLIBS)
sqldbg: genconv.c novell.h e2net.h e2net.o sqlextlib.c
	$(CC) $(CFLAGS) -DREC_PROT1=ora_app_recognise -o sqldbg genconv.c -DDEBUG sqlextlib.c e2net.o malloc.o $(CLIBS)
snoopfix: snoopfix.c e2net.o novell.o
	$(CC) $(CFLAGS) -o snoopfix snoopfix.c novell.o e2net.o $(CLIBS)
bpcs: bpcs.o novell.o e2net.o
	$(CC) $(CFLAGS) -o bpcs bpcs.o novell.o e2net.o $(CLIBS)
bpcs.o: bpcs.c novell.h e2net.h
	$(CC) $(CFLAGS) -c bpcs.c
novell.o: novell.c novell.h
	$(CC) $(CFLAGS) -c novell.c
e2net.o: e2net.c e2net.h
	$(CC) $(CFLAGS) -c e2net.c
sqlextlib.o: sqlextlib.c e2net.h
	$(CC) $(CFLAGS) -c sqlextlib.c
sybextlib.o: sybextlib.c e2net.h
	$(CC) $(CFLAGS) -DVERBOSE -c sybextlib.c
pathextlib.o: pathextlib.c e2net.h
	$(CC) $(CFLAGS) -c pathextlib.c
ipdanal: ipdanal.o ipdinrec.o
	$(CC) $(CFLAGS) -o ipdanal ipdanal.o ipdinrec.o $(CLIBS)
ipdanal.o: ipdanal.c ipdrive.h
	$(CC) $(CFLAGS) -c ipdanal.c
webdrive.o: webdrive.c webdrive.h
	$(CC) -DPATH_AT $(CFLAGS) -c webdrive.c
ipdrive.o: ipdrive.c ipdrive.h
	$(CC) -DPATH_AT $(CFLAGS) -c ipdrive.c
ipdinrec.o: ipdinrec.c ipdrive.h
	$(CC) -DPATH_AT $(CFLAGS) -c ipdinrec.c
win95tst: win95tst.o 
	$(CC) $(CFLAGS) -o win95tst win95tst.o -lwsock32 -lcrtdll -luser32 -lkernel32
win95tst.o: minitest.c
	$(CC) $(CFLAGS) -c minitest.c
	mv minitest.o win95tst.o
ipdrive: ipdrive.o ipdinrec.o ../native/e2comnt/comlib.a
	$(CC) $(CFLAGS) -o ipdrive ipdrive.o ipdinrec.o $(LIBS)
webdrive: webdrive.o ../native/e2comnt/comlib.a
	$(CC) $(CFLAGS) -o webdrive webdrive.o $(LIBS)

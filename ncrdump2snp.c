/************************************************************************
 * Convert a file captured by the Sequent llctrace utility to one that the
 * E2 snoop-oriented facilities can handle.
 *
 * The layout claims to mirror the General Network Sniffer format.
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1994\n";
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
extern int errno;
/***************************************************************************
 * Functions in this file.
 */
#define ENALIGN(x) ((x%4)?(x+(4-(x%4))):x)
extern int errno;
struct snoop_header {
    long len;
    long saved_len;
    long unknown[2];
    long secs_since_1970;
    long musecs;
};
struct	ether_header {
	unsigned char ether_dhost[6];
	unsigned char ether_shost[6];
	unsigned short	ether_type;
};
#define	ETHERTYPE_IP		(0x0800)	/* IP protocol */
/*
 * The alignments are all screwed up, so we use the knwon lengths
 * to get the copies right
 */
#define MAC_LEN 13
#define SNAP_LEN 8
#define ETHER_LEN 14
#define PAD_LENGTH 3
struct  machdr {
    unchar  pad[PAD_LENGTH];        /* Frame control field */
    unchar  fc;                     /* Frame control field */
    unchar  da[6];                  /* Destination address */
    unchar  sa[6];                  /* Source address */
};
/*
    Every LLC frame sent on the network must have an LLC header.  The
    format and contents of this header for TCP/IP are defined in
    RFC1103.
*/
struct  llchdr {
    unchar  dsap;                   /* dsap field */
    unchar  ssap;                   /* ssap field */
    unchar  control;                /* control field */
    unchar  proto_id[3];            /* Protocol id field/org code */
    ushort  etype;                  /* Ether type field */
};
/*
    The entire header for a TCP/IP FDDI frame looks like the following...
*/
struct  fddihdr {
    struct machdr   mh;
    struct llchdr   lh;
};
long match_host = 0;
/*
 * Write out the message with an Ethernet rather than an FDDI header,
 * losing the LLC SNAP header in the process.
 */
static void snoop_write(s,m)
struct snoop_header * s;
char * m;
{
int j;
static char * last_msg;
static int last_sz;
static struct	ether_header e;
static struct	fddihdr f;
struct ip ip;
    memcpy(((char *) &f) + 3, m, MAC_LEN + SNAP_LEN);
    f.lh.etype = htons(f.lh.etype);
    if (f.lh.etype == ETHERTYPE_IP)
    { 
        if (match_host != 0)
        {
            memcpy((unsigned char *) &ip, m + MAC_LEN + SNAP_LEN,sizeof(ip));
            if (memcmp((char *) &match_host, (char *) & ip.ip_src,
                        sizeof(match_host))
              && memcmp((char *) &match_host, (char *) & ip.ip_dst,
                        sizeof(match_host)))
                return;
        }
    }
    else
    {
        fprintf(stderr, "Ether Type:%x\n", f.lh.etype);
        return;
    }
    if (last_sz != 0)
    {
        if (last_sz == (s->saved_len - SNAP_LEN - MAC_LEN)
          && memcmp(last_msg,m + SNAP_LEN + MAC_LEN,last_sz) == 0)
             return;
        free(last_msg); 
    }
    last_sz = s->saved_len - SNAP_LEN - MAC_LEN;
    last_msg = (char *) malloc(last_sz);
    memcpy(last_msg,  m + SNAP_LEN + MAC_LEN, last_sz);
    memcpy((char *) &e.ether_dhost[0], (char *)& f.mh.da, sizeof(f.mh.da));
    memcpy((char *) &e.ether_shost[0], (char *)& f.mh.sa, sizeof(f.mh.sa));
    e.ether_type = htons(f.lh.etype);
    j = last_sz + ETHER_LEN;
    j = ENALIGN(j);
    s->saved_len = htonl(j);
    s->len = s->saved_len;
    s->secs_since_1970 = htonl((s->secs_since_1970));
    s->musecs = htonl((s->musecs));
    if (j < 32768)
    {
        fwrite((char *) s,sizeof(char),
          sizeof(struct snoop_header),stdout);         /* The snoop header */
        fwrite((char *) &e, sizeof(char),
          ETHER_LEN,stdout);                           /* The ether header */
        fwrite(m + SNAP_LEN + MAC_LEN,sizeof(char), j- ETHER_LEN,stdout); 
                                                       /* The packet */
    }
    else
        fprintf(stderr, "Funny Length:%d\n", j);
    return;
}
/**************************************************************************
 * Main Program
 * VVVVVVVVVVVV
 */
main(argc,argv)
int argc;
char ** argv;
{
char ch;
static struct snoop_header snoop;
unsigned long dayn;
unsigned long secn;
unsigned long runn;
time_t base_time;
unsigned char buf[65536];
int ret;
int i,j,k;
char* fname;
    while ( ( ch = getopt ( argc, argv, "hi:" ) ) != EOF )
    {
        switch ( ch )
        {
                case 'i' :
                    match_host = inet_addr(optarg);
                    break;
                case 'h' :
                    (void) puts("ncrdumpe2snp: NCR tcpdump to snoop converter\n\
  You can specify:\n\
  -i to select a particular host (default 0, all)\n\
Then list the files to process. The output is emitted on stdout\n");
                    exit(0);
                default:
                case '?' : /* Default - invalid opt.*/
                       (void) fprintf(stderr,"Invalid argument; try -h\n");
                       exit(1);
                    break;
        }
    }
    strcpy(&buf[0], "ncrdump2snp");
    (void) fwrite(&buf[0],sizeof(char),16,stdout);
    for (i = optind; i < argc; i++)
    {
    FILE *f;
        fname = argv[i];
        if ((f = fopen(fname,"r")) == (FILE *)NULL)
        {
            perror("fopen() failed");
            (void) fprintf(stderr,
                  "Open of %s failed with UNIX errno %d\n",argv[i],errno);
            exit(1);
        }
        fseek(f,27,0);
        ret = fread(&buf[0],sizeof(unsigned char),4,f);
        secn = buf[0] + 256*buf[1];
        dayn = buf[2] + 256*buf[3];
/*
 * Day number looks like days since some strange time in the past.
 */
        base_time =  (1117+dayn)*86400 + secn + 19800;
        fseek(f,42,0);
        while ((ret = fread(&buf[0],sizeof(unsigned char),20,f)) > 0)
        {
            snoop.saved_len = buf[12]*256 + buf[11];
            snoop.len = snoop.saved_len;
            runn =   buf[6] + buf[7]*256 + buf[8]*256*256  + buf[9]*256*256*256;
            snoop.secs_since_1970 = base_time + (2*runn)/1000000;
            snoop.musecs =  (2*runn) % 1000000;
            if (snoop.saved_len > 65536)
            {
                (void) fprintf(stderr,
              "Length is %d; Cannot handle packets of more than 65536 bytes\n",
                    snoop.saved_len);
                exit(1);
            }
            else
            if (snoop.saved_len < 16 || snoop.saved_len > 5000)
            {
               
                (void) fprintf(stderr,
              "Funny packet at offset %d; len: %d\n\
            snoop.saved_len: %d\n",
            ftell(f),
            snoop.saved_len);
                /* fseek(f,-16,1); */
                continue;
            }
            if ((ret = fread(&buf[0],sizeof(unsigned char), snoop.saved_len, f)) < 1)
            {
                perror("fread() failed");
                (void) fprintf(stderr,
        "Read of %s : %d bytes failed with UNIX errno %d\n",argv[i], 
                        snoop.saved_len, errno);
                exit(1);
            }
            else
            {
                (void) fprintf(stderr,
        "Read %s : %d bytes at %d\n",argv[i], 
                        snoop.saved_len, ftell(f) - 
                        snoop.saved_len);
            }
            snoop_write(&snoop, &buf[0]);
        }
        fclose(f);
    }
    exit(0);
}

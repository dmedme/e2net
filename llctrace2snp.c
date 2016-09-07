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
#include "e2net.h"
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
long match_host = 0;
static FILE * of;
/*
 * The alignments are all screwed up, so we use the known lengths
 * to get the copies right
 */
#define SNAP_LEN 8
#define ETHER_LEN 14
#ifdef AIX
#define MAC_LEN 14
typedef unsigned char unchar;
#else
#ifdef PTX
#define MAC_LEN 13
#else
#define MAC_LEN 14
#endif
#endif
/*
 * Load fddi header
 */
static void load_fddi_hdr(fp, m)
struct fddihdr * fp;
char * m;
{
    memcpy(&(fp->mh.da[0]), m+2,6);                  /* Destination address */
    memcpy(&(fp->mh.sa[0]), m+8,6);                  /* Source address */
    memcpy(&(fp->lh.etype), m+20,2);                 /* Packet Type */
    return;
}
/*
 * Write out the message with an Ethernet rather than an FDDI header,
 * losing the LLC SNAP header in the process.
 */
static void snoop_snap_write(s,m)
struct snoop_header * s;
char * m;
{
int j;
static char * last_msg;
static int last_sz;
static struct	ether_header e;
static struct	fddihdr f;
struct ip ip;
    load_fddi_hdr(&f,m);
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
    memcpy((char *) &(e.ether_dhost), (char *) &(f.mh.da),
                       sizeof(f.mh.da));
    memcpy((char *) &(e.ether_shost), (char *) &(f.mh.sa),
                       sizeof(f.mh.sa));
    e.ether_type = htons(f.lh.etype);
    j = last_sz + ETHER_LEN;
    j = ENALIGN(j);
    s->saved_len = htonl(j);
    s->len = s->saved_len;
    s->secs_since_1970 = htonl(s->secs_since_1970);
    s->musecs = htonl(s->musecs);
    if (j < 32768)
    {
        fwrite((char *) s,sizeof(char),
          sizeof(struct snoop_header),of);         /* The snoop header */
        fwrite((char *) &e, sizeof(char),
          ETHER_LEN,of);                           /* The ether header */
        fwrite(m + SNAP_LEN + MAC_LEN,sizeof(char), j- ETHER_LEN,of); 
                                                       /* The packet */
    }
    else
        fprintf(stderr, "Funny Length:%d\n", j);
    return;
}
/*
 * Write out the message with a snoop header.
 */
static void snoop_write(s,m)
struct snoop_header * s;
char * m;
{
int j;
struct ip ip;

    if (match_host != 0)
    {
        memcpy((unsigned char *) &ip, m + MAC_LEN,sizeof(ip));
        if (memcmp((char *) &match_host, (char *) & ip.ip_src,
                    sizeof(match_host))
          && memcmp((char *) &match_host, (char *) & ip.ip_dst,
                    sizeof(match_host)))
            return;
    }
    j = ENALIGN(s->saved_len);
    s->saved_len = htonl(j);
    s->len = s->saved_len;
    s->secs_since_1970 = htonl(s->secs_since_1970);
    s->musecs = htonl(s->musecs);
    if (j < 32768)
    {
        fwrite((char *) s,sizeof(char),
          sizeof(struct snoop_header),of);         /* The snoop header */
        fwrite(m, sizeof(char), j, of); 
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
unsigned long first_runn = 0;
unsigned long last_time = 0;
time_t base_time;
int off_time;
double secs_since;
char * x;
unsigned char buf[65536];
int ret;
int i,j,k;
char* fname;
int snap_flag = 0;
    of = stdout;
    while ( ( ch = getopt ( argc, argv, "ho:i:s" ) ) != EOF )
    {
        switch ( ch )
        {
                case 'o' :
                    of = fopen(optarg, "wb");
                    break;
                case 'i' :
                    match_host = inet_addr(optarg);
                    break;
                case 's' :
                    snap_flag = 1;
                    break;
                case 'h' :
                    (void) puts("llctrace2snp: llctrace to snoop converter\n\
  You can specify:\n\
  -i to select a particular host (default 0, all)\n\
  -o to name an output file (default is stdout)\n\
  -s to indicate that the packets have a snap header\n\
Then list the files to process.\n");
                    exit(0);
                default:
                case '?' : /* Default - invalid opt.*/
                       (void) fprintf(stderr,"Invalid argument; try -h\n");
                       exit(1);
                    break;
        }
    }
    strcpy(&buf[0], "llctrace2snp");
    (void) fwrite(&buf[0],sizeof(char),16,of);
    for (i = optind; i < argc; i++)
    {
    FILE *f;
        fname = argv[i];
        if ((f = fopen(fname,"rb")) == (FILE *)NULL)
        {
            perror("fopen() failed");
            (void) fprintf(stderr,
                  "Open of %s failed with UNIX errno %d\n",argv[i],errno);
            exit(1);
        }
        off_time = -1;
        fseek(f,27,0);
        ret = fread(&buf[0],sizeof(unsigned char),4,f);
        secn = buf[0] + 256*buf[1];
        dayn = buf[2] + 256*buf[3];
/*
 * Dayn is a date, encoded (LSB->MSB) 5 bits day, 4 bits month, 7 bits years
 * since 1980.
 *
 * secn is hours and minutes, coded (MSB->LSB) 5 bits hour, 6 bits minute, 5
 * bits number of 2 seconds.
 */
        sprintf(&buf[0],"%04u-%02u-%02u", 1980 + ((dayn & 0xfe00) >> 9),
               ((dayn & 0x1e0) >> 5), (dayn & 0x1f));
        (void) date_val(&buf[0], "YYYY-MM-DD", &x, &secs_since);
        base_time =  ((long) secs_since) + 3600*((secn & 0xf800) >> 11) +
                     60 * ((secn & 0x7e0) >> 5) + 2*(secn & 0x1f);
        fseek(f,22,1);
        while ((ret = fread(&buf[0],sizeof(unsigned char),20 - 3*snap_flag,f)) > 0)
        {
            snoop.saved_len = buf[3]*256 + buf[2] - 14 +3*snap_flag;
            snoop.len = snoop.saved_len;
            runn =   buf[6] + buf[7]*256 + buf[8]*256*256  + buf[9]*256*256*256;
            if (off_time == -1)
            {
                first_runn = runn;
                off_time = (runn/1000000 ) * 2;
            }
            if (runn  < first_runn)
            {
                off_time = (runn/1000000 ) * 2;
                base_time = last_time;
                first_runn = runn;
            }
            snoop.secs_since_1970 = base_time + runn/500000 - off_time;
            snoop.musecs =  (runn % 500000) * 2;
            last_time = snoop.secs_since_1970;
            if (snoop.saved_len > 65536)
            {
                (void) fprintf(stderr,
              "Length is %d; Cannot handle packets of more than 65536 bytes\n",
                    snoop.saved_len);
                exit(1);
            }
            else
            if (snoop.saved_len < sizeof(16) || snoop.saved_len > 5000)
            {
               
                (void) fprintf(stderr,
              "Funny packet at offset %d; len: %d\n\
            snoop.saved_len: %d\n",
            ftell(f),
            snoop.saved_len);
                fseek(f,-16,1);
                continue;
            }
            if ((ret = fread(&buf[0],sizeof(unsigned char), snoop.saved_len, f)) < 1)
            {
                perror("fread() failed");
                (void) fprintf(stderr,
        "Read of %s : %d bytes failed with UNIX errno %d\n",argv[i], k, errno);
                exit(1);
            }
            if (snap_flag)
                snoop_snap_write(&snoop, &buf[0]);
            else
                snoop_write(&snoop, &buf[0]);
        }
        fclose(f);
    }
    exit(0);
}

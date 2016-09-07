/************************************************************************
 * Convert a file captured by the AIX or HP tcpdump utility to one that the
 * E2 snoop-oriented facilities can handle.
 *
 * Snoop  File Format (from RFC 1761)
 * ==================================

   The snoop packet capture file is an array of octets structured as
   follows:

        +------------------------+
        |                        |
        |      File Header       |
        |                        |
        +------------------------+
        |                        |
        |     Packet Record      |
        ~        Number 1        ~
        |                        |
        +------------------------+
        .                        .
        .                        .
        .                        .
        +------------------------+
        |                        |
        |     Packet Record      |
        ~        Number N        ~
        |                        |
        +------------------------+

   The File Header is a fixed-length field containing general
   information about the packet file and the format of the packet
   records it contains.  One or more variable-length Packet Record
   fields follow the File Header field.  Each Packet Record field holds
   the data of one captured packet.

3. File Header

   The structure of the File Header is as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                     Identification Pattern                    +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Version Number = 2                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Datalink Type                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Identification Pattern:

                A 64-bit (8 octet) pattern used to identify the file as
                a snoop packet capture file.  The Identification Pattern
                consists of the 8 hexadecimal octets:

                        73 6E 6F 6F 70 00 00 00

                This is the ASCII string "snoop" followed by three null
                octets.

        Version Number:

                A 32-bit (4 octet) unsigned integer value representing
                the version of the packet capture file being used.  This
                document describes version number 2.  (Version number 1
                was used in early implementations and is now obsolete.)

        Datalink Type:

                A 32-bit (4 octet) field identifying the type of
                datalink header used in the packet records that follow.
                The datalink type codes are listed in the table below:

                Datalink Type           Code
                -------------           ----
                IEEE 802.3              0
                IEEE 802.4 Token Bus    1
                IEEE 802.5 Token Ring   2
                IEEE 802.6 Metro Net    3
                Ethernet                4
                HDLC                    5
                Character Synchronous   6
                IBM Channel-to-Channel  7
                FDDI                    8
                Other                   9
                Unassigned              10 - 4294967295

4. Packet Record Format

   Each packet record holds a partial or complete copy of one packet as
   well as some descriptive information about that packet.  The packet
   may be truncated in order to limit the amount of data to be stored in
   the packet file.  In addition, the packet record may be padded in
   order for it to align on a convenient machine-dependent boundary.
   Each packet record holds 24 octets of descriptive information about
   the packet, followed by the packet data, which is variable-length,
   and an optional pad field.  The descriptive information is structured

   as six 32-bit (4-octet) integer values.

   The structure of the packet record is as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Original Length                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Included Length                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Packet Record Length                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Cumulative Drops                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Timestamp Seconds                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Timestamp Microseconds                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                          Packet Data                          .
    .                                                               .
    +                                               +- - - - - - - -+
    |                                               |     Pad       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Original Length

                32-bit unsigned integer representing the length in
                octets of the captured packet as received via a network.

        Included Length

                32-bit unsigned integer representing the length of the
                Packet Data field.  This is the number of octets of the
                captured packet that are included in this packet record.
                If the received packet was truncated, the Included
                Length field will be less than the Original Length
                field.

        Packet Record Length

                32-bit unsigned integer representing the total length of
                this packet record in octets.  This includes the 24
                octets of descriptive information, the length of the
                Packet Data field, and the length of the Pad field.

        Cumulative Drops

                32-bit unsigned integer representing the number of
                packets that were lost by the system that created the
                packet file between the first packet record in the
                file and this one.  Packets may be lost because of
                insufficient resources in the capturing system, or for
                other reasons.  Note: some implementations lack the
                ability to count dropped packets.  Those
                implementations may set the cumulative drops value to
                zero.

        Timestamp Seconds

                32-bit unsigned integer representing the time, in
                seconds since January 1, 1970, when the packet arrived.

        Timestamp Microseconds

                32-bit unsigned integer representing microsecond
                resolution of packet arrival time.

        Packet Data

                Variable-length field holding the packet that was
                captured, beginning with its datalink header.  The
                Datalink Type field of the file header can be used to
                determine how to decode the datalink header.  The length
                of the Packet Data field is given in the Included Length
                field.

        Pad

                Variable-length field holding zero or more octets that
                pads the packet record out to a convenient boundary.

5.  Data Format

   All integer values are stored in "big-endian" order, with the high-
   order bits first.
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1994\n";
#include <sys/types.h>
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#endif
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef LCC
#ifndef VCC2003
#include <unistd.h>
#endif
#endif
#include <errno.h>
#include <time.h>
#include "ansi.h"
#include "e2net.h"
#ifndef NOBPF_H
#include <net/bpf.h>
#else
#ifdef MINGW32
#define u_int unsigned int
#endif
struct timeval32 {
unsigned int tv_sec;
unsigned int tv_usec;
};
struct bpf_hdr {
	struct timeval32	bh_tstamp;	/* time stamp */
	unsigned int	bh_caplen;	/* length of captured portion */
	unsigned int	bh_datalen;	/* original length of packet */
};
#endif
#ifdef OSF
#define USE_BPF
#endif
#ifdef LINUX
#define USE_BPF
#endif

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
    unsigned int len;
    unsigned int saved_len;
    unsigned int record_len;
    unsigned int cumulative_drops;
    unsigned int secs_since_1970;
    unsigned int musecs;
};
#define	ETHERTYPE_IP		(0x0800)	/* IP protocol */
/*
 * The alignments are all screwed up, so we use the known lengths
 * to get the copies right
 */
#define SNAP_LEN 8
#define ETHER_LEN 14
#ifdef AIX
#define MAC_LEN 14
#else
#define MAC_LEN 13
#endif
static unsigned int match_host = 0;
static FILE *of;
struct aix_hdr {
    unsigned int secs_since_1970;
    unsigned int musecs;
    unsigned int saved_len;
    unsigned int len;
};
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
    s->saved_len = htonl(j);
    j = ENALIGN(j);
    s->record_len = htonl(j + sizeof(struct snoop_header));
    s->len = s->saved_len;
    s->secs_since_1970 = htonl( s->secs_since_1970);
    s->musecs = htonl( s->musecs);
    if (j <= 65536)
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

    j = ENALIGN(s->saved_len);
    s->saved_len = htonl(s->saved_len);
    s->len = s->saved_len;
    s->record_len = htonl(j + sizeof(struct snoop_header));
    s->secs_since_1970 = htonl( s->secs_since_1970);
    s->musecs = htonl( s->musecs);
    if (j < 65536)
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
unsigned char buf[65536];
static int big_little_flag;
static int resynch(f, aix, t)
FILE *f;
#ifdef USE_BPF
struct bpf_hdr *aix;
#else
struct aix_hdr *aix;
#endif
unsigned int t;
{
int ret;
unsigned char sync_buf[(sizeof(*aix))];

    ret = fread(&sync_buf[0],sizeof(unsigned char),sizeof(*aix),f);
    while (ret >= 0)
    {
        memcpy((unsigned char *) aix, &sync_buf[0],sizeof(*aix));
#ifdef USE_BPF
        if (big_little_flag)
        {
            aix->bh_caplen = ntohl(aix->bh_caplen);
            aix->bh_datalen = ntohl(aix->bh_datalen);
            aix->bh_tstamp.tv_sec = ntohl(aix->bh_tstamp.tv_sec);
            aix->bh_tstamp.tv_usec = ntohl(aix->bh_tstamp.tv_usec);
        }
        ret = aix->bh_tstamp.tv_sec - t;
#ifdef DEBUG
        fprintf(stderr,
"During resynch():ret: %d record_len:%u saved_len: %u secs: %u musecs:%u\n",
                    ret, aix->bh_datalen, aix->bh_caplen, aix->bh_tstamp.tv_sec,
                    aix->bh_tstamp.tv_usec);
#endif
        if (aix->bh_datalen > 0 && aix->bh_datalen < 65536 && ret >= 0 && ret < 600)
            return 1;
#else
        if (big_little_flag)
        {
            aix->len = ntohl(aix->len);
            aix->secs_since_1970 = ntohl(aix->secs_since_1970);
            aix->musecs = ntohl(aix->musecs);
            aix->saved_len = ntohl(aix->saved_len);
        }
        ret = aix->secs_since_1970 - t;
#ifdef DEBUG
            fprintf(stderr,
"During resynch():ret: %d len: %u saved_len: %u secs: %u musecs:%u\n",
                     ret,  aix->len,
                      aix->saved_len, aix->secs_since_1970,
                     aix->musecs);
#endif
        if (aix->len > 0 && aix->len <= 65536 && ret >= 0 && ret < 600)
            return 1;
#endif
        for (ret = 0; ret < (sizeof(*aix) - 1); ret++)
            sync_buf[ret] = sync_buf[ret+1];
        ret = fgetc(f);
        sync_buf[(sizeof(*aix) - 1)] = ret;
    }
    fprintf(stderr,
          "resynch() failed:ret: %d offset: %u errno: %d\n", ret, ftell(f),
                  errno);
    return 0;
}
static int check_header(buf)
unsigned char * buf;
{
    if (buf[0] == 0xd4
     && buf[1] == 0xc3
     && buf[2] == 0xb2
     && buf[3] == 0xa1)
        return 0;
    else
    if (buf[3] == 0xd4
     && buf[2] == 0xc3
     && buf[1] == 0xb2
     && buf[0] == 0xa1)
        return 1;
    else
        return -1;
}
static int file_proc(f, snap_flag, scale_factor, fname)
FILE * f;
int snap_flag;
int scale_factor;
char * fname;
{
int ret;
static struct snoop_header snoop;
#ifdef USE_BPF
struct bpf_hdr aix;
#else
struct aix_hdr aix;
#endif

    (void) fread(&buf[0],1,24,f);   /* Skip the header */
    if ((big_little_flag = check_header(&buf[0])) < 0)
    {
        (void) fprintf(stderr, "File %s lacks valid header\n",
                 fname);
        return 1;
    }
    while((ret = fread((char *) &aix,sizeof(unsigned char),sizeof(aix),f)) > 0)
    {
#ifdef USE_BPF
#ifdef DEBUG
        fprintf(stderr,"%x:%x:%x:%x\n",
            aix.bh_tstamp.tv_sec,
            aix.bh_tstamp.tv_usec,
            aix.bh_caplen,
            aix.bh_datalen);
#endif
        if (big_little_flag)
        {
            aix.bh_datalen = ntohl(aix.bh_datalen);
            snoop.saved_len = ntohl(aix.bh_caplen);
        }
        else
            snoop.saved_len = aix.bh_caplen;
        snoop.len = snoop.saved_len;
        snoop.record_len = snoop.saved_len + 24;
        if (aix.bh_datalen > 65536)
#else
        if (big_little_flag)
            aix.saved_len = ntohl(aix.saved_len);
        snoop.saved_len = aix.saved_len;
        snoop.len = aix.saved_len;
        snoop.record_len = snoop.saved_len + 24;
        if (aix.saved_len > 65536)
#endif
        {
            if (check_header((unsigned char *) &aix) != -1)
            {
                fread((char *) &aix,sizeof(unsigned char),24 - sizeof(aix),f);
                continue; /* Assume concatenated tcpdump files */
            } 
            (void) fprintf(stderr,
           "Length in %s is %u at %u; Cannot handle packets of more than 65536 bytes\n",
                 fname, snoop.saved_len, ftell(f));
             resynch(f, &aix, snoop.secs_since_1970);
#ifdef USE_BPF
            if (big_little_flag)
            {
                aix.bh_datalen = ntohl(aix.bh_datalen);
                snoop.saved_len = ntohl(aix.bh_caplen);
            }
            else
                snoop.saved_len = aix.bh_caplen;
            snoop.len = snoop.saved_len;
            snoop.record_len = snoop.saved_len + 24;
#else
            if (big_little_flag)
                aix.saved_len = ntohl(aix.saved_len);
            snoop.saved_len = aix.saved_len;
            snoop.len = aix.saved_len;
            snoop.record_len = snoop.saved_len + 24;
#endif
        }
        else
#ifdef USE_BPF
        if (aix.bh_datalen < 16 || aix.bh_datalen > 65536)
#else
        if (aix.saved_len < 16 || aix.saved_len > 65536)
#endif
        {
            if (check_header((unsigned char *) &aix) != -1)
            {
                fread((char *) &aix,sizeof(unsigned char),24 - sizeof(aix),f);
                continue; /* Assume concatenated tcpdump files */
            } 
            (void) fprintf(stderr, "Funny packet in %s at offset %d; len: %u\n",
                  fname, ftell(f), snoop.saved_len);
            resynch(f, &aix, snoop.secs_since_1970);
#ifdef USE_BPF
            if (big_little_flag)
            {
                aix.bh_datalen = ntohl(aix.bh_datalen);
                snoop.saved_len = ntohl(aix.bh_caplen);
            }
            else
                snoop.saved_len = aix.bh_caplen;
            snoop.len = snoop.saved_len;
            snoop.record_len = snoop.saved_len + 24;
#else
            if (big_little_flag)
                aix.saved_len = ntohl(aix.saved_len);
            snoop.saved_len = aix.saved_len;
            snoop.len = aix.saved_len;
            snoop.record_len = snoop.saved_len + 24;
#endif
        }
#ifdef USE_BPF
        if (big_little_flag)
        {
            snoop.secs_since_1970 = ntohl(aix.bh_tstamp.tv_sec);
            snoop.musecs =  ntohl(aix.bh_tstamp.tv_usec);
        }
        else
        {
            snoop.secs_since_1970 = aix.bh_tstamp.tv_sec;
            snoop.musecs =  aix.bh_tstamp.tv_usec;
        }
#else
        if (big_little_flag)
        {
            snoop.secs_since_1970 = ntohl(aix.secs_since_1970);
            snoop.musecs =  ntohl(aix.musecs)/scale_factor;
        }
        else
        {
            snoop.secs_since_1970 = aix.secs_since_1970;
            snoop.musecs =  aix.musecs/scale_factor;
        }
#endif
        if (snoop.saved_len > 65536)
        {
            (void) fprintf(stderr,
           "Length in %s is %u at %lu; Cannot handle packets of more than 65536 bytes\n",
                 fname, snoop.saved_len, ftell(f));
            return 0;
        }
        else
        if (snoop.saved_len < 16 || snoop.saved_len > 65536)
        {
           
            (void) fprintf(stderr,
          "Funny packet in %s at offset %d; len: %d\n",
                 fname, ftell(f), snoop.saved_len);
            /* fseek(f,-16,1); */
            continue;
        }
        if ((ret = fread(&buf[0],sizeof(unsigned char), snoop.saved_len, f)) < 1)
        {
            perror("fread() failed");
            (void) fprintf(stderr,
    "Read of %s : %d bytes failed with UNIX errno %d\n",fname, 
                    snoop.saved_len, errno);
            exit(1);
        }
#ifdef DEBUG
        else
        {
            (void) fprintf(stderr,
    "Read %s : %d bytes at %d\n",fname, 
                    snoop.saved_len, ftell(f) - 
                    snoop.saved_len);
        }
#endif
        if (snap_flag)
            snoop_snap_write(&snoop, &buf[0]);
        else
            snoop_write(&snoop, &buf[0]);
    }
    return 1;
}
/**************************************************************************
 * Main Program
 * VVVVVVVVVVVV
 */
main(argc,argv)
int argc;
char ** argv;
{
int  ch;
int scale_factor = 1;
int i;
int snap_flag = 0;

    of = stdout;
    while ( ( ch = getopt ( argc, argv, "f:shi:o:" ) ) != EOF )
    {
        switch ( ch )
        {
        case 'f' :
            scale_factor = atoi(optarg);
            if (scale_factor < 1)
                scale_factor = 1;
            break;
        case 's' :
            snap_flag = 1;
            break;
        case 'i' :
            match_host = inet_addr(optarg);
            break;
        case 'o' :
            if ((of = fopen(optarg, "wb")) == NULL)
            {
                perror(optarg);
                fprintf(stderr, "Failed to open %s for writing, error: %d\n",
                        optarg, errno);
                exit(1);
            }
            break;
        case 'h' :
            (void) puts("aixdump2snp: AIX tcpdump to snoop converter\n\
  You can specify:\n\
  -i to select a particular host (default 0, all)\n\
  -o to select a named output file (default stdout)\n\
  -s to indicate snap headers present\n\
Then list the files to process. The output is emitted to the output file\n");
            exit(0);
        default:
        case '?' : /* Default - invalid opt.*/
               (void) fputs("Invalid argument; try -h\n", stderr);
               exit(1);
            break;
        }
    }
    memset(buf,0,16);
    strcpy(&buf[0], "snoop");
    buf[11] = 2;
    (void) fwrite(&buf[0],sizeof(char),16,of);
    if (optind == argc)
        file_proc(stdin, snap_flag, scale_factor,"(stdin)");
    else
    for (i = optind; i < argc; i++)
    {
    FILE *f;

        if ((f = fopen(argv[i],"rb")) == (FILE *)NULL)
        {
            perror("fopen() failed");
            (void) fprintf(stderr,
                  "Open of %s failed with UNIX errno %d\n", argv[i], errno);
            continue;
        }
        if (!file_proc(f, snap_flag, scale_factor, argv[i]))
            (void) fprintf(stderr, "Issue with %s\n", argv[i]);
        fclose(f);
    }
    exit(0);
}

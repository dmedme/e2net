/************************************************************************bout
 * genconv.c - Routines for calculating response time figures.
 *
 * Scan an Ethernet trace file and pull out enough data to perform traffic
 * analysis.
 *
 * Information that we want to gather:
 * -  Transaction Times
 * -  Split between PC, Network and Server
 * -  Traffic Volumes, in and out, bytes and packets
 * -  Information that enables the particular transaction to be identified
 *
 * This program aims to function on any system, regardless of the form of
 * the packet trace encapsulation or the presence of the appropriate
 * headers.
 *
 * Typically link with -lsocket -linet -lnsl, depending on what exists.
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1994\n";
/* #define RETRANS_TRAP */
#ifdef __STRICT_ANSI
#undef __STRICT_ANSI
#endif
#include <sys/types.h>
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
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#endif
#endif
#include "hashlib.h"
#include "novell.h"
#include "e2net.h"
#include "webrep.h"
/************************************************************************
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
struct snoop_header {
    unsigned int len;
    unsigned int saved_len;
    unsigned int record_len;
    unsigned int cumulative_drops;
    unsigned int secs_since_1970;
    unsigned int musecs;
};
static struct web_rep_con * wrcp;
static FILE * alert_fp;
static int verbose = 0;
static void web_rep_anal();
static int default_age = 0;     /* Kill off idle sessions? */
/***************************************************************************
 * Functions in this file.
 */
static void accum_generic();
static int resynch();
/*
 * List of functions that decide whether packets are interesting. Define the
 * ones wanted in the makefile.
 */
#ifdef DUMP
int pick_dump();
#endif
#ifdef REC_PROT1
int REC_PROT1();
#endif
#ifdef REC_PROT2
int REC_PROT2();
#endif
#ifdef REC_PROT3
int REC_PROT3();
#endif
#ifdef REC_PROT4
int REC_PROT4();
#endif
static int (*fun_chain[])() =
{
#ifdef REC_PROT1
REC_PROT1,
#endif
#ifdef REC_PROT2
REC_PROT2,
#endif
#ifdef REC_PROT3
REC_PROT3,
#endif
#ifdef REC_PROT4
REC_PROT4,
#endif
#ifdef DUMP
pick_dump,
#endif
NULL
};
/*
 * Function to arrange for the invocation of application-specific code
 */
int app_recognise(frp)
struct frame_con * frp;
{
int i;
    for (i = 0; fun_chain[i] != NULL; i++)
        if (fun_chain[i](frp))
            return 1;    /* Set up application-specific structures          */
    return 0;
}
void do_dump(f, dir_flag)
struct frame_con *f;
int dir_flag;
{
    circbuf_dump(f->pack_ring, f->ofp);
    return;
}
int pick_dump(frp)
struct frame_con * frp;
{
static int sess_seq;
char fname[28];
    if (frp->prot == E2_TCP)
    {
        frp->do_mess = do_dump;
        sprintf(fname,"tcpsess_%d",sess_seq++);
        frp->ofp = fopen(fname,"wb");
        return 1;
    }
    return 0;
}
/***********************************************************************
 * Getopt support
 */
static int ebcdic = 0;
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
/***********************************************************************
 * PATHSYNC Event Support. These routines inject the PATH timing instructions
 * into all open session files.
 */
#define ECHO_SERVICE 7
static int event_id;
static char * event_desc;
static void open_event(frp)
struct frame_con * frp;
{
char buf0[3];

    if (frp->ofp != stdout && frp->ofp != NULL)
    {
        get_event_id(event_id, buf0);
        fprintf(frp->ofp, "\\S%s:120:%s \\\n", buf0, event_desc);
        frp->event_id = event_id;
    }
    return;
}
static void close_event(frp)
struct frame_con * frp;
{
char buf0[3];

    if (frp->ofp != stdout && frp->ofp != NULL && frp->event_id != 0)
    {
        get_event_id(event_id, buf0);
        fprintf(frp->ofp, "\\T%X:\\\n",buf0);
        frp->event_id = 0;
    }
    return;
}
/*
 * Facilities to clear down sessions on exit.
 */
static struct frame_con * anchor;
static HASH_CON * open_sess;
HASH_CON * get_open_sess() { return open_sess; }
static struct snoop_header  snoop;
void match_dismantle()
{
    while (anchor != (struct frame_con *) NULL)
    {
#ifdef DEBUG
         printf("Hash value: %u\n", uhash_key(anchor, MAX_SESS));
#endif
         if (anchor->ofp == NULL)
             anchor->ofp = stdout;
         if (anchor->do_mess != NULL)
             fputs("\\C:", anchor->ofp);
         date_out(anchor->ofp,snoop.secs_since_1970,snoop.musecs);
         frame_dump(anchor, "Session Summary|", verbose);
#ifndef PACKDUMP
#ifdef WEB_REP
         if (wrcp != NULL)
             web_rep_anal(anchor);
#endif
#endif
         match_remove(open_sess, &anchor, anchor);
    }
    return;
}
static void age_out(frp)
struct frame_con * frp;
{
    if ((snoop.secs_since_1970 - frp->this_time.tv_sec) > default_age)
    {
        if (frp->do_mess != NULL)
            fputs("\\C:", frp->ofp);
        date_out(frp->ofp,snoop.secs_since_1970,snoop.musecs);
        frame_dump(frp, "Session Summary|", verbose);
#ifndef PACKDUMP
#ifdef WEB_REP
        if (wrcp != NULL)
            web_rep_anal(frp);
#endif
#endif
        match_remove(open_sess, &anchor, frp);
    }
    else
        fflush(frp->ofp);
    return;
}
struct aix_hdr {
    unsigned int secs_since_1970;
    unsigned int musecs;
    unsigned int saved_len;
    unsigned int len;
};
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
static int tresynch(f, big_little_flag, aix, t)
FILE *f;
int big_little_flag;
struct aix_hdr *aix;
unsigned int t;
{
int ret;
unsigned char sync_buf[(sizeof(*aix))];

    ret = fread(&sync_buf[0],sizeof(unsigned char),sizeof(*aix),f);
    while (ret >= 0)
    {
        memcpy((unsigned char *) aix, &sync_buf[0],sizeof(*aix));
        if (big_little_flag)
        {
            aix->len = ntohl(aix->len);
            aix->secs_since_1970 = ntohl(aix->secs_since_1970);
            aix->musecs = ntohl(aix->musecs);
            aix->saved_len = ntohl(aix->saved_len);
        }
        ret = aix->secs_since_1970 - t;
        if (aix->saved_len > 0 && aix->saved_len < 131072 && ret >= 0 && ret < 600)
            return 1;
        for (ret = 0; ret < (sizeof(*aix) - 1); ret++)
            sync_buf[ret] = sync_buf[ret+1];
        ret = fgetc(f);
        sync_buf[(sizeof(*aix) - 1)] = ret;
    }
    fputs( "tresynch() failed\n", stderr);
    return 0;
}
static int tread(buf, big_little_flag, f)
char * buf;
int big_little_flag;
FILE * f;
{
int ret;
static struct snoop_header snoop;
struct aix_hdr aix;

concatenated:
    if ((ret = fread((char *) &aix,sizeof(unsigned char),sizeof(aix),f)) > 0)
    {
resynched:
        if (big_little_flag)
            aix.saved_len = ntohl(aix.saved_len);
#ifdef DEBUG
        fprintf(stderr,"%x:%x:%x:%x\n",
            aix.secs_since_1970,
            aix.musecs,
            aix.len,
            aix.saved_len);
#endif
        if (aix.saved_len > 131072 || aix.saved_len < 16)
        {
            if (check_header((unsigned char *) &aix) != -1)
            {
                fread((char *) &aix,sizeof(unsigned char),24 - sizeof(aix),f);
                goto concatenated; /* Assume concatenated tcpdump files */
            } 
            (void) fprintf(stderr,
           "tread:Length is %u at %u; Cannot handle packets of more than 131072 bytes\n",
                 aix.saved_len, ftell(f));
            if (tresynch(f, big_little_flag, &aix, snoop.secs_since_1970))
                goto resynched;
            return -1;
        }
        if (big_little_flag)
        {
            snoop.secs_since_1970 = ntohl(aix.secs_since_1970);
            snoop.musecs =  ntohl(aix.musecs);
        }
        else
        {
            snoop.secs_since_1970 = aix.secs_since_1970;
            snoop.musecs =  aix.musecs;
        }
        snoop.saved_len = aix.saved_len;
        snoop.len = aix.len;
        snoop.record_len = aix.saved_len + 24;
        memcpy(buf, (char *) &snoop, sizeof(snoop));
        return sizeof(snoop);
    }
    return ret;
}
/*****************************************************************************
 * Main Program
 * VVVVVVVVVVVV
 */
int main(argc,argv)
int argc;
char ** argv;
{
int tcpdump_flag = 0;
int big_little_flag;
struct circbuf * pack_ring;
struct pack_con * pack_con;
int align_flag;
int running_offset;
int ch;
int snap_flag = 0;
int retrans = 10;
int number = 1;
struct frame_con work_sess;           /* To hold converted temporarily */
unsigned int last_good_time;
unsigned int last_purge_time = 0;
int gap = 600;
int con_pack = 0;
int dir_flag = 0;
struct ether_header eth;
struct ip ip;
struct tcphdr tcp;
struct udphdr udp;
char * alertfile;
char * whois_bin;
char * country_bin;
char * sql_bin;
unsigned char buf[131072];
int ret;
int i,j,k;
struct frame_con * frp;

    open_sess = hash(MAX_SESS,uhash_key,ucomp_key);
    ebcdic = 0;
    align_flag = 0;
#ifdef SYBASE
/*
 * This is really badsort. We split the arguments between the network capture
 * files and the badsort input files based on the presence of a "--" argument.
 */
    for (i = argc - 1; i > 0; i--)
        if (!strcmp(argv[i], "--"))
            break;
    if (i > 0)
    {
        badsort_main(i, argv);
        optind = i + 1;
    }
    else
    if (optind == 0)
        optind = 1;
#else
    while ( ( ch = getopt ( argc, argv, "a:g:hvr:stp:l:w:" ) ) != EOF )
    {
        switch ( ch )
        {
        case 'a' :
            default_age = atoi(optarg);
            break;
        case 'g' :
            gap = atoi(optarg);
            break;
        case 't' :
            tcpdump_flag = 1;
            break;
        case 's' :
            snap_flag = 4;
            break;
        case 'l' :
            align_flag = atoi(optarg);
            if (align_flag < 1)
                align_flag = 4;
            break;
        case 'p' :
            con_pack = atoi(optarg);
            break;
        case 'v' :
            verbose = 1;
            break;
        case 'r' :
            retrans = atoi(optarg);
            break;
        case 'w' :
#ifndef PACKDUMP
            alertfile = strtok(optarg,":");
            if ((alert_fp = fopen(alertfile, "wb")) == NULL)
            {
                perror("fopen()");
                fprintf(stderr, "Failed to open alert file %s error %d\n",
                         alertfile, errno);
                break;
            }
            whois_bin = strtok(NULL,":");
            country_bin = strtok(NULL,":");
            sql_bin = strtok(NULL,":");
#ifdef WEB_REP
            if ((wrcp = web_rep_init(whois_bin,country_bin,sql_bin)) == NULL)
                fprintf(stderr, "Failed to initialise web reputation files %s, %s and %s\n",
                      whois_bin, country_bin, sql_bin);
#endif
#endif
            break;
        case 'h' :
            (void) puts("genconv: TCP problem-oriented monitoring\n\
Options:\n\
-a Age to discard idle sessions (default 7200; 0 to disable)\n\
-d Output date in English\n\
-p Output this packet number (for debug purposes)\n\
-l structures are aligned on these boundaries\n\
-g Excessive network threshold\n\
-s Snap headers present\n\
-t tcpdump format rather than snoop\n\
-v Report verbosely\n\
-r Set the retranmission report threshold\n\
-w Do Web Reputation Reporting (whois:country:alerts)\n\
List the files to process. The output is emitted on stdout\n");
                    exit(0);
        default:
        case '?' : /* Default - invalid opt.*/
            (void) fputs("Invalid argument; try -h\n",stderr);
            exit(1);
        }
    }
#endif
    if ((pack_ring = circbuf_cre(2048, pack_drop)) == (struct circbuf *) NULL)
    {
        (void) fputs("Global circular buffer allocation failed\n",stderr);
        exit(1);
    }
    for (i = optind; i < argc; i++)
    {
    FILE *f;

        if (*argv[i] == '\0')
            continue;
        if (*argv[i] == '-' && *(argv[i] + 1) == 0)
            f = stdin;
        else
        if ((f = fopen(argv[i],"rb")) == (FILE *)NULL)
        {
            perror("fopen() failed");
            (void) fprintf(stderr,
                  "Open of %s failed with UNIX errno %d\n",argv[i],errno);
            continue;
        }
        if (tcpdump_flag)
        {
            (void) fread(&buf[0],1,24,f);   /* Skip the header */
            if ((big_little_flag = check_header(&buf[0])) < 0)
            {
                (void) fprintf(stderr, "File %s lacks valid header\n",
                         argv[i]);
                continue;
            }
        }
        else
            (void) fread(&buf[0], sizeof(char), 16, f); /* Skip the snoop header */
        while ((ret = (tcpdump_flag) ? tread(&buf[0], big_little_flag, f) :
                  fread(&buf[0],sizeof(unsigned char),sizeof(snoop),f)) > 0)
        {
        int iplen;
        int tcplen;
        int dir_flag;

file_cat:
            memcpy((unsigned char *) &snoop, &buf[0],sizeof(snoop));
#ifdef DEBUG
            fprintf(stderr,
                   "ret: %d pos: %u len: %u saved_len: %u secs: %u musecs:%u\n",
                    ret, ftell(f),
                     snoop.len, snoop.saved_len, snoop.secs_since_1970,
            snoop.musecs);
#endif
            if (!tcpdump_flag)
            {
                snoop.len = ntohl(snoop.len);
                snoop.saved_len = ntohl(snoop.saved_len);
                snoop.record_len = ntohl(snoop.record_len);
                snoop.secs_since_1970 = ntohl(snoop.secs_since_1970);
                snoop.musecs = ntohl(snoop.musecs);
            }
/*
 * Frig for AIX capture files
 */
            if (snoop.musecs > 1000000)
                snoop.musecs = snoop.musecs/1000;
#ifdef DEBUG
            fprintf(stderr,
                   "After NTOH: len: %u saved_len: %u secs: %u musecs:%u\n",
                     snoop.len, snoop.saved_len, snoop.secs_since_1970,
                     snoop.musecs);
#endif
            if (snoop.saved_len > 131072)
            {
                if (!strcmp(buf, "snoop"))
                {   /* Handle concatenated snoop files */
                    memcpy((unsigned char *) &buf[0],
                         (unsigned char *) &buf[16], sizeof(snoop) - 16);
                    fread(&buf[sizeof(snoop) - 16],sizeof(unsigned char),16,f);
                    goto file_cat;
                }
                (void) fprintf(stderr,
      "Length is %d at %u; Cannot handle packets of more than 131072 bytes\n",
                 snoop.len, ftell(f));
                if (tcpdump_flag || !resynch(f,&snoop, last_good_time))
                    goto next_file;
            }
            k = snoop.record_len - sizeof(snoop);
            if (k == 0)
                continue;
            if ((ret = fread(&buf[0],sizeof(unsigned char),k,f)) < 1)
            {
                perror("fread() failed");
                (void) fprintf(stderr,
              "Read of %s failed with UNIX errno %d\n",argv[i],errno);
                break;
            }
            memcpy((unsigned char *) &eth, &buf[0],sizeof(eth));
            eth.ether_type = ntohs(eth.ether_type);
            if (eth.ether_type == ETHERTYPE_IP && snap_flag != 4)
                snap_flag = 0;
            else
            if (eth.ether_type == ETH_P_8021Q)
            {
                eth.ether_type = ETHERTYPE_IP;
                snap_flag = 2;
            }
            running_offset = sizeof(eth) + 2* snap_flag;
            if (align_flag && (running_offset % align_flag))
               running_offset += align_flag - (running_offset % align_flag);
#ifdef DEBUG
            if (number && number == con_pack)
                printf("Reached packet:%d\n", con_pack);
#endif
/*
 * Start initialising the session control record
 */
            memset((char *) &work_sess, 0, sizeof(work_sess));
            work_sess.phys_from[0] = 6;
            memcpy(&(work_sess.phys_from[1]),
                (unsigned char *) &eth.ether_shost, 6);
            work_sess.phys_to[0] = 6;
            memcpy(&(work_sess.phys_to[1]),
                (unsigned char *) &eth.ether_dhost, 6);
            work_sess.this_time.tv_sec = snoop.secs_since_1970;
            work_sess.this_time.tv_usec = snoop.musecs;
            work_sess.pack_len = snoop.len;
            work_sess.pack_no = number++;
            if (eth.ether_type == ETHERTYPE_IP || snap_flag || align_flag)
            { 
/*
 * Set up the host details
 */
                memcpy((unsigned char *) &ip, &buf[running_offset],
                             sizeof(ip));
                iplen = ntohs(ip.ip_len);
                if (iplen == 0)
                {
                    iplen = snoop.len - running_offset;
                    ip.ip_len = ntohs(iplen);
                }
                work_sess.net_from[0] = 4;
                memcpy(&(work_sess.net_from[1]),
                    (unsigned char *) &ip.ip_src, 4);
                work_sess.net_to[0] = 4;
                memcpy(&(work_sess.net_to[1]),
                    (unsigned char *) &ip.ip_dst, 4);
                running_offset += sizeof(ip);
                if (align_flag && (running_offset % align_flag))
                    running_offset += align_flag -(running_offset % align_flag);
                if (ip.ip_p == IPPROTO_TCP)
                {
                    last_good_time = work_sess.this_time.tv_sec;
                    memcpy((unsigned char *) &tcp,
                           &buf[running_offset],
                           sizeof(tcp));
                    tcp.th_sport = ntohs(tcp.th_sport);
                    tcp.th_dport = ntohs(tcp.th_dport);
                    work_sess.tcp_flags = tcp.th_flags; 
                    work_sess.port_from[0] = 2;
                    memcpy(&(work_sess.port_from[1]),
                              (unsigned char *) &tcp.th_sport, 2);
                    work_sess.port_to[0] = 2;
                    memcpy(&(work_sess.port_to[1]),
                              (unsigned char *) &tcp.th_dport, 2);
                    work_sess.prot = E2_TCP;
#ifdef AIX
                    tcplen = iplen - sizeof(ip) - 
                        4 * (tcp.th_off >> 4);
#else
#ifdef OSF
                    tcplen = iplen - sizeof(ip) - 
                        4 * (tcp.th_off >> 4);
#else
                    tcplen = iplen - sizeof(ip) - tcp.th_off*4;
#endif
#endif
                }
                else
                if (ip.ip_p == IPPROTO_UDP)
                {
                    memcpy((unsigned char *) &udp,
                           &buf[running_offset],
                           sizeof(udp));
                    udp.uh_sport = ntohs(udp.uh_sport);
                    udp.uh_dport = ntohs(udp.uh_dport);
                    udp.uh_ulen = ntohs(udp.uh_ulen);
                    work_sess.port_from[0] = 2;
                    memcpy(&(work_sess.port_from[1]),
                        (unsigned char *) &udp.uh_sport, 2);
                    work_sess.port_to[0] = 2;
                    memcpy(&(work_sess.port_to[1]),
                         (unsigned char *) &udp.uh_dport, 2);
                    work_sess.prot = E2_UDP;
                }
                else
                if (ip.ip_p == IPPROTO_ICMP)
                    work_sess.prot = E2_ICMP;
                else
                if (ip.ip_p > IPPROTO_ICMP)
                    work_sess.prot = E2_ICMP + ip.ip_p;
            }
            else
            switch(eth.ether_type)
            {
            case ETHERTYPE_REVARP:
                work_sess.prot = E2_REVARP;
                break;
            case ETHERTYPE_ARP:
                work_sess.prot = E2_ARP;
                break;
            case ETHERTYPE_PUP:
                work_sess.prot = E2_PUP;
                break;
            case ETHERTYPE_X75:
                work_sess.prot = E2_X75;
                break;
            case ETHERTYPE_X25:
                work_sess.prot = E2_X25;
                break;
            case ETHERTYPE_BANYAN:
                work_sess.prot = E2_BANYAN;
                break;
            case ETHERTYPE_DECMOP1:
                work_sess.prot = E2_DECMOP1;
                break;
            case ETHERTYPE_DECMOP2:
                work_sess.prot = E2_DECMOP2;
                break;
            case ETHERTYPE_DECNET:
                work_sess.prot = E2_DECNET;
                break;
            case ETHERTYPE_DECLAT:
                work_sess.prot = E2_DECLAT;
                break;
            case ETHERTYPE_DECDIAGNOSTIC:
                work_sess.prot = E2_DECDIAGNOSTIC;
                break;
            case ETHERTYPE_DECLANBRIDGE:
                work_sess.prot = E2_DECLANBRIDGE;
                break;
            case ETHERTYPE_DECETHENCR:
                work_sess.prot = E2_DECETHENCR;
                break;
            case ETHERTYPE_APPLETALK:
                work_sess.prot = E2_APPLETALK;
                break;
            case ETHERTYPE_IBMSNA:
                work_sess.prot = E2_IBMSNA;
                break;
            case ETHERTYPE_NETWARE:
                work_sess.prot = E2_NOVELL;
                break;
            case ETHERTYPE_SNMP:
                work_sess.prot = E2_SNMP;
                break;
            default:
                if (eth.ether_type >= IEEE802_3_TYPE  )
                {
                    work_sess.prot = E2_UNKNOWN;
                }
                else
                {
/*
 * The type is actually a length field
 */
                   if (eth.ether_type < 30)
                       work_sess.prot = E2_LLC;
                   else
                       work_sess.prot = E2_NOVELL;
                }
            }
            if ((frp = match_true(open_sess, &work_sess))
                                 == (struct frame_con *) NULL)
            {
/*
 * Completely ignore stray FIN packets or stray ACK's and try and get them the right
 * way round.
 */
                if (work_sess.prot == E2_TCP
                   && ((work_sess.tcp_flags & TH_FIN)
                     || (!(work_sess.tcp_flags & TH_SYN) && (
                         !tcplen || ( tcp.th_sport < tcp.th_dport 
                                 &&  tcp.th_sport < 1024)))))
                    continue;
                frp = match_add(open_sess, &anchor, &work_sess);
                if ((frp->pack_ring = circbuf_cre(128, pack_drop))
                     == (struct circbuf *) NULL)
                {
                    (void) fputs("Session circular buffer allocation failed\n",
                                  stderr);
                    exit(1);
                }
                dir_flag = 0;
            }
            else
            {
                if (! hcntstrcmp(work_sess.net_from, work_sess.net_to))
                    dir_flag =  ! (! hcntstrcmp(work_sess.port_from,
                                  frp->port_from));
                else
                    dir_flag =  ! (! hcntstrcmp(work_sess.net_from,
                                  frp->net_from));
                frp->this_time = work_sess.this_time;
                frp->pack_len = work_sess.pack_len;
            }
/*
 * Save the packet
 */
            pack_con = pack_save(work_sess.pack_no, snoop.saved_len,
                                 work_sess.pack_len, &buf[0],
                                 work_sess.this_time.tv_sec,
                                 work_sess.this_time.tv_usec);
            (void) circbuf_add(pack_ring, (char *) pack_con);
            if (frp->do_mess == NULL)
                (void) circbuf_add(frp->pack_ring, (char *) pack_con);
            pack_con->ref_cnt++;
            if (work_sess.prot == E2_TCP)
            {
                pack_con->tcp_flags = tcp.th_flags;
                pack_con->tcp_len = tcplen;
                running_offset += tcp.th_off*4;
                if (align_flag && (running_offset % align_flag))
                    running_offset += align_flag -(running_offset % align_flag);
                pack_con->tcp_ptr = pack_con->pack_ptr + running_offset;
                pack_con->seq = ntohl(tcp.th_seq);
                pack_con->ack = ntohl(tcp.th_ack);
                pack_con->win = ntohs(tcp.th_win);
            }
/*
 * We want to keep a few seconds worth of packets in total.
 * In addition, we want to keep packets with sessions, so that,
 * in the event of an extended response or some unexpected
 * session termination, these can be output.
 */ 
            accum_generic(frp, dir_flag, pack_con);
#ifdef PACKDUMP
            if (verbose)
            {
                head_print(stdout, frp);
                fputc('\n', stdout);
            }
#endif
/*
 * Application protocol logic goes here, if there is any
 */
            if (frp->do_mess != NULL)
            {
                if (frp->do_mess == do_dump)
                    frp->do_mess = NULL;
#ifdef DEBUG
                if (pack_con->pack_no >= 60 && pack_con->pack_no <= 70)
                {
                    fprintf(stderr, "About to accum packet %d\n",
                                        pack_con->pack_no); 
                    fflush(stderr);
                }
#endif
                if (work_sess.prot == E2_TCP)
                    tcp_frame_accum(frp, pack_con, dir_flag);
                else
                if (frp->do_mess != NULL)
                {
                    running_offset += sizeof(udp);
                    if (align_flag && (running_offset % align_flag))
                        running_offset += align_flag -
                                          (running_offset % align_flag);
                    frp->hold_buf[dir_flag] = pack_con->pack_ptr + 
                                      running_offset;
                    frp->top[dir_flag] = pack_con->pack_ptr + 
                                          snoop.saved_len;
                    frp->do_mess(frp, dir_flag);
                }
#ifdef DEBUG
                if (pack_con->pack_no >= 60 && pack_con->pack_no <= 70)
                {
                    fprintf(stderr, "Have accum packet %d\n",
                                        pack_con->pack_no); 
                    fflush(stderr);
                }
#endif
#ifdef DEBUG_FULL
                do_dump(frp,dir_flag);
#endif
                if (frp->do_mess == NULL)
                    frp->do_mess = do_dump;
            }
/*
 * Output logic triggered by thresholds
 */
            if (work_sess.prot == E2_TCP)
            {
                if (frp->fin_cnt > 1
                 || (frp->fin_cnt == 1 && (frp->cnt[0] + frp->cnt[1]) <= 1))
                {
                    if (!verbose && frp->fin_cnt != 10)
                    {
                        circbuf_des(frp->pack_ring);
                        frp->pack_ring = (struct circbuf *) NULL;
                    }
                    if (frp->ofp == NULL)
                        frp->ofp = stdout;
                    if (frp->do_mess != NULL)
                        fputs("\\C:", frp->ofp);
                    date_out(frp->ofp,snoop.secs_since_1970,snoop.musecs);
                    if (frp->fin_cnt == 10)
                        frame_dump(frp, "Session Reset|", verbose);
                    else
                        frame_dump(frp, "Session Complete|", verbose);
#ifndef PACKDUMP
#ifdef WEB_REP
                    if (wrcp != NULL)
                        web_rep_anal(frp);
#endif
#endif
                    match_remove(open_sess, &anchor, frp);
                }
#ifdef RETRANS_TRAP
                else
                if (frp->retrans[dir_flag] > retrans)
                {
                    date_out(frp->ofp,snoop.secs_since_1970,snoop.musecs);
                    frame_dump(frp,
               "More than threshold retransmissions|", verbose);
                    fputs("Recent Traffic\n==============\n", frp->ofp);
                    circbuf_dump(pack_ring, frp->ofp);
                }
#endif
#ifdef NETTIME_TRAP
                else
                if (frp->nt_tim[dir_flag].tv_sec > gap)
                {
                    date_out(frp->ofp,snoop.secs_since_1970,snoop.musecs);
                    frame_dump(frp,
               "More than a threshold network delay\n=======================================\n", verbose);
                    fputs("Recent Traffic\n==============\n", frp->ofp);
                    circbuf_dump(pack_ring, frp->ofp);
                }
#endif
            }
#ifndef WEBDUMP
            else
            if (work_sess.prot == E2_UDP && udp.uh_dport == ECHO_SERVICE)
            {
            char buf0[3];

                if (event_id != 0)
                {
                    get_event_id(event_id, buf0);
                    iterate(open_sess, NULL, close_event);
                    printf("TT|0|%s\n", buf0);
                    event_id++;
                }
                else
                    event_id = 1;
/*
 * This is one of our event definitions. Only pick up the ECHO packet
 * going in one direction, by specifying the Destination port. Note that
 * we expect PATHSYNC to put a trailing NULL on the message.
 */
                event_desc = pack_con->pack_ptr + running_offset
                                + sizeof(udp);
                iterate(open_sess, NULL, open_event);
                get_event_id(event_id, buf0);
                printf("ST|0|%s|%s\n", buf0, event_desc);
            }
#endif
#ifdef DEBUG
            circbuf_dump(pack_ring, stdout);
            fflush(stdout);
#endif
            if (default_age > 0
              &&  (snoop.secs_since_1970 - last_purge_time) > default_age)
            {
                if (last_purge_time != 0)
                    iterate(open_sess, NULL, age_out);
                last_purge_time = snoop.secs_since_1970;
            }
        }
next_file:
        if (f != stdin)
            fclose(f);
        match_dismantle();
        event_id = 0;
    }
#ifdef OUTPUT_SCRIPT
    output_script();
#endif
#ifdef SYBASE
    finish();
#endif
    exit(0);
}
#ifndef PACKDUMP
static void sql_acl_check(f)
struct frame_con * f;
{
unsigned int uh;
struct in_addr host_to_test;
unsigned short int from, to;
char x1[16];
struct rep_struct * rsp;
int out;
/*
 * Save the ports. Unlike the IP addresses, they are in Machine order.
 */
    memcpy((unsigned char *) &from, &(f->port_from[1]), sizeof(unsigned short));
    memcpy((unsigned char *) &to, &(f->port_to[1]), sizeof(unsigned short));

    if (f->net_from[1] == 10
      && f->net_from[2] == 200
      && (f->net_from[3] == 60 || f->net_from[2] == 80)
      && (from == 1433 || from == 3389))
    {
        memcpy((char  *) &host_to_test, &(f->net_to[1]), sizeof(host_to_test));
        uh = (f->net_to[1] << 24) |(f->net_to[2] << 16)
                                        |(f->net_to[3] << 8) |f->net_to[4];
        out = 1;
    }
    else
    if (f->net_to[1] == 10
      && f->net_to[2] == 200
      && (f->net_to[3] == 60 || f->net_to[2] == 80)
      && (to == 1433 || to == 3389))
    {
        memcpy((char  *) &host_to_test, &(f->net_from[1]), sizeof(host_to_test));
        uh = (f->net_from[1] << 24) |(f->net_from[2] << 16)
                                        |(f->net_from[3] << 8) |f->net_from[4];
        out = 0;
    }
    else
        return;
#ifdef WEB_REP
    if ((rsp = rep_find_any(wrcp->rsp_sql,wrcp->rsp_sql_top, uh)) == NULL)
    {   /* It isn't allowed ... */
        e2inet_ntoa_r(host_to_test, x1);
        fputs(x1,alert_fp);
        fputs("|SQL|", alert_fp);
        date_out(alert_fp, f->this_time.tv_sec, f->this_time.tv_usec);
        ip_dir_print(alert_fp, f, out);
    }
#endif
    return;
}
#ifdef WEB_REP
/*
 * Has values specific to EMR ...
 */
static void web_rep_anal(f)
struct frame_con * f;
{
unsigned int uh;
struct in_addr host_to_test;
unsigned short int from, to;
char x1[16];
struct rep_struct * rsp;
int out;

    if (f->prot != E2_TCP || f->net_from[1] == 224 || f->net_to[1] == 224 )
        return; /* Multi-cast */
    if ((f->net_from[1] == 10
      || (f->net_from[1] == 192 && f->net_from[2] == 168) 
      || (f->net_from[1] == 172 && f->net_from[2] >= 16 && f->net_from[2] <= 31))
     &&
         (f->net_to[1] == 10
      || (f->net_to[1] == 192 && f->net_to[2] == 168) 
      || (f->net_to[1] == 172 && f->net_to[2] >= 16 && f->net_to[2] <= 31)))
    {  /* All internal */
        sql_acl_check(f);
        return;
    }
/*
 * Save the ports. Unlike the IP addresses, they are in Machine order.
 */
    memcpy((unsigned char *) &from, &(f->port_from[1]), sizeof(unsigned short));
    memcpy((unsigned char *) &to, &(f->port_to[1]), sizeof(unsigned short));
/*
 * Rogue RDP or Citrix connections
 */
    if ((f->net_from[1] == 10
     && (from == 3389 || from == 1494 || from == 2598)
     && to > 1023)
     || (f->net_to[1] == 10
     && (to == 3389 || to == 1494 || to == 2598)
     && from >1023))
    {
        if (f->net_to[1] == 10)
        {
            memcpy((char  *) &host_to_test, &(f->net_from[1]), sizeof(host_to_test));
            out = 0;
        }
        else
        {
            memcpy((char  *) &host_to_test, &(f->net_to[1]), sizeof(host_to_test));
            out = 1;
        }
        e2inet_ntoa_r(host_to_test, x1);
        fputs(x1,alert_fp);
        fputs("|HACK|",alert_fp);
        date_out(alert_fp, f->this_time.tv_sec, f->this_time.tv_usec);
        ip_dir_print(alert_fp, f, out);
        fputc('\n',alert_fp);
        return;
    }
/*
 * FTP Connections - clear text passwords ...
 */
    if ((f->net_from[1] == 10
     && (to == 20 || to == 21))
     || (f->net_to[1] == 10
     && (from == 20 || from == 21)))
    {
        if (f->net_to[1] == 10)
        {
            memcpy((char  *) &host_to_test, &(f->net_from[1]), sizeof(host_to_test));
            out = 0;
        }
        else
        {
            memcpy((char  *) &host_to_test, &(f->net_to[1]), sizeof(host_to_test));
            out = 1;
        }
        e2inet_ntoa_r(host_to_test, x1);
        fputs(x1,alert_fp);
        fputs("|FTP|",alert_fp);
        date_out(alert_fp, f->this_time.tv_sec, f->this_time.tv_usec);
        ip_dir_print(alert_fp, f, out);
        fputc('\n',alert_fp);
        return;
    }
/*
 * The test for tunnel-ness - more going out than coming in
 */
    if ((f->net_from[1] == 10 && f->net_from[2] == 200
      && (f->net_from[3] == 34 || f->net_from[3] == 68)
      && f->net_from[4] == 75
      && (to == 443 || to == 80)
      && f->cnt[0] > 5
      && f->cnt[1] > 5
      && f->len[0] > f->len[1])
     || (f->net_to[1] == 10 && f->net_to[2] == 200
      && (f->net_to[3] == 34 || f->net_to[3] == 68)
      && f->net_to[4] == 75
      && (from == 443 || from == 80)
      && f->cnt[0] > 5
      && f->cnt[1] > 5
      && f->len[1] > f->len[0]))
    {
        if (f->net_to[1] == 10)
        {
            memcpy((char  *) &host_to_test, &(f->net_from[1]), sizeof(host_to_test));
            uh = (f->net_from[1] << 24) |(f->net_from[2] << 16)
                                        |(f->net_from[3] << 8) |f->net_from[4];
            out = 1;
        }
        else
        {
            memcpy((char  *) &host_to_test, &(f->net_to[1]), sizeof(host_to_test));
            uh = (f->net_to[1] << 24) |(f->net_to[2] << 16)
                                        |(f->net_to[3] << 8) |f->net_to[4];
            out = 0;
        }
#ifdef WEB_REP
        if ((rsp = rep_find_lowest(wrcp->rsp_whois,wrcp->rsp_whois_top, uh)) == NULL)
        {   /* We haven't seen its like before */
            e2inet_ntoa_r(host_to_test, x1);
            fputs(x1,alert_fp);
            fputs("|NEW|",alert_fp);
            date_out(alert_fp, f->this_time.tv_sec, f->this_time.tv_usec);
            ip_dir_print(alert_fp, f, out);
            if ((rsp = rep_find_any(wrcp->rsp_country,wrcp->rsp_country_top, uh)) != NULL)
                fprintf(alert_fp,"|%s|%s", rsp->iprange, rsp->label);
            fputc('\n',alert_fp);
        }
#endif
    }
    return;
}
#endif
#endif
/*
 * The code here must carry out accumulator updates at the TCP
 * protocol rather than application level.
 *
 * Note that the full duplex TCP link is actually treated as being half
 * duplex here, since time is only apportioned to one bucket.
 */
static void accum_generic (f,dir_flag, pcp)
struct frame_con * f;
int dir_flag;
struct pack_con * pcp;
{
struct timeval last_to_now;

    f->cnt[dir_flag]++;
    f->len[dir_flag] += f->pack_len;
    f->last_t[dir_flag] = f->this_time;
/*
 * Adjust the total time breakdowns. There are two cases.
 * If the message is not TCP:
 * -  If the message is in in the same direction as the last one, we increment
 *    the cs_tim for that direction.
 * -  Otherwise, we increment the nt_tim.
 * If the message is TCP:
 * -  We do it properly, using the th_flags etc.
 *
 * Begin: work out how much time we are going to apportion
 */
    if (f->up_to.tv_sec != 0 || f->up_to.tv_usec != 0)
        tvdiff(&(f->last_t[dir_flag].tv_sec),
                   &(f->last_t[dir_flag].tv_usec),
                   &(f->up_to.tv_sec),
                   &(f->up_to.tv_usec),
                   &(last_to_now.tv_sec), &(last_to_now.tv_usec));
    else
    {
        last_to_now.tv_sec = 0;
        last_to_now.tv_usec = 0;
    }
    if (f->prot != E2_TCP)
    {
        if (f->up_to.tv_sec != 0
         || f->up_to.tv_usec != 0)
        {
            if (f->last_out == dir_flag)
            {
                tvadd(&(f->cs_tim[dir_flag].tv_sec),
                      &(f->cs_tim[dir_flag].tv_usec),
                      &(last_to_now.tv_sec), &(last_to_now.tv_usec),
                      &(f->cs_tim[dir_flag].tv_sec),
                      &(f->cs_tim[dir_flag].tv_usec));
            }
            else
            {
                tvadd(&(f->nt_tim[dir_flag].tv_sec),
                      &(f->nt_tim[dir_flag].tv_usec),
                      &(last_to_now.tv_sec), &(last_to_now.tv_usec),
                      &(f->nt_tim[dir_flag].tv_sec),
                      &(f->nt_tim[dir_flag].tv_usec));
            }
        }
        f->last_out = dir_flag;
    }
    else
/*
 * TCP stuff
 */
    {
        if ((pcp->tcp_flags & TH_PUSH) && (f->seq[dir_flag] > pcp->seq))
        {
/*
 * A retransmission: All the time goes to the network. But we need to
 * distinguish TCP keepalive retransmissions, and count them as client rather
 * than server.
 */
            if (f->seq[dir_flag] == (pcp->seq + 1))
            {
                tvadd(&(f->cs_tim[dir_flag].tv_sec),
                      &(f->cs_tim[dir_flag].tv_usec),
                      &(last_to_now.tv_sec), &(last_to_now.tv_usec),
                      &(f->cs_tim[dir_flag].tv_sec),
                      &(f->cs_tim[dir_flag].tv_usec));
                pcp->cs_tim[dir_flag] = last_to_now;
            }
            else
            {
                f->retrans[dir_flag]++;
                tvadd(&(f->nt_tim[dir_flag].tv_sec),
                      &(f->nt_tim[dir_flag].tv_usec),
                      &(last_to_now.tv_sec), &(last_to_now.tv_usec),
                      &(f->nt_tim[dir_flag].tv_sec),
                      &(f->nt_tim[dir_flag].tv_usec));
                pcp->nt_tim[dir_flag] = last_to_now;
            }
        }
        else
        {
/*
 * We need to look for:
 * - Dropped packets
 * - Times when the WIN value has been reached
 * - Exactly what the startup and shutdown sequences are
 */
            if ((pcp->tcp_flags & TH_ACK) && pcp->ack > f->ack[dir_flag])
            {
                tvadd(&(f->nt_tim[dir_flag].tv_sec),
                      &(f->nt_tim[dir_flag].tv_usec),
                      &(last_to_now.tv_sec), &(last_to_now.tv_usec),
                      &(f->nt_tim[dir_flag].tv_sec),
                      &(f->nt_tim[dir_flag].tv_usec));
                pcp->nt_tim[dir_flag] = last_to_now;
            }
            else
            {
                tvadd(&(f->cs_tim[dir_flag].tv_sec),
                      &(f->cs_tim[dir_flag].tv_usec),
                      &(last_to_now.tv_sec), &(last_to_now.tv_usec),
                      &(f->cs_tim[dir_flag].tv_sec),
                      &(f->cs_tim[dir_flag].tv_usec));
                pcp->cs_tim[dir_flag] = last_to_now;
            }
            if (pcp->tcp_flags & TH_ACK)
                f->ack[dir_flag] = pcp->ack;
            if (pcp->tcp_flags & TH_FIN)
                f->fin_cnt++;
            if (pcp->tcp_flags & TH_RST)
                f->fin_cnt = 10;        /* Flag abnormal termination */
        }
        f->win[dir_flag] = pcp->win;
        if (pcp->tcp_len > 0)
            f->last_out = dir_flag;
#ifdef SINGLE
        if (pcp->nt_tim[dir_flag].tv_sec > 0)
            frame_dump(f,
               "More than a 1 second network delay\n=======================================\n", verbose);
#endif
    }
    f->up_to = f->last_t[dir_flag];
    return;
}
static int resynch(f, snoop,t)
FILE *f;
struct snoop_header * snoop;
unsigned int t;
{
int ret;
unsigned char buf[(sizeof(*snoop))];
    ret = fread(&buf[0],sizeof(unsigned char),sizeof(*snoop),f);
    while (ret >= 0)
    {
        memcpy((unsigned char *) snoop, &buf[0],sizeof(*snoop));
        snoop->len = ntohl(snoop->len);
        snoop->secs_since_1970 = ntohl(snoop->secs_since_1970);
        snoop->musecs = ntohl(snoop->musecs);
        snoop->saved_len = ntohl(snoop->saved_len);
        snoop->record_len = ntohl(snoop->record_len);
        ret = snoop->secs_since_1970 - t;
#ifdef DEBUG
            fprintf(stderr,
"During resynch():ret: %d record_len:%u len: %u saved_len: %u secs: %u musecs:%u\n",
                     ret, snoop->record_len, snoop->len,
                      snoop->saved_len, snoop->secs_since_1970,
                     snoop->musecs);
#endif
        if (snoop->len > 0 && snoop->len < 131072 && ret >= 0 && ret < 600)
            return 1;
        for (ret = 0; ret < (sizeof(*snoop) - 1); ret++)
            buf[ret] = buf[ret+1];
        ret = fgetc(f);
        buf[(sizeof(*snoop) - 1)] = ret;
    }
    fprintf(stderr,
          "resynch() failed:ret: %d offset: %u errno: %d\n", ret, ftell(f),
                  errno);
    return 0;
}
#ifdef MINGW32
char * ctime_r(tp, bp)
time_t * tp;
char * bp;
{
    return strcpy(bp, ctime(tp));
}
#endif
#ifdef PACKDUMP
int cscalc() {}
int Lfree() {}
#endif

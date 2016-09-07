/************************************************************************
 * Scan an Ethernet trace file and pull out enough data to perform traffic
 * analysis.
 *
 * This program aims to function on any system, regardless of the form of
 * the packet trace encapsulation or the presence of the appropriate
 * headers.
 *
 * Typically link with -lsocket -linet -lnsl, depending on what exists.
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1994\n";
#ifdef __STRICT_ANSI
#undef __STRICT_ANSI
#endif
#include <sys/types.h>
#include <time.h>
#ifndef LCC
#ifndef VCC2003
#include <unistd.h>
#include <sys/time.h>
#endif
#endif
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "novell.h"
#include "ansi.h"
#include "e2net.h"
#include "bmmatch.h"

struct snoop_header {
    unsigned int len;
    unsigned int saved_len;
    unsigned int record_len;
    unsigned int cumulative_drops;
    unsigned int secs_since_1970;
    unsigned int musecs;
};
static char * fname;
static void do_merge();
void app_recognise(frp)
struct frame_con frp;
{
    return;
}
/*
 * TCPDUMP (PCAP) file support
 */
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
        if (aix->len > 0 && aix->len < 131072 && ret >= 0 && ret < 600)
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
           "tread:Length is %u at %lu; Cannot handle packets of more than 131072 bytes\n",
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
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
static unsigned int pick_host[10];
static int pick_cnt;
static int pick_port[600];
static int app_cnt;
/**************************************************************************
 * Main Program
 * VVVVVVVVVVVV
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
main(argc,argv)
int argc;
char ** argv;
{
static char * help_text = "snoopfix: working snoop file reader\n\
Options:\n\
-a Application port (may occur multiple times)\n\
-b Binary Output\n\
-c Include a dump of all packet payloads except for SMB\n\
-d Output date in English\n\
-e Recognise EBCDIC rather than ASCII, and translate\n\
-f Filter using the match string\n\
-g gap - Use this value to break the stream into transactions\n\
-h Output this message\n\
-i Host to include (may occur multiple times)\n\
-l structures are aligned on these boundaries\n\
-m merge snoop files from different interfaces\n\
-n Number the packets\n\
-o Named output file\n\
-p Include a dump of the packet payloads including SMB\n\
-r Make the time stamps running times rather than absolute times\n\
-s Frames have snap headers\n\
-t tcpdump (PCAP) rather than snoop file input\n\
-u Invert the sense of the selection\n\
-v Include a dump of the packets\n\
-x Use this date format (the default is seconds since 1970)\n\
-y Print records after that time.\n\
-z Print records before that time.\n\
List of files to process. Use - for stdin.\n\
The default output is emitted on stdout\n";
char * date_format;
unsigned int first_time;
double valid_time;
unsigned int last_time;
unsigned int check_time;
int merge_flag = 0;
int time_check;
int iplen, tcplen;
int snap_flag = 0;
int align_flag;
int ch;
int verbose = 0;
int tcpdump_flag = 0;
int running = 0;
int number = 0;
struct snoop_header snoop;
unsigned int t1 = 0;
unsigned int m1 = 0;
unsigned int t2 = 0;
unsigned int m2 = 0;
unsigned int t3 = 0;
unsigned int m3 = 0;
unsigned int t4 = 0;
unsigned int m4 = 0;
unsigned int l = 0;
int big_little_flag;
int gap = 0;
int date_flag = 0;
struct ether_header eth;
FILE * ofp;
struct ip ip;
struct tcphdr tcp;
struct udphdr udp;
int running_offset;
char * filter;
struct bm_table * bp;
int flag = 0;
unsigned char buf[131072];
int ret;
int i,j,k;
char *x, *x1, *x2;
int invert_sense = 0;

    clear_ebcdic_flag();
    ofp = stdout;
    filter = NULL;
    bp = NULL;
    date_format = (char *) NULL;
    first_time = 0;
    last_time = 0x7fffffff;
    time_check = 0;
    align_flag = 0;
    while ( ( ch = getopt ( argc, argv, "a:bcdef:g:hi:l:mno:prstuvx:y:z:" ) ) != EOF )
    {
        switch ( ch )
        {
        case 'a':
            if (app_cnt < 600)
                pick_port[app_cnt++] =  atoi(optarg);
            else
                fputs("Can only select up to 600 ports at a time\n", stderr);
            break;
        case 'b' :
            verbose = -1;
            break;
        case 'c' :
            verbose = 2;
            break;
        case 'd' :
            date_flag = 1;
            break;
        case 'e' :
            set_ebcdic_flag();
            break;
        case 'g' :
            gap = atoi(optarg);
            break;
        case 'f' :
#ifdef DEBUG
            flag = atoi(optarg);
#endif
            filter = optarg;
            break;
        case 'h' :
            (void) fputs(help_text, stderr);
            exit(0);
        case 'i':
            if (pick_cnt < 10)
                pick_host[pick_cnt++] =  inet_addr(optarg);
            else
                fputs("Can only select up to 10 hosts at a time\n", stderr);
            break;
        case 'l' :
            align_flag = atoi(optarg);
            if (align_flag < 1)
                align_flag = 4;
            break;
        case 'm' :
            merge_flag = 1;
            break;
        case 'n' :
            number = 1;
            break;
        case 'o' :
            if ((ofp = fopen(optarg, "wb")) == (FILE *) NULL)
            {
                perror("fopen() failed");
                fprintf(stderr, "Could not open %s; will use stdout\n",
                         optarg);
                ofp = stdout;
            }
            break;
        case 'p' :
            verbose = 3;
            break;
        case 'r' :
            running = 1;
            break;
        case 's' :
            snap_flag = 4;
            break;
        case 't' :
            tcpdump_flag = 4;
            break;
        case 'u' :
            invert_sense = 1;
            break;
        case 'v' :
            verbose = 1;
            break;
        case 'x':
             date_format = optarg;
             break;
        case 'y' :
        case 'z' :
            time_check = 1;
            if ( date_format != (char *) NULL)
            {
                if ( !date_val(optarg,date_format,&x,&valid_time))
                {
/*
 * Time argument is not a valid date
 */
                   (void) fputs(help_text, stdout);
                   exit(0);
                }
                if (ch == 'y')
                    first_time = (unsigned int) valid_time;
                else
                    last_time = (unsigned int) valid_time;
            }
            else
            {
                if (ch == 'y')
                    first_time = atoi(optarg);
                else
                    last_time = atoi(optarg);
            }
            break;
        default:
        case '?' : /* Default - invalid opt.*/
            (void) fputs("Invalid argument\n", stderr);
            (void) fputs(help_text, stderr);
            exit(1);
        }
    }
    if (filter)
        bp = bm_compile(filter);
/*
 * If binary output, write out the file header
 */
    if (verbose == -1)
    {
        memset(&buf[0],0,16);
        strcpy(&buf[0], "snoop");
        buf[11] = 2;
        (void) fwrite(&buf[0],sizeof(char),16,ofp);
    }
    if (merge_flag && argc - optind != 2)
    {
        fputs("Merge only supported for exactly 2 files\n", stderr);
        exit(1);
    }
    else
    if (merge_flag )
        do_merge(argv[optind],argv[optind + 1], ofp);
    else
    for (i = optind; i < argc; i++)
    {
    FILE *f;

        fname = argv[i];
        if (*fname == '-' && *(fname + 1) == 0)
            f = stdin;
        else
        if ((f = fopen(fname,"rb")) == (FILE *)NULL)
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
            (void) fread(&buf,16,1, f);   /* Skip the snoop header */
        while ((ret = (tcpdump_flag) ? tread(&buf[0], big_little_flag, f) :
                  fread(&buf[0],sizeof(unsigned char),sizeof(snoop),f)) > 0)
        {
            memcpy((unsigned char *) &snoop, &buf[0], sizeof(snoop));
            if (!tcpdump_flag)
            {
                snoop.saved_len = ntohl(snoop.saved_len);
                snoop.record_len = ntohl(snoop.record_len);
            }
            if (snoop.saved_len > 131072)
            {
                (void) fprintf(stderr,
          "Length is 0x%x; Cannot handle packets of more than 131072 bytes\n",
                   snoop.saved_len);
                exit(1);
            }
            if (verbose != -1)
            {
                if (!tcpdump_flag)
                {
                    snoop.len = ntohl(snoop.len);
                    snoop.secs_since_1970 = ntohl(snoop.secs_since_1970);
                    snoop.musecs = ntohl(snoop.musecs);
                }
                l += snoop.len;
                if (running)
                {
                    tvdiff32(&(snoop.secs_since_1970), &(snoop.musecs),&t1,&m1,
                                          &t2,&m2);
                    tvdiff32(&(snoop.secs_since_1970),&(snoop.musecs),&t3,&m3,
                                          &t4,&m4);
                    t1 = snoop.secs_since_1970;
                    m1 = snoop.musecs;
                    if (gap && t2 > gap)
                    {
                        fputs("************ GAP **************\n", stdout);
                        l = 0;
                        if (t3 == 0)
                        {
                            t3 = t1;
                            m3 = m1;
                        }
                    }
                }
                else
                {
                    t2 = snoop.secs_since_1970;
                    m2 = snoop.musecs;
                }
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
            if (filter && (bm_match(bp, &buf[0], &buf[snoop.saved_len])
                                == NULL))
                continue;
            if (time_check)
            {
                if (verbose == -1 && !tcpdump_flag)
                    check_time = ntohl(snoop.secs_since_1970);
                else
                    check_time = snoop.secs_since_1970;
                if (check_time < first_time || check_time > last_time)
                    continue;
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
            running_offset = sizeof(eth) + 2 * snap_flag;
            if (align_flag && (running_offset % align_flag))
               running_offset += align_flag - (running_offset % align_flag);
            if (eth.ether_type == ETHERTYPE_IP || snap_flag || align_flag)
            {
                memcpy((unsigned char *) &ip, &buf[running_offset],
                       sizeof(ip));
                if (pick_cnt)
                {
                    for (j = 0; j < pick_cnt; j++)
                        if (!memcmp((char *) &pick_host[j], 
                                  (char *) &(ip.ip_src), 4)
                          || !memcmp((char *) &pick_host[j], 
                                  (char *) &(ip.ip_dst), 4))
                            break;
                    if ((j == pick_cnt) ^ invert_sense)
                        continue;
                }
                running_offset += sizeof(ip);
                if (align_flag && (running_offset % align_flag))
                    running_offset += align_flag -(running_offset % align_flag);
                if (app_cnt)
                {
                    if (ip.ip_p == IPPROTO_TCP)
                    {
                        memcpy((unsigned char *) &tcp,
                             &buf[running_offset],
                               sizeof(tcp));
                        tcp.th_sport = ntohs(tcp.th_sport);
                        tcp.th_dport = ntohs(tcp.th_dport);
#ifdef AIX
                        tcp.th_off >>= 4;
#endif
#ifdef OSF
                        tcp.th_off >>= 4;
#endif
                        for (j = 0; j < app_cnt; j++)
                            if (pick_port[j] == tcp.th_sport
                             || pick_port[j] == tcp.th_dport)
                                break;
                        if ((j == app_cnt) ^ invert_sense)
                            continue;
                    }
                    else
                    if (ip.ip_p == IPPROTO_UDP)
                    {
                        memcpy((unsigned char *) &udp,
                           &buf[running_offset], sizeof(udp));
                        udp.uh_dport = ntohs(udp.uh_dport);
                        udp.uh_sport = ntohs(udp.uh_sport);
                        for (j = 0; j < app_cnt; j++)
                            if (pick_port[j] == udp.uh_sport
                             || pick_port[j] == udp.uh_dport)
                                break;
                        if (j == app_cnt)
                            continue;
                    }
                    else
                        continue;
                }
            }
            else
            if (pick_cnt || app_cnt)
                continue;
            if (verbose == -1)
            {
                snoop.record_len = htonl(snoop.saved_len + sizeof(snoop));
                k = snoop.saved_len;
                snoop.saved_len = htonl(snoop.saved_len);
                if (tcpdump_flag)
                {
                    snoop.len = htonl(snoop.len);
                    snoop.secs_since_1970 = htonl(snoop.secs_since_1970);
                    snoop.musecs = htonl(snoop.musecs);
                }
                fwrite((char *) &snoop, sizeof(char), 
                            sizeof(snoop), ofp);
                fwrite(&buf[0], sizeof(char), k, ofp);
                continue;
            }
            if (number)
            {
#ifdef DEBUG
                if (number == flag)
                    fprintf(stderr, "Reached packet %d\n", flag);
#endif
                fprintf(ofp, "%d|",number++);
            }
#ifdef NOETHER_H
            fprintf(ofp, "%02x:%02x:%02x:%02x:%02x:%02x|\
%02x:%02x:%02x:%02x:%02x:%02x|\
%d|",
                 (unsigned int) *((unsigned char *) & eth.ether_shost),
                 (unsigned int) *(((unsigned char *) & eth.ether_shost) + 1),
                 (unsigned int) *(((unsigned char *) & eth.ether_shost) + 2),
                 (unsigned int) *(((unsigned char *) & eth.ether_shost) + 3),
                 (unsigned int) *(((unsigned char *) & eth.ether_shost) + 4),
                 (unsigned int) *(((unsigned char *) & eth.ether_shost) + 5),
                 (unsigned int) *((unsigned char *) & eth.ether_dhost),
                 (unsigned int) *(((unsigned char *) & eth.ether_dhost) + 1),
                 (unsigned int) *(((unsigned char *) & eth.ether_dhost) + 2),
                 (unsigned int) *(((unsigned char *) & eth.ether_dhost) + 3),
                 (unsigned int) *(((unsigned char *) & eth.ether_dhost) + 4),
                 (unsigned int) *(((unsigned char *) & eth.ether_dhost) + 5),
                     snoop.len);
            if (date_flag)
            {
                time_t t1 = (time_t) snoop.secs_since_1970;
                x = ctime(&t1);
                fprintf(ofp, "%2.2s %3.3s %4.4s %8.8s.%06d|",
                        (x + 8), (x + 4), (x + 20), (x + 11),
                           snoop.musecs);
            }
            else
                fprintf(ofp, "%d.%06d|", t2, m2);
#else
            x1 = strdup(ether_ntoa(&(eth.ether_shost)));
            x2 = strdup(ether_ntoa(&(eth.ether_dhost)));
            if (date_flag)
            {
                time_t t1 = (time_t) snoop.secs_since_1970;
                x = ctime(&t1);
                fprintf(ofp, "%s|%s|%d|%2.2s %3.3s %4.4s %8.8s.%06d|",x1,x2,
                       snoop.len, (x + 8), (x + 4), (x + 20), (x + 11),
                           snoop.musecs);
            }
            else
                fprintf(ofp, "%s|%s|%d|%d.%06d|",x1,x2, snoop.len, t2, m2);
            free(x1);
            free(x2);
#endif
            if (running)
                fprintf(ofp, "%d|%d.%06d|", l, t4, m4);
            if (eth.ether_type == ETHERTYPE_IP || snap_flag || align_flag)
            {
                iplen = ntohs(ip.ip_len);
                if (iplen == 0)
                {
                    iplen = snoop.len - running_offset + sizeof(ip);
                    ip.ip_len = ntohs(iplen);
                }
                fputs( inet_ntoa(ip.ip_src)  ,ofp);
                putc('|', ofp);
                fputs(inet_ntoa(ip.ip_dst) ,ofp);
                putc('|', ofp);
                if (ip.ip_p == IPPROTO_TCP)
                {
                    if (!app_cnt)
                    {
                        memcpy((unsigned char *) &tcp,
                               &buf[running_offset],
                               sizeof(tcp));
                        tcp.th_sport = ntohs(tcp.th_sport);
                        tcp.th_dport = ntohs(tcp.th_dport);
#ifdef AIX
                        tcp.th_off >>= 4;
#endif
#ifdef OSF
                        tcp.th_off >>= 4;
#endif
                    }
                    tcplen = iplen - sizeof(ip) - tcp.th_off*4;
                    fprintf(ofp, "%u|%u|%u|%x\n",tcp.th_sport,tcp.th_dport,
                                 tcplen, tcp.th_flags);
                    if ((verbose == 2
                      && tcp.th_sport != 139
                      && tcp.th_dport != 139) || verbose == 3)
                    {
                        running_offset += tcp.th_off*4;
                        if (align_flag && (running_offset % align_flag))
                            running_offset += align_flag -(running_offset % align_flag);
                        (void) gen_handle(ofp,
                                &buf[running_offset],
&buf[ (snoop.saved_len < (running_offset + tcplen)) ? snoop.saved_len :running_offset + tcplen], 1);
                    }
                    fflush(ofp);
                }
                else
                if (ip.ip_p == IPPROTO_UDP)
                {
                    if (!app_cnt)
                    {
                        memcpy((unsigned char *) &udp,
                               &buf[running_offset],
                               sizeof(udp));
                        udp.uh_dport = ntohs(udp.uh_dport);
                        udp.uh_sport = ntohs(udp.uh_sport);
                    }
                    udp.uh_ulen = ntohs(udp.uh_ulen);
                    fprintf(ofp, "%u|%u|%u\n",udp.uh_sport,udp.uh_dport,
                                 udp.uh_ulen);
                    if (verbose >= 2)
                    {
                        running_offset += sizeof(udp);
                        if (align_flag && (running_offset % align_flag))
                            running_offset += align_flag -
                                  (running_offset % align_flag);
                        (void) gen_handle(ofp,
                                 &buf[running_offset],
                                 &buf[snoop.saved_len], 1);
                    }
                    fflush(ofp);
                }
                else
                    fputs("||\n", ofp);
            }
            else
            switch(eth.ether_type)
            {
            case ETHERTYPE_REVARP:
                fputs("REVARP|\n", ofp);
                break;
            case ETHERTYPE_ARP:
                fputs("ARP|\n", ofp);
                break;
            case ETHERTYPE_PUP:
                fputs("PUP|\n", ofp);
                break;
            case ETHERTYPE_X75:
                fputs("X75|\n", ofp);
                break;
            case ETHERTYPE_X25:
                fputs("X25|\n", ofp);
                break;
            case ETHERTYPE_BANYAN:
                fputs("BANYAN|\n", ofp);
                break;
            case ETHERTYPE_DECMOP1:
                fputs("DECMOP1|\n", ofp);
                break;
            case ETHERTYPE_DECMOP2:
                fputs("DECMOP2|\n", ofp);
                break;
            case ETHERTYPE_DECNET:
                fputs("DECNET|\n", ofp);
                break;
            case ETHERTYPE_DECLAT:
                fputs("DECLAT|\n", ofp);
                break;
            case ETHERTYPE_DECDIAGNOSTIC:
                fputs("DECDIAGNOSTIC|\n", ofp);
                break;
            case ETHERTYPE_DECLANBRIDGE:
                fputs("DECLANBRIDGE|\n", ofp);
                break;
            case ETHERTYPE_DECETHENCR:
                fputs("DECETHENCR|\n", ofp);
                break;
            case ETHERTYPE_APPLETALK:
                fputs("APPLETALK|\n", ofp);
                break;
            case ETHERTYPE_IBMSNA:
                fputs("IBMSNA|\n", ofp);
                break;
            case ETHERTYPE_NETWARE:
                fputs("NOVELL|\n", ofp);
                break;
            case ETHERTYPE_SNMP:
                fputs("SNMP|\n", ofp);
                break;
            default:
                if (eth.ether_type >= IEEE802_3_TYPE  )
                {
                    fputs("UNKNOWN|\n", ofp);
                }
                else
                {
/*
 * The type is actually a length field
 */
                   if (eth.ether_type < 30)
                       fputs("LLC|\n", ofp);
                   else
                       (void) ipx_dump(ofp,
                            &buf[sizeof(eth)],&buf[snoop.saved_len], 0);
                               fputs("NOVELL|\n", ofp);
                }
            }
            if (verbose == 1)
                (void) gen_handle(ofp, &buf[0],&buf[snoop.saved_len], 1);
        }
        if (f != stdin)
            (void) fclose(f);
    }
    exit(0);
}
static void read_snoop(ifp, buffer, merge_flag, chan_id)
FILE * ifp;
struct snoop_header * buffer;
int * merge_flag;
int chan_id;
{
    if (fread(buffer,sizeof(*buffer),sizeof(char), ifp) < 1)
        *merge_flag |= chan_id;
    return;
}
static void write_snoop(ifp, ofp, buffer)
FILE *ifp;
FILE * ofp;
struct snoop_header * buffer;
{
char buf[131072];
int record_len;

    fwrite(buffer,sizeof(*buffer),sizeof(char), ofp);
    record_len =ntohl(buffer->record_len) - sizeof(*buffer);
    if (record_len > sizeof(buf))
    {
        fprintf(stderr, "Record length (%u) exceeds 131072?\n", record_len);
        exit(1);
    }
    fread(buf,record_len, sizeof(char), ifp);
    fwrite(buf, record_len, sizeof(char), ofp);
    return;
}
/*
 * Compare headers. Never return match (since we don't do anything special
 * on match)
 *
 * Arbitrarily write the first buffer in the case of a match
 *
 * What possessed me to use these flag bits?
 */
static int match_headers(snp1, snp2)
struct snoop_header * snp1;
struct snoop_header * snp2;
{
int tm1;
int tm2;

    tm1 = ntohl(snp1->secs_since_1970);
    tm2 = ntohl(snp2->secs_since_1970);
    if (tm1 < tm2)
        return 4;
    else
    if (tm1 > tm2)
        return 8;
    tm1 = ntohl(snp1->musecs);
    tm2 = ntohl(snp2->musecs);
    if (tm1 > tm2)
        return 8;
    else
        return 4;
}
/*
 * Function to merge snoop files from different interfaces by date.
 */
static void do_merge(fn1, fn2, ofp)
char * fn1;
char * fn2;
FILE * ofp;
{
FILE * fn2_channel;
FILE * fn1_channel;
unsigned int merge_flag;
char buf[16];

struct snoop_header fn2_snoop, fn1_snoop;
/*
 * Create a list of the files to match in changemem
 */
    if ((fn1_channel = fopen(fn1,"rb")) == (FILE *) NULL)
        return;
    if ((fn2_channel = fopen(fn2,"rb")) == (FILE *) NULL)
        return;
/*
 * Skip the file headers and write the file header
 */
    fread(buf, 16, sizeof(char), fn1_channel);
    fread(buf, 16, sizeof(char), fn2_channel);
    fwrite(buf,16, sizeof(char), ofp);
    merge_flag = 0;
/*
 * Get the first record from the second file
 */
    read_snoop(fn2_channel, &fn2_snoop, &merge_flag, 2);
    if (merge_flag & 2)
        return;
    read_snoop(fn1_channel, &fn1_snoop, &merge_flag, 1);
            /* read the first record */
    if (merge_flag & 1)
        return;
/*******************************************************************************
 *     Main Control; loop - merge the two files until both are exhausted
 ******************************************************************************/
    while  ((merge_flag & 3) != 3)
    {
        if ((merge_flag & 3) == 0)
            merge_flag = match_headers(&fn1_snoop, &fn2_snoop);
        else
            merge_flag &= ~12;

        if (merge_flag & 9)
        {   /* File 1 has run out, or File 1 is later */
            write_snoop(fn2_channel, ofp, &fn2_snoop);
                    /* write out the record */
            read_snoop(fn2_channel, &fn2_snoop, &merge_flag, 2);
                    /* read the next record */
        }
        else
        if (merge_flag & 6)
        {   /* File 2 has run out, or File 2 is later */
            write_snoop(fn1_channel, ofp, &fn1_snoop);
                    /* write out the record */
            read_snoop(fn1_channel, &fn1_snoop, &merge_flag, 1);
                    /* read the next record */
        }
    }
    fclose(fn2_channel);
    fclose(fn1_channel);
    fclose(ofp);
    return;
}
#ifdef MINGW32
char * ctime_r(tp, bp)
time_t * tp;
char * bp;
{
    return strcpy(bp, ctime(tp));
}
#endif

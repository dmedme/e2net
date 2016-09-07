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
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#ifndef NOETHER_H
#define NOETHER_H
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
char * inet_addr();
/*
 * Defines all the headers for the FDDI packets
 *
    Here are definitions to assist in adding LLC headers or MAC headers
    on transmits and stripping them on receives.

    Every frame sent on an FDDI network must have a MAC header.
*/
#define PAD_LENGTH      3           /* Fill fc out to a word boundary */
struct  machdr {
    unchar  machdr_pad[PAD_LENGTH];
    unchar  fc;                     /* Frame control field */
    unchar  da[6];                  /* Destination address */
    unchar  sa[6];                  /* Source address */
};
#define LLC_FC  0x50                /* Our llc fc field, async and long addr */
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
#define FIXED_DSAP      0xaa        /* RFC1103 defines dsap and ssap */
#define FIXED_SSAP      0xaa        /*         for TCP/IP packets. */
#define PROTO_ID        0           /* It also defines protocol id */
#define LLC_CONTROL     3           /* and control field as well */
/*
    The entire header for a TCP/IP frame looks like the following...
*/
struct  fddihdr {
    struct machdr   mh;
    struct llchdr   lh;
};
struct ether_addr {
   unsigned char addr[6];
};
struct	fddi_header {
	u_char  fddi_ph[3];	 
	u_char	fddi_fc;
	u_char	fddi_dhost[6];
	u_char	fddi_shost[6];
};
#define	ETHERTYPE_PUP		(0x0200)	/* PUP protocol */
#define	ETHERTYPE_IP		(0x0800)	/* IP protocol */
#define	ETHERTYPE_ARP		(0x0806)	/* Addr. resolution protocol */
#define	ETHERTYPE_REVARP	(0x8035)	/* Reverse ARP */
#define	ETHERTYPE_MAX		(0xffff)	/* Max valid ethernet type */
struct	ether_header {
	struct	ether_addr	ether_dhost;
	struct	ether_addr	ether_shost;
	u_short	ether_type;
};
/***************************************************************************
 * Functions in this file.
 */
static unsigned char * gen_handle(unsigned char *p,
    unsigned char * top, int write_flag);
static unsigned char * hex_in_out( unsigned char * out, unsigned char * in);
static void hex_out( unsigned char *b, unsigned char * top);
static void hex_line_out( unsigned char *b, unsigned char * top);
static unsigned char * bin_handle( unsigned char *p,
    unsigned char *top, int write_flag);
static unsigned char * asc_handle( unsigned char *p,
    unsigned char *top, int write_flag);
static char * fname;
static void tvdiff( long * t1, long * m1, long * t2, long * m2,
long * t3, long *m3);
#define ENALIGN(x) ((x%4)?(x+(4-(x%4))):x)
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
extern int errno;
/**************************************************************************
 * Main Program
 * VVVVVVVVVVVV
 */
main(argc,argv)
int argc;
char ** argv;
{
char ch;
int verbose = 0;
int running = 0;
int number = 0;
struct enstamp {
	u_short ens_stamplen;	/* number of bytes in this stamp struct */
	u_short ens_flags;	/* see below				*/
	u_short	ens_count;	/* number of bytes in packet		*/
				/*	(not counting this stamp struct) */
	u_short	ens_dropped;	/* number of packets dropped for this	*/
				/*	filter since previous packet	*/
				/*	(valid only for last-match filter) */
	u_long	ens_ifoverflows;
				/* number of packets missed by interface */
				/*	(cumulative)			*/
	struct timeval ens_tstamp;
				/* time packet was received (more or less) */
};
struct enstamp snoop;
long t1 = 0;
long m1 = 0;
long t2 = 0;
long m2 = 0;
long t3 = 0;
long m3 = 0;
long t4 = 0;
long m4 = 0;
long l = 0;
unsigned long dayn;
unsigned long secn;
unsigned long runn;
time_t base_time;
struct fddi_header eth;
struct llchdr llc;
struct ip ip;
struct tcphdr tcp;
unsigned char buf[65536];
int ret;
int i,j,k;
char * x1, *x2;
int date_flag = 0;

    while ( ( ch = getopt ( argc, argv, "dnhvr" ) ) != EOF )
    {
        switch ( ch )
        {
        case 'd' :
            date_flag = 1;
            break;
        case 'n' :
            number = 1;
            break;
        case 'v' :
            verbose = 1;
            break;
        case 'r' :
            running = 1;
            break;
        case 'h' :
            (void) puts("lltracefix: working lltrace file reader\n\
Options:\n\
-n Number the packets\n\
-d Print human-readable time stamps\n\
-v Include a dump of the packets\n\
-r Make the time stamps running times rather than absolute times\n\
List the files to process. The output is emitted on stdout\n");
                    exit(0);
        default:
        case '?' : /* Default - invalid opt.*/
            (void) fprintf(stderr,"Invalid argument; try -h\n");
            exit(1);
        }
    }
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
        fseek(f,22,1);
        while ((ret = fread(&buf[0],sizeof(unsigned char),17,f)) > 0)
        {
            snoop.ens_count = buf[3]*256 + buf[2] - 11;
            runn =   buf[6] + buf[7]*256 + buf[8]*256*256  + buf[9]*256*256*256;
            snoop.ens_tstamp.tv_sec = base_time + (2*runn)/1000000;
            snoop.ens_tstamp.tv_usec =  (2*runn) % 1000000;
            if (snoop.ens_count > 65536)
            {
                (void) fprintf(stderr,
              "Length is %d; Cannot handle packets of more than 65536 bytes\n",
                    snoop.ens_count);
                exit(1);
            }
            else
            if (snoop.ens_count < sizeof(eth) || snoop.ens_count > 5000)
            {
               
                (void) fprintf(stdout,
              "Funny packet at offset %d; Read:\n\
            snoop.ens_stamplen: %d\n\
            snoop.ens_flags: %d\n\
            snoop.ens_count: %d\n\
            snoop.ens_dropped: %d\n\
            snoop.ens_ifoverflows: %d\n\
            snoop.ens_tstamp.tv_sec: %d\n\
            snoop.ens_tstamp.tv_usec: %d\n",
            ftell(f),
            snoop.ens_stamplen,
            snoop.ens_flags,
            snoop.ens_count,
            snoop.ens_dropped,
            snoop.ens_ifoverflows,
            snoop.ens_tstamp.tv_sec,
            snoop.ens_tstamp.tv_usec);
                fseek(f,-sizeof(snoop) +1,1);
                continue;
            }
            k = snoop.ens_count;
            if ((ret = fread(&buf[0],sizeof(unsigned char), k, f)) < 1)
            {
                perror("fread() failed");
                (void) fprintf(stderr,
        "Read of %s : %d bytes failed with UNIX errno %d\n",argv[i], k, errno);
                exit(1);
            }
            memcpy((unsigned char *) &eth, &buf[0],sizeof(eth));
            memcpy((unsigned char *) &llc, &buf[sizeof(eth)],sizeof(llc));
            llc.etype = ntohs(llc.etype);
            if (number)
                printf("%d|",number++);
            if (date_flag)
            {
                char * x = ctime(&(snoop.ens_tstamp.tv_sec));
                printf("%2.2s %3.3s %4.4s %8.8s.%06d|",
                           (x + 8), (x + 4), (x + 20), (x + 11),
                               snoop.ens_tstamp.tv_usec);
            }
            else
                printf("%d.%06d|", snoop.ens_tstamp.tv_sec,
                               snoop.ens_tstamp.tv_usec);

#ifdef NOETHER_H
            printf("%02x:%02x:%02x:%02x:%02x:%02x|\
%02x:%02x:%02x:%02x:%02x:%02x|\
%d|%d.%06d|",
                 (unsigned int) *((unsigned char *) & eth.fddi_shost),
                 (unsigned int) *(((unsigned char *) & eth.fddi_shost) + 1),
                 (unsigned int) *(((unsigned char *) & eth.fddi_shost) + 2),
                 (unsigned int) *(((unsigned char *) & eth.fddi_shost) + 3),
                 (unsigned int) *(((unsigned char *) & eth.fddi_shost) + 4),
                 (unsigned int) *(((unsigned char *) & eth.fddi_shost) + 5),
                 (unsigned int) *((unsigned char *) & eth.fddi_dhost),
                 (unsigned int) *(((unsigned char *) & eth.fddi_dhost) + 1),
                 (unsigned int) *(((unsigned char *) & eth.fddi_dhost) + 2),
                 (unsigned int) *(((unsigned char *) & eth.fddi_dhost) + 3),
                 (unsigned int) *(((unsigned char *) & eth.fddi_dhost) + 4),
                 (unsigned int) *(((unsigned char *) & eth.fddi_dhost) + 5),
                     snoop.ens_count, t2, m2);
#else
                 x1 = strdup(ether_ntoa(&(eth.fddi_shost)));
                 x2 = strdup(ether_ntoa(&(eth.fddi_dhost)));
                 printf("%s|%s|%d|%d.%06d|",x1,x2, snoop.ens_count, t2, m2);
                 free(x1);
                 free(x2);
#endif
            if (llc.etype == ETHERTYPE_IP)
            { 
            char * x;
                memcpy((unsigned char *) &ip,
                  &buf[sizeof(eth) + sizeof(llc)],sizeof(ip));
                fputs(inet_ntoa( ip.ip_src), stdout);
                putchar('|');
                fputs( inet_ntoa( ip.ip_dst), stdout);
                putchar('|');
                if (ip.ip_p == IPPROTO_TCP)
                {
                    int ip_len;
                    int tcp_len;
                    int rcp_off;
                    memcpy((unsigned char *) &tcp,
                           &buf[sizeof(eth) + sizeof(llc) + sizeof(ip)],
                           sizeof(tcp));
                    tcp.th_sport = ntohs(tcp.th_sport);
                    tcp.th_dport = ntohs(tcp.th_dport);
                    printf("%d|%d|\n",tcp.th_sport,tcp.th_dport);
                            fflush(stdout);
                }
                else
                    puts("||");
            }
            else
                puts("||||");
            if (verbose)
                (void) gen_handle(&buf[0],&buf[snoop.ens_count], 1);
        }
    }
    exit(0);
}
/**************************************************************************
 * Output clear text when we encounter it, otherwise hexadecimal.
 */
static unsigned char * gen_handle(p, top, write_flag)
unsigned char *p;
unsigned char *top;
int write_flag;
{
    while ((p = bin_handle(p,top,write_flag)) < top) 
        p = asc_handle(p,top,write_flag);
    putchar((int) '\n');
    return top;
}
/**************************************************************************
 * Output clear text when we encounter it.
 */
static unsigned char * asc_handle(p, top, write_flag)
unsigned char *p;
unsigned char *top;
int write_flag;
{
unsigned char *la;
    for (la = p;
             la < top &&
             (*la == '\t'
             || *la == '\n'
             || *la == '\r'
             || *la == '\f'
             || (*la > (unsigned char) 31 && *la < (unsigned char) 127));
                 la++);
    if (write_flag && (la - p))
    {
        int len=(la -p);
        int olen = 79;
        while (len)
        {
            if (olen > len)
                olen = len;
            fwrite(p,sizeof(char), olen,stdout);
            len -= olen;
            p += olen;
            if (len)
               fputs("\\\n", stdout);
        }
    }
    return la;
}
/**************************************************************************
 * Output non-clear text as blocks of Hexadecimal.
 */
static unsigned char * bin_handle(p,top,write_flag)
unsigned char *p;
unsigned char *top;
int write_flag;
{
unsigned     char *la;
    for (la = p;
             la < top &&
             ((*la != '\t'
             && *la != '\n'
             && *la != '\r'
             && *la != '\f'
             && (*la < (unsigned char) 32 ||  *la > (unsigned char) 126))
             || ((asc_handle(la, top, 0) - la) < 4));
                 la++);
    if (write_flag && (la - p))
        hex_line_out(p,la);
    return la;
}
/**************************************************************************
 * Output Hexadecimal in Lines.
 */
static void hex_line_out(b,top)
unsigned char *b;
unsigned char * top;
{
int olen = 30;
int len = (top - b);
register unsigned char * x = b, x1;
    do 
    {
        if (olen > len)
            olen = len;
        hex_out(x, x + olen);
        x += olen;
        putchar((int) '\n'); 
        len -= olen;
    }
    while (len > 0);
    return;
}
/**************************************************************************
 * Output Hexadecimal. Flag them with a leading and trailing single quote
 */
static void hex_out(b,top)
unsigned char *b;
unsigned char * top;
{
int len = (top - b);
register unsigned char * x = b, x1;
register int i;
    putchar((int) '\''); 
    for (i = len; i; i--, x++)
    { 
        x1 = (char) (((((int ) *x) & 0xf0) >> 4) + 48);
        if (x1 > '9')
           x1 += (char) 7;
        putchar((int) x1); 
        x1 = (unsigned char) ((((int ) *x) & 0x0f) + 48);
        if (x1 > '9')
           x1 += (unsigned char) 7;
        putchar((int) x1); 
    }
    putchar((int) '\''); 
    return;
}
/*
 * Bring in hexadecimal strings, and output a stream of bytes.
 */
static unsigned char * hex_in_out(out, in)
unsigned char * out;
unsigned char * in;
{
/*
 * Build up half-byte at a time, subtracting 48 initially, and subtracting
 * another 7 (to get the range from A-F) if > (char) 9;
 */
    register unsigned char * x = out,  * x1 = in;
    while (*x1 != '\0')
    {
        register char x2;
        x2 = *x1 - (char) 48;
        if (x2 > (char) 9)
           x2 -= (char) 7; 
        if (x2 > (char) 15)
           x2 -= (char) 32;    /* Handle lower case */
        *x = (unsigned char) (((int ) x2) << 4);
        x1++;
        if (*x1 == '\0')
            break;
        x2 = *x1++ - (char) 48;
        if (x2 > (char) 9)
           x2 -= (char) 7; 
        *x++ |= x2;
    }
    return x;
}

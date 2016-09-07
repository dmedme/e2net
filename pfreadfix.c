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
#include <net/pfilt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
/***************************************************************************
 * Elements that may, depending on circumstances, need uncommenting.
 *
 ****************************** ETHERNET ***********************************
 */
#ifndef NOETHER_H
#include <sys/ethernet.h>
char * ether_ntoa();
#else
struct ether_addr {
   unsigned char addr[6];
};
#include <netinet/if_fddi.h>
#include <net/if_llc.h>
/*
struct	fddi_header {
	u_char  fddi_ph[3];	 
	u_char	fddi_fc;
	u_char	fddi_dhost[6];
	u_char	fddi_shost[6];
};
*/

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
#endif
/*
 ******************************    IP    ***********************************
 */
#ifndef NOIP_H
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
struct ip { 
#ifdef _BIT_FIELDS_LTOH 
 	u_char	ip_hl:4,		/* header length  */
 		ip_v:4;			/* version  */
#else 
 	u_char	ip_v:4,			/* version  */
 		ip_hl:4;		/* header length  */
#endif 
 	u_char	ip_tos;			/* type of service  */
 	short	ip_len;			/* total length  */
 	u_short	ip_id;			/* identification  */
 	short	ip_off;			/* fragment offset field  */
#define	IP_DF 0x4000			/* dont fragment flag  */
#define	IP_MF 0x2000			/* more fragments flag  */
 	u_char	ip_ttl;			/* time to live  */
 	u_char	ip_p;			/* protocol  */
 	u_short	ip_sum;			/* checksum  */
	struct	in_addr ip_src, ip_dst;	/* source and dest address  */
}; 
/*
 ******************************   TCP    ***********************************
 */
struct tcphdr { 
 	u_short	th_sport;		/* source port  */
 	u_short	th_dport;		/* destination port  */
 	tcp_seq	th_seq;			/* sequence number  */
 	tcp_seq	th_ack;			/* acknowledgement number  */
#ifdef _BIT_FIELDS_LTOH 
 	u_int	th_x2:4,		/* (unused)  */
 		th_off:4;		/* data offset  */
#else 
 	u_int	th_off:4,		/* data offset  */
 		th_x2:4;		/* (unused)  */
#endif 
	u_char	th_flags; 
#define	TH_FIN	0x01 
#define	TH_SYN	0x02 
#define	TH_RST	0x04 
#define	TH_PUSH	0x08 
#define	TH_ACK	0x10 
#define	TH_URG	0x20 
 	u_short	th_win;			/* window  */
 	u_short	th_sum;			/* checksum  */
 	u_short	th_urp;			/* urgent pointer  */
}; 
#endif
/*
 ****************************** SUN RPC  ***********************************
 */
/* struct reply_body { */
/* 	enum reply_stat rp_stat; */
/* 	union { */
/* 		struct accepted_reply RP_ar; */
/* 		struct rejected_reply RP_dr; */
/* 	} ru; */
/* #define	rp_acpt	ru.RP_ar */
/* #define	rp_rjct	ru.RP_dr */
/* }; */
/*  * Body of a SUN rpc request call. */
/* struct call_body { */
/* 	u_long cb_rpcvers;	/* must be equal to two */
/* 	u_long cb_prog; */
/* 	u_long cb_vers; */
/* 	u_long cb_proc; */
/* 	struct opaque_auth cb_cred; */
/* 	struct opaque_auth cb_verf; /* protocol specific - provided by client */
/* }; */
/*  * The rpc message */
/* struct rpc_msg { */
/* 	u_long			rm_xid; */
/* 	enum msg_type		rm_direction; */
/* 	union { */
/* 		struct call_body RM_cmb; */
/* 		struct reply_body RM_rmb; */
/* 	} ru; */
/* #define	rm_call		ru.RM_cmb */
/* #define	rm_reply	ru.RM_rmb */
/* }; */
/* #define	acpted_rply	ru.RM_rmb.ru.RP_ar */
/* #define	rjcted_rply	ru.RM_rmb.ru.RP_dr */
/***************************************************************************
 * Functions in this file.
 */
static char * fname;
static void tvdiff( long * t1, long * m1, long * t2, long * m2,
     long * t3, long * m3);
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
/*
struct enstamp {
	u_short ens_stamplen;	/o number of bytes in this stamp struct o/
	u_short ens_flags;	/o see below				o/
	u_short	ens_count;	/o number of bytes in packet		o/
				/o	(not counting this stamp struct) o/
	u_short	ens_dropped;	/o number of packets dropped for this	o/
				/o	filter since previous packet	o/
				/o	(valid only for last-match filter) o/
	u_long	ens_ifoverflows;
				/o number of packets missed by interface o/
				/o	(cumulative)			o/
	struct timeval ens_tstamp;
				/o time packet was received (more or less) o/
};
*/
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
struct fddi_header eth;
struct llc llc;
struct ip ip;
struct tcphdr tcp;
unsigned char buf[65536];
int ret;
int i,j,k;
char * x1, *x2;



    while ( ( ch = getopt ( argc, argv, "nhvr" ) ) != EOF )
    {
        switch ( ch )
        {
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
            (void) puts("snoopfix: working snoop file reader\n\
Options:\n\
-n Number the packets\n\
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
        while ((ret = fread(&buf[0],sizeof(unsigned char),sizeof(snoop),f)) > 0)
        {
            memcpy((unsigned char *) &snoop, &buf[0],sizeof(snoop));
            l += snoop.ens_count;
            if (running)
            {
                tvdiff(&(snoop.ens_tstamp.tv_sec),&(snoop.ens_tstamp.tv_usec),&t1,&m1,&t2,&m2);
                tvdiff(&(snoop.ens_tstamp.tv_sec),&(snoop.ens_tstamp.tv_usec),&t3,&m3,&t4,&m4);
                t1 = snoop.ens_tstamp.tv_sec;
                m1 = snoop.ens_tstamp.tv_usec;
                if (t2 > 10)
                {
                    puts("************ GAP **************");
                    l = 0;
                    t3 = t1;
                    m3 = m1;
                }
            }
            else
            {
                t2 = snoop.ens_tstamp.tv_sec;
                m2 = snoop.ens_tstamp.tv_usec;
            }
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
            k = ENALIGN(snoop.ens_count);
            if ((ret = fread(&buf[0],sizeof(unsigned char), k, f)) < 1)
            {
                perror("fread() failed");
                (void) fprintf(stderr,
        "Read of %s : %d bytes failed with UNIX errno %d\n",argv[i], k, errno);
                exit(1);
            }
            memcpy((unsigned char *) &eth, &buf[0],sizeof(eth));
            memcpy((unsigned char *) &llc, &buf[sizeof(eth)],sizeof(llc));
            llc.llc_un.type_snap.ether_type = ntohs(llc.llc_un.type_snap.ether_type);
            if (number)
                printf("%d|",number++);
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
            if (running)
                printf("%d|%d.%06d|", l, t4, m4);
            if (llc.llc_un.type_snap.ether_type == ETHERTYPE_IP)
            { 
                memcpy((unsigned char *) &ip, &buf[sizeof(eth) + sizeof(llc)],sizeof(ip));
                fputs( inet_ntoa(ip.ip_src),stdout);
                putchar('|');
                fputs( inet_ntoa(ip.ip_dst),stdout);
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
                (void) gen_handle(stdout, &buf[0],&buf[snoop.ens_count], 1);
        }
    }
    exit(0);
}
static void tvdiff(t1, m1, t2, m2, t3, m3)
long * t1;
long * m1;
long * t2;
long * m2;
long * t3;
long * m3;
{
    *t3 = *t1 - *t2; 
    *m3 = *m1 - *m2; 
    if (*m3 < 0)
    {
        *m3 += 1000000;
        *t3--;
    }
    return;
}

/***************************************************************************
 * Elements that may, depending on circumstances, need uncommenting.
 */
#ifndef E2NET_H
#define E2NET_H
#include "ansi.h"
#ifdef HP7
typedef unsigned char unchar;
#endif
#ifdef LINUX
typedef unsigned char unchar;
#endif
#ifdef OSF
typedef unsigned char unchar;
#define th_off th_xoff
#endif
#include "bmmatch.h"
/****************************** ETHERNET ***********************************
 * Definitions not usually found on UNIX systems.
 */
#define ETHERTYPE_X75            0x0801
#define ETHERTYPE_X25            0x0805
#define ETHERTYPE_BANYAN         0x0BAD
#define ETHERTYPE_DECMOP1        0x6001
#define ETHERTYPE_DECMOP2        0x6002
#define ETHERTYPE_DECNET         0x6003
#define ETHERTYPE_DECLAT         0x6004
#define ETHERTYPE_DECDIAGNOSTIC  0x6005
#define ETHERTYPE_DECLANBRIDGE   0x8038
#define ETHERTYPE_DECETHENCR     0x803D
#define ETHERTYPE_APPLETALK      0x809B
#define ETHERTYPE_IBMSNA         0x80F3
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages     */
#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages	*/
#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM	*/
#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport
					 * over Ethernet
					 */
#define ETHERTYPE_NETWARE        0x8137
#define ETHERTYPE_SNMP           0x814C
#define ETHERTYPE_NS		0x0600
#define	ETHERTYPE_SPRITE	0x0500
#define ETHERTYPE_TRAIL		0x1000
#define	ETHERTYPE_MOPDL		0x6001
#define	ETHERTYPE_MOPRC		0x6002
#define	ETHERTYPE_DN		0x6003
#define	ETHERTYPE_LAT		0x6004
#define ETHERTYPE_SCA		0x6007
#define ETHERTYPE_REVARP	0x8035
#define	ETHERTYPE_LANBRIDGE	0x8038
#define	ETHERTYPE_DECDNS	0x803c
#define	ETHERTYPE_DECDTS	0x803e
#define	ETHERTYPE_VEXP		0x805b
#define	ETHERTYPE_VPROD		0x805c
#define ETHERTYPE_ATALK		0x809b
#define ETHERTYPE_AARP		0x80f3
#define ETHERTYPE_IPV6		0x86dd
#define	ETHERTYPE_LOOPBACK	0x9000

#define IEEE802_3_TYPE        0x05DC  /* If the packet type is less than this
                                       * the value is a length, not a type.
                                       */
#ifndef NOETHER_H
#include <sys/ethernet.h>
char * ether_ntoa();
#else
#define	ETHERTYPE_PUP		(0x0200)	/* PUP protocol */
#define	ETHERTYPE_IP		(0x0800)	/* IP protocol */
#define	ETHERTYPE_ARP		(0x0806)	/* Addr. resolution protocol */
#define	ETHERTYPE_MAX		(0xffff)	/* Max valid ethernet type */
struct	ether_header {
	unsigned char	ether_dhost[6];
	unsigned char	ether_shost[6];
	unsigned short	ether_type;
};
/*******************************************************************************
 * ARP frame (used to map IP to Ethernet)
 */
typedef struct _ARP_FRAME
{
unsigned char DestAddr[6];
unsigned char SrcAddr[6];
unsigned char Type[2];        /* == ARP_TYPE  (0x0806)                        */
unsigned char HWType[2];      /* Type of hardware (in this case Ethernet)     */
unsigned char ProtocolType[2];/* Type of protocol (in this case IP)           */
unsigned char HLen;           /* Length of hardware address (6 bytes)         */
unsigned char PLen;           /* Length of protocol address (4 bytes)         */
unsigned char Operation[2];   /* Operation (ARP or RARP) ?                    */
unsigned char SenderHWAddr[6];/* Sender's Ethernet address                    */
unsigned char SenderIPAddr[4];/* Sender's IP address                          */
unsigned char TargetHWAddr[6];/* Target Ethernet address                      */
unsigned char TargetIPAddr[4];/* Target IP address                            */
unsigned char Unused[32];     /* Padding to minimum legal packet length       */
}
ARP_FRAME;
#endif
/*
 ******************************    IP    ***********************************
 */
#ifndef NOIP_H
#ifdef NT4
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define inet_ntoa e2inet_ntoa
char * e2inet_ntoa();
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#ifdef AIX
#ifndef LINUX
#define _NO_BITFIELDS
#define ip_fv	ip_fvhl
typedef unsigned char unchar;
#endif
#endif
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifdef PTX
/*
 * The ANSI-C prototype macro used by <arpa/inet> is screwed up
 */
char * inet_ntoa();
#else
#include <arpa/inet.h>
#endif
#endif
#else
#define INADDR_ANY              (unsigned int)0x00000000
/* Socket types. */
#define SOCK_STREAM	1		/* stream (connection) socket	*/
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
#define SOCK_RAW	3		/* raw socket			*/
#define SOCK_RDM	4		/* reliably-delivered message	*/
#define SOCK_SEQPACKET	5		/* sequential packet socket	*/
#define SOCK_PACKET	10		/* CYGWIN specific way of	*/
					/* getting packets at the dev	*/
					/* level.  For writing rarp and	*/
					/* other similar things on the	*/
					/* user level.			*/
/* Supported address families. */
/*
 * Address families.
 */
#define AF_UNSPEC       0               /* unspecified */
#define AF_UNIX         1               /* local to host (pipes, portals) */
#define AF_INET         2               /* internetwork: UDP, TCP, etc. */
#define AF_IMPLINK      3               /* arpanet imp addresses */
#define AF_PUP          4               /* pup protocols: e.g. BSP */
#define AF_CHAOS        5               /* mit CHAOS protocols */
#define AF_NS           6               /* XEROX NS protocols */
#define AF_ISO          7               /* ISO protocols */
#define AF_OSI          AF_ISO          /* OSI is ISO */
#define AF_ECMA         8               /* european computer manufacturers */
#define AF_DATAKIT      9               /* datakit protocols */
#define AF_CCITT        10              /* CCITT protocols, X.25 etc */
#define AF_SNA          11              /* IBM SNA */
#define AF_DECnet       12              /* DECnet */
#define AF_DLI          13              /* Direct data link interface */
#define AF_LAT          14              /* LAT */
#define AF_HYLINK       15              /* NSC Hyperchannel */
#define AF_APPLETALK    16              /* AppleTalk */
#define AF_NETBIOS      17              /* NetBios-style addresses */

#define AF_MAX          18
/*
 * Protocol families, same as address families for now.
 */
#define PF_UNSPEC       AF_UNSPEC
#define PF_UNIX         AF_UNIX
#define PF_INET         AF_INET
#define PF_IMPLINK      AF_IMPLINK
#define PF_PUP          AF_PUP
#define PF_CHAOS        AF_CHAOS
#define PF_NS           AF_NS
#define PF_ISO          AF_ISO
#define PF_OSI          AF_OSI
#define PF_ECMA         AF_ECMA
#define PF_DATAKIT      AF_DATAKIT
#define PF_CCITT        AF_CCITT
#define PF_SNA          AF_SNA
#define PF_DECnet       AF_DECnet
#define PF_DLI          AF_DLI
#define PF_LAT          AF_LAT
#define PF_HYLINK       AF_HYLINK
#define PF_APPLETALK    AF_APPLETALK

#define PF_MAX          AF_MAX
struct in_addr {
    unsigned int in_addr;
};
#define s_addr in_addr
#ifdef NT4
#ifndef MINGW32
typedef unsigned char unchar;
#endif
#else
struct sockaddr {
  unsigned short	sa_family;	/* address family, AF_xxx	*/
  char			sa_data[14];	/* 14 bytes of protocol address	*/
};
#endif
/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/
struct sockaddr_in {
  short int		sin_family;	/* Address family		*/
  unsigned short int	sin_port;	/* Port number			*/
  struct in_addr	sin_addr;	/* Internet address		*/

  /* Pad to size of `struct sockaddr'. */
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			sizeof(unsigned short int) - sizeof(struct in_addr)];
};
#define sin_zero	__pad		/* for BSD UNIX comp. -FvK	*/
struct  servent {
  char    *s_name;      /* official service name */
  char    **s_aliases;  /* alias list */
  short   s_port;       /* port # */
  char    *s_proto;     /* protocol to use */
};

struct  protoent {
  char    *p_name;      /* official protocol name */
  char    **p_aliases;  /* alias list */
  short   p_proto;      /* protocol # */
};
struct  hostent {
  char    *h_name;                /* official name of host */
  char    **h_aliases;            /* alias list */
  short   h_addrtype;             /* host address type */
  short   h_length;               /* length of address */
  char    **h_addr_list;          /* list of addresses */
#define h_addr  h_addr_list[0]    /* address, for backward compat */
};
#ifdef NT4
#ifdef MINGW32
#ifndef LCC
#ifndef VCC2003
#define STDCALL     __attribute__ ((stdcall))
#else
#define STDCALL     __stdcall
#endif
#else
#define STDCALL     __stdcall
#endif
#else
#define STDCALL
#endif
#else
#define STDCALL
#endif
#ifdef MINGW32
typedef unsigned char u_char;
typedef unsigned char unchar;
typedef unsigned int u_long;
typedef unsigned short int ushort;
#ifdef LCC
struct timeval {
    unsigned int tv_sec;         /* seconds */
    unsigned int tv_usec;        /* and microseconds */
};
#endif
#ifdef VCC2003
struct timeval {
    unsigned int tv_sec;         /* seconds */
    unsigned int tv_usec;        /* and microseconds */
};
#endif
typedef unsigned int ulong;
unsigned int STDCALL inet_addr(char *);
unsigned int STDCALL htonl(unsigned int);
unsigned short STDCALL htons(unsigned int);
/*
 * The performance of this is not acceptable
char * STDCALL inet_ntoa(struct in_addr);
*/
#define inet_ntoa e2inet_ntoa
char * e2inet_ntoa();
unsigned int STDCALL ntohl(unsigned int);
unsigned short STDCALL ntohs(unsigned int);
int STDCALL alarm(unsigned int);
void STDCALL shutdown(unsigned int, unsigned int);
struct hostent * STDCALL gethostbyname(char *); 
int STDCALL getsockname(unsigned int, void *, unsigned int *);
struct protoent * STDCALL getprotobyname(char *);
int STDCALL socket(int, int, int);
int STDCALL connect(int, void *, int);
int STDCALL bind(int, void *, int);
int STDCALL listen(int, int);
int STDCALL accept(int, void *, int *);
int STDCALL fork(void);
int STDCALL select(unsigned int, void *, void *, void *, void *);
#endif
struct ip { 
#ifdef _BIT_FIELDS_LTOH 
 	unsigned char	ip_hl:4,		/* header length  */
 		ip_v:4;			/* version  */
#else 
#ifdef LCC
        unsigned char e2_dummy;
#define ip_v ((e2_dummy & 0xf0) >> 4)
#define ip_hl (e2_dummy & 0xf)
#else
 	unsigned char	ip_v:4,			/* version  */
 		ip_hl:4;		/* header length  */
#endif
#endif 
 	unsigned char	ip_tos;			/* type of service  */
 	short	ip_len;			/* total length  */
 	unsigned short	ip_id;			/* identification  */
 	short	ip_off;			/* fragment offset field  */
#define	IP_DF 0x4000			/* dont fragment flag  */
#define	IP_MF 0x2000			/* more fragments flag  */
 	unsigned char	ip_ttl;			/* time to live  */
 	unsigned char	ip_p;			/* protocol  */
 	unsigned short	ip_sum;			/* checksum  */
	struct	in_addr ip_src, ip_dst;	/* source and dest address  */
}; 
/*
 * Protocols
 */
#define	IPPROTO_IP		0		/* dummy for IP */
#define	IPPROTO_ICMP		1		/* control message protocol */
#define	IPPROTO_IGMP		2		/* group control protocol */
#define	IPPROTO_GGP		3		/* gateway^2 (deprecated) */
#define	IPPROTO_ENCAP		4		/* IP in IP encapsulation */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_EGP		8		/* exterior gateway protocol */
#define	IPPROTO_PUP		12		/* pup */
#define	IPPROTO_UDP		17		/* user datagram protocol */
#define	IPPROTO_IDP		22		/* xns idp */
#define	IPPROTO_HELLO		63		/* "hello" routing protocol */
#define	IPPROTO_ND		77		/* UNOFFICIAL net disk proto */
#define	IPPROTO_EON		80		/* ISO clnp */
#endif
#ifndef NOTCP_H
/*
 ******************************   TCP    ***********************************
 */
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else
#define _BIT_FIELDS_LTOH 
typedef unsigned int tcp_seq;
struct tcphdr { 
 	unsigned short	th_sport;		/* source port  */
 	unsigned short	th_dport;		/* destination port  */
 	tcp_seq	th_seq;			/* sequence number  */
 	tcp_seq	th_ack;			/* acknowledgement number  */
#ifdef _BIT_FIELDS_LTOH 
 	unsigned int	th_x2:4,		/* (unused)  */
 		th_off:4;		/* data offset  */
#else 
 	unsigned int	th_off:4,		/* data offset  */
 		th_x2:4;		/* (unused)  */
#endif 
	unsigned char	th_flags; 
#define	TH_FIN	0x01 
#define	TH_SYN	0x02 
#define	TH_RST	0x04 
#define	TH_PUSH	0x08 
#define	TH_ACK	0x10 
#define	TH_URG	0x20 
 	unsigned short	th_win;			/* window  */
 	unsigned short	th_sum;			/* checksum  */
 	unsigned short	th_urp;			/* urgent pointer  */
}; 
#define TCP_NODELAY 1
/*
 ******************************   UDP    ***********************************
 */
struct udphdr {
     unsigned short    uh_sport;        /* Source port       */
     unsigned short    uh_dport;        /* Destination port  */
     short    uh_ulen;                  /* UDP length        */
     unsigned short    uh_sum;          /* UDP checksum      */
};
#endif
/*
 ****************************** ICMP  **************************************
 */
#ifndef IPVERSION
#define IPVERSION 4
#endif
#ifndef NOIP_ICMP_H
#ifdef NOIP_H
#include <netinet/ip_icmp.h>
#endif
#else
#ifndef u_short
#ifdef MINGW32
typedef unsigned short u_short;
#endif
#endif
#ifndef n_short
typedef unsigned short n_short;
#endif
#ifndef n_time
typedef      u_long  n_time;            /* ms since 00:00 GMT               */
#endif
struct icmp {
        u_char  icmp_type;              /* type of message, see below */
        u_char  icmp_code;              /* type sub code */
        u_short icmp_cksum;             /* ones complement cksum of struct */
        union {
                u_char ih_pptr;                 /* ICMP_PARAMPROB */
                struct in_addr ih_gwaddr;       /* ICMP_REDIRECT */
                struct ih_idseq {
                        n_short icd_id;
                        n_short icd_seq;
                } ih_idseq;
                int ih_void;
        } icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
        union {
                struct id_ts {
                        n_time its_otime;
                        n_time its_rtime;
                        n_time its_ttime; 
                } id_ts;
                struct id_ip  {
                        struct ip idi_ip;
                        /* options and then 64 bits of data */
                } id_ip;
                u_long  id_mask;
                char    id_data[1];
        } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
}; 
#define ICMP_ECHOREPLY          0               /* echo reply */
#define ICMP_UNREACH            3               /* dest unreachable, codes: */
#define         ICMP_UNREACH_NET        0               /* bad net */
#define         ICMP_UNREACH_HOST       1               /* bad host */
#define         ICMP_UNREACH_PROTOCOL   2               /* bad protocol */
#define         ICMP_UNREACH_PORT       3               /* bad port */
#define         ICMP_UNREACH_NEEDFRAG   4               /* IP_DF caused drop */
#define         ICMP_UNREACH_SRCFAIL    5               /* src route failed */
#define ICMP_SOURCEQUENCH       4               /* packet lost, slow down */
#define ICMP_REDIRECT           5               /* shorter route, codes: */
#define         ICMP_REDIRECT_NET       0               /* for network */
#define         ICMP_REDIRECT_HOST      1               /* for host */
#define         ICMP_REDIRECT_TOSNET    2               /* for tos and net */
#define         ICMP_REDIRECT_TOSHOST   3               /* for tos and host */
#define ICMP_ECHO               8               /* echo service */
#define ICMP_TIMXCEED           11              /* time exceeded, code: */
#define         ICMP_TIMXCEED_INTRANS   0               /* ttl==0 in transit */
#define         ICMP_TIMXCEED_REASS     1               /* ttl==0 in reass */
#define ICMP_PARAMPROB          12              /* ip header bad */
#define ICMP_TSTAMP             13              /* timestamp request */
#define ICMP_TSTAMPREPLY        14              /* timestamp reply */
#define ICMP_IREQ               15              /* information request */
#define ICMP_IREQREPLY          16              /* information reply */  
#define ICMP_MASKREQ            17              /* address mask request */
#define ICMP_MASKREPLY          18              /* address mask reply */

#define ICMP_MAXTYPE            18

#define ICMP_INFOTYPE(type) \
        ((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
        (type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY || \
        (type) == ICMP_IREQ || (type) == ICMP_IREQREPLY || \
        (type) == ICMP_MASKREQ || (type) == ICMP_MASKREPLY) 
#endif
/*
 ****************************** SUN RPC  ***********************************
 */
#ifndef NOSUNRPC_H
/* #include <rpc/rpc.h> */
/* #include <rpc/rpc_msg.h> */
#else
struct reply_body { 
	enum reply_stat rp_stat; 
	union { 
		struct accepted_reply RP_ar; 
		struct rejected_reply RP_dr; 
	} ru; 
#define	rp_acpt	ru.RP_ar 
#define	rp_rjct	ru.RP_dr 
}; 
/*
 * Body of a SUN rpc request call. 
 */
struct call_body { 
	unsigned int cb_rpcvers;	/* must be equal to two  */
	unsigned int cb_prog; 
	unsigned int cb_vers; 
	unsigned int cb_proc; 
	struct opaque_auth cb_cred; 
	struct opaque_auth cb_verf; /* protocol specific - provided by client  */
}; 
/*
 * The rpc message 
 */
struct rpc_msg { 
	unsigned int			rm_xid; 
	enum msg_type		rm_direction; 
	union { 
		struct call_body RM_cmb; 
		struct reply_body RM_rmb; 
	} ru; 
#define	rm_call		ru.RM_cmb 
#define	rm_reply	ru.RM_rmb 
}; 
#define	acpted_rply	ru.RM_rmb.ru.RP_ar 
#define	rjcted_rply	ru.RM_rmb.ru.RP_dr 
#endif
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
    unsigned char  dsap;                   /* dsap field */
    unsigned char  ssap;                   /* ssap field */
    unsigned char  control;                /* control field */
    unsigned char  proto_id[3];            /* Protocol id field/org code */
    unsigned short int  etype;             /* Ether type field */
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
struct	fddi_header {
	unsigned char  fddi_ph[3];	 
	unsigned char	fddi_fc;
	unsigned char	fddi_dhost[6];
	unsigned char	fddi_shost[6];
};
#ifdef SOL10
void tvdiff ANSIARGS((long * t1, long * m1, long * t2,
                      long * m2, long * t3, long * m3));
void tvdiff32 ANSIARGS((int * t1, int * m1, int * t2,
                      int * m2, int * t3, int * m3));
void tvadd ANSIARGS((long * t1, long * m1, long * t2,
                      long * m2, long * t3, long * m3));
void tvadd32 ANSIARGS((int * t1, int * m1, int * t2,
                      int * m2, int * t3, int * m3));
#else
void tvdiff ANSIARGS((int * t1, int * m1, int * t2,
                      int * m2, int * t3, int * m3));
#define tvdiff32 tvdiff
#define tvadd32 tvadd
#endif
/*
 * Session Tracking
 */
#define MAX_SESS 512
#define E2_UNKNOWN 0
#define E2_TCP 1
#define E2_UDP 2
#define E2_ARP 3
#define E2_REVARP 4
#define E2_NOVELL 5
#define E2_LLC 6
#define E2_PUP 7
#define E2_X75 8
#define E2_X25 9
#define E2_BANYAN 10
#define E2_DECMOP1 11
#define E2_DECMOP2 12
#define E2_DECNET  13
#define E2_DECLAT  14
#define E2_DECDIAGNOSTIC 15
#define E2_DECLANBRIDGE 16
#define E2_DECETHENCR 17
#define E2_APPLETALK 18
#define E2_IBMSNA  19
#define E2_SNMP 20
/*
 * ICMP must be the highest, because we put the other unrecognised protocols
 * above it
 */
#define E2_ICMP 21
#ifdef AIX
#ifndef SD_SEND
#define SD_SEND 1
#endif
#endif
/************************************************************************
 * Structure for tracking individual packets
 */
struct pack_con {
    int pack_no;          /* Ordinal of packet in stream               */
    int pack_len;         /* Length of captured packet                 */
    int orig_len;         /* Pre-truncation length                     */
    struct timeval timestamp;  /* Time when                            */
    struct timeval cs_tim[2];  /* Time on client/server                */
    struct timeval nt_tim[2];  /* Time on network                      */
    int ref_cnt;          /* Number of references (to control free())  */
    unsigned int seq;     /* TCP Seq (if applicable)                   */
    unsigned int ack;     /* TCP Ack (if applicable)                   */
    char * pack_ptr;      /* The packet itself (the next address)      */
    char * tcp_ptr;       /* TCP Data (if applicable)                  */
    unsigned short tcp_len;    /* TCP Length (if applicable)           */
    unsigned short win;   /* TCP Win (if applicable)                   */
    unsigned char tcp_flags;   /* TCP flags (if applicable)            */
};
/***********************************************************************
 * Structure for managing remembered packets. Holds a circular buffer of
 * non-descript pointers. Handles wrap by discarding the element encountered.
 */
struct circbuf {
    int buf_cnt;
    volatile char ** head;
    volatile char ** tail;
    char ** base;
    char ** top;
    void (*get_rid)();
};
struct circbuf * circbuf_cre ANSIARGS((int nelems, void (*get_rid)()));
void circbuf_des ANSIARGS((struct circbuf * buf));
int circbuf_add ANSIARGS(( struct circbuf * buf, char* x));
int circbuf_take ANSIARGS((struct circbuf * buf, char ** x));
int circbuf_read ANSIARGS((struct circbuf * buf, char ** x, int ind));
/************************************************************************
 * Structure for tracking application message fragments
 */
struct frame_con {
/*
 * Session Identifiers - these are counted binary values, and are hashed
 * The hash function produces the same number regardless of the direction
 * of the packet, so we only need to store one hash entry for each session.
 */
int prot;                     /* The protocol - as per the above define    */
unsigned char phys_from[10];  /* Length plus address (eg. Ethernet)        */
unsigned char phys_to[10];    /* Length plus address (eg. Ethernet)        */
unsigned char net_from[10];   /* Length plus address (eg. IP Host)         */
unsigned char net_to[10];     /* Length plus address (eg. IP Host)         */
unsigned char port_from[10];  /* Length plus address (eg. IP port)         */
unsigned char port_to[10];    /* Length plus address (eg. IP port)         */
char label[40];
char * long_label;
int reverse_sense;            /* Flag which is client, which server.       */
/*
 * Remembered packets
 */
struct circbuf * pack_ring;
/*
 * Details of the current packet.
 */
int pack_no;
struct timeval this_time;          /* The current packet time           */
int pack_len;
int tcp_flags;                     /* Avoid stray application sessions  */
/*
 * TCP-specific information.
 */
unsigned int seq[2];              /* TCP protocol handling       */
unsigned int ack[2];              /* TCP protocol handling       */
unsigned short win[2];             /* TCP protocol handling       */
int fin_cnt;                       /* Number of TCP FIN's seen    */
int last_out;                      /* The direction of the last message */
int cnt[2];                        /* Numbers of packets used     */
int len[2];                        /* Network Length of packets seen    */
int retrans[2];                   /* Count of retransmissions          */
struct timeval last_t[2];          /* Last time stamp             */
struct timeval cs_tim[2];          /* Time on client/server       */
struct timeval nt_tim[2];          /* Time on network             */
/*
 * Application protocol details
 */
int last_app_out;                  /* For the last APPLICATION message  */
int fix_size;                      /* Header Fixed Length               */
int fix_mult;                      /* Whether the header counts         */
int off_flag;                      /* Offset to length                  */
int len_len;                       /* Length of length                  */
int big_little;                    /* Big (0)/Little (1) Endian flag    */
char reserve[2][32];               /* In case we haven't read the fixed */
int res_len[2];                    /* length yet                        */
int left[2];                       /* The number of bytes held          */
unsigned char * hold_buf[2];       /* Where the messages are            */
unsigned char * top[2];            /* Pointers to end of messages       */
struct timeval ini_t[2];           /* First time stamp                  */
int gap;                           /* Size of gap for timing purposes   */
struct timeval tran_start;         /* Gap begin time                    */
int tran_cnt[2];                   /* Numbers of packets used           */
int tran_len[2];                   /* Application Length of packets used */
struct timeval tran_cs_tim[2];     /* Used to work out client/server time */
struct timeval tran_nt_tim[2];     /* Used to work out time on network    */
struct timeval up_to;              /* Last time apportioned             */
void (*do_mess)();                 /* Application message function      */
void (*cleanup)();                 /* Application cleanup function      */
FILE * ofp;                        /* Where to dump the output to       */
struct frame_con * prev_frame_con;
struct frame_con * next_frame_con;
char * app_ptr;                    /* Pointer to application-private data */
int event_id;                      /* Current script event, if applicable */
int corrupt_flag;                  /* Flag to prevent spurious response logs */
};
/*
 * Functions in e2net.c
 */
int uhash_key();
int ucomp_key();
struct frame_con * match_true();
struct frame_con * match_add();
int hcntstrcmp();
struct pack_con * pack_save();
void pack_drop();
void frame_dump();
void ip_dir_print();
void circbuf_dump();
void accum_response();
void output_response();
void get_event_id();
void pack_head_print();
#endif

/*
 * Scan a snoop file and pull out the OpenLink SQL statements. 
 */
#include <sys/types.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <rpc/rpc.h>
#include <rpc/rpc_msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#ifdef BIGENDIAN
#define rl(x) (x)
#define rh(x) (x)
#else
static long rl(x)
long x;
{
union lb { long l; char b[4]; } li,lo;
   li.l = x;
   lo.b[0] = li.b[3];
   lo.b[1] = li.b[2];
   lo.b[2] = li.b[1];
   lo.b[3] = li.b[0];
   return lo.l;
}
static short int rh(x)
short int x;
{
union sb { short int s; char b[2]; } si,so;
   si.s = x;
   so.b[0] = si.b[1];
   so.b[1] = si.b[0];
   return so.s;
}
#endif
main(argc,argv)
int argc;
char ** argv;
{
int tcp_pack_no = 1;         /* Cross Reference to the Packet File */
time_t last_time = 0;
time_t last_event = 0;
int more_flag = 0;
int event=0xa1;
struct snoop_header {
    long len;
    long unknown[3];
    long secs_since_1970;
    long musecs;
} snoop;
struct ether_header eth;
struct ip ip;
struct tcphdr tcp;
struct rpc_msg rpc;
XDR xdr;
unsigned char buf[65536];
int ret;
int i,j,k;

/*
struct	ether_header {
	struct	ether_addr	ether_dhost;
	struct	ether_addr	ether_shost;
	u_short	ether_type;
};
*/

/* #define	ETHERTYPE_PUP		(0x0200)	/* PUP protocol */
/* #define	ETHERTYPE_IP		(0x0800)	/* IP protocol */
/* #define	ETHERTYPE_ARP		(0x0806)	/* Addr. resolution protocol */
/* #define	ETHERTYPE_REVARP	(0x8035)	/* Reverse ARP */
/* #define	ETHERTYPE_MAX		(0xffff)	/* Max valid ethernet type */
/* struct ip { */
/* #ifdef _BIT_FIELDS_LTOH */
/* 	u_char	ip_hl:4,		/* header length */
/* 		ip_v:4;			/* version */
/* #else */
/* 	u_char	ip_v:4,			/* version */
/* 		ip_hl:4;		/* header length */
/* #endif */
/* 	u_char	ip_tos;			/* type of service */
/* 	short	ip_len;			/* total length */
/* 	u_short	ip_id;			/* identification */
/* 	short	ip_off;			/* fragment offset field */
/* #define	IP_DF 0x4000			/* dont fragment flag */
/* #define	IP_MF 0x2000			/* more fragments flag */
/* 	u_char	ip_ttl;			/* time to live */
/* 	u_char	ip_p;			/* protocol */
/* 	u_short	ip_sum;			/* checksum */
/* 	struct	in_addr ip_src, ip_dst;	/* source and dest address */
/* }; */
/* struct tcphdr { */
/* 	u_short	th_sport;		/* source port */
/* 	u_short	th_dport;		/* destination port */
/* 	tcp_seq	th_seq;			/* sequence number */
/* 	tcp_seq	th_ack;			/* acknowledgement number */
/* #ifdef _BIT_FIELDS_LTOH */
/* 	u_int	th_x2:4,		/* (unused) */
/* 		th_off:4;		/* data offset */
/* #else */
/* 	u_int	th_off:4,		/* data offset */
/* 		th_x2:4;		/* (unused) */
/* #endif */
/* 	u_char	th_flags; */
/* #define	TH_FIN	0x01 */
/* #define	TH_SYN	0x02 */
/* #define	TH_RST	0x04 */
/* #define	TH_PUSH	0x08 */
/* #define	TH_ACK	0x10 */
/* #define	TH_URG	0x20 */
/* 	u_short	th_win;			/* window */
/* 	u_short	th_sum;			/* checksum */
/* 	u_short	th_urp;			/* urgent pointer */
/* }; */
/* struct reply_body { */
/* 	enum reply_stat rp_stat; */
/* 	union { */
/* 		struct accepted_reply RP_ar; */
/* 		struct rejected_reply RP_dr; */
/* 	} ru; */
/* #define	rp_acpt	ru.RP_ar */
/* #define	rp_rjct	ru.RP_dr */
/* }; */
/*  * Body of an rpc request call. */
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
    
    for (i = 1; i < argc; i++)
    {
    FILE *f;
        if ((f = fopen(argv[i],"r")) == (FILE *)NULL)
        {
            perror("fopen() failed");
            (void) fprintf(stderr,
                  "Open of %s failed with UNIX errno %d\n",argv[i],errno);
            exit(1);
        }
        (void) fseek(f,16,0);   /* Skip the snoop header */
        while ((ret = fread(&buf[0],sizeof(unsigned char),sizeof(snoop),f)) > 0)
        {
            memcpy((unsigned char *) &snoop, &buf[0],sizeof(snoop));
            snoop.len = rl(snoop.len);
            snoop.secs_since_1970 = rl(snoop.secs_since_1970);
            snoop.musecs = rl(snoop.musecs);
            if (snoop.len > 65536)
            {
                (void) fprintf(stderr,
              "Length is %d; Cannot handle packets of more than 65536 bytes\n");
                exit(1);
            }
            j = (snoop.len % 4);
            if (j)
                k = snoop.len + (4 - j);
            else
                k = snoop.len;
            if ((ret = fread(&buf[0],sizeof(unsigned char),k,f)) < 1)
            {
                perror("fread() failed");
                (void) fprintf(stderr,
              "Read of %s failed with UNIX errno %d\n",argv[i],errno);
                exit(1);
            }
            memcpy((unsigned char *) &eth, &buf[0],sizeof(eth));
            eth.ether_type = rh(eth.ether_type);
            tcp_pack_no++;
            if (eth.ether_type == ETHERTYPE_IP)
            { 
                memcpy((unsigned char *) &ip, &buf[sizeof(eth)],sizeof(ip));
                if (ip.ip_p == IPPROTO_TCP)
                {
                    int ip_len;
                    int tcp_len;
                    int rcp_off;
                    memcpy((unsigned char *) &tcp,
                           &buf[sizeof(eth) + sizeof(ip)],
                           sizeof(tcp));
                    ip_len = 256*buf[sizeof(eth) + ((char *) (&ip.ip_len) -
                             ((char *) &ip))]
                           + buf[sizeof(eth) + ((char *) (&ip.ip_len) -
                             ((char *) &ip)) + 1];
                    tcp_len = ip_len - sizeof(ip) - tcp.th_off*4;
                    if (tcp_len > 0)
                    {
                        if (more_flag)
                        {
                            more_flag = 0;
                            printf("%*.*s\n/\n",
                                       tcp_len,tcp_len,
                                       &buf[54]);
                            continue;
                        }
                        rcp_off = sizeof(eth)+sizeof(ip)+(tcp.th_off + 1)*4;
                        if (tcp_len > 52 &&
                             buf[rcp_off -4] == 0x80 &&
                             buf[rcp_off -3] == 0x00)
                        { 
/*
 * This is a SUN RPC packet.  Only go for the execute SQL procedure call
 * packets.
 */ 
                            xdrmem_create(&xdr, &buf[rcp_off],
                                          sizeof(buf) - rcp_off,
                               XDR_DECODE);
                            xdr_callmsg(&xdr, &rpc);
                            xdr_destroy(&xdr);
/*
 *                      memcpy((unsigned char *) &rpc, &buf[rcp_off],
 *                               sizeof(rpc));
 *                      rpc.rm_call.cb_prog = rl(rpc.rm_call.cb_prog);
 *                      rpc.rm_call.cb_vers = rl(rpc.rm_call.cb_vers);
 *                      rpc.rm_call.cb_proc = rl(rpc.rm_call.cb_proc);
 */
                            if (rpc.rm_direction == CALL &&
                                rpc.rm_call.cb_prog == 300272 &&
                                rpc.rm_call.cb_vers == 2 &&
                                rpc.rm_call.cb_proc == 12)
                            {
                               char * x = ctime(&(snoop.secs_since_1970));
                               printf(
                                "\\C:%d:%d: %2.2s %3.3s %4.4s %8.8s.%06.6d\\\n",
                                       tcp_pack_no, tcp_len,
                                       (x + 8), (x + 4), (x + 20), (x + 11),
                                       snoop.musecs);
#ifdef AUTO_EVENTS
                                if ((snoop.secs_since_1970 - last_time) > 3)
                                {
                                    if (last_time != 0)
                                    {
                                        printf("\\T%X:\\\n",event++);
                                        printf("\\W%d\\\n",
                                           (snoop.secs_since_1970 - 
                                               last_time));
                                    }
                                    printf( "\\S%X:120:Event %X\\\n",
                                               event,event);
                                }
#endif
                                last_time = snoop.secs_since_1970;
                                if ((((256 * buf[rcp_off - 2]) +
                                    buf[rcp_off - 1]) != (tcp_len - 4)))
                                {
                                    more_flag = 1;
                                    printf("%*.*s",
                                       tcp_len - 52,tcp_len - 52,
                                       &buf[rcp_off + 48]);
                                }
                                else
                                    printf("%*.*s\n/\n",
                                       tcp_len - 52,tcp_len - 52,
                                       &buf[rcp_off + 48]);
                            }
                        }
                    }
                }
            }
        }
        if (last_time != 0)
            printf("\\T%X:\\\n",event++);
    }
    exit(0);
}

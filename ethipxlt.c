/*
 * Scan a snoop file and pull out the Ethernet and IP elements.
 */
#include <sys/types.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <rpc/rpc.h>
#include <rpc/rpc_msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
char * strdup();
static char * fname;
static char * ename;
static char * iname;
main(argc,argv)
int argc;
char ** argv;
{
int eth_pack_no = 0;         /* Cross Reference to the Packet File */
time_t last_time = 0;
time_t last_event = 0;
int more_flag = 0;
int event=0xa1;
struct snoop_header {
    long len;
    long saved_len;
    long unknown[2];
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
    
FILE *f, *fe, *fi;
    fname = argv[1];
    ename = argv[2];
    iname = argv[3];
    if ((f = fopen(fname,"r")) == (FILE *)NULL)
    {
        perror("fopen() failed");
        (void) fprintf(stderr,
              "Open of %s failed with UNIX errno %d\n",argv[1],errno);
        exit(1);
    }
    (void) fseek(f,16,0);   /* Skip the snoop header */
    while ((ret = fread(&buf[0],sizeof(unsigned char),sizeof(snoop),f)) > 0)
    {
        eth_pack_no++;
        memcpy((unsigned char *) &snoop, &buf[0],sizeof(snoop));
        snoop.len = ntohl(snoop.len);
        snoop.saved_len = ntohl(snoop.saved_len);
        snoop.secs_since_1970 = ntohl(snoop.secs_since_1970);
        snoop.musecs = ntohl(snoop.musecs);
        if (snoop.len > 65536)
        {
            (void) fprintf(stderr,
          "Length is %d; Cannot handle packets of more than 65536 bytes\n");
            exit(1);
        }
        j = (snoop.saved_len % 4);
        if (j)
            k = snoop.saved_len + (4 - j);
        else
            k = snoop.saved_len;
        if ((ret = fread(&buf[0],sizeof(unsigned char),k,f)) < 1)
        {
            perror("fread() failed");
            (void) fprintf(stderr,
          "Read of %s failed with UNIX errno %d\n",argv[i],errno);
            exit(1);
        }
        memcpy((unsigned char *) &eth, &buf[0],sizeof(eth));
        eth.ether_type = ntohs(eth.ether_type);
        if (eth.ether_type == ETHERTYPE_IP)
        { 
        char * x1;
        char * x2;
        memcpy((unsigned char *) &ip, &buf[sizeof(eth)],sizeof(ip));
            x1 = strdup(inet_ntoa(ip.ip_src));
            x2 = strdup(inet_ntoa(ip.ip_dst));
            printf("%s %s\n",ether_ntoa(&(eth.ether_shost)), x1);
            printf("%s %s\n",ether_ntoa(&(eth.ether_dhost)), x2);
            free(x1);
            free(x2);
        }
    }
    (void) fclose(f);
    exit(0);
}

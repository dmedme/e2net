/*
 * Novell Message format information
 *
 * Novell IPX Message format.
 */
typedef struct ipx_hdr {
   unsigned short int ipx_checksum; /* Always 0xffff */
   unsigned short int ipx_len;      /* IPX Header + Data */
   unsigned char ipx_tc;            /* Contains the number of hops; < 16 */
   unsigned char ipx_pt;            /* Packet type; 0,4 IPX; 5 SPX; 17 NCP */
   unsigned char ipx_dnodea[6];     /* Broadcast is 0xffffffffffff       */
   unsigned int ipx_dneta;     /* Local is 0x00000000               */
   unsigned short int ipx_dsocka;   /* Socket 0x0451=NCP 0x452=SAP 0x0453=RIP*/
   unsigned char ipx_snodea[6];     /* Never 0xffffffffffff              */
   unsigned int ipx_sneta;     /* Source network address            */
   unsigned short int ipx_ssocka;   /* Source socket; clients 0x4000-0x8000 */
} ipx_hdr;
#define IPX_LEN 30
/*
 * Message Types
 */
#define IPX_PACK_IPX0 0x0
/*
 * Speculative
 */
#define IPX_PACK_RIP 0x1
#define IPX_PACK_IPX4 0x4
#define IPX_PACK_SPX 0x5
#define IPX_PACK_NCP 0x11
#define IPX_SOCK_NCP 0x0451
#define IPX_SOCK_SAP 0x0452
#define IPX_SOCK_RIP 0x0453
/*
 * Novell SAP Details
 *
 * Service Types
 */
#define SAP_STF 0x4
#define SAP_STJ 0x5
#define SAP_STP 0x7
/*
 * SAP Query
 */
typedef struct sap_sqy {
   unsigned short int sqy_pt;
   unsigned short int sqy_st;
} sap_sqy;
#define SAP_SQY_PTN 0x3
/*
 * SAP Response
 */
typedef struct sap_srp {
   unsigned short int srp_pt;
   struct server {
       unsigned short int srv_st;
       unsigned char srv_name[48];
       unsigned int srv_neta;
       unsigned char srv_nodea[6];
       unsigned short int srv_socka;
       unsigned short int srv_hop;
   } server[7];
} sap_srp;
#define SAP_SRV_LEN 64
#define SAP_SRP_PTG 0x2
#define SAP_SRP_PTN 0x4
/*
 * RIP Request and Response Packets
 */
typedef struct rip {
   unsigned short int rip_pt;
   struct network {
       unsigned int rip_neta;
       unsigned short int rip_hop; /* 0-15 hops;16 unreachable;0xffff request */
       unsigned short int rip_ticks;
   } network[50];
} rip;
#define RIP_NET_LEN 8
#define RIP_REQ_PT 0x1
#define RIP_RSP_PT 0x2
/*
 * SPX Packet Format
 */
typedef struct spx_hdr {
    unsigned char spx_cc;             /* Connection Control */
    unsigned char spx_dt;             /* Datastream Type    */
    unsigned short int spx_scid;      /* Source Connection ID */
    unsigned short int spx_dcid;      /* Destination Connection ID
                                         (0xffff initially) */
    unsigned short int spx_seq;       /* Sequence Number; incremented after
                                         successful acknowledgement    */
    unsigned short int spx_ack;       /* Acknowledgement Number ; next SPX
                                         sequence expected  */
    unsigned short int spx_allcn;     /* Number of free buffers */
} spx_hdr;
#define SPX_LEN 12
/*
 * SPX Connection Control
 */
#define SPX_CC_EOM 0x10
#define SPX_CC_ATTN 0x20
#define SPX_CC_ACKR 0x40
#define SPX_CC_SYS 0x80
#define SPX_DT_EOC 0xFE
#define SPX_DT_EOCA 0xFF
/*
 * NCP Packet Format
 *
 * NCP Request
 */
typedef struct ncp_req {
    unsigned short int req_rt;        /* Request type */
    unsigned char req_seq;            /* Sequence     */
    unsigned char req_cnl;            /* Connection Number Low */
    unsigned char req_tn;             /* Task Number  */
    unsigned char req_cnh;            /* Connection Number High; always 0x00 */
} ncp_req;
/*
 * NCP Request Types
 */
#define NCP_REQ_CSC 0x1111
#define NCP_REQ_GSR 0x2222
#define NCP_REQ_TSC 0x5555
#define NCP_REQ_BMP 0x7777

/*
 * NCP Reply
 */
typedef struct ncp_rep {
    unsigned short int rep_rt;        /* Reply type */
    unsigned char rep_seq;            /* Sequence     */
    unsigned char rep_cnl;            /* Connection Number Low */
    unsigned char rep_tn;             /* Task Number  */
    unsigned char rep_cnh;            /* Connection Number High; always 0x00 */
    unsigned char rep_cc;             /* Completion Code; 0 OK, 1 not OK */
    unsigned char rep_cs;             /* Connection Status               */
} ncp_rep;
/*
 * NCP Reply Types
 */
#define NCP_REP_SR 0x3333
#define NCP_REP_BMP 0x7777
#define NCP_REP_RBP 0x9999
/*
 * BMP Header
 */
typedef struct ncp_bmp {
    unsigned short int bmp_rt;        /* Request type              */
    unsigned char bmp_flags;          /* Flags                     */
    unsigned char bmp_st;             /* Stream Type               */
    unsigned int bmp_scid;       /* Source Connection ID      */
    unsigned int bmp_dcid;       /* Destination Connection ID */
    unsigned int bmp_pseq;       /* Packet Sequence Number    */
    unsigned int bmp_sdt;        /* Send Delay Time           */
    unsigned short int bmp_bseq;      /* Burst Sequence Number     */
    unsigned short int bmp_aseq;      /* Ack. Sequence Number      */
    unsigned int bmp_tbl;        /* Total Burst Length        */
    unsigned int bmp_boff;       /* Burst Offset              */
    unsigned short int bmp_blen;      /* Burst Length              */
    unsigned short int bmp_flen;      /* Fragment List Entries     */
    unsigned int bmp_fun;        /* Function                  */
    unsigned int bmp_fh;         /* File Handle               */
    unsigned int bmp_soff;       /* Starting Offset           */
    unsigned int bmp_btw;        /* Bytes to Write            */
} ncp_bmp;
#define BMP_LEN 52
/*
 * Function to dump them out
 */
unsigned char * ipx_dump( /* FILE * fp, unsigned char *p, unsigned char * top, int write_flag */ );

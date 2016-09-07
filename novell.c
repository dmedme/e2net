/*
 * novell.c - recognise Novell packets
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems Limited 1997";
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#include <unistd.h>
#endif
#endif
#include "ansi.h"
#include "e2net.h"
#include "novell.h"
/*
 * Functions declared in this file
 */
static void host_dump( /* FILE *fp, unsigned char *x */ );
static void sock_dump( /* FILE *fp, unsigned short int x */ );
static void st_dump( /* FILE *fp, unsigned short int x */ );
static void sap_pt_dump( /* FILE *fp, unsigned short int x */ );
static void sap_dump( /* FILE *fp, unsigned char * p, unsigned char * top, int write_flag */ );
static void rip_pt_dump( /* FILE *fp, unsigned short int x */ );
static void rip_dump( /* FILE *fp, unsigned char * p, unsigned char * top, int write_flag */ );
static void spx_cc_dump( /* FILE *fp, unsigned char x */ );
static void spx_dt_dump( /* FILE *fp, unsigned char x */ );
static void spx_dump( /* FILE *fp, unsigned char * p, unsigned char * top, int write_flag */ );
static void ncp_rt_dump( /* FILE *fp, unsigned short int x */ );
static void ncp_dump( /* FILE *fp, unsigned char * p, unsigned char * top, int write_flag */ );
static void bmp_dump( /* FILE *fp, unsigned char * p, unsigned char * top, int write_flag */ );
/*
 * Novell Message format information
 *
 * Novell IPX Message format.
 */
static void host_dump(fp, x)
FILE * fp;
unsigned char * x;
{
    fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x|",
                 (unsigned int) *(x),
                 (unsigned int) *((x) + 1),
                 (unsigned int) *((x) + 2),
                 (unsigned int) *((x) + 3),
                 (unsigned int) *((x) + 4),
                 (unsigned int) *((x) + 5));
    return;
}
static void sock_dump(fp, x)
FILE * fp;
unsigned short int x;
{
    switch(x)
    {
    case IPX_SOCK_NCP:
        fputs("IPX_SOCK_NCP|", fp);
        break;
    case IPX_SOCK_SAP:
        fputs("IPX_SOCK_SAP|", fp);
        break;
    case IPX_SOCK_RIP:
        fputs("IPX_SOCK_RIP|", fp);
        break;
    default:
        if (x >= 0x4000 && x <= 0x8000)
            fputs("CLIENT:", fp);
        else
            fputs("UNKNOWN:", fp);
        fprintf(fp, "%x|",x);
        break;
    }
    return;
}
unsigned char * ipx_dump(fp, p, top, write_flag)
FILE * fp;
unsigned char * p;
unsigned char * top;
int write_flag;
{
ipx_hdr ipx;
    memcpy((char *) &ipx, p, IPX_LEN);
    ipx.ipx_len = ntohs(ipx.ipx_len);
    ipx.ipx_dneta = ntohl(ipx.ipx_dneta);
    ipx.ipx_dsocka = ntohs(ipx.ipx_dsocka);
    ipx.ipx_sneta = ntohl(ipx.ipx_sneta);
    ipx.ipx_ssocka = ntohs(ipx.ipx_ssocka);
    if (top > p + ipx.ipx_len)
        top = p + ipx.ipx_len;
    p += IPX_LEN;
/*
 * Output type, length, Source Network, Host, Socket; Destination Network,
 * Host, Socket;
 * Length
 */
    switch (ipx.ipx_pt)
    {
    case IPX_PACK_IPX0:
        fputs("IPX0|", fp);
        break; 
    case IPX_PACK_RIP:
        fputs("RIP|", fp);
        break; 
    case IPX_PACK_IPX4:
        fputs("IPX4|", fp);
        break; 
    case IPX_PACK_SPX:
        fputs("SPX|", fp);
        break; 
    case IPX_PACK_NCP:
        fputs("NCP|", fp);
        break; 
    default:
        fputs("LLC|\n", fp);
        return;
        break;
    }
    fprintf(fp,  "%x|", ipx.ipx_sneta);
    host_dump(fp, &(ipx.ipx_snodea[0]));
    sock_dump(fp, ipx.ipx_ssocka);
    fprintf(fp,  "%x|", ipx.ipx_dneta);
    host_dump(fp, &(ipx.ipx_dnodea[0]));
    sock_dump(fp, ipx.ipx_dsocka);
    fprintf(fp, "%d|", ipx.ipx_len); 
    switch (ipx.ipx_pt)
    {
    case IPX_PACK_SPX:
        spx_dump(fp, p, top, write_flag);
        break; 
    case IPX_PACK_NCP:
        ncp_dump(fp, p, top, write_flag);
        break; 
    case IPX_PACK_IPX0:
    case IPX_PACK_IPX4:
    default:
        if (ipx.ipx_ssocka == IPX_SOCK_NCP
         || ipx.ipx_dsocka == IPX_SOCK_NCP)
            ncp_dump(fp, p, top, write_flag);
        else
        if (ipx.ipx_ssocka == IPX_SOCK_SAP
         || ipx.ipx_dsocka == IPX_SOCK_SAP)
            sap_dump(fp, p, top, write_flag);
        else
        if (ipx.ipx_ssocka == IPX_SOCK_RIP
         || ipx.ipx_dsocka == IPX_SOCK_RIP)
            rip_dump(fp, p, top, write_flag);
        else
            gen_handle(fp, p, top, write_flag);
        break;
    }
    fputc('\n', fp);
    return top;
}
/*
 * Novell SAP Details
 *
 * Service Types
 */
static void st_dump(fp, x)
FILE * fp;
unsigned short int x;
{
    switch (x)
    {
    case SAP_STF:
        fputs("SAP_STF|", fp);
        break;
    case SAP_STJ:
        fputs("SAP_STJ|", fp);
        break;
    case SAP_STP:
        fputs("SAP_STP|", fp);
        break;
    default:
        fprintf(fp, "UNKNOWN:%d|", x);
        break;
    }
    return;
}
/*
 * SAP Packet Types
 */
static void sap_pt_dump(fp, x)
FILE *fp;
unsigned short int x;
{
    switch (x)
    {
    case SAP_SQY_PTN:
        fputs("SAP_SQY_PTN|", fp);
        break;
    case SAP_SRP_PTN:
        fputs("SAP_SRP_PTN|", fp);
        break;
    case SAP_SRP_PTG:
        fputs("SAP_SRP_PTG|", fp);
        break;
    default:
        fprintf(fp, "UNKNOWN:%d|", x);
        break;
    }
    return;
}
/*
 * SAP Query and Response
 */
static void sap_dump(fp, p,top,write_flag)
FILE *fp;
unsigned char * p;
unsigned char * top;
int write_flag;
{
sap_sqy sqy;
sap_srp srp;
struct server s;
int i;
    memcpy((char *) &sqy, p, sizeof(sqy));
    sqy.sqy_pt = ntohs(sqy.sqy_pt);
    sqy.sqy_st = ntohs(sqy.sqy_st);
    sap_pt_dump(fp, sqy.sqy_pt);
    if (sqy.sqy_pt ==  SAP_SQY_PTN)
        st_dump(fp, sqy.sqy_st);
    else
    if (sqy.sqy_pt ==  SAP_SRP_PTN
     || sqy.sqy_pt ==  SAP_SRP_PTG)
    {
        for (i = 7, p += sizeof(srp.srp_pt);
              (p <= (top - SAP_SRV_LEN)) && i > 0;
                   i--)
        {
            memcpy((char *) &(s.srv_st), p, sizeof(s.srv_st)); 
            p += sizeof(s.srv_st);
            s.srv_st = ntohs(s.srv_st);
            st_dump(fp, s.srv_st);
            memcpy((char *) &(s.srv_name[0]), p, sizeof(s.srv_name)); 
            p += sizeof(s.srv_name);
            fputs((char *) &(s.srv_name[0]), fp);
            fputc('|', fp);
            memcpy((char *) &(s.srv_neta), p, sizeof(s.srv_neta)); 
            p += sizeof(s.srv_neta);
            s.srv_neta = ntohl(s.srv_neta);
            fprintf(fp,  "%x|", s.srv_neta);
            memcpy((char *) &(s.srv_nodea[0]), p, sizeof(s.srv_nodea)); 
            p += sizeof(s.srv_nodea);
            host_dump(fp, &(s.srv_nodea[0]));
            memcpy((char *) &(s.srv_socka), p, sizeof(s.srv_socka)); 
            p += sizeof(s.srv_socka);
            s.srv_socka = ntohs(s.srv_socka);
            sock_dump(fp, s.srv_socka);
            memcpy((char *) &(s.srv_hop), p, sizeof(s.srv_hop)); 
            p += sizeof(s.srv_hop);
            s.srv_hop = ntohs(s.srv_hop);
            fprintf(fp,  "%d|", s.srv_hop);
        }
    }
    else
        gen_handle(fp, p, top, write_flag);
    return;
}
/*
 * RIP Packet Types
 */
static void rip_pt_dump(fp, x)
FILE * fp;
unsigned short int x;
{
    switch (x)
    {
    case RIP_REQ_PT:
        fputs("RIP_REQ_PT|", fp);
        break;
    case RIP_RSP_PT:
        fputs("RIP_RSP_PT|", fp);
        break;
    default:
        fprintf(fp, "UNKNOWN:%d|", x);
        break;
    }
    return;
}
/*
 * RIP Query and Response
 */
static void rip_dump(fp, p,top,write_flag)
FILE * fp;
unsigned char * p;
unsigned char * top;
int write_flag;
{
rip rip;
struct network n;
int i;
    memcpy((char *) &rip, p, sizeof(rip));
    rip.rip_pt = ntohs(rip.rip_pt);
    rip_pt_dump(fp, rip.rip_pt);
    if (rip.rip_pt == RIP_REQ_PT
     || rip.rip_pt == RIP_RSP_PT)
    {
        for (i = 50, p += sizeof(rip.rip_pt);
              (p <= (top - RIP_NET_LEN)) && i > 0;
                   p += RIP_NET_LEN, i--)
        {
            memcpy((char *) &n, p, RIP_NET_LEN);
            n.rip_neta = ntohl(n.rip_neta);
            fprintf(fp,  "%x|", n.rip_neta);
            n.rip_hop = ntohs(n.rip_hop);
            fprintf(fp,  "%d|", n.rip_hop);
            n.rip_ticks = ntohs(n.rip_ticks);
            fprintf(fp,  "%d|", n.rip_ticks);
        }
    }
    else
        gen_handle(fp, p, top, write_flag);
    return;
}
/*
 * SPX Connection Control
 */
static void spx_cc_dump(fp, x)
FILE * fp;
unsigned char x;
{
int so_far = 0;
    if ((x & SPX_CC_EOM) == SPX_CC_EOM)
    {
        fputs("EOM", fp);
        so_far++;
    }
    if ((x & SPX_CC_ATTN) == SPX_CC_ATTN)
    {
        if (so_far)
            fputc(':', fp);
        fputs("ATTN", fp);
        so_far++;
    }
    if ((x & SPX_CC_ACKR) == SPX_CC_ACKR)
    {
        if (so_far)
            fputc(':', fp);
        fputs("ACKR", fp);
        so_far++;
    }
    if ((x & SPX_CC_SYS) == SPX_CC_SYS)
    {
        if (so_far)
            fputc(':', fp);
        fputs("SYS", fp);
        so_far++;
    }
    if (!so_far && x == '\0')
        fputs("NONE", fp);
    else
    if (!so_far && x != '\0')
        fprintf(fp, "UNKNOWN:%x", (unsigned int) x);
    fputc('|', fp);
    return;
}
/*
 * SPX Datastream Type
 */
static void spx_dt_dump(fp, x)
FILE * fp;
unsigned char x;
{
    switch (x)
    {
    case SPX_DT_EOC:
        fputs("SPX_DT_EOC|", fp);
        break;
    case SPX_DT_EOCA:
        fputs("SPX_DT_EOCA|", fp);
        break;
    default:
        fprintf(fp, "UNKNOWN:%d|", x);
        break;
    }
    return;
}
/*
 * SPX Packets
 */
static void spx_dump(fp, p,top,write_flag)
FILE * fp;
unsigned char * p;
unsigned char * top;
int write_flag;
{
spx_hdr spx;

    memcpy((char *) &spx, p, SPX_LEN);
    spx_cc_dump(fp, spx.spx_cc);
    spx_dt_dump(fp, spx.spx_dt);
    spx.spx_scid = ntohs(spx.spx_scid);
    spx.spx_dcid = ntohs(spx.spx_dcid);
    spx.spx_seq = ntohs(spx.spx_seq);
    spx.spx_ack = ntohs(spx.spx_ack);
    spx.spx_allcn = ntohs(spx.spx_allcn);

    fprintf(fp, "%x|",spx.spx_scid);
    fprintf(fp, "%x|",spx.spx_dcid);
    fprintf(fp, "%d|",spx.spx_seq);
    fprintf(fp, "%d|",spx.spx_ack);
    fprintf(fp, "%d|",spx.spx_allcn);
    p += SPX_LEN;
    if (p < top)
        gen_handle(fp, p, top, write_flag);
    return;
}
/*
 * NCP Packet Format
 */
static void ncp_rt_dump(fp, x)
FILE * fp;
unsigned short int x;
{
    switch (x)
    {
    case NCP_REQ_CSC:
        fputs("NCP_REQ_CSC|", fp);
        break;
    case NCP_REQ_GSR:
        fputs("NCP_REQ_GSR|", fp);
        break;
    case NCP_REQ_TSC:
        fputs("NCP_REQ_TSC|", fp);
        break;
    case NCP_REQ_BMP:
        fputs("NCP_REQ_BMP|", fp);
        break;
    case NCP_REP_SR:
        fputs("NCP_REP_SR|", fp);
        break;
    case NCP_REP_RBP:
        fputs("NCP_REP_RBP|", fp);
        break;
    default:
        fprintf(fp, "UNKNOWN:%x|", x);
        break;
    }
    return;
}
static void ncp_dump(fp, p,top,write_flag)
FILE *fp;
unsigned char * p;
unsigned char * top;
int write_flag;
{
ncp_req req;
ncp_rep rep;

    memcpy((char *) &req, p, sizeof(req));
    req.req_rt = ntohs(req.req_rt);
    ncp_rt_dump(fp, req.req_rt);
    fprintf(fp, "%u|", (unsigned int) req.req_seq);  /* Sequence     */
    fprintf(fp, "%u|", (unsigned int) req.req_cnl);  /* Connection Number Low */
    fprintf(fp, "%u|", (unsigned int) req.req_tn);   /* Task Number  */
    fprintf(fp, "%u|", (unsigned int) req.req_cnh);  /* Connection Number High;
                                                      * always 0x00 */
    if (req.req_rt ==  NCP_REP_SR
     || req.req_rt ==  NCP_REP_RBP)
    {
        memcpy((char *) &rep, p, sizeof(rep));
        fprintf(fp, "%u|", (unsigned int) rep.rep_cc);
        fprintf(fp, "%u|", (unsigned int) rep.rep_cs);
        p += sizeof(rep);
    }
    else
        p += sizeof(req);
    if (req.req_rt ==  NCP_REQ_BMP)
    {
        bmp_dump(fp, p,top,write_flag);
        p += BMP_LEN;
    }
    gen_handle(fp, p, top, write_flag);
    return;
}
/*
 * BMP Packets
 */
static void bmp_dump(fp, p,top,write_flag)
FILE * fp;
unsigned char * p;
unsigned char * top;
int write_flag;
{
ncp_bmp bmp;

    memcpy((char *) &bmp, p, sizeof(bmp));
    bmp.bmp_rt = ntohs(bmp.bmp_rt);       /* Request type              */
    bmp.bmp_scid = ntohl(bmp.bmp_scid);   /* Source Connection ID      */
    bmp.bmp_dcid = ntohl(bmp.bmp_dcid);   /* Destination Connection ID */
    bmp.bmp_pseq = ntohl(bmp.bmp_pseq);   /* Packet Sequence Number    */
    bmp.bmp_sdt = ntohl(bmp.bmp_sdt);     /* Send Delay Time           */
    bmp.bmp_bseq = ntohs(bmp.bmp_bseq);   /* Burst Sequence Number     */
    bmp.bmp_aseq = ntohs(bmp.bmp_aseq);   /* Ack. Sequence Number      */
    bmp.bmp_tbl = ntohl(bmp.bmp_tbl);     /* Total Burst Length        */
    bmp.bmp_boff = ntohl(bmp.bmp_boff);   /* Burst Offset              */
    bmp.bmp_blen = ntohs(bmp.bmp_blen);   /* Burst Length              */
    bmp.bmp_flen = ntohs(bmp.bmp_flen);   /* Fragment List Entries     */
    bmp.bmp_fun = ntohl(bmp.bmp_fun);     /* Function                  */
    bmp.bmp_fh = ntohl(bmp.bmp_fh);       /* File Handle               */
    bmp.bmp_soff = ntohl(bmp.bmp_soff);   /* Starting Offset           */
    bmp.bmp_btw = ntohl(bmp.bmp_btw);     /* Bytes to Write            */
    fprintf(fp, "%x|", (unsigned int) bmp.bmp_flags);    /* Flags      */
    fprintf(fp, "%x|", (unsigned int) bmp.bmp_st);    /* Stream Type   */
    fprintf(fp, "%x|", bmp.bmp_rt );     /* Request type               */
    fprintf(fp, "%x|", bmp.bmp_scid );   /* Source Connection ID       */
    fprintf(fp, "%x|", bmp.bmp_dcid );   /* Destination Connection ID  */
    fprintf(fp, "%u|", bmp.bmp_pseq );   /* Packet Sequence Number     */
    fprintf(fp, "%u|", bmp.bmp_sdt );    /* Send Delay Time            */
    fprintf(fp, "%u|", bmp.bmp_bseq );   /* Burst Sequence Number      */
    fprintf(fp, "%u|", bmp.bmp_aseq );   /* Ack. Sequence Number       */
    fprintf(fp, "%u|", bmp.bmp_tbl );    /* Total Burst Length         */
    fprintf(fp, "%u|", bmp.bmp_boff );   /* Burst Offset               */
    fprintf(fp, "%u|", bmp.bmp_blen );   /* Burst Length               */
    fprintf(fp, "%u|", bmp.bmp_flen );   /* Fragment List Entries      */
    fprintf(fp, "%u|", bmp.bmp_fun );    /* Function                   */
    fprintf(fp, "%u|", bmp.bmp_fh );     /* File Handle                */
    fprintf(fp, "%u|", bmp.bmp_soff );   /* Starting Offset            */
    fprintf(fp, "%u|", bmp.bmp_btw );    /* Bytes to Write             */
    return;
}

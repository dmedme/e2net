/*
 * resum.c - re-process genconv output to make up for the missing packet
 *           details
 */
static char * sccs_id= "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems Limited, 1998\n";
static unsigned char hold_buf[65536];
static unsigned char temp_buf[65536];
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "ansi.h"
#include "e2net.h"
#include <rpc/rpc.h>
#include <rpc/rpc_msg.h>
void pack_id();
void app_recognise(frp)
struct frame_con frp;
{
    return;
}
/**************************************************************************
 *VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
 * Main program starts here
 */ 
main()
{
int len, i, j;
int cnt = 0;
FILE * ofp;
char fname[36];
unsigned char * ptr;

    while (fgets( &hold_buf[0], sizeof(hold_buf) -1, stdin ) != 
                     (char *) NULL)
    {
/*
        if (!strncmp((char *) &hold_buf[0],
                     "More than threshold retransmissions", 35))
*/
        {
restart:
            (void) fgets( &hold_buf[0], sizeof(hold_buf) -1, stdin );
            if (fgets( &hold_buf[0], sizeof(hold_buf) -1, stdin ) != 
                      (char *) NULL)
            {
                sprintf(fname,"badsam%d.dat", cnt++);
                if ((ofp = fopen(fname, "wb")) != (FILE *) NULL)
                {
                    fputs(hold_buf, ofp);
/*
                    while (fgets( &hold_buf[0], sizeof(hold_buf) -1, stdin ) != 
                      (char *) NULL)
                    {
                        if (!strncmp((char *) &hold_buf[0],
                           "Recent Traffic", 14))
                            break;
                        fputs(hold_buf, ofp);
                    }
                    (void) fgets( &hold_buf[0], sizeof(hold_buf) -1, stdin );
*/
                    while (fgets( &hold_buf[0], sizeof(hold_buf) -1, stdin ) != 
                      (char *) NULL)
                    {
                        if (!strncmp((char *) &hold_buf[0],
                              "More than threshold retransmissions", 35))
                        {
                            fclose(ofp);
                            goto restart;
                        }
                        else
                        if (!strncmp((char *) &hold_buf[0], "Session ", 8)
                          || !strncmp((char *) &hold_buf[0], "More than ", 10))
                            break;
                        ptr = strrchr(hold_buf, '|');
                        if (ptr != (char *) NULL)
                        {
                            len = atoi(ptr + 1);
                        }
                        else
                            len = 0;
                        hold_buf[strlen(hold_buf) - 1] = '|';
                        fputs(hold_buf, ofp);
                        ptr = &temp_buf[0];
                        while (fgets(&hold_buf[0], sizeof(hold_buf) -1, stdin)
                                  != (char *) NULL)
                        {
                            if (strlen(hold_buf) == 1
                             && (ptr - &temp_buf[0]) >= len)
                                break;
                            ptr += get_bin(ptr, hold_buf, strlen(hold_buf));
                        }
                        pack_id(ofp, temp_buf, (ptr - temp_buf));
                    }
                    fclose(ofp);
                }
            }
        }
    }
    exit(0);
}
/*
 * Code to generate binary from a mixed buffer of ASCII and hexadecimal
 */ 
int get_bin(tbuf, tlook, cnt)
unsigned char * tbuf;
unsigned char * tlook;
int cnt;
{
unsigned char * cur_pos;
unsigned char * sav_tbuf = tbuf;
int len;
notnewline:
    while (cnt > 0)
/*
 * Is this a length of hexadecimal?
 */
    {
        if (*tlook == '\''
          && (cur_pos = strchr(tlook+1,'\'')) > (tlook + 1)
          && strspn(tlook+1,"0123456789ABCDEFabcdef") ==
                          (len = (cur_pos - tlook - 1)))
        {
            cnt -= (3 + len);
            tlook++;
            *(tlook + len) = (unsigned char) 0;
            tbuf = hex_in_out(tbuf, tlook);
            tlook = cur_pos + 2;   /* Hexadecimal always ends on a new line */
        }
/*
 * Is this a run of characters?
 */
        else
        if ((len = strcspn(tlook,"'")))
        {
            memcpy(tbuf,tlook,len);
            tlook += len;
            tbuf += len;
            cnt -= len;
        }
/*
 * Otherwise, we have a stray "'"
 */
        else
        {
            *tbuf++ = *tlook++;
            cnt--;
        }
    }
    return tbuf - sav_tbuf;
}
/*
 * Read in a line to tlook, dropping escaped newlines.
 */
int getescline(fp, tlook)
FILE * fp;
char * tlook;
{
int p; 
char * cur_pos = tlook;
int do_esc = 0;
    p = getc(fp);
/*
 * Scarper if all done
 */
    if ( p == EOF )
        return p;
    else
/*
 * Pick up the next line, stripping out escapes
 */
    {
        for (;;)
        {
            if (p == (int) '\\')
            {
                p = getc(fp);
                if ( p == EOF )
                    break;
                else
                if (p == '\n')
                    p = getc(fp);
                else
                    *cur_pos++ = '\\';
            }
            *cur_pos++ = p;
            if (p == (int) '\n')
                break;
            p = getc(fp);
            if ( p == EOF )
                p = '\n';
        }
        *cur_pos = '\0';
        return (cur_pos - tlook);
    }
}
/*
 * Output Packet identification details
 */
void pack_id(fp, buf, len)
FILE * fp;
unsigned char *buf;
int len;
{
struct rpc_msg rpc;
XDR xdr;
struct ether_header eth;
struct ip ip;
struct tcphdr tcp;
    memcpy((unsigned char *) &eth, buf,sizeof(eth));
    eth.ether_type = ntohs(eth.ether_type);
#ifdef NOETHER_H
    fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x|%02x:%02x:%02x:%02x:%02x:%02x|",
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
         (unsigned int) *(((unsigned char *) & eth.ether_dhost) + 5));
#else
     fputs(ether_ntoa(&(eth.ether_shost)), fp);
     fputc('|', fp);
     fputs(ether_ntoa(&(eth.ether_dhost)), fp);
        fputc('|', fp);
#endif
     if (eth.ether_type == ETHERTYPE_IP)
     { 
         memcpy((unsigned char *) &ip, buf +sizeof(eth),sizeof(ip));
         fputs( inet_ntoa(ip.ip_src), fp);
         fputc('|', fp);
         fputs(inet_ntoa(ip.ip_dst), fp);
         fputc('|', fp);
         if (ip.ip_p == IPPROTO_TCP)
         {
         int tcp_len;
         int ip_len;
         int rcp_off;
            ip_len = 256*buf[sizeof(eth) + ((char *) (&ip.ip_len) -
                             ((char *) &ip))]
                           + buf[sizeof(eth) + ((char *) (&ip.ip_len) -
                             ((char *) &ip)) + 1];
            memcpy((unsigned char *) &tcp,
                   buf + sizeof(eth) + sizeof(ip),
                   sizeof(tcp));
            tcp.th_sport = ntohs(tcp.th_sport);
            tcp.th_dport = ntohs(tcp.th_dport);
            fprintf(fp, "%d|%d|",tcp.th_sport,tcp.th_dport);
            tcp_len = ip_len - sizeof(ip) - tcp.th_off*4;
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
                              65536 - rcp_off,
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
                fprintf(fp, "RPC|%u|%u|%u|%u|", 
                    rpc.rm_direction,
                    rpc.rm_call.cb_prog,
                    rpc.rm_call.cb_vers,
                    rpc.rm_call.cb_proc);
                if (rpc.rm_direction == CALL &&
                    rpc.rm_call.cb_prog == 300272 &&
                    rpc.rm_call.cb_vers == 2 &&
                    rpc.rm_call.cb_proc == 12)
                {
                    if ((((256 * buf[rcp_off - 2]) +
                        buf[rcp_off - 1]) != (tcp_len - 4)))
                    {
                        fprintf(fp, "%*.*s",
                           tcp_len - 52,tcp_len - 52,
                           &buf[rcp_off + 48]);
                    }
                    else
                        fprintf(fp, "%*.*s\n/\n",
                           tcp_len - 52,tcp_len - 52,
                           &buf[rcp_off + 48]);
                }
            }
        }
        else
            fputs("||", fp);
    }
    else
    if ( eth.ether_type == ETHERTYPE_REVARP)
    {
         fputs("REVARP|", fp);
    }
    else
    if ( eth.ether_type == ETHERTYPE_ARP)
    {
         fputs("ARP|", fp);
    }
    else
    if ( eth.ether_type == ETHERTYPE_PUP)
    {
         fputs("PUP|", fp);
    }
    else
    {
        if (eth.ether_type < 30)
            fputs("LLC|", fp);
        else
            (void) ipx_dump(fp, &buf[sizeof(eth)],&buf[len], 0);
    }
    fputc('\n', fp);
    return;
}

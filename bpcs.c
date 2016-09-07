/************************************************************************
 * bpcs.c - Routines for sorting out BPCS V.6 Traffic Profiles
 *
 * Information that we want to gather:
 * -  Transaction Times
 * -  Split between PC, Network and Server
 * -  Traffic Volumes, in and out, bytes and packets
 * -  Information that enables the particular transaction to be identified
 *
 * Method:
 * -  Filter on all TCP packets. 5000 is Thick Client, 9007 is Thin Client.
 * -  Accumulate entire messages
 * -  Fish for interesting fields from the messages
 * -  Log elapsed times for multiple TCP packet messages
 * -  Leave full computation of traffic details to an AWK pass.
 *
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "novell.h"
#include "ansi.h"
#include "e2net.h"
static char * fname;
static void accum_response ();
static void output_response ();
void frame_accum();
void do_dumb();
void do_bpcs_thick();
void do_bpcs_thin();
/*
 * This is a dummy, awaiting the day when the code here is fully integrated
 * with the other recognition modules that we have.
 */
void app_recognise(frp)
struct frame_con frp;
{
    return;
}
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
extern int errno;
/*
 * Do we want these sessions?
 */
static int match_port[30];         /* List of ports to match against */
static int match_cnt;              /* Number of ports in the list    */
static struct frame_con * flist[30];
static struct frame_con * match_add(port)
int port;
{
    if (match_cnt < 30)
    {
       match_port[match_cnt] = port;
       flist[match_cnt] =
           (struct frame_con *) calloc(1, sizeof(struct frame_con));
       match_cnt++;
    }
    return flist[match_cnt - 1];
}
static struct frame_con * match_true(from,to)
int from;
int to;
{
int i;
#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif
    for (i = 0; i < match_cnt; i++)
    {
       if (match_port[i] == from || match_port[i] == to)
           return flist[i];
    }
    return (struct frame_con *) NULL;
}
static void date_out(secs,musecs)
long secs;
long musecs;
{
char * x = ctime(&(secs));
    printf("%2.2s %3.3s %4.4s %8.8s.%06d|",
            (x + 8), (x + 4), (x + 20), (x + 11),
            musecs);
    return;
}
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
struct snoop_header {
    long len;
    long saved_len;
    long unknown[2];
    long secs_since_1970;
    long musecs;
} snoop;
long t1 = 0;
long m1 = 0;
long t2 = 0;
long m2 = 0;
long t3 = 0;
long m3 = 0;
long t4 = 0;
long m4 = 0;
long l = 0;
int gap = 0;
int con_pack = 0;
int date_flag = 0;
struct ether_header eth;
struct ip ip;
struct tcphdr tcp;
unsigned char buf[65536];
int ret;
int i,j,k;
char * x1, *x2;
struct frame_con * frp;

    while ( ( ch = getopt ( argc, argv, "g:nhvrds:o:" ) ) != EOF )
    {
        switch ( ch )
        {
        case 'g' :
            gap = atoi(optarg);
            break;
        case 's' :
            con_pack = atoi(optarg);
            break;
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
            (void) puts("bpcs: BPCS-orientated snoop file reader\n\
Options:\n\
-d Output date in English\n\
-n Number the packets\n\
-s Output this packet number (for debug purposes)\n\
-g gap - Use this value to break the stream into transactions\n\
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
        (void) fseek(f,16,0);   /* Skip the snoop header */
        while ((ret = fread(&buf[0],sizeof(unsigned char),sizeof(snoop),f)) > 0)
        {
            memcpy((unsigned char *) &snoop, &buf[0],sizeof(snoop));
            snoop.len = ntohl(snoop.len);
            snoop.saved_len = ntohl(snoop.saved_len);
            snoop.secs_since_1970 = ntohl(snoop.secs_since_1970);
            snoop.musecs = ntohl(snoop.musecs);
            l += snoop.len;
            if (running)
            {
                tvdiff(&(snoop.secs_since_1970), &(snoop.musecs),&t1,&m1,
                                      &t2,&m2);
                tvdiff(&(snoop.secs_since_1970),&(snoop.musecs),&t3,&m3,
                                      &t4,&m4);
                t1 = snoop.secs_since_1970;
                m1 = snoop.musecs;
            }
            else
            {
                t2 = snoop.secs_since_1970;
                m2 = snoop.musecs;
            }
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
            if (number && number == con_pack)
                printf("Reached packet:%d\n", con_pack);
            if (number)
                printf("%d|",number++);
#ifdef NOETHER_H
            printf("%02x:%02x:%02x:%02x:%02x:%02x|\
%02x:%02x:%02x:%02x:%02x:%02x|\
%d|%d.%06d|",
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
                     snoop.len, t2, m2);
#else
                 x1 = strdup(ether_ntoa(&(eth.ether_shost)));
                 x2 = strdup(ether_ntoa(&(eth.ether_dhost)));
                 printf("%s|%s|%d|",x1,x2, snoop.len);
                 if (date_flag)
                     date_out( snoop.secs_since_1970, m2);
                 else
                     printf("%d.%06d|", t2, m2);
                 free(x1);
                 free(x2);
#endif
            if (running)
                printf("%d|%d.%06d|", l, t4, m4);
            if (eth.ether_type == ETHERTYPE_IP)
            { 
                memcpy((unsigned char *) &ip, &buf[sizeof(eth)],sizeof(ip));
                fputs( inet_ntoa(ip.ip_src)  ,stdout);
                putchar('|');
                fputs(inet_ntoa(ip.ip_dst) ,stdout);
                putchar('|');
                if (ip.ip_p == IPPROTO_TCP)
                {
                    int ip_len;
                    int tcp_len;
                    int rcp_off;
                    memcpy((unsigned char *) &tcp,
                           &buf[sizeof(eth) + sizeof(ip)],
                           sizeof(tcp));
                    tcp.th_sport = ntohs(tcp.th_sport);
                    tcp.th_dport = ntohs(tcp.th_dport);
                    printf("%d|%d|",tcp.th_sport,tcp.th_dport);
                    ip_len = ntohs(ip.ip_len);
                    tcp_len = ip_len - sizeof(ip) - tcp.th_off*4;
                    if (tcp_len > 0)
                    {
                    int dir_flag;
                    int which_port = 0;
                    int adjust;
                       if (tcp.th_sport == 5000 || tcp.th_dport == 5000)
                           which_port = 5000;
                       else
                       if  (tcp.th_sport == 9007 || tcp.th_dport == 9007)
                           which_port = 9007;
                       else
                       if  (tcp.th_sport == 23 || tcp.th_dport == 23)
                           which_port = 23;
                       if (which_port)
                       {
                       struct timeval t;
                           t.tv_sec = snoop.secs_since_1970;
                           t.tv_usec = snoop.musecs;
                           dir_flag = (tcp.th_sport == which_port) ? 0 : 1;
                           if ((frp = match_true(tcp.th_sport,tcp.th_dport))
                                 == (struct frame_con *) NULL)
                           {
                               frp = match_add((which_port == tcp.th_dport) ?
                                      ((int) tcp.th_sport): (int) tcp.th_dport);
                               frp->gap = gap;
                               if (which_port == 5000)
                               {
                                   frp->off_flag = 1;
                                   frp->do_mess = do_bpcs_thick;
                               }
                               else
                               if (which_port == 9007)
                                   frp->do_mess = do_bpcs_thin;
                               else
                               if (which_port == 23)
                               {
                                   frp->do_mess = do_dumb;
                               }
                               frp->seq[dir_flag] = ntohl(tcp.th_seq);
                               frp->seq[!dir_flag] = ntohl(tcp.th_ack);
                           }
                           adjust = (frp->seq[dir_flag] - ntohl(tcp.th_seq));
                           if (adjust > 0)    /* Otherwise we have lost it */
                               tcp_len = tcp_len
                                     - (frp->seq[dir_flag] - ntohl(tcp.th_seq));
                           else
                           if (adjust < 0)
                           {
                               unsigned char * missed = (unsigned char *)
                                     calloc(1,-adjust);
#ifdef DEBUG
                               printf("Dropped: %d\n", -adjust);
                               fflush(stdout);
#endif
                               frame_accum(-adjust,
                                    missed,
                                    (which_port == tcp.th_dport)
                                              ?((int) tcp.th_sport):0,
                                   &(t), frp);
                               free(missed);
                               frp->seq[dir_flag] -= adjust;
                           }
                           if (tcp_len > 0)
                           {                  /* Otherwise we have it      */
                               frame_accum(tcp_len,
                                    &buf[sizeof(eth) + ip_len - tcp_len],
                                    (which_port == tcp.th_dport)
                                              ?((int) tcp.th_sport):0,
                                   &(t), frp);
                               frp->seq[dir_flag] += tcp_len;
                           }
                       }
                    }
                    putchar('\n');
                    fflush(stdout);
                }
                else
                    puts("||");
            }
            else
                (void) ipx_dump(stdout,
                                 &buf[sizeof(eth)],&buf[snoop.saved_len], 1);
            if (verbose)
                (void) gen_handle(stdout,
                                 &buf[0],&buf[snoop.saved_len], 1);
        }
    }
    exit(0);
}
/*
 * Handle framing. The assumption is that messages always start with
 * a two byte length
 */
void frame_accum(len, p, out, t, f)
int len;
char *p;
int out;
struct timeval *t;
struct frame_con *f;
{
int dir_flag;
int sav_len;
/*
 * If new message, allocate a new buffer
 */
    if (f->do_mess == NULL)
    {
        putchar('\n');
        fwrite(p,sizeof(char),len,stdout);
        putchar('\n');
        return;
    }
    if (out)
        dir_flag = 1;
    else
        dir_flag = 0;
    if (!(f->last_out) && out)
        f->last_out = out;
/*
 * Dropped something; resynchronise, discarding what we have
 */
    if (out && (f->last_out) && (f->last_out) != out)
    {
        f->left[0] = 0;
        f->left[1] = 0;
        f->cnt[0] = 0;
        f->cnt[1] = 0;
    }
#ifdef DEBUG
    printf("Length: %d Message:\n", len);
    gen_handle(stdout, p,p+len,1);
    puts("--------");
    printf("dir_flag: %d f->left[dir_flag]: %d\n",dir_flag,f->left[dir_flag]);
    puts("========");
#endif
multi_mess:
/*
 * This is a new message starting
 */
    if (f->left[dir_flag] == 0)
    {
/*
 * Frig to only have one frame routine
 */
        if (f->do_mess == do_bpcs_thick)
        {      /* Thick Client */
            if (len + f->res_len[dir_flag] < (sizeof(short int) + f->off_flag))
            {
                memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p, len);
                f->res_len[dir_flag] += len;
                return;
            }
            else
            if (f->res_len[dir_flag] != 0)
            {
                memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p, 
                    sizeof(short int) + f->off_flag - f->res_len[dir_flag]);
                p += (sizeof(short int) + f->off_flag - f->res_len[dir_flag]);
                len -= (sizeof(short int) + f->off_flag - f->res_len[dir_flag]);
                f->res_len[dir_flag] = sizeof(short int) + f->off_flag;
                memcpy((char *) &(f->left[dir_flag]),
                       &(f->reserve[dir_flag][f->off_flag]),
                                 sizeof(short int));
            }
            else
                memcpy((char *) &(f->left[dir_flag]), p + f->off_flag,
                    sizeof(short int));
            f->left[dir_flag] = ntohs(f->left[dir_flag]);
            if (f->left[dir_flag] == 0)
                return;
        }
        else
        if (f->do_mess == do_bpcs_thin)
        {      /* Thin Client */
            if (len + f->res_len[dir_flag] < (sizeof(long int)))
            {
                memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p, len);
                f->res_len[dir_flag] += len;
                return;
            }
            else
            if (f->res_len[dir_flag] != 0)
            {
                memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p, 
                    sizeof(long int)  - f->res_len[dir_flag]);
                p += (sizeof(long int)  - f->res_len[dir_flag]);
                len -= (sizeof(long int)  - f->res_len[dir_flag]);
                f->res_len[dir_flag] = sizeof(long int);
                memcpy((char *) &(f->left[dir_flag]),
                       &(f->reserve[dir_flag][0]),
                                 sizeof(long int));
            }
            else
                memcpy((char *) &(f->left[dir_flag]), p, sizeof(long int));
            f->left[dir_flag] =  ntohl(f->left[dir_flag]) + 4;
            if (f->left[dir_flag] < 4)
            {
                f->left[dir_flag] = 0;
                return;
            }
        }
        else
            f->left[dir_flag] =  len;
        f->ini_t[dir_flag] = *t;
        f->cnt[dir_flag] = 1;
        if (f->left[dir_flag] > 16000)
        {   /* Apparently lost synchronisation */
            f->left[dir_flag] = 0;
            return;
        }
        if (dir_flag && (f->do_mess == do_bpcs_thick ||
           (f->do_mess == do_bpcs_thin && f->left[dir_flag] > 4)))
            output_response(f,dir_flag);
        f->len[dir_flag] = f->left[dir_flag];
        f->hold_buf[dir_flag] = (unsigned char *)
              malloc((f->left[dir_flag] > (len + f->res_len[dir_flag]))?
                    f->left[dir_flag] : (len + f->res_len[dir_flag]));
        f->top[dir_flag] = f->hold_buf[dir_flag];
    }
    else
    {
/*
 * This piece has the end of an existing message, and a new one starts in the
 * middle of it. Allocate space at the end of the existing buffer for the
 * overshoot.
 */
        f->cnt[dir_flag]++;
        if (f->left[dir_flag] < len)
        {
            sav_len = f->top[dir_flag] - f->hold_buf[dir_flag];
            f->hold_buf[dir_flag] = (unsigned char *)
                 realloc(f->hold_buf[dir_flag],
                          sav_len + len + f->res_len[dir_flag]);
            f->top[dir_flag] = f->hold_buf[dir_flag] + sav_len;
        }
    }
    if (len < 0)
        abort();
/*
 * Copy the arrived data into the buffer, including part of the next message
 * if it is present.
 */
    if (f->res_len[dir_flag])
    {
        memcpy(f->top[dir_flag],&(f->reserve[dir_flag][0]),
            f->res_len[dir_flag]);
        f->top[dir_flag] += f->res_len[dir_flag];
        f->res_len[dir_flag] = 0;
    }
    memcpy(f->top[dir_flag],p,len);
    f->top[dir_flag] += len;
    f->left[dir_flag] -= len;
/*
 * Whole message accumulated, process. -left[dir_flag] is the length of
 * the extra fragment at the end.
 */
    if (f->left[dir_flag] < 0)
    {
        f->top[dir_flag] += f->left[dir_flag];
        f->last_t[dir_flag] = *t;
        (*(f->do_mess))(f, dir_flag);
        f->ini_t[dir_flag] = *t;
        sav_len = (len + f->left[dir_flag]);
        p += sav_len;
        len = -(f->left[dir_flag]);
        f->left[dir_flag] = 0;
        free((f->hold_buf[dir_flag]));
        goto multi_mess;
    }
    if (f->left[dir_flag] == 0)
    {
        f->last_t[dir_flag] = *t;
        (*(f->do_mess))(f, dir_flag);
        f->ini_t[dir_flag] = *t;
        free(f->hold_buf[dir_flag]);
    }
#ifdef DEBUG
    else
    {
        puts("Still to come:");
        printf("dir_flag: %d left[dir_flag]: %d\n",dir_flag,f->left[dir_flag]);
        puts("========");
    }
#endif
    return;
}
/*
 * Common routine to work out overall response times for transactions
 *
 * A transaction starts when a non-zero message is sent to the server,
 * and is seen to end when there is a gap of more than gap between the
 * last application message from the server, and this message from the 
 * client.
 *
 * Zero length BPCS application messages do not elicit application responses;
 * these must be ignored.
 */
static void output_response (f,dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval first_to_now;
struct timeval last_to_now;
struct timeval resp_time;
/*
 * If the message is going from the client to the server (ie. dir_flag = 1),
 * work out the response time so far (ie. last server response - initial
 * client response), and the time from this packet to the tran_start
 * packet, and the time from this packet to the last server packet.
 *
 * If the response time is positive, and the gap time is greater than
 * the gap, we need to output a response record:
 * - Record Type
 * - Label
 * - Time Start
 * - Response
 * - Packets Out
 * - Packets In
 * - Bytes Out
 * - Bytes In
 *
 * If the response time is negative, and the time between now and the
 * start of the transaction is greater than the gap, or we have output
 * details, we need to clear the accumulators and reset the transaction start.
 */
    if (dir_flag)
    {
        tvdiff(&(f->ini_t[1].tv_sec),    /* The time when this message began */
               &(f->ini_t[1].tv_usec),
               &(f->tran_start.tv_sec),  /* The time when the previous       */
               &(f->tran_start.tv_usec), /* transaction began                */
               &(first_to_now.tv_sec),   /* The difference                   */
               &(first_to_now.tv_usec));
        tvdiff(&(f->up_to.tv_sec),
               &(f->up_to.tv_usec),
               &(f->tran_start.tv_sec),
               &(f->tran_start.tv_usec),
               &(resp_time.tv_sec),      /* The Response Time               */
               &(resp_time.tv_usec));
        tvdiff(&(f->ini_t[1].tv_sec),
               &(f->ini_t[1].tv_usec),
               &(f->up_to.tv_sec),
               &(f->up_to.tv_usec),
               &(last_to_now.tv_sec),    /* The Gap                         */
               &(last_to_now.tv_usec));
        if (last_to_now.tv_sec >= f->gap && f->tran_cnt[0] > 0)
        {
            printf("RESPONSE|%s|%d.%06d|%d.%06d|%d|%d|%d|%d|%d.%06d|%d.%06d|",
                f->label, f->tran_start.tv_sec, f->tran_start.tv_usec,
                resp_time.tv_sec, resp_time.tv_usec,
                f->tran_cnt[1], f->tran_cnt[0],
                f->tran_len[1], f->tran_len[0],
                f->cs_tim[1].tv_sec, f->cs_tim[1].tv_usec,
                f->cs_tim[0].tv_sec, f->cs_tim[0].tv_usec);
            date_out(f->tran_start.tv_sec, f->tran_start.tv_usec);
        }
        if ((last_to_now.tv_sec >= f->gap 
          && f->tran_cnt[0] > 0)
         || (f->tran_cnt[0] == 0 && first_to_now.tv_sec >= f->gap))
        {
            f->tran_start = f->ini_t[1];
            f->up_to = f->ini_t[1];
            f->tran_cnt[0] = 0;
            f->tran_cnt[1] = 0;
            f->tran_len[0] = 0;
            f->tran_len[1] = 0;
            f->cs_tim[0].tv_sec = 0;
            f->cs_tim[0].tv_usec = 0;
            f->cs_tim[1].tv_sec = 0;
            f->cs_tim[1].tv_usec = 0;
        }
    }
    return;
}
/*
 * Add details to the accumulators if we are in a transaction.
 */
static void accum_response (f,dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval first_to_now;
struct timeval last_to_now;
struct timeval resp_time;
    if (f->do_mess == do_bpcs_thin && f->len[dir_flag] <= 4)
        return;
    f->tran_cnt[dir_flag] += f->cnt[dir_flag];
    f->tran_len[dir_flag] += f->len[dir_flag];
/*
 * Adjust the total time breakdowns
 */
    tvdiff(&(f->last_t[dir_flag].tv_sec),
           &(f->last_t[dir_flag].tv_usec),
           &(f->up_to.tv_sec),
           &(f->up_to.tv_usec),
           &(last_to_now.tv_sec), &(last_to_now.tv_usec));
    tvadd(&(f->cs_tim[dir_flag].tv_sec),
          &(f->cs_tim[dir_flag].tv_usec),
          &(last_to_now.tv_sec), &(last_to_now.tv_usec),
          &(f->cs_tim[dir_flag].tv_sec),
          &(f->cs_tim[dir_flag].tv_usec));
    f->up_to = f->last_t[dir_flag];
    return;
}
/*
 * Handle a thick BPCS message
 */
void do_bpcs_thick(f, dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval el_diff;
int i;
unsigned char * p1;
    fputs("THICK|", stdout);
    tvdiff(&(f->last_t[dir_flag].tv_sec),&(f->last_t[dir_flag].tv_usec),
           &(f->ini_t[dir_flag].tv_sec),&(f->ini_t[dir_flag].tv_usec),
           &(el_diff.tv_sec), &(el_diff.tv_usec));
    if (f->len[dir_flag] > 54)
    {
        for (i = 38, p1 = f->hold_buf[dir_flag] + 27; i ; i--, p1++)
            *p1 = asc_ind(*p1);
        printf("%d.%06d|%d.%06d|%d|%d|%-38.38s|",
           f->ini_t[dir_flag].tv_sec,
           f->ini_t[dir_flag].tv_usec,
           el_diff.tv_sec, el_diff.tv_usec, f->cnt[dir_flag],f->len[dir_flag],
           f->hold_buf[dir_flag] + 27);
        if (dir_flag)
        {
            memcpy(f->label,f->hold_buf[dir_flag] + 27,38);
            f->label[39] = '\0';
        }
    }
    else
        printf("%d.%06d|%d.%06d|%d|%d|SHORT|",
           f->ini_t[dir_flag].tv_sec,
           f->ini_t[dir_flag].tv_usec,
           el_diff.tv_sec, el_diff.tv_usec, f->cnt[dir_flag],f->len[dir_flag]);
    accum_response(f,dir_flag);
    return;
}
/*
 * Routines to pre-process information from incoming and outgoing
 * buffers so that it is valid ptydrive input
 */
static unsigned char * path_in_stuff(in, len)
unsigned char * in;
int len;
{
unsigned char buf[2048];
register unsigned char *x1=in, *x2=buf;
    while (len-- > 0)
    {
        if (*x1 == '`')
        {   /* In case back quotes appear in the input strings */
            *x2++ = '`';
            *x2++ = ' ';
            *x2++ = '\'';
            *x2++ = '`';
            *x2++ = '\'';
            *x2++ = ' ';
        }
        *x2++ = *x1++;
    }
    *x2 = '\0';
    return (unsigned char *) strdup((char *) (&buf[0]));
}
/*
 * Handle a thin BPCS message
 */
void do_bpcs_thin(f, dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval el_diff;
int i;
unsigned char * p1;
static int done_flag;
static char buf1[64];
static char buf2[512];
    if (!done_flag)
    {
        re_comp(" UD BPCS Mixed Mode", buf1, (long int) sizeof(buf1));
        re_comp("[A-Z][A-Z][A-Z][0-9][0-9][0-9]", buf2, (long int) sizeof(buf2));
        done_flag = 1;
    }
    fputs("THIN|", stdout);
    tvdiff(&(f->last_t[dir_flag].tv_sec),&(f->last_t[dir_flag].tv_usec),
           &(f->ini_t[dir_flag].tv_sec),&(f->ini_t[dir_flag].tv_usec),
           &(el_diff.tv_sec), &(el_diff.tv_usec));
    p1 = f->hold_buf[dir_flag];
    if (!re_scan(&p1, buf1, f->len[dir_flag])
      || !re_scan(&p1, buf2, f->len[dir_flag]))
        p1 = (unsigned char *) "UNKNOWN";
    else
    if (!dir_flag)
    {
/*
 * The Transaction label will only be in data from the server to the client
 */ 
        strncpy(f->label,p1,38);
        f->label[39] = '\0';
    }
    printf("%d.%06d|%d.%06d|%d|%d|%-7.7s|",
           f->ini_t[dir_flag].tv_sec,
           f->ini_t[dir_flag].tv_usec,
           el_diff.tv_sec, el_diff.tv_usec, f->cnt[dir_flag],f->len[dir_flag],
           p1);
    accum_response(f,dir_flag);
    fflush(stdout);
    return;
}

/*
 * Scan a snoop file and pull out the Delphi elements (hopefully). 
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include "e2net.h"
#define ECHO_SERVICE 7

#include "dfsdrive.h"
void delphi_frame_accum();
static char * fname;
main(argc,argv)
int argc;
char ** argv;
{
HASH_CON *open_sess = hash(MAX_SESS,uhash_key,ucomp_key);
struct frame_con * anchor = (struct frame_con *) NULL, *frp;
struct frame_con work_sess;     /* To hold converted temporarily */
int tcp_pack_no = 1;    /* Cross Reference to the Packet File */
time_t last_time = 0;
time_t last_event = 0;
int more_flag = 0;
int event=0xa1;
long adjust;
struct snoop_header {
    long len;
    long unknown[3];
    long secs_since_1970;
    long musecs;
} snoop;
struct ether_header eth;
struct ip ip;
struct tcphdr tcp;
struct udphdr udp;
unsigned char buf[65536];
int ret;
int i,j,k;
int dir_flag;

    dfs_init();
    for (i = 1; i < argc; i++)
    {
    FILE *f;
        fname = argv[i];
        if ((f = fopen(fname,"rb")) == (FILE *)NULL)
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
            snoop.secs_since_1970 = ntohl(snoop.secs_since_1970);
            snoop.musecs = ntohl(snoop.musecs);
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
            eth.ether_type = ntohs(eth.ether_type);
/*
 * Start initialising the session control record
 */
            memset((char *) &work_sess, 0, sizeof(work_sess));
            work_sess.phys_from[0] = 6;
            memcpy(&(work_sess.phys_from[1]),
                (unsigned char *) &eth.ether_shost, 6);
            work_sess.phys_to[0] = 6;
            memcpy(&(work_sess.phys_to[1]),
                (unsigned char *) &eth.ether_dhost, 6);
            work_sess.this_time.tv_sec = snoop.secs_since_1970;
            work_sess.this_time.tv_usec = snoop.musecs;
            work_sess.pack_len = snoop.len;
            work_sess.pack_no = tcp_pack_no++;
            if (eth.ether_type == ETHERTYPE_IP)
            { 
                memcpy((unsigned char *) &ip, &buf[sizeof(eth)],sizeof(ip));
                work_sess.net_from[0] = 4;
                memcpy(&(work_sess.net_from[1]),
                        (unsigned char *) &(ip.ip_src), 4);
                work_sess.net_to[0] = 4;
                memcpy(&(work_sess.net_to[1]),
                        (unsigned char *) &(ip.ip_dst), 4);
                if (ip.ip_p == IPPROTO_TCP)
                {
                    int x_ip_len;
                    int tcp_len;
                    int rcp_off;
                    memcpy((unsigned char *) &tcp,
                           &buf[sizeof(eth) + sizeof(ip)],
                           sizeof(tcp));
                    tcp.th_sport = ntohs(tcp.th_sport);
                    tcp.th_dport = ntohs(tcp.th_dport);
                    x_ip_len = 256*buf[sizeof(eth) + ((char *) (&(ip.ip_len)) -
                             ((char *) &ip))]
                           + buf[sizeof(eth) + ((char *) (&(ip.ip_len)) -
                             ((char *) &ip)) + 1];
#ifdef AIX
                    tcp_len = x_ip_len - sizeof(ip) - ((tcp.th_off)>>4)*4;
#else
                    tcp_len = x_ip_len - sizeof(ip) - tcp.th_off*4;
#endif
                    work_sess.port_from[0] = 2;
                    memcpy(&(work_sess.port_from[1]),
                              (unsigned char *) &tcp.th_sport, 2);
                    work_sess.port_to[0] = 2;
                    memcpy(&(work_sess.port_to[1]),
                              (unsigned char *) &tcp.th_dport, 2);
                    work_sess.prot = E2_TCP;
                    if ((frp = match_true(open_sess, &work_sess))
                                 == (struct frame_con *) NULL)
                    {
                        frp = match_add(open_sess, &anchor, &work_sess);
                        dir_flag = 0;
                        frp->off_flag = 2;
                        frp->len_len = 2;
                        frp->fix_size = 4;
                        frp->do_mess = do_dfs;
                        if (work_sess.prot == E2_TCP)
                        {
                            frp->seq[dir_flag] = ntohl(tcp.th_seq);
                            frp->seq[!dir_flag] = ntohl(tcp.th_ack);
                        }
                    }
                    else
                    {
                        dir_flag =  ! (! hcntstrcmp(work_sess.phys_from,
                                  frp->phys_from));
                        frp->this_time = work_sess.this_time;
                        frp->pack_len = work_sess.pack_len;
                        frp->pack_no = work_sess.pack_no;
                    }
                    if (tcp_len > 0)
                    {
                        adjust = (frp->seq[dir_flag] - ntohl(tcp.th_seq));
#ifdef DEBUG
                        if (adjust != 0)
                        {
                            printf("Adjustment Value: %d\n", adjust);
                            fflush(stdout);
                        }
#endif
                        if (adjust > 0 && 0 == 1) /* Otherwise we have lost it */
                            tcp_len = tcp_len
                                  - (frp->seq[dir_flag] - ntohl(tcp.th_seq));
                        else
                        if (adjust < 0 && 0 == 1)
                        {
                        unsigned char * missed = (unsigned char *)
                                          calloc(1,-adjust);
#ifdef DEBUG
                            printf("Dropped: %d\n", -adjust);
                                    fflush(stdout);
#endif
                            delphi_frame_accum(-adjust, missed, dir_flag, frp);
                            free(missed);
                            frp->seq[dir_flag] -= adjust;
                        }
                        if (tcp_len > 0)
                        {                  /* Otherwise we have it      */
                            delphi_frame_accum(tcp_len,
                                 &buf[sizeof(eth) + x_ip_len - tcp_len],
                                 dir_flag, frp);
                            frp->seq[dir_flag] += tcp_len;
                        }
                        frp->seq[dir_flag] = ntohl(tcp.th_seq) + tcp_len;
                    }
                }
                else
                if (ip.ip_p == IPPROTO_UDP)
                {
                    memcpy((unsigned char *) &udp,
                           &buf[sizeof(eth) + sizeof(ip)],
                           sizeof(udp));
                    udp.uh_dport = ntohs(udp.uh_dport);
                    if (udp.uh_dport == ECHO_SERVICE)
                    {
                    static struct in_addr echo_host;
                        if (last_time != 0)
                        {
                            if (memcmp((char *) &echo_host,
                                (char *) &(ip.ip_src), sizeof(struct in_addr)))
                                continue;
                            printf("\\T%X:\\\n",event++);
                        }
                        else
                            memcpy((char *) &echo_host,
                               (char *) &(ip.ip_src), sizeof(struct in_addr));
                        last_time = snoop.secs_since_1970;
/*
 * This is one of our event definitions. Only pick up the echoe packet
 * going in one direction, by remembering the host it came from.
 */
                        udp.uh_ulen = ntohs(udp.uh_ulen);
                        printf( "\\S%X:120:", event);
                        fwrite(&buf[sizeof(eth) + sizeof(ip) + sizeof(udp)],
                                sizeof(char),udp.uh_ulen - sizeof(udp),stdout);
                        putchar('\\');
                        putchar('\n');
                    }
                }
            }
        }
        if (last_time != 0)
            printf("\\T%X:\\\n",event++);
    }
    exit(0);
}
/*****************************************************************************
 * Useful date utility function
 */
static void date_out(fp, secs, musecs)
FILE * fp;
long secs;
long musecs;
{
char * x = ctime(&(secs));
    fprintf(fp, "%2.2s %3.3s %4.4s %8.8s.%06d",
            (x + 8), (x + 4), (x + 20), (x + 11),
            musecs);
    return;
}
/*
 * Handle framing for Delphi messages
 */
void delphi_frame_accum(len, p, out,  f)
int len;
char *p;
int out;
struct frame_con *f;
{
int dir_flag;
int sav_len;
    if (f->do_mess == NULL)
    {
        putchar('\n');
        fwrite(p,sizeof(char),len,stdout);
        putchar('\n');
        return;
    }
/*
 * Output packet details if the direction has changed
 */
    if (f->last_out != out)
    {
    char * x1;
    char * x2;
    struct in_addr x3;
    unsigned short x4,x5;
        memcpy((char *) &x3, &(f->net_from[1]), sizeof(long));
        x1 = strdup(inet_ntoa(x3));
        memcpy((char *) &x3, &(f->net_to[1]), sizeof(long));
        x2 = strdup(inet_ntoa(x3));
        printf( "\\C:%d:%d:", f->pack_no, f->pack_len);
        date_out(stdout, f->this_time.tv_sec, f->this_time.tv_usec);
        puts("\\");
        memcpy((char *) &x4, &(f->port_from[1]), sizeof(unsigned short));
        memcpy((char *) &x5, &(f->port_to[1]), sizeof(unsigned short));
        if (!out)
            printf( "\\M:%s;%d:%s;%d\\\n", x1, x4,  x2, x5);
        else
            printf( "\\M:%s;%d:%s;%d\\\n", x2, x5,  x1, x4);
        free(x1);
        free(x2);
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
    gen_handle(p,p+len,1);
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
 * The first step is to make sure that we have at least the fixed size header.
 * The fixed header is 4 bytes, with a 2 byte message type followed by a
 * 2 byte length (in MSB/LSB order). If we do not, we must wait.
 */
        if (len + f->res_len[dir_flag] < (sizeof(short int) + f->off_flag))
        {
            memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p, len);
            f->res_len[dir_flag] += len;
            return;
        }
        else
/*
 * If we have a reserved amount, pull the length from there, and adjust the
 * main buffer details accordingly. 
 */
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
#ifdef AIX
        f->left[dir_flag] = ((f->left[dir_flag]>>8)&0xff)
               +(((f->left[dir_flag])<<8)&0xff00) + 4;
#else
        f->left[dir_flag] = ntohs(f->left[dir_flag]) + 4;
#endif

        f->ini_t[dir_flag] = f->this_time;
        f->cnt[dir_flag] = 1;
        if (f->left[dir_flag] > 16000)
        {   /* Apparently lost synchronisation */
            f->left[dir_flag] = 0;
            return;
        }
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
        f->last_t[dir_flag] = f->this_time;
        (*(f->do_mess))(f, dir_flag);
        f->ini_t[dir_flag] = f->this_time;
        sav_len = (len + f->left[dir_flag]);
        p += sav_len;
        len = -(f->left[dir_flag]);
        f->left[dir_flag] = 0;
        free((f->hold_buf[dir_flag]));
        goto multi_mess;
    }
    if (f->left[dir_flag] == 0)
    {
        f->last_t[dir_flag] = f->this_time;
        (*(f->do_mess))(f, dir_flag);
        f->ini_t[dir_flag] = f->this_time;
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

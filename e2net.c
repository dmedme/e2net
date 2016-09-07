/************************************************************************
 * e2net.c - Routines to enhance E2 network code commonality.
 *
 * Scan an Ethernet trace file and pull out enough data to perform traffic
 * analysis.
 *
 * Information that we want to gather:
 * -  Transaction Times
 * -  Split between PC, Network and Server
 * -  Traffic Volumes, in and out, bytes and packets
 * -  Information that enables the particular transaction to be identified
 *
 * This program aims to function on any system, regardless of the form of
 * the packet trace encapsulation or the presence of the appropriate
 * headers.
 *
 * Typically link with -lsocket -linet -lnsl, depending on what exists.
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1994\n";
#ifdef __STRICT_ANSI
#undef __STRICT_ANSI
#endif
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef LCC
#ifndef VCC2003
#include <unistd.h>
#endif
#endif
#include <errno.h>
#include <time.h>
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#endif
#endif
#include "hashlib.h"
#include "webrep.h"
#include "e2net.h"
void do_dumb();
static char * e2ether_ntoa_r(x, ret_buf)
char *x;
char *ret_buf;
{

    sprintf(ret_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                 (unsigned int) *((unsigned char *) x),
                 (unsigned int) *(((unsigned char *) x) + 1),
                 (unsigned int) *(((unsigned char *) x) + 2),
                 (unsigned int) *(((unsigned char *) x) + 3),
                 (unsigned int) *(((unsigned char *) x) + 4),
                 (unsigned int) *(((unsigned char *) x) + 5));
    return ret_buf;
}
static char *e2ether_ntoa(x)
char *x;
{
static char ret_buf[20];

    return e2ether_ntoa_r(x, &ret_buf[0]);
}
/*
 * Get little-endian number
 */
unsigned int get_lit_end(x,len)
unsigned char * x;
int len;
{
unsigned int i;
int j;

    for (i = 0, j=0; j < len; j++)
    {
        i = i + (((unsigned) (*x)) << (j * 8));
        x++;
    }
    return i;
}
/*
 * Get bigendian number
 */
unsigned int get_big_end(x,len)
unsigned char * x;
int len;
{
unsigned int i;

    for (i = 0; len > 0; len--)
    {
        i = (i << 8) + ((unsigned) (*x));
        x++;
    }
    return i;
}
/*
 * Generate a (hopefully unique) event ID from a sequence
 */
void get_event_id(seq, buf)
int seq; 
char * buf;
{
    buf[2] = 0;
    buf[1] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[seq % 36];
    buf[0] = "ABCDEGHIJKLMNOPQSUVWY"[(seq / 36) % 21];
    return;
}
/**********************************************************************
 * Compare a counted binary value
 */
int hcntstrcmp(x1_ptr, x2_ptr)
unsigned char * x1_ptr;
unsigned char * x2_ptr;
{
unsigned char * t_ptr;

int switch_flag;
unsigned char i;

    i = *x2_ptr++;
    if (i == *x1_ptr)
    {                     /* Same length */
        switch_flag = 0;
    }
    else
    if ( *x1_ptr < i)
    {                     /* First record longer */
        i = *x1_ptr;
        switch_flag = -1;
    }
    else
    {                     /* Second record shorter */
        switch_flag = 1;
    }
    x1_ptr++;
    if (i || switch_flag)
    {                     /* if this is not an empty one */
        for ( t_ptr = x1_ptr + i;
                  x1_ptr < t_ptr && (*x1_ptr == *x2_ptr);
                     x1_ptr++, x2_ptr++);
                                  /* find where they differ */
        if (x1_ptr >= t_ptr)
            return switch_flag;
        else
        if (*x1_ptr > *x2_ptr)
            return 1;
        else
            return -1;
    }
    else
        return switch_flag;
}
/*
 * Calculate a hash value for a counted binary value
 */
static unsigned cnthash(w,modulo)
unsigned char *w;
int modulo;
{
unsigned char *p;
unsigned int x,y;

    x = *w++;
    for (p = w + x - 1, y=0;  p >= w;  x--, p--)
    {
        y += x;
        y *= (*p);
    }
    x = y & (modulo-1);
    return(x);
}
/*
 * Hash the key fields. The intention is that this hash function does not
 * depend on the ordering of the from and to fields.
 */
int uhash_key (utp,modulo)
struct frame_con * utp;
int modulo;
{
    if (utp->prot == E2_TCP || utp->prot == E2_UDP)
    return (utp->prot ^
           cnthash(utp->net_from,modulo) ^
           cnthash(utp->net_to,modulo) ^
           cnthash(utp->port_from,modulo) ^
           cnthash(utp->port_to,modulo)) &(modulo - 1);
    else
    return (utp->prot ^ cnthash(utp->phys_from,modulo) ^
           cnthash(utp->phys_to,modulo) ^
           cnthash(utp->net_from,modulo) ^
           cnthash(utp->net_to,modulo) ^
           cnthash(utp->port_from,modulo) ^
           cnthash(utp->port_to,modulo)) &(modulo - 1);

}
/*
 * Compare pairs of key fields for the session hash table.
 */
int ucomp_key(utp1,  utp2)
struct frame_con * utp1;
struct frame_con * utp2;
{
int i;

    if (utp1->prot == utp2->prot)
        i = 0;
    else
    if (utp1->prot < utp2->prot)
        i = -1;
    else
        i = 1;
    if (!i)
    {
        i = hcntstrcmp(utp1->net_from, utp2->net_from);
        if (!i)
        {
            i = hcntstrcmp(utp1->net_to, utp2->net_to);
            if (!i)
            {
                i = hcntstrcmp(utp1->port_from, utp2->port_from);
                if (!i)
                {
                    i = hcntstrcmp(utp1->port_to, utp2->port_to);
                    if (!i && utp1->prot != E2_TCP && utp1->prot != E2_UDP)
                    {
                        i = hcntstrcmp(utp1->phys_to, utp2->phys_to);
                        if (!i)
                            i = hcntstrcmp(utp1->phys_from,utp2->phys_from);
                    }
                }
            }
        }
        if (i)
        {
            i = hcntstrcmp(utp1->net_to, utp2->net_from);
            if (!i)
            {
                i = hcntstrcmp(utp1->net_from, utp2->net_to);
                if (!i)
                {
                    i = hcntstrcmp(utp1->port_from, utp2->port_to);
                    if (!i)
                    {
                        i = hcntstrcmp(utp1->port_to, utp2->port_from);
                        if (!i && utp1->prot != E2_TCP && utp1->prot != E2_UDP)
                        {
                            i = hcntstrcmp(utp1->phys_from, utp2->phys_to);
                            if (!i)
                                i = hcntstrcmp(utp1->phys_to,
                                                utp2->phys_from);
                        }
                    }
                }
            }
        }
    }
    return i;
}
/*
 * Create a new session record
 */
struct frame_con * match_add(open_sess, sess_anchor, frp)
HASH_CON * open_sess;
struct frame_con ** sess_anchor;
struct frame_con * frp;
{
struct frame_con * un = (struct frame_con *) malloc(sizeof(struct frame_con));

    *un = *frp;
    if (*sess_anchor != (struct frame_con *) NULL)
        (*sess_anchor)->prev_frame_con = un;
    un->next_frame_con = *sess_anchor;
    un->prev_frame_con = (struct frame_con *) NULL;
    *sess_anchor = un;
    insert(open_sess,un,un);
    un->last_out = -1;    /* To trigger "not the same" processing first time */
    un->last_app_out = -1;
                          /* To trigger "not the same" processing first time */
    un->event_id = 0;
    un->len_len = 0;
    un->corrupt_flag = 0;
    un->reverse_sense = 0;
                          /* Default is the from is the client, to server    */
    un->fix_size = 0;
    un->cleanup = NULL;
    un->long_label = NULL;
    if (app_recognise(un))
        return un;        /* Set up application-specific structures          */
    if (un->ofp == (FILE *) NULL)
        un->ofp = stdout; /* Default output destination                      */
    un->do_mess = NULL;
    un->app_ptr = (char *) NULL;
    return un;
}
/*
 * Remove a session record
 */
void match_remove(open_sess, sess_anchor, frp)
HASH_CON * open_sess;
struct frame_con ** sess_anchor;
struct frame_con * frp;
{
/*
 * Unlink the entry from the chain
 */
    if (frp->prev_frame_con == (struct frame_con *) NULL)
        *sess_anchor = frp->next_frame_con;
    else
        frp->prev_frame_con->next_frame_con = frp->next_frame_con;
    if (frp->next_frame_con != (struct frame_con *) NULL)
        frp->next_frame_con->prev_frame_con = frp->prev_frame_con;
/*
 * Remove the hash pointer
 */
    hremove(open_sess,frp);
/*
 * Get rid of the packets linked to this session
 */
    if (frp->pack_ring != (struct circbuf *) NULL)
        circbuf_des(frp->pack_ring);
/*
 * Write a socket close message if we are tracing an application
 */
    if (frp->do_mess != NULL && frp->prot == E2_TCP)
    {
        if (frp->ofp != NULL)
        {
            fputs("\\X:", frp->ofp);
            ip_dir_print(frp->ofp, frp, 0);
            fputs("\\\n", frp->ofp);
            if (frp->event_id != 0)
                fprintf(frp->ofp, "\\T%X:\\\n", frp->event_id);
        }
        if (frp->cleanup != NULL)
            (*(frp->cleanup))(frp);  /* Bespoke cleanup; includes file close */
        else
        if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
            fclose(frp->ofp);
    }
    if (frp->long_label != (char *) NULL)
        free(frp->long_label);
    free(frp);
    return;
}
/*
 * Search for an existing session record
 */
struct frame_con * match_true(open_sess, from)
HASH_CON * open_sess;
struct frame_con * from;
{
HIPT * h;
    if ((h = lookup(open_sess, (char *) from)) != (HIPT *) NULL)
        return (struct frame_con *) (h->body);
    else
        return (struct frame_con *)  NULL ;
}
/*****************************************************************************
 * Useful date utility function
 */
void date_out(fp, secs, musecs)
FILE * fp;
unsigned int secs;
unsigned int musecs;
{
time_t t = (time_t) secs;
char buf[32];
#ifdef SOLAR
char * x = ctime_r(&t, buf, sizeof(buf));
#else
char * x = ctime_r(&t, buf);
#endif

    if (x != (char *) NULL)
        fprintf(fp, "%2.2s %3.3s %4.4s %8.8s.%06d|",
            (x + 8), (x + 4), (x + 20), (x + 11),
            musecs);
    return;
}
/*
 * The Win32 inet_ntoa is incredibly expensive, hence these
 */
char * e2inet_ntoa_r(l, ret_buf)
struct in_addr l;
char * ret_buf;
{
union {
unsigned char c[4];
struct in_addr l;
} test;

    test.l = l;
    if (test.c[0] == 255 && test.c[1] == 2 && test.c[2] == 0 && test.c[3] == 0)
        fputs("WTF!?\n", stderr);
    sprintf(ret_buf, "%u.%u.%u.%u", test.c[0], test.c[1], test.c[2], test.c[3]);
    return ret_buf;
}
#ifdef NT4
char * e2inet_ntoa(l)
struct in_addr l;
{
static char ret_buf[16];

    return e2inet_ntoa_r(l, ret_buf);
}
#endif
/*
 * Useful from/to function
 */
void ip_dir_copy(buf, f, out)
char * buf;
struct frame_con * f;
int out;
{
char x1[16];
char x2[16];
unsigned short x4,x5;
unsigned char c[4];

    memcpy(c, &(f->net_from[1]), sizeof(unsigned int));
    sprintf(x1, "%u.%u.%u.%u", c[0], c[1], c[2], c[3]);
    memcpy(c, &(f->net_to[1]), sizeof(unsigned int));
    sprintf(x2, "%u.%u.%u.%u", c[0], c[1], c[2], c[3]);
    memcpy((char *) &x4, &(f->port_from[1]), sizeof(unsigned short));
    memcpy((char *) &x5, &(f->port_to[1]), sizeof(unsigned short));
    if (!out)
        sprintf(buf, "%s;%d:%s;%d", x1, x4,  x2, x5);
    else
        sprintf(buf, "%s;%d:%s;%d", x2, x5,  x1, x4);
    return;
}
/*
 * Useful from/to output function
 */
void ip_dir_print(fp, f, out)
FILE * fp;
struct frame_con * f;
int out;
{
char x[50];

    ip_dir_copy(x, f, out);
    fputs(x, fp);
    return;
}
/*
 * Print packet size and timing
 */
void pst_print(fp, frp, date_flag)
FILE * fp;
struct frame_con * frp;
int date_flag;
{
    fprintf(fp, "%d|", frp->pack_no);
    if (date_flag)
        date_out(fp, frp->this_time.tv_sec, frp->this_time.tv_usec);
    else
        fprintf(fp, "%u.%06d|", frp->this_time.tv_sec, frp->this_time.tv_usec);
    fprintf(fp, "%d|", frp->pack_len);
    return;
}
/*
 * Print packet head details
 */
void head_print(fp, frp)
FILE * fp;
struct frame_con * frp;
{
char x[20];
    fputs (e2ether_ntoa_r(&(frp->phys_from[1]), x), fp);
    fputc('|', fp);
    fputs (e2ether_ntoa_r(&(frp->phys_to[1]), x), fp);
    fputc('|', fp);
    switch(frp->prot)
    {
    case E2_TCP:
        fputs("TCP|",fp);
        break;
    case E2_UDP:
        fputs("UDP|",fp);
        break;
    case E2_ARP:
        fputs("ARP|",fp);
        break;
    case E2_REVARP:
        fputs("REVARP|",fp);
        break;
    case E2_NOVELL:
        fputs("NOVELL|",fp);
        break;
    case E2_LLC:
        fputs("LLC|",fp);
        break;
    case E2_PUP:
        fputs("PUP|",fp);
        break;
    case E2_X75:
        fputs("X75|", fp);
        break;
    case E2_X25:
        fputs("X25|", fp);
        break;
    case E2_BANYAN:
        fputs("BANYAN|", fp);
        break;
    case E2_DECMOP1:
        fputs("DECMOP1|", fp);
        break;
    case E2_DECMOP2:
        fputs("DECMOP2|", fp);
        break;
    case E2_DECNET:
        fputs("DECNET|", fp);
        break;
    case E2_DECLAT:
        fputs("DECLAT|", fp);
        break;
    case E2_DECDIAGNOSTIC:
        fputs("DECDIAGNOSTIC|", fp);
        break;
    case E2_DECLANBRIDGE:
        fputs("DECLANBRIDGE|", fp);
        break;
    case E2_DECETHENCR:
        fputs("DECETHENCR|", fp);
        break;
    case E2_APPLETALK:
        fputs("APPLETALK|", fp);
        break;
    case E2_IBMSNA:
        fputs("IBMSNA|", fp);
        break;
    case E2_SNMP:
        fputs("SNMP|", fp);
        break;
    case E2_ICMP:
        fputs("ICMP|",fp);
        break;
    case E2_UNKNOWN:
        fputs("UNKNOWN|",fp);
        break;
    default:
        fprintf(fp, "IP_%d|",frp->prot - E2_ICMP);
        break;
    }
    if (frp->prot == E2_TCP || frp->prot == E2_UDP || frp->prot >= E2_ICMP)
    {
    struct in_addr x;
    unsigned short int from, to;
    char x1[16];

        memcpy((char  *) &x, &(frp->net_from[1]), sizeof(struct in_addr));
        fputs( e2inet_ntoa_r(x, x1)  ,fp);
        fputc('|', fp);
        memcpy((char  *) &x, &(frp->net_to[1]), sizeof(struct in_addr));
        fputs(e2inet_ntoa_r(x, x1) ,fp);
        memcpy((char  *) &from, &(frp->port_from[1]),
             sizeof(unsigned short int));
        memcpy((char  *) &to, &(frp->port_to[1]),
             sizeof(unsigned short int));
        fprintf(fp, "|%d|%d|", from, to);
    }
    else
        fputs( "||||", fp);
    return;
}
/*
 * Print packet summary details
 */
void gen_print(fp, frp)
FILE * fp;
struct frame_con * frp;
{
    fprintf(fp, "%d|%d|%d|%d|%d|%d|%d.%06d|%d.%06d|%d.%06d|%d.%06d|",
    frp->cnt[0],
    frp->cnt[1],
    frp->len[0],
    frp->len[1],
    frp->retrans[0],
    frp->retrans[1],
    frp->cs_tim[0].tv_sec,
    frp->cs_tim[0].tv_usec,
    frp->nt_tim[0].tv_sec,
    frp->nt_tim[0].tv_usec,
    frp->nt_tim[1].tv_sec,
    frp->nt_tim[1].tv_usec,
    frp->cs_tim[1].tv_sec,
    frp->cs_tim[1].tv_usec);
    return;
}
/***************************************************************************
 * Timeval arithmetic functions
 *
 * t3 = t1 - t2
 */
void tvdiff(t1, m1, t2, m2, t3, m3)
#ifdef SOL10
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
        *m3 = (*m3) + 1000000;
        (*t3)--;
    }
    return;
}
void tvdiff32(t1, m1, t2, m2, t3, m3)
#endif
int * t1;
int * m1;
int * t2;
int * m2;
int * t3;
int * m3;
{
    *t3 = *t1 - *t2;
    *m3 = *m1 - *m2;
    if (*m3 < 0)
    {
        *m3 = (*m3) + 1000000;
        (*t3)--;
    }
    return;
}
/*
 * t3 = t1 + t2
 */
void tvadd(t1, m1, t2, m2, t3, m3)
#ifdef SOL10
long * t1;
long * m1;
long * t2;
long * m2;
long * t3;
long * m3;
{
    *t3 = *t1 + *t2;
    *m3 = *m1 + *m2;
    if (*m3 > 1000000)
    {
        *m3 = (*m3) - 1000000;
        (*t3)++;
    }
    return;
}
void tvadd32(t1, m1, t2, m2, t3, m3)
#endif
int * t1;
int * m1;
int * t2;
int * m2;
int * t3;
int * m3;
{
    *t3 = *t1 + *t2;
    *m3 = *m1 + *m2;
    if (*m3 > 1000000)
    {
        *m3 = (*m3) - 1000000;
        (*t3)++;
    }
    return;
}
/**************************************************************************
 * Functions to hang on to packets.
 *
 * Save a packet, with control details
 */
struct pack_con * pack_save(pack_no, pack_len, orig_len, pack_ptr, secs, usecs)
int pack_no;          /* Ordinal of packet in stream               */
int pack_len;         /* Length of captured packet                 */
int orig_len;         /* Pre-truncation length                     */
char * pack_ptr;      /* The packet itself                         */
int secs;
int usecs;
{
struct pack_con * buf = (struct pack_con *) malloc(sizeof(struct pack_con)
                              + (pack_len + 8) * sizeof(char));
    if (buf == NULL)
    {
        fputs("We have run out of memory in pack_save\n", stderr);
        exit(1);
    }
    buf->pack_no = pack_no;
    buf->pack_len = pack_len;
    buf->tcp_len = 0;
    buf->tcp_flags = 0;
    buf->seq = 0;
    buf->ack = 0;
    buf->win = 0;
    buf->orig_len = orig_len;
    buf->ref_cnt = 1;
    buf->pack_ptr = (char *) (buf + 1);
    memcpy(buf->pack_ptr, pack_ptr, pack_len);
    buf->timestamp.tv_sec = secs;
    buf->timestamp.tv_usec = usecs;
    buf->cs_tim[0].tv_sec = 0;
    buf->cs_tim[0].tv_usec = 0;
    buf->cs_tim[1].tv_sec = 0;
    buf->cs_tim[1].tv_usec = 0;
    buf->nt_tim[0].tv_sec = 0;
    buf->nt_tim[0].tv_usec = 0;
    buf->nt_tim[1].tv_sec = 0;
    buf->nt_tim[1].tv_usec = 0;
    return buf;
}
/*
 * Function to bin a packet. Used with the circular buffer management
 */
void pack_drop(buf)
struct pack_con * buf;
{
    buf->ref_cnt--;
    if (buf->ref_cnt <= 0)
        free(buf);
    return;
}
/**************************************************************************
 * Functions to manage circular buffers.
 *
 * Create a circular buffer
 */
struct circbuf * circbuf_cre(nelems, get_rid)
int nelems;
void (*get_rid)();
{
struct circbuf * buf = (struct circbuf *) malloc(sizeof(struct circbuf)
                              + (nelems+1) * sizeof(char *));
    if (buf == (struct circbuf *) NULL)
        return (struct circbuf *) NULL;
    else
    {
        buf->buf_cnt = 0;
        buf->get_rid = get_rid;
        buf->head = (char **) (buf + 1);
        buf->tail = buf->head;
        buf->base = buf->head;
        buf->top = buf->head + nelems;
        return buf;
    }
}
/*
 * Destroy a circular buffer
 */
void circbuf_des(buf)
struct circbuf * buf;
{
char * lp;

   if (buf->get_rid != NULL)
       while(circbuf_take(buf, &lp) >= 0)
           (*(buf->get_rid))(lp);
   free(buf);
   return;
}
#ifdef DO_WATCH
static char ** to_be_checked;
static char * check_value;
void do_check(narr)
char * narr;
{
    if (to_be_checked != (char **) NULL && *to_be_checked != check_value)
    {
        fprintf(stderr, "Corruption detected by %s, was %x now %x\n", narr,
                (unsigned long) check_value, (unsigned long) *to_be_checked);
        to_be_checked = (char **) NULL;
    }
    return;
}
#endif
/*
 * Add an element to the buffer
 */
int circbuf_add(buf,x)
struct circbuf *buf;
char *x;
{
register struct circbuf * rbuf = buf;
register char ** new_head = rbuf->head;

    new_head++;
    if (new_head == rbuf->top)
        new_head = rbuf->base;
    if (new_head == rbuf->tail)
    {
    char *lp;

        if (rbuf->get_rid == NULL
          || circbuf_take(rbuf, &lp) < 0)
            return 0;   /* Would wrap round and no discard; cannot process */
        (*(rbuf->get_rid))(lp);
    }
#ifdef DO_WATCH
    if ((unsigned long) x == 0x30a38d8)
    {
        to_be_checked = rbuf->head;
        check_value = x;
    }
    else
        do_check("circbuf_add()");
#endif
    *(rbuf->head) =  x;
    rbuf->head = new_head;
#ifdef DO_WATCH
    fprintf(stderr,"Add:%x:%d:%x\n", (unsigned long) rbuf, rbuf->buf_cnt,
             (unsigned long) x);
    do_check("circbuf_add() after fprintf");
    fflush(stdout);
    fflush(stderr);
#endif
    return ++(rbuf->buf_cnt);
}
/*
 * Remove an element from the buffer.
 */
int circbuf_take(buf,x)
struct circbuf * buf;
char ** x;
{
register struct circbuf * rbuf = buf;

    if (rbuf->buf_cnt <= 0)
        return -1;
    else
        *x = *(rbuf->tail++);
    if (rbuf->tail == rbuf->top)
        rbuf->tail = rbuf->base;
#ifdef DEBUG_FULL
    if (*x < (char *) 0x400000)
    {
        (void) fprintf(stderr,
             "Logic Error: returning invalid pointer %x from circbuf_take()!\n\
Count: %d Base: %x Tail:%x Head: %x Top: %x\n", (unsigned long) *x,
                 (rbuf->buf_cnt - 1), (unsigned long) (rbuf->base),
                 (unsigned long) (rbuf->tail), (unsigned long) (rbuf->head),
                 (unsigned long) (rbuf->top));
        fflush(stdout);
        fflush(stderr);
        return -1;
    }
#endif
#ifdef DO_WATCH
    do_check("circbuf_take()");
    fprintf(stderr,"Take:%x:%d:%x\n", (unsigned long) rbuf, rbuf->buf_cnt,
                   (unsigned long) *x);
    fflush(stdout);
    fflush(stderr);
#endif
    return --(rbuf->buf_cnt);
}
/*
 * Read an element from the buffer. The index is:
 * - 1 based
 * - LIFO (in that the newest item has the lowest index).
 */
int circbuf_read(buf, x, ind)
struct circbuf * buf;
char ** x;
int ind;
{
char ** rptr;

    if (ind < 1 || buf->buf_cnt < ind)
        return -1;     /* An error if the index is out of range */
#ifdef FIFO_NUMBERING
    rptr = buf->tail + ind - 1;
    if (rptr >= buf->top)
        rptr -= (buf->top - buf->base);
#else
    rptr = buf->head - ind;
    if (rptr < buf->base)
        rptr += (buf->top - buf->base);
#endif
    *x = *rptr;
    return buf->buf_cnt;
}
void pack_head_print(pcp, ofp)
struct pack_con *pcp;
FILE *ofp;
{
    fprintf(ofp, "%d|", pcp->pack_no);
    date_out(ofp, pcp->timestamp.tv_sec, pcp->timestamp.tv_usec);
    fprintf(ofp, "%d|%d.%06d|%d.%06d|%d.%06d|%d.%06d|%d|%x|%u|%u|%u|%d\n",
            pcp->orig_len,
            pcp->cs_tim[0].tv_sec,
            pcp->cs_tim[0].tv_usec,
            pcp->nt_tim[0].tv_sec,
            pcp->nt_tim[0].tv_usec,
            pcp->nt_tim[1].tv_sec,
            pcp->nt_tim[1].tv_usec,
            pcp->cs_tim[1].tv_sec,
            pcp->cs_tim[1].tv_usec,
            pcp->tcp_len,
            (((unsigned int) pcp->tcp_flags) & 0xff),
            pcp->seq,
            pcp->ack,
            pcp->win,
            pcp->pack_len);
     return;
}
/*
 * Dump out the packets in a circular buffer
 */
void circbuf_dump(pack_ring, ofp)
struct circbuf *pack_ring;
FILE *ofp;
{
struct pack_con *pcp;

    if (ofp == NULL)
        return;
    while (circbuf_take(pack_ring, (char **) &pcp) >= 0)
    {
         pack_head_print(pcp, ofp);
#ifdef DEBUG
        fflush(ofp);
#endif
        gen_handle(ofp, pcp->pack_ptr, pcp->pack_ptr+pcp->pack_len,1);
        pack_drop(pcp);
    }
    return;
}
/*
 * Dump session details
 */
void frame_dump(frp, lbl, verbose_flag)
struct frame_con * frp;
char * lbl;
int verbose_flag;
{
    if (frp->ofp == NULL)
        return;
    fputs(lbl, frp->ofp);
    head_print(frp->ofp,frp);
    gen_print(frp->ofp,frp);
    if (frp->do_mess != NULL)
        fputc('\\', frp->ofp);
    fputc('\n', frp->ofp);
    if (verbose_flag && frp->pack_ring != (struct circbuf *) NULL)
        circbuf_dump(frp->pack_ring, frp->ofp);
    return;
}
/*
 * Accumulate complete application messages from a TCP stream.
 * - Something must have initialised the fixed length, length size and
 *   offset fields, and the function that processes messages.
 * - The code requires that the pack length and the original length are the same
 * - Make adjustments for retransmissions and gaps
 * - Out is the direction flag.
 */
void tcp_frame_accum(f, pcp, out)
struct frame_con *f;
struct pack_con *pcp;
int out;
{
unsigned char *p;
int len;
int dir_flag;
int sav_len;
unsigned char * t_pack = (unsigned char *) NULL;

    if (f->do_mess == NULL && f->ofp != NULL)
    {
        fputc('\n', f->ofp);
        fwrite(pcp->tcp_ptr,sizeof(char),pcp->tcp_len,f->ofp);
        fputc('\n', f->ofp);
        return;
    }
    else
    if (pcp->pack_len != pcp->orig_len)
    {
#ifdef DEBUG
        if (frp->ofp != NULL)
        {
            fprintf(f->ofp,
             "Truncated packet: %d to %d\n", pcp->orig_len, pcp->pack_len);
            fflush(f->ofp);
        }
#endif
        return;
    }
#ifdef DEBUG
    if (frp->ofp != NULL)
    {
        (void) gen_handle(f->ofp,
            (unsigned char *) (pcp->tcp_ptr),
            ((unsigned char *) (pcp->tcp_ptr + pcp->tcp_len) >
            (unsigned char *) (pcp->pack_ptr + pcp->pack_len)) ?
            (unsigned char *) (pcp->pack_ptr + pcp->pack_len) :
            (unsigned char *) (pcp->tcp_ptr + pcp->tcp_len),1);
        fflush(f->ofp);
    }
#endif
/*
 * First, work out where the message fragment starts.
 * - Is there a retransmitted element or a dropped element?
 */
    if ((f->seq[out]) != 0)
    {
        if (f->seq[out] <= (pcp->seq + 1) && f->seq[out] >= (pcp->seq - 1))
        {
/*
 * I suspect that this phenomenom signals zero length messages
 */
            len = pcp->tcp_len;
            f->seq[out] = pcp->seq;
        }
        else
        {
            len = pcp->tcp_len - (f->seq[out] - pcp->seq);
            if (len != pcp->tcp_len)
            {
                if (f->ofp != NULL)
                {
                    fprintf(f->ofp,
   "\\Corruption in %d (%s) %s: this_time: %u.%06d Old seq: %u New seq: %u Old len: %d New len: %d\\\n",
                pcp->pack_no,
                (out ? ("S=>C") : ("C=>S")),
                (len > pcp->tcp_len) ? "drop" : "retransmission",
                   f->this_time.tv_sec, f->this_time.tv_usec,
                   f->seq[out], pcp->seq, pcp->tcp_len, len);
                    fflush(f->ofp);
                }
                if (len > pcp->tcp_len)
                {
                    f->corrupt_flag = 1; /* Lost a bit; response calculations
                                          * are not safe */
                    f->len[out]++;       /* Perhaps better would be to add
                                            based on the average packet size?
                                          */
                    f->len[out] += (len - pcp->tcp_len);
                                         /* Add the dropped to the totals */
                }
            }
            if (len <= 0  && len > -32768)
            {
                f->corrupt_flag = 1;  /* Response calculations can be thrown */
                if (f->seq[out] == 0)
                {           /* We missed the start of the session */
                    len = pcp->tcp_len;
                    f->seq[out] = pcp->seq;
                }
                else
                    return;        /* Ignore re-transmission   */
            }
            else
            if (f->left[out] == 0 || len > 32768 || len <= -32768)
            {                      /* Re-synchronise from here */
                len = pcp->tcp_len;
                f->seq[out] = pcp->seq;
            }
        }
    }
    else
        len = pcp->tcp_len;
#ifdef DEBUG
    if (f->ofp != NULL)
    {
        fprintf(f->ofp, "old_seq: %u new_seq: %u old_len: %d new_len: %d\n",
           f->seq[out], pcp->seq, pcp->tcp_len, len);
        fflush(f->ofp);
    }
#endif
    f->seq[out] = pcp->seq + pcp->tcp_len;
    if (len > pcp->tcp_len)
    {
        t_pack = (unsigned char *) calloc(len, 1);
#ifdef DEBUG
        if (f->ofp != NULL)
        {
            fprintf(f->ofp, "Dropped: %d\n", (len - (pcp->tcp_len)));
            fflush(f->ofp);
        }
#endif
        memcpy(t_pack + (len - pcp->tcp_len), pcp->tcp_ptr, pcp->tcp_len);
        p = t_pack;
        f->corrupt_flag = 1;     /* Response calculations can be thrown */
    }
    else
    if (len == 0)
        return;
    else
        p = (unsigned char *) (pcp->tcp_ptr + pcp->tcp_len - len);
/*
 * Output packet details if the direction has changed
 */
#ifdef VERBOSE
    if (f->last_app_out != out && f->ofp != NULL)
    {
        fprintf(f->ofp, "\\C:%d:%d:", pcp->pack_no, f->pack_len);
        date_out(f->ofp, f->this_time.tv_sec, f->this_time.tv_usec);
        ip_dir_print(f->ofp, f, out);
        fputs("\\\n", f->ofp);
    }
#endif
    if (out)
        dir_flag = 1;
    else
        dir_flag = 0;
    f->last_app_out = out;
#ifdef DEBUG
    if (f->ofp != NULL)
    {
        fprintf(f->ofp, "Length: %d Message:\n", len);
        fflush(f->ofp);
        gen_handle(f->ofp, p,(p+len <=pcp->pack_ptr + pcp->pack_len)? (p+len):
                          (pcp->pack_ptr + pcp->pack_len),1);
        fputs("--------\n", f->ofp);
        fprintf(f->ofp,
          "dir_flag: %d f->left[dir_flag]: %d\n",dir_flag,f->left[dir_flag]);
        fputs("========\n", f->ofp);
        fflush(f->ofp);
    }
#endif
multi_mess:
/*
 * This is a new message starting
 */
    if (f->left[dir_flag] == 0)
    {
        if (!(f->len_len))
            f->left[dir_flag] = len;
        else
        {
/*
 * The first step is to make sure that we have at least the fixed size header.
 */
            if (len + f->res_len[dir_flag] < f->fix_size)
            {
                return; /* MSSQL, discard ... */
                memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p, len);
                f->res_len[dir_flag] += len;
                if (t_pack != (unsigned char *) NULL)
                    free(t_pack);
                return;
            }
            else
/*
 * If we have a reserved amount, pull the length from there, and adjust the
 * main buffer details accordingly.
 *
 * If big_little is true, the length is little-endian.
 */
            if (f->res_len[dir_flag] != 0)
            {
                memcpy(&(f->reserve[dir_flag][(f->res_len[dir_flag])]), p,
                     f->fix_size - f->res_len[dir_flag]);
                p += (f->fix_size - f->res_len[dir_flag]);
                len -= (f->fix_size - f->res_len[dir_flag]);
                f->res_len[dir_flag] = f->fix_size;
                f->left[dir_flag] = ((f->big_little)
                      ? get_lit_end( &(f->reserve[dir_flag][f->off_flag]),
                                 f->len_len)
                      : get_big_end( &(f->reserve[dir_flag][f->off_flag]),
                                 f->len_len))
                   + ((f->fix_mult)?f->fix_size:0);
            }
            else
                f->left[dir_flag] = ((f->big_little)
                      ? get_lit_end( p + f->off_flag, f->len_len)
                      : get_big_end(p + f->off_flag, f->len_len))
                   + ((f->fix_mult)?f->fix_size:0);
        }
        f->ini_t[dir_flag] = f->this_time;
        if ((f->len_len == 2 && f->left[dir_flag] > 32766)
         || (f->len_len == 4 && f->left[dir_flag] > 32766 * 256)
         || f->left[dir_flag] == 0)
        {   /* Apparently lost synchronisation */
#ifdef DEBUG
        if (f->ofp != NULL)
        {
            fprintf(f->ofp,"Apparently lost synchronisation: length = %d\n",
            f->left[dir_flag]);
            fflush(f->ofp);
        }
#endif
            f->corrupt_flag = 1;
            f->res_len[dir_flag] = 0;
            f->left[dir_flag] = 0;
            if (t_pack != (unsigned char *) NULL)
                free(t_pack);
            return;
        }
        f->hold_buf[dir_flag] = (unsigned char *)
              malloc((f->left[dir_flag] > (len + f->res_len[dir_flag]))?
                    f->left[dir_flag] : (len + f->res_len[dir_flag]));
#ifdef DEBUG
    if (f->ofp != NULL)
    {
        fprintf(f->ofp,
           "malloc(): len: %d f->left[dir_flag]: %d f->res_len[dir_flag]: %d\n",
                          len, f->left[dir_flag], f->res_len[dir_flag]);
        fflush(f->ofp);
    }
#endif
        f->top[dir_flag] = f->hold_buf[dir_flag];
    }
    else
    {
/*
 * This piece has the end of an existing message, and a new one starts in the
 * middle of it. Allocate space at the end of the existing buffer for the
 * overshoot.
 */
        if (f->left[dir_flag] < len)
        {
            sav_len = f->top[dir_flag] - f->hold_buf[dir_flag];
            f->hold_buf[dir_flag] = (unsigned char *)
                 realloc(f->hold_buf[dir_flag],
                          sav_len + len + f->res_len[dir_flag]);
            f->top[dir_flag] = f->hold_buf[dir_flag] + sav_len;
        }
    }
    if (len < 0 || f->top[dir_flag] < f->hold_buf[dir_flag])
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
    if  (p+len <=pcp->pack_ptr + pcp->pack_len)
        memcpy(f->top[dir_flag],p,len);
    else
        memcpy(f->top[dir_flag],p,
                          ((unsigned char *)(pcp->pack_ptr + pcp->pack_len)) -  p);
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
/*
 * ccsextlib.c does not handle this case properly
 */
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
        if (f->left[dir_flag] == 0)
            free(f->hold_buf[dir_flag]);
    }
#ifdef DEBUG
    else
    if (f->ofp != NULL)
    {
        fputs("Still to come:\n", f->ofp);
        fprintf(f->ofp,
             "dir_flag: %d left[dir_flag]: %d\n",dir_flag,f->left[dir_flag]);
        fputs("========\n", f->ofp);
        fflush(f->ofp);
    }
#endif
    if (t_pack != (unsigned char *) NULL)
        free(t_pack);
    pack_drop(pcp);
    return;
}
/*****************************************************************************
 * Common routine to work out overall response times for transactions
 *
 * A transaction starts when a non-zero message is sent to the server,
 * and is seen to end when there is a gap of more than gap between the
 * last application message from the server, and this message from the
 * client.
 *
 * The gap is set protocol by protocol. Set it to zero to give per-message
 * timings.
 *
 * Because we cannot guarantee to see the packet in the right direction first,
 * our server may be the From or To. The toggling of dir_flag takes care of
 * this.
 */
void output_response (f,dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval first_to_now;
struct timeval last_to_now;
struct timeval resp_time;
/*
 * When the message is going from the client to the server
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
    tvdiff(&(f->last_t[dir_flag].tv_sec), /* The time when this message began */
           &(f->last_t[dir_flag].tv_usec),
           &(f->tran_start.tv_sec),       /* The time when the previous       */
           &(f->tran_start.tv_usec),      /* transaction began                */
           &(first_to_now.tv_sec),        /* The difference                   */
           &(first_to_now.tv_usec));
    tvdiff(&(f->last_t[!dir_flag].tv_sec),
           &(f->last_t[!dir_flag].tv_usec),
           &(f->tran_start.tv_sec),
           &(f->tran_start.tv_usec),
           &(resp_time.tv_sec),           /* The Response Time               */
           &(resp_time.tv_usec));
    tvdiff(&(f->last_t[dir_flag].tv_sec),
           &(f->last_t[dir_flag].tv_usec),
           &(f->last_t[!dir_flag].tv_sec),
           &(f->last_t[!dir_flag].tv_usec),
           &(last_to_now.tv_sec),         /* The Gap                         */
           &(last_to_now.tv_usec));
    if (f->tran_start.tv_sec != 0)
    {
        if (last_to_now.tv_sec >= f->gap
          && f->tran_cnt[0] < f->cnt[0] && f->tran_cnt[1] < f->cnt[1])
        {
            if (f->corrupt_flag)
                f->corrupt_flag = 0;
/*            else */
            if (f->ofp != NULL)
            {
                head_print(f->ofp, f);
                fprintf(f->ofp, "RESPONSE|%s|%d.%06d|%d.%06d|%d|%d|%d|%d|",
                    ((f->long_label == (char *) NULL) ?
                         f->label : f->long_label),
                    f->tran_start.tv_sec, f->tran_start.tv_usec,
                    resp_time.tv_sec, resp_time.tv_usec,
                    f->cnt[!dir_flag] - f->tran_cnt[!dir_flag],
                    f->cnt[dir_flag] - f->tran_cnt[dir_flag],
                    f->len[!dir_flag] - f->tran_len[!dir_flag],
                    f->len[dir_flag] - f->tran_len[dir_flag]);
                date_out(f->ofp, f->tran_start.tv_sec, f->tran_start.tv_usec);
                fputc('\n', f->ofp);
            }
        }
    }
/*
 * The first case below corresponds to a timing having been output.
 *
 * The second case resets the start time if there was no response to the
 * last packet in the same direction.
 */
    if ((last_to_now.tv_sec >= f->gap
         && f->tran_cnt[dir_flag] < f->cnt[dir_flag])
     || (f->tran_cnt[!dir_flag] == f->cnt[!dir_flag]
       && first_to_now.tv_sec >= f->gap))
    {
        f->tran_start = f->last_t[dir_flag];
        f->tran_cnt[0] = f->cnt[0];
        f->tran_cnt[1] = f->cnt[1];
        f->tran_len[0] = f->len[0];
        f->tran_len[1] = f->len[1];
    }
    return;
}

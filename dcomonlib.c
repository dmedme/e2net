/*
 * Scan a captured network packets and work out DCOM response times
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";
#include <sys/types.h>
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#endif
#endif
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
#include "e2conv.h"
#include "e2net.h"
#include "hashlib.h"
static void mess_handle();
static void do_dcom();
/*
 * Things we use for classifying responses
 */
static struct bm_tags {
    int len;
    int uni_flag;
    unsigned char tag[36];
    struct bm_table * bp;
}
bm_tags[] =  {
    { 12, 1, { '<', 0, 'N', 0, 'A', 0, 'M', 0, 'E', 0, '>', 0} },
    { 18, 1, { '<', 0, 'S', 0, 'P', 0, '_',0, 'N', 0, 'A', 0, 'M', 0, 'E', 0, '>', 0} },
    { 24, 1, { '<', 0, 'I', 0, '_', 0, 'U',0,'S',0,'E',0,'R',0, 'N', 0, 'A', 0, 'M', 0, 'E', 0, '>', 0} },
    { 28, 1, { '<', 0, 'I', 0, '_', 0, 'C',0,'A',0,'S',0,'E',0, 'N', 0, 'U', 0, 'M', 0, 'B', 0,'E',0,'R',0, '>', 0} },
    { 30, 1, { '<', 0, 'I', 0, '_', 0, 'C',0,'A',0,'S',0,'E',0,'_',0, 'N', 0, 'U', 0, 'M', 0, 'B', 0,'E',0,'R',0, '>', 0} },
    { 24, 1, { '<', 0, 'I', 0, '_', 0, 'C',0,'A',0,'S',0,'E',0, 'N', 0, 'U', 0, 'M', 0, '>', 0} },
    { 26, 1, { '<', 0, 'I', 0, '_', 0, 'C',0,'A',0,'S',0,'E',0,'_',0, 'N', 0, 'U', 0, 'M', 0, '>', 0} },
    {0}
};
static struct bm_tags odd_tags[] = {
    { 7, 0, { 'N','T','L', 'M','S','S','P'} },
    { 4, 0, { 'M','E','O', 'W'} },
    { 34, 1, { 'C', 0, 'A', 0, 'S',0,'E',0,'V',0,'I',0,'E',0, 'W', 0, '.', 0, 'G', 0, 'E', 0,'T',0,'C',0, 'A', 0, 'S',0,'E',0,'S',0} },
    {0}
};

/*
 * Structure allocated when a session is started that holds session state.
 *
 * This code handles multiple parallel sessions, but discards asynchronous
 * calls. The USER_MESSAGES are ignored.
 */
struct mess_frame {
    int context_id;
    int call_id;
    int uni_flag;
    int uni_cnt;
    unsigned char *uni_label[8];
    struct timeval tv;
    int in_use;
};
struct dcom_context {
    unsigned char *hold_buf[2]; /* Place for assembling application messages */
    unsigned char * top[2];
    struct mess_frame mess[32];
    int hwm;
    unsigned char flag;
};
static struct frame_con * cur_frame;
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */
static int match_port[100];    /* List of ports to match against          */

static int match_cnt;              /* Number of ports in the list    */
static void dcom_match_add(port)
int port;
{
    if (match_cnt < 100)
    {
       match_port[match_cnt] = port;
       match_cnt++;
    }
    return;
}
/*
 * Allow listener ports to be specified in the environment
 */
static void extend_listen_list()
{
char * x;
int i;

    extend_listen_flag = 1;
    if ((x = getenv("E2_DCOM_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)
                dcom_match_add(i);
        }
    }
    return;
}
static int dcom_match_true(from,to)
int from;
int to;
{
int i;

    return 1;
#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif
    for (i = 0; i < match_cnt; i++)
    {
       if (match_port[i] == from || match_port[i] == to)
       {
           if (match_port[i] == to)
               return  1; /* Flag which end is the client */
           else
               return -1;
       }
    }
    return 0;
}
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
register struct dcom_context * rop = (struct dcom_context *) frp->app_ptr;

/*
 * Free up the malloc()ed memory
 */
    if (rop != (struct dcom_context *) NULL)
        free((char *) rop);
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
        fclose(frp->ofp);
    return;
}
/*
 * Function to set up a Microsoft DCOM stream decoder. Separated from
 * dcom_app_recognise() so that we can recognise the DCOM traffic on the fly.
 * HTTP to DCOM.
 */
void dcom_app_initialise(frp)
struct frame_con *frp;
{
struct dcom_context * dcomp;

    frp->app_ptr = malloc(sizeof(struct dcom_context)+65536 + 8);
    dcomp = (struct dcom_context *) (frp->app_ptr);
    memset((char *) dcomp, 0, sizeof(*dcomp));
    dcomp->hold_buf[0] = (unsigned char *) (dcomp + 1);
    dcomp->hold_buf[1] = dcomp->hold_buf[0] + 32768;
    dcomp->top[0] = dcomp->hold_buf[0];
    dcomp->top[1] = dcomp->hold_buf[1];
    dcomp->hwm = 0;
    dcomp->flag = 0;
    frp->off_flag = 8;
    frp->len_len = 2;
    frp->big_little = 1; /* Length in little-endian */
    frp->fix_size = 24;
    frp->fix_mult = 0;
    frp->do_mess = do_dcom;
    frp->gap = 0;
    return;
}
/*******************************************************************************
 * Function that is called to process messages before we know the they are DCOM
 *******************************************************************************
 * Messages consist of:
 * - A 24 byte header
 *   - A 1 byte version major (5)
 *   - A 1 byte version minor (0)
 *   - A 1 byte packet type (0 = Request)
 *   - A 1 byte packet flags
 *      1 - First frag
 *      2 - Last frag
 *      4 - Cancel pending
 *      8 - Reserved
 *      16 - Multiplex
 *      32 - Did not execute
 *      64 - Maybe
 *      128 - Object
 *   - A 1 byte data representation (0x10 = little endian, ASCII)
 *   - A 1 byte Floating Point representation ( 0x00, not IEEE)
 *   - A 2 byte filler? (0x0000)
 *   - A 2 byte little-endian Frag Length. This is inclusive. Offset is 8
 *   - A 2 byte authorisation length
 *   - A 4 byte call id (sequence number)
 *   - A 4 byte allocation hint. The sum of the payloads for related frags.
 *     it matches the payload, it we allow for the last n (16 in this case)
 *     bytes for the NTLMSSP verifier, preceded by 8 bytes of auth type. 
 *   - A 2 byte context ID; relates to the session. Context ID + call ID
 *     match request/response.
 *   - A 2 operation number
 * - A 16 byte Object ID, if the object flag is set
 * - Some number of bytes of payload.
 * - 8 bytes of Auth header
 *   - A 1 byte auth type; (0x10) = NTLMSSP
 *   - A 1 byte auth level; (0x02) = Connect
 *   - A 1 byte auth pad len; (0x00)
 *   - A 1 byte auth reserved; (0x00)
 *   - A 4 byte auth context ID.
 *   - A 12 byte NTLMSSP Verifier
 */
static void do_check(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
    char *x =frp->hold_buf[dir_flag];
    int i = frp->top[dir_flag] -frp->hold_buf[dir_flag];

        if (i >=24
         && *x == 5
         && *(x + 1) == 0
         && *(x + 4) == 0x10
         && *(x + 5) == 0
         && *(x + 6) == 0
         && *(x + 7) == 0)
        {
            dcom_app_initialise(frp);
            do_dcom(frp, dir_flag);
            return;
        }
    }
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int dcom_app_recognise(frp)
struct frame_con *frp;
{
char fname[32];
int i;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is identified in the list of interesting ports, managed
 *    with dcom_match_add() and dcom_match_true()
 */
    if (extend_listen_flag == 0)
        extend_listen_list();
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;
    struct dcom_context * dcomp;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if ((i = dcom_match_true(from, to)))
        {
        static int sess_cnt = 0;

            sprintf(fname,"dcom_%d.msg", sess_cnt++);
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            if (i < 0)
                frp->reverse_sense = 1;
            frp->do_mess = do_check;
            frp->cleanup = do_cleanup;
            fputs( "\\M:", frp->ofp);
            ip_dir_print(frp->ofp, frp, 0);
            fputs( "\\\n", frp->ofp);
            return 1;
        }
    }
    return 0;
}
/*
 * Dump out a human-readable rendition of the Microsoft DCOM messages
 * - Messages consist of:
 *   - A 24 byte header
 *   - An optional 16 byte Object UUID
 *   - 'Stub Data' (arguments for the remotely invoked animal)
 *   - Security stuff (8 bytes plus the auth details)
 */
unsigned char * dcom_handle(ofp, base, top, out_flag)
FILE *ofp;
unsigned char * base;
unsigned char * top;
int out_flag;
{
    return gen_handle(ofp, base, top, out_flag);
}
/*
 * Deal with a fragment of Microsoft DCOM traffic
 */
static void dcom_dispose(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * x;
unsigned char * top;
struct dcom_context * ap = (struct dcom_context *) (frp->app_ptr);

    x = ap->hold_buf[dir_flag];
    top = ap->top[dir_flag];
    if (*x != '\0'
     || x + x[3] + (x[2] << 8) + (x[1] << 16) + (x[0] << 24) == top)
    {
        fprintf(frp->ofp, "\\%c:B:",
           ((!dir_flag) ^ frp->reverse_sense) ? 'D' : 'A');
        ip_dir_print(frp->ofp, frp, dir_flag);
        fputs("\\\n", frp->ofp);
        while  (x < top)
            x = dcom_handle(frp->ofp, x, top, 1);
        fprintf(frp->ofp, "\\%c:E\\\n",
           ((!dir_flag) ^ frp->reverse_sense) ? 'D' : 'A');
    }
    return;
}
/*
 * Special version of the standard response output routine. This is needed
 * because we write on seeing the return packet, rather than on the next
 * request, as we normally do.
 */
void dcomoutput_response (f,dir_flag, to_match)
struct frame_con * f;
int dir_flag;
int to_match;
{
struct timeval resp_time;
struct dcom_context * dcomp = (struct dcom_context *) (f->app_ptr);
unsigned char label[81];
unsigned char * lp;
unsigned char * ep;
int i, len;
/*
 * We need to output a response record:
 * - Record Type
 * - Label
 * - Time Start
 * - Response
 * - Packets Out
 * - Packets In
 * - Bytes Out
 * - Bytes In
 */
    if ( dcomp->mess[to_match].uni_cnt == 0)
        lp = "";
    else
    if ( dcomp->mess[to_match].uni_flag == 1)
    {
        for ( lp = label, i = 0;
                 (i < dcomp->mess[to_match].uni_cnt) && (lp < &label[81]);
                    i++)
        {
            
            if ((ep = memchr(dcomp->mess[to_match].uni_label[i],'<',
                  2 * (&label[80] - lp))) != NULL)
            {
                len = (ep - dcomp->mess[to_match].uni_label[i])/2;
                uni2asc(lp, dcomp->mess[to_match].uni_label[i], len);
                lp += len;
                *lp = '}';
                lp++;
            }
        }
        lp--;
        *lp = '\0';
        lp = label;
    }
    else
    {
        for ( lp = label, i = 0;
                 (i < dcomp->mess[to_match].uni_cnt) && (lp < &label[81]);
                    i++)
        {
        struct bm_tags * btp = (struct bm_tag *)
                             dcomp->mess[to_match].uni_label[i];

            if (btp->uni_flag)
            {
                len = btp->len/2;
                if (len > (&label[80] - lp))
                    len =  (&label[80] - lp);
                uni2asc(lp, btp->tag, len);
            }
            else
            {
                len =  btp->len;
                if (len > (&label[80] - lp))
                    len =  (&label[80] - lp);
                memcpy(lp, btp->tag, len);
            }
            lp += len;
            *lp = '}';
            lp++;
        }
        lp--;
        *lp = '\0';
        lp = label;
    }
    if (dir_flag == -1)
    {
        head_print(f->ofp, f);
        fprintf(f->ofp, "DROPPED|%s|%d.%06d|",
            lp,
            (dcomp->mess[to_match].tv.tv_sec),
            (dcomp->mess[to_match].tv.tv_usec));
        date_out(f->ofp,
            (dcomp->mess[to_match].tv.tv_sec),
            (dcomp->mess[to_match].tv.tv_usec));
        fputc('\n', f->ofp);
        return;
    }
    tvdiff(&(f->last_t[dir_flag].tv_sec),
           &(f->last_t[dir_flag].tv_usec),
           &(dcomp->mess[to_match].tv.tv_sec),
           &(dcomp->mess[to_match].tv.tv_usec),
           &(resp_time.tv_sec),           /* The Response Time               */
           &(resp_time.tv_usec));
    head_print(f->ofp, f);
    fprintf(f->ofp, "RESPONSE|%s|%d.%06d|%d.%06d|%d|%d|%d|%d|",
            lp,
           (dcomp->mess[to_match].tv.tv_sec),
           (dcomp->mess[to_match].tv.tv_usec),
            resp_time.tv_sec, resp_time.tv_usec,
            f->cnt[!dir_flag] - f->tran_cnt[!dir_flag],
            f->cnt[dir_flag] - f->tran_cnt[dir_flag],
            f->len[!dir_flag] - f->tran_len[!dir_flag],
            f->len[dir_flag] - f->tran_len[dir_flag]);
    date_out(f->ofp,
            (dcomp->mess[to_match].tv.tv_sec),
            (dcomp->mess[to_match].tv.tv_usec));
    fputc('\n', f->ofp);
    f->tran_cnt[0] = f->cnt[0];
    f->tran_cnt[1] = f->cnt[1];
    f->tran_len[0] = f->len[0];
    f->tran_len[1] = f->len[1];
    f->label[0] = '\0';
    return;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum(), if we appear to be looking at DCOM.
 */
static void do_dcom(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * p;
unsigned char * p1;
int last_frag;
int tran_len;
int len;
int i;
struct dcom_context * dcomp;
struct bm_tags *stp = &bm_tags[0];

    if (bm_tags[0].bp == (struct bm_table *) NULL)
    {  /* Array of interesting XML tags to look for */

        while (stp->len != 0)
        {
            stp->bp = bm_compile_bin(stp->tag, stp->len);
            stp++;
        }
        for (stp = &odd_tags[0]; stp->len != 0; stp++)
            stp->bp = bm_compile_bin(stp->tag, stp->len);
    }
    cur_frame = frp;
/*
 * First we have the Header to deal with
 */
    p = frp->hold_buf[dir_flag];
    len = frp->top[dir_flag] - p;
#ifdef DEBUG
    fprintf(frp->ofp, "do_dcom(%lx) = (%lx, %d)\n", (long) frp,
               p, len);
    fflush(frp->ofp);
#endif
    dcomp = (struct dcom_context *) (frp->app_ptr);
    dcomp->flag = *(p + 3);
/*
 * Outgoing message with the First flag set; save the details.
 */
    if (((!dir_flag) ^ frp->reverse_sense) && (dcomp->flag & 1))
    {
        if ((dcomp->top[dir_flag]  - dcomp->hold_buf[dir_flag]) + len > 32768)
        {                         /* Too little buffer space */
            for (i = 0; i < dcomp->hwm; i++)
            {
                if (dcomp->mess[i].in_use)
                    dcomoutput_response(frp, -1, i);
                         /* Record the drop */
            }
            dcomp->top[dir_flag] = dcomp->hold_buf[dir_flag]; /* Discard it */
            dcomp->hwm = 0;
            memset(&dcomp->mess[0], 0, sizeof(dcomp->mess));
            if (len  > 32768)
                return;
        }
/***********************************************************************
 * Manage a stack of messages
 */
        memcpy(dcomp->top[dir_flag], p , len);
        for (i = 0; i < dcomp->hwm; i++)
            if (dcomp->mess[i].in_use == 0)
                break;
        dcomp->mess[i].in_use = 1;
        dcomp->mess[i].context_id = 
         (int) (*(dcomp->top[dir_flag] +20) + ((*(dcomp->top[dir_flag] + 21)) << 8));
        dcomp->mess[i].call_id =
        (int) (*(dcomp->top[dir_flag] + 12) + ((*(dcomp->top[dir_flag] + 13)) << 8) +
                 ((*(dcomp->top[dir_flag] + 14)) << 16) + ((*(dcomp->top[dir_flag] + 15)) << 24));
/*
 * The Transaction labels will only be in data from PC to the server
 */
        for (stp = &bm_tags[0], dcomp->mess[i].uni_cnt = 0;
                stp->len != 0;
                    stp++)
        {
            if ( (p1 = bm_match(stp->bp, dcomp->top[dir_flag],
                       dcomp->top[dir_flag] + len )) != (unsigned char *) NULL
               && memchr(p1 + stp->len, '<', dcomp->top[dir_flag] + len
                              - (p1 + stp->len))  != NULL)
            {
                dcomp->mess[i].uni_label[dcomp->mess[i].uni_cnt] = p1 +stp->len;
                dcomp->mess[i].uni_cnt++;
            }
        }
        if (dcomp->mess[i].uni_cnt >0)
            dcomp->mess[i].uni_flag = 1;
        else
        for (stp = &odd_tags[0], dcomp->mess[i].uni_flag = 0;
                stp->len != 0;
                    stp++)
        {
            if ( (p1 = bm_match(stp->bp, dcomp->top[dir_flag],
                       dcomp->top[dir_flag] + len )) != (unsigned char *) NULL)
            {
                dcomp->mess[i].uni_label[dcomp->mess[i].uni_cnt] = 
                       (char *) stp;
                dcomp->mess[i].uni_cnt++;
            }
        }
        dcomp->mess[i].tv = frp->last_t[dir_flag];     /* Time stamp */
        if (i >= dcomp->hwm && i < 31)
            dcomp->hwm++;
        dcomp->top[dir_flag] += len;
#ifdef DEBUG
        fprintf(frp->ofp, "do_dcom(%lx)\nSaved\n", (long) frp);
        gen_handle(frp->ofp, dcomp->hold_buf[dir_flag], dcomp->top[dir_flag], 1);
        fflush(frp->ofp);
#endif
        mess_handle(frp, p, p + len, (!dir_flag) ^ frp->reverse_sense);
    }
    else
    if (!((!dir_flag) ^ frp->reverse_sense) && (dcomp->flag & 2))
    {               /* Response packet with Last flag set */
/*
 * See if the from and to tally
 */
        for (i = 0, len = 0; i < dcomp->hwm; i++)
        {
            if (dcomp->mess[i].in_use)
            {
                if ((dcomp->mess[i].context_id ==
         (int) (*(p +20) + ((*(p + 21)) << 8)))
        && dcomp->mess[i].call_id ==
        (int) (*(p + 12) + ((*(p + 13)) << 8) +
                 ((*(p + 14)) << 16) + ((*(p + 15)) << 24)))
                    break;
                if (dcomp->mess[i].tv.tv_sec < frp->last_t[dir_flag].tv_sec - 600)
                {
                    dcomoutput_response(frp, -1, i);
                         /* Record the drop */
                    dcomp->mess[i].in_use = 0;   /* Time out dropped stuff */
                }
                else
                    len++;
            }
        }
        if (i >= dcomp->hwm)
        {
#ifdef DEBUG
            fputs("do_dcom() response message does not correspond\n\
ONE\n", frp->ofp);
            gen_handle(frp->ofp, p, p + len, 1);
            fputs("OTHER\n",  frp->ofp);
            gen_handle(frp->ofp, dcomp->hold_buf[!dir_flag],
                            dcomp->top[!dir_flag], 1);
            fflush(frp->ofp);
#endif
            if (len == 0)
            {
                head_print(frp->ofp, frp);
                fprintf(frp->ofp, "DROPPED|Unknown|%d.%06d|",
                    (frp->last_t[dir_flag].tv_sec),
                    (frp->last_t[dir_flag].tv_usec));
                date_out(frp->ofp,
                    (frp->last_t[dir_flag].tv_sec),
                    (frp->last_t[dir_flag].tv_usec));
                fputc('\n', frp->ofp);
                dcomp->top[!dir_flag] = dcomp->hold_buf[!dir_flag];
                dcomp->hwm = 0;
            }
            return;
        }
        dcom_dispose(frp, !dir_flag);   /* Record the response */
        dcomoutput_response(frp, dir_flag, i);   /* Record the response */
        dcomp->mess[i].in_use = 0;
        if (i == dcomp->hwm - 1)
        {
            do
            {
                dcomp->hwm--;
                i--;
            }
            while (i >= 0 && dcomp->mess[i].in_use == 0);
        }
        if ( dcomp->hwm == 0)
        {
            dcomp->top[!dir_flag] = dcomp->hold_buf[!dir_flag];
            memset(&dcomp->mess[0], 0, sizeof(dcomp->mess));
        }
    }
    return;
}
/**************************************************************************
 * Deal with the Microsoft DCOM TCP Stream
 */
static void mess_handle(frp, hold_buf,top,out)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * top;
int out;
{
unsigned char * x = hold_buf;
unsigned char * x1;
struct dcom_context * dcomp = (struct dcom_context *) frp->app_ptr;
int j;
int offset;

#ifdef DEBUG
    fprintf(frp->ofp, "mess_handle(%lx, %lx, %lx, %d)\n", (long) frp,
               (long) hold_buf, (long) top, out);
    fflush(frp->ofp);
    out = 1;
#endif
/*
 * 1 Byte Record Type
 */
    if (top <= x)
    {
        fprintf(frp->ofp, "x: %lx top: %lx\n", (long) x, (long) top);
        fflush(frp->ofp);
        fflush(stdout);
        fflush(stderr);
        return;
    }
/*
 * We are never interested in the return data
 * handle
 */
    if (!out)
        return;
#ifdef DEBUG
    fflush(frp->ofp);
#endif
    return;
}

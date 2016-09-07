/*
 * Scan a snoop file and pull out the SYBASE OpenClient elements.
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
static void do_syboc();
/*
 * Variables needed to pull in e2srclib.c, for wrapsql(). Note that look_tok
 * and look_status are really enum's.
 */
char * tbuf;
char * tlook;
int tlen;
int look_tok;
int look_status;
/*
 * Structure allocated to tie cursors to their SQL text.
 */
struct cursor_map {
    char cursor_name[32];
    unsigned int cursor_handle;
    struct syb_context * sybp;
    char * sql_text;
    struct cursor_map * next;
};
/*
 * Structure allocated when a session is started that holds session state.
 *
 * This code handles multiple parallel sessions, but may not handle
 * asynchronous SQL calls.
 */
struct syb_context {
    unsigned char *hold_buf[2]; /* Place for assembling application messages */
    unsigned char * top[2];
    struct cursor_map * anchor; /* Cursor name/handle/SQL text mapping       */
    int incomp_flag;            /* Flag that the cursor_map is not complete  */
    int tcnt;
    struct frame_con * parent_frp;  /* If this is owned by an SMB session  */
    char dts[256];
    char sql[16384];            /* The last SQL statement                    */
};
static struct frame_con * cur_frame;
static HASH_CON *ht;                       /* The cursor hash table      */
/*
 * Cursor hash function
 */
static unsigned hash_func(x, modulo)
unsigned char * x;
int modulo;
{
    return(((int) (((unsigned long) ((struct cursor_map *) x)->sybp) ^
                  (((struct cursor_map *) x)->cursor_handle))) & (modulo-1));
}
/*
 * Cursor hash comparison function
 */
static int comp_func(x1, x2)
unsigned char * x1;
unsigned char * x2;
{
    if ((((struct cursor_map *) x1)->sybp == ((struct cursor_map *) x2)->sybp)
     && (((struct cursor_map *) x1)->cursor_handle
           == ((struct cursor_map *) x2)->cursor_handle))
        return 0;
    else
    if (((struct cursor_map *) x1)->sybp < ((struct cursor_map *) x2)->sybp)
        return -1;
    else
    if (((struct cursor_map *) x1)->sybp > ((struct cursor_map *) x2)->sybp)
        return 1;
    else
    if (((struct cursor_map *) x1)->cursor_handle
                 < ((struct cursor_map *) x2)->cursor_handle)
        return -1;
    else
        return 1;
}
/*
 * Initialise the cursor structure
 */
static struct cursor_map * new_cursor(sybp, cnl, cursor_name, stl, sql_text)
struct syb_context * sybp;
int cnl;
unsigned char * cursor_name;
int stl;
unsigned char * sql_text;
{
struct cursor_map * x;

    if ((x = (struct cursor_map *) malloc( sizeof(struct cursor_map)))
          == (struct cursor_map *) NULL)
        return x;
    memcpy(x->cursor_name, cursor_name, cnl);
    x->cursor_name[cnl] = '\0';
    x->sql_text = (char *) malloc(stl + 1);
    memcpy(x->sql_text, sql_text, stl);
    *(x->sql_text + stl) = '\0';
    x->next = sybp->anchor;
    sybp->anchor = x;
    x->sybp = sybp;
    x->cursor_handle = 0;
    sybp->incomp_flag = 1;
    return x;
} 
/*
 * Update the cursor structure
 */
static void update_cursor(sybp, cursor_handle)
struct syb_context * sybp;
unsigned int cursor_handle;
{
    if (cursor_handle != 0)
    {
        sybp->anchor->cursor_handle = cursor_handle;
        insert(ht, (char *) (sybp->anchor), (char *) (sybp->anchor));
        sybp->incomp_flag = 0;
#ifdef DEBUG
        fprintf(cur_frame->ofp,"%s %x\n",sybp->anchor->cursor_name,
                     cursor_handle);
#endif
    }
    return;
} 
/*
 * Find a cursor structure, if possible
 */
static struct cursor_map * find_cursor(sybp, cursor_handle)
struct syb_context * sybp;
unsigned int cursor_handle;
{
struct cursor_map x;
HIPT *h;

    x.cursor_handle = cursor_handle;
    x.sybp = sybp;
    if ((h = lookup(ht, (char *) &x)) != (HIPT *) NULL)
        return (struct cursor_map *) (h->body);
    else
        return (struct cursor_map *) NULL;
} 
/*
 * Doctored standard routine that calls the badsort code.
 */
static void syboutput_response (f,dir_flag)
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
            if (((struct syb_context *) f->app_ptr)->parent_frp
                                != (struct frame_con *) NULL)
            {
                f->corrupt_flag =
                  ((struct syb_context *) f->app_ptr)->parent_frp->corrupt_flag;
                ((struct syb_context *) f->app_ptr)->parent_frp->corrupt_flag 
                             = 0;
            }
            if (f->corrupt_flag)
                f->corrupt_flag = 0;
            else
            {
#ifdef VERBOSE
                head_print(f->ofp, f);
                fprintf(f->ofp, "RESPONSE|%s|%d.%06d|%d.%06d|%d|%d|%d|%d|",
                        f->label, f->tran_start.tv_sec, f->tran_start.tv_usec,
                        resp_time.tv_sec, resp_time.tv_usec,
                    f->cnt[!dir_flag] - f->tran_cnt[!dir_flag],
                    f->cnt[dir_flag] - f->tran_cnt[dir_flag],
                    f->len[!dir_flag] - f->tran_len[!dir_flag],
                    f->len[dir_flag] - f->tran_len[dir_flag]);
                date_out(f->ofp, f->tran_start.tv_sec, f->tran_start.tv_usec);
                fputc('\n', f->ofp);
#endif
                do_one_capture(
                      strlen(((struct syb_context *) f->app_ptr)->sql),
                             ((struct syb_context *) f->app_ptr)->sql,
                          f->tran_start.tv_sec,
                           ((double) resp_time.tv_sec)
                         + ((double) resp_time.tv_usec)/1000000.0);
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
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */

static int match_cnt;              /* Number of ports in the list    */
static void syb_match_add(port)
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
    ht = hash(2048, hash_func, comp_func); /* Create the cursor hash table */
    if ((x = getenv("E2_SYB_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
                syb_match_add(i);
        }
    }
    return;
}
static int syb_match_true(from,to)
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
register struct syb_context * rop = (struct syb_context *) frp->app_ptr;
struct cursor_map  *x, *x1;

    if (rop != (struct syb_context *) NULL)
    {
/*
 * Free up the malloc()ed memory
 *
 * First the cursor entries
 */
        for (x = rop->anchor; x != (struct cursor_map *) NULL; )
        {
            x1 = x;
            x = x->next;
            free(x1->sql_text);
            hremove(ht, (char *) x1);
            free((char *) x1);
        }
        free(rop->hold_buf[0]);
        free(rop->hold_buf[1]);
        free((char *) rop);
    }
    return;
}
/*
 * Function to set up a Sybase TDS stream decoder. Separated from
 * syb_app_recognise() so that it can be called for the SMB-embedded case.
 */
void syb_app_initialise(frp, reverse_flag, parent_frp)
struct frame_con *frp;
int reverse_flag;
struct frame_con *parent_frp;
{
static int sess_cnt = 0;
char fname[32];
struct syb_context * sybp;

    sprintf(fname,"syb_%d.sql", sess_cnt++);
    frp->ofp = fopen(fname, "wb");
    if (frp->ofp == (FILE *) NULL)
        frp->ofp = stdout;   /* Out of file descriptors */
    frp->app_ptr = calloc(sizeof(struct syb_context),1);
    sybp = (struct syb_context *) (frp->app_ptr);
    sybp->hold_buf[0] = (unsigned char *) malloc(32768);
    sybp->hold_buf[1] = (unsigned char *) malloc(32768);
    sybp->top[0] = sybp->hold_buf[0];
    sybp->top[1] = sybp->hold_buf[1];
    sybp->parent_frp = parent_frp;
    if (reverse_flag < 0)
        frp->reverse_sense = 1;
    frp->off_flag = 2;
    frp->len_len = 2;
    frp->big_little = 0;
    frp->fix_size = 8;
    frp->fix_mult = 0;
    frp->do_mess = do_syboc;
    frp->cleanup = do_cleanup;
    frp->gap = 0;           /* Anything over 10 seconds is slow */
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int syb_app_recognise(frp)
struct frame_con *frp;
{
int i;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is identified in the list of interesting ports, managed
 *    with syb_match_add() and syb_match_true()
 */
    if (extend_listen_flag == 0)
        extend_listen_list();
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;
    struct syb_context * sybp;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if ((i = syb_match_true(from, to)))
        {
            syb_app_initialise(frp, i, (struct frame_con *) NULL);
            return 1;
        }
    }
    return 0;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum()
 */
static void do_syboc(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * p;
int last_frag;
int tran_len;
int len;
struct syb_context * sybp;

    cur_frame = frp;
/*
 * We have a Sybase Open Client Transport Header to discard.
 */
    p = frp->hold_buf[dir_flag];
    last_frag = (int) *(p + 1);
    tran_len = 256 *((unsigned) *(p+2)) + ((unsigned) *(p + 3));
    len = frp->top[dir_flag] - frp->hold_buf[dir_flag];
    if (tran_len < 8)
    {
#ifdef DEBUG
        fputs("Corrupt length?\n", frp->ofp);
        gen_handle(frp->ofp,frp->hold_buf[dir_flag],frp->top[dir_flag],  1);
#endif
    }
#ifdef DEBUG
    fprintf(frp->ofp, "do_syboc(%lx) = (%lx, %d, %d)\n", (long) frp,
               p, len, tran_len);
    fflush(frp->ofp);
#endif
    if (tran_len <= 8)
        return;
    sybp = (struct syb_context *) (frp->app_ptr);
    if (tran_len == len
      && last_frag
      && sybp->top[dir_flag] == sybp->hold_buf[dir_flag])
    {
        if ((!dir_flag) ^ frp->reverse_sense)
            syboutput_response(frp, dir_flag);         /* The last response */
        mess_handle(frp, p + 8, p + len, (!dir_flag) ^ frp->reverse_sense);
        return;
    }
    if ((sybp->top[dir_flag]  - sybp->hold_buf[dir_flag]) + (len - 8) >
             32768 || len < 8)
    {                         /* Too little buffer space */
        frp->corrupt_flag = 1;
        sybp->top[dir_flag] = sybp->hold_buf[dir_flag];     /* Discard it all */
        return;
    }
    memcpy(sybp->top[dir_flag], p + 8, len - 8);
    sybp->top[dir_flag] += (len - 8);
    if (last_frag)
    {
        if ((!dir_flag) ^ frp->reverse_sense)
            syboutput_response(frp, dir_flag); /* The last response */
        mess_handle(frp, sybp->hold_buf[dir_flag], sybp->top[dir_flag],
                                  (!dir_flag)^ frp->reverse_sense);
        sybp->top[dir_flag] = sybp->hold_buf[dir_flag];
    }
    return;
}
/******************************************************************************
 * Return a 4 byte little-endian number
 */
unsigned int get_syb_long(x)
unsigned char * x;
{
unsigned int i;
int j;
    
    for (i = 0, j=0; j < 4; j++)
    {
        i = i + (((unsigned) (*x)) << (j * 8));
        x++;
    }
    return i;
}
/*
 * Output a bind variable so that sqldrive would be able to re-read it.
 */
static int bind_out(fp, p, t, offset, last_flag)
FILE *fp;
unsigned char *p;
char t;
int offset;
int last_flag;
{
unsigned char buf[256];
unsigned char * ret;
unsigned int out_len;
int no_quote;

#ifndef VERBOSE
    return 0;
#endif
#ifdef DEBUG
    fprintf(fp, "bind_out(%lx, %lx, %u, %d, %d)\n", (long) fp,
               (long) p, (unsigned) t, offset, last_flag);
    fflush(fp);
#endif
    switch(t)
    {
    case 0x30: /* SYBINT1 */
    case 0x32: /* SYBBIT */
    case 0x34: /* SYBINT2 */
    case 0x38: /* SYBINT4 */
    case 0x26: /* SYBINTN */
    case 0x7A: /* SYBMONEY4 */
    case 0x68: /* SYBBITN */
        out_len = sprintf(&buf[0],"%u",counted_int(p,1));
        no_quote = 2;
        ret=&buf[0];
        break;
    case 0x6C: /* SYBNUMERIC */
    case 0x6A: /* SYBDECIMAL */
        ret = pin( p + 1, *p);
        out_len = strlen(ret);
        no_quote = 2;
        break;
    case 0xA7: /* XSYBCHAR */
    case 0xAF: /* XSYBVARCHAR */
        out_len = *p + (*p + 1) << 8;
        ret = p + 2;
        no_quote = 0;
        break;
    case 0xE7: /* XSYBNVARCHAR */
    case 0xEF: /* XSYBNCHAR */
        out_len = *p + (*p + 1) << 8;
        if (out_len > BUFSIZ/2 - 1)
            out_len = BUFSIZ/2 - 1;
        ret = hexin( p + 2, out_len);
        out_len = strlen(ret);
        no_quote = 2;
        break;
    case 0x3B: /* SYBREAL */
        ret = fin( p + 1, *p);
        out_len = strlen(ret);
        no_quote = 2;
        break;
    case 0x3E: /* SYBFLT8 */
        ret = din( p + 1, *p);
        out_len = strlen(ret);
        no_quote = 2;
        break;
    case 0xff:
        out_len = 0;
        ret = "";
        break;
    case 0x23: /* SYBTEXT */
    case 0x27: /* SYBVARCHAR */
    case 0x2F: /* SYBCHAR */
    case 0x63: /* SYBNTEXT */
    case 0x67: /* SYBNVARCHAR */
        out_len = *p;
        no_quote = 0;
        ret = p + 1;
        break;
    case 0x1F: /* SYBVOID */
    case 0x22: /* SYBIMAGE */
    case 0x25: /* SYBVARBINARY */
    case 0x2D: /* SYBBINARY */
    case 0x3A: /* SYBDATETIME4 */
    case 0x3C: /* SYBMONEY */
    case 0x3D: /* SYBDATETIME */
    case 0x6D: /* SYBFLTN */
    case 0x6E: /* SYBMONEYN */
    case 0x6F: /* SYBDATETIMN */
    default:
        ret = hexin( p + 1, *p);
        no_quote = 2;
        out_len = strlen(ret);
        break;
    }
    return out_field(fp,(FILE *) NULL, ret, (short int) out_len,
             (short int) ((last_flag ? 2 : 3) - no_quote), offset);
} 
/*
 * Deal with a Sybase Cursor data block, without the benefit of data type
 * information. How would we distinguish different rows in the data?
 * It is not that important, because in the benchmark situation, this is
 * returned data, and will not be part of the script. It is only used whilst
 * the scripts are being developed, so that data values can be tracked as they
 * are used in subsequent SQL statements.
 */
static unsigned char * do_data(frp, x, top)
struct frame_con * frp;
unsigned char * x;
unsigned char * top;
{
int last_flag, offset, tp;
unsigned char * p, * fe;

#ifndef VERBOSE
    return top;
#endif
    offset = 0;
    last_flag = 0;
    while ( x < top)
    {
        if (*x > 0)
        {
            if (*x > 8)
            {
/*
 * Check for possible single byte flag
 */
                fe = (top > x + *x + 1) ? (x + *x + 1) : top;
                for (p = x + 1; p < fe; p++)
                    if (*p < ' ' || *p > 128)
                        break;
                if (p != fe)
                {
                    fprintf(frp->ofp, "%u,", (unsigned int) *x);
                    offset += 4;
                    x++;
                    continue;
                }
            }
            else
            if (*(x + 1) < ' ' || *(x + 1) > 128)
                tp = 1;
            else
                tp = 0; 
            if ((x + *x + 1) >= top)
                last_flag = 1;
            offset = bind_out(frp->ofp, x, tp, offset, last_flag);
        }
        x += *x + 1;
    }
    return x;
}
/*
 * Deal with a Sybase Cursor data block, with the benefit of data type
 * information. We distinguish different rows in the data using the count
 * of types in tcnt.
 */
static unsigned char * do_data_types(frp, x, top)
struct frame_con * frp;
unsigned char * x;
unsigned char * top;
{
int last_flag, offset, tp;
unsigned char * p, * fe;
struct syb_context * sybp = (struct syb_context *) frp->app_ptr;
int i;
/*
 * If we knew the row count, we could handle the end better. At present, the
 * data types are garbage.
 */
    while ( x < top)
    {
        offset = 0;
        last_flag = 0;
        for (i = 0; i < sybp->tcnt && x < top; i++)
        {
            if (i == (sybp->tcnt - 1))
                last_flag = 1;
            if (*x > 0)
            {
                tp = sybp->dts[i];
                if (*x > 8)
                {
/*
 * Check for possible single byte flag
 */
                    fe = (top > x + *x + 1) ? (x + *x + 1) : top;
                    for (p = x + 1; p < fe; p++)
                        if (*p < ' ' || *p > 128)
                            break;
                    if (p != fe)
                    {
                        fprintf(frp->ofp, "%u", (unsigned int) *x);
                        offset += 4;
                        x++;
                        if (last_flag)
                            fputc('\n', frp->ofp);
                        else
                            fputc(',', frp->ofp);
                        continue;
                    }
                    else
                        tp = 0;
                }
                offset = bind_out(frp->ofp, x, tp, offset, last_flag);
            }
            else
                offset = out_field(frp->ofp,(FILE *) NULL, "", (short int) 0,
                     (short int) ((last_flag ? 2 : 3)), offset);
            x += *x + 1;
        }
    }
    return x;
}
/*
 * Deal with Sybase Bind variables types
 */
static unsigned char * do_binds(frp, x, top)
struct frame_con * frp;
unsigned char * x;
unsigned char * top;
{
int j;
struct syb_context * sybp = (struct syb_context *) frp->app_ptr;

#ifdef DEBUG
    fprintf(frp->ofp, "do_binds(%lx, %lx, %lx)\n", (long) frp,
               (long) x, (long) top);
    fflush(frp->ofp);
#endif
    if (x < top && *x == 0xec)
    {
/*
 * There is a 5 byte field including a count of the bind variables,
 * followed by the bind variable datatypes. At some point we might think
 * about setting the data types correctly.
 */
        sybp->tcnt = ((unsigned int) *(x+3));     
        x += 5;
        if (sybp->tcnt > 0)
        {
            for (j = 0; j < sybp->tcnt && x < top; j++)
            {
                if (*x != 0)
                {
                    fputc(' ', frp->ofp);
                    fwrite(x + 1, sizeof(char), *x, frp->ofp);
                    x += *x + 5;
                }
                else
                    x += 5;
                if (*x == 0xff)
                {
                    sybp->dts[j] = *x;
                    x += 2;
                    continue;
                }
                x++;
                sybp->dts[j] = *x;
#ifdef DEBUG
                fprintf(frp->ofp," %d -> %x\n", j, *x);
#endif
                switch(*x)
                {
                case 0x30: /* SYBINT1 */
                case 0x32: /* SYBBIT */
                case 0x34: /* SYBINT2 */
                case 0x38: /* SYBINT4 */
                case 0x3A: /* SYBDATETIME4 */
                case 0x3B: /* SYBREAL */
                case 0x3C: /* SYBMONEY */
                case 0x3D: /* SYBDATETIME */
                case 0x3E: /* SYBFLT8 */
                case 0x68: /* SYBBITN */
                case 0x7A: /* SYBMONEY4 */
                case 0xff:
                    x++;
                    break;
                case 0x2F: /* SYBCHAR */
                case 0x27: /* SYBVARCHAR */
                case 0x26: /* SYBINTN */
                case 0x23: /* SYBTEXT */
                case 0x63: /* SYBNTEXT */
                case 0x22: /* SYBIMAGE */
                case 0x2D: /* SYBBINARY */
                case 0x1F: /* SYBVOID */
                case 0x25: /* SYBVARBINARY */
                case 0x67: /* SYBNVARCHAR */
                case 0x6C: /* SYBNUMERIC */
                case 0x6A: /* SYBDECIMAL */
                case 0x6D: /* SYBFLTN */
                case 0x6E: /* SYBMONEYN */
                case 0x6F: /* SYBDATETIMN */
                case 0xA7: /* XSYBCHAR */
                case 0xAF: /* XSYBVARCHAR */
                case 0xE7: /* XSYBNVARCHAR */
                case 0xEF: /* XSYBNCHAR */
                default:
                    x += 3;
                    break;
                }
            }
        }
    }
    return x;
}
/*
 * Deal with a Sybase SQL message
 */
static unsigned char * do_sql(frp, hold_buf, x, top)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * x;
unsigned char * top;
{
unsigned int i;
int j;

    i = get_syb_long(x) - 1;
    x += 5;
    if (x + i > top)
    {
        if (x + i > top + 80)
        {
            frp->corrupt_flag = 1;
            return top;
        }
        else
            i = top - x;
    }
    if (i >= (sizeof(((struct syb_context *) (frp->app_ptr))->sql) - 32))
    {
        fprintf(frp->ofp, "LOGIC ERROR: SQL Statement is %d bytes\n",
                               i);
        return top;
    }
    memcpy(((struct syb_context *) (frp->app_ptr))->sql, x, i);
    ((struct syb_context *) (frp->app_ptr))->sql[i] = '\0';
#ifdef VERBOSE
    wrapsql(frp->ofp, i, x, top, &j);
#endif
    x += i;
    return x;
}
/*
 * Deal with a Sybase SQL message
 */
static unsigned char * do_simple(frp, hold_buf, x, top)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * x;
unsigned char * top;
{
unsigned int i;
int j;

    x += 5;
    i = *x + *(x + 1) * 256;
    if (x + i > top)
    {
        if (x + i > top + 80)
        {
            frp->corrupt_flag = 1;
            return top;
        }
        else
            i = top - x;
    }
    x += 2;
    if (i >= (sizeof(((struct syb_context *) (frp->app_ptr))->sql) - 32))
    {
        fprintf(frp->ofp, "LOGIC ERROR: SQL Statement is %d bytes\n",
                               i);
        return top;
    }
    memcpy(((struct syb_context *) (frp->app_ptr))->sql, x, i);
    ((struct syb_context *) (frp->app_ptr))->sql[i] = '\0';
#ifdef VERBOSE
    wrapsql(frp->ofp, i, x, top, &j);
#endif
    x += i;
    return x;
}
/*
 * Deal with a Sybase Remote Procedure Call
 */
static unsigned char * do_remote_procedure(frp, hold_buf, x, top)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * x;
unsigned char * top;
{
char * ret;
unsigned int i;
int j;
int offset;
struct syb_context * sybp = (struct syb_context *) frp->app_ptr;

    ret = x + *x + 2;
    if (ret > top)
    {
        frp->corrupt_flag = 1;
        return top;
    }
    x += 2;
    memcpy(sybp->sql, "EXECUTE ", 8);
    memcpy(&(sybp->sql[8]), x + 1, *x);
    sybp->sql[8 + *x] = '\0';
    fwrite(sybp->sql, sizeof(char), 8 + *x, frp->ofp);
    fputc(' ', frp->ofp);
    x = ret;
    i = 1;
    while (x < top)
    {
        if (*x == 0xec)
        {
            offset = ftell(frp->ofp);
            x = do_binds(frp, x, top);
            if (offset != ftell(frp->ofp))
            {
                fputs("\n/\n", frp->ofp);
                i = 0;
            }
        }
        else
        if (*x == 0xd7)
        {
            x++;
            offset = 0;
            for (j = 0; j < sybp->tcnt && x < top; j++)
            {
#ifdef VERBOSE
                offset = bind_out(frp->ofp, x, sybp->dts[j], offset, 
                                     ((j == (sybp->tcnt - 1)) ? 1: 0));
#endif
                x += *x + 1;
            }
        }
        else
            break;
    }
    if (i)
        fputs("\n/\n", frp->ofp);
    return x;
}
/*
 * Deal with a message preceded by the ZZZZZ construct.
 */
static unsigned char * error_locate(x,top, len)
unsigned char *x;
unsigned char * top;
int *len;
{
    x += 9;
    if (x < top)
    {
        x += *x + 3;
        if (len != (int *) NULL)
            *len = (*x << 8) + *(x + 1);
        x += 3;
        if (x < top)
            return x;
    }
    return (unsigned char *) NULL;
}
/*
 * Deal with column name/type values
 */
unsigned char * get_types(x, top, tcnt, dts)
unsigned char * x;
unsigned char * top;
int * tcnt;
char * dts;
{
unsigned int to_do = *(x + 3);

    x += 5;
    *tcnt = to_do;
#ifdef DEBUG
    fprintf(cur_frame->ofp, "to_do:%d\n", to_do);
#endif
    while (to_do > 0 && x < top)
    {
#ifdef DEBUG
        fwrite(x + 1, sizeof(char), *x, cur_frame->ofp);
        fputc('\n', cur_frame->ofp);
#endif
        x += (*x + 1);
        if (x > (top - 7))
        {
            fputs("Lost synchronisation in get_types()\n", cur_frame->ofp);
            gen_handle(cur_frame->ofp, x,top,1);
            break;
        }
        if (*x == 0x10 || *x == 0 || *x == 30)
            x += 5;
        else
            x += 4;
        if (*x > 0x2f)
        {
            x += 2;
            *dts = (char) 1;
        }
        else
        {
            x += 3;
            *dts = (char) 0;
        }
        dts++;
        to_do--;
    }
    x += 6;
    return x;
}
/*
 * Output the cursor narratives, looking up the cursor name as we do so. Note
 * that feeding the following back in as text leads to different message
 * patterns on replay to those captured here.
 */
static char * out_cursor(frp, x)
struct frame_con * frp;
unsigned char * x;
{
char * op_name;
unsigned int cursor_handle;
struct cursor_map *cp;

    switch (*x)
    {
    case 0x84:
        op_name = "OPEN";
        break;
    case 0x82:
        op_name = "FETCH";
        break;
    case 0x80:
        op_name = "CLOSE";
        break;
    default:
        op_name = "Logic Error";
        break;
    }
    cursor_handle = get_syb_long(x + 3);
    if (cursor_handle == 0
     && ((struct syb_context *)(frp->app_ptr))->incomp_flag)
    {
#ifdef VERBOSE
        fprintf(frp->ofp, "%s %s\n/\n", op_name,
                ((struct syb_context *)(frp->app_ptr))->anchor->cursor_name);
#endif
    }
    else
    if ((cp = find_cursor(frp->app_ptr, cursor_handle))
              == (struct cursor_map *) NULL) 
    {
#ifdef VERBOSE
        fprintf(frp->ofp, "%s %x\n/\n", op_name, cursor_handle);
#endif
        sprintf(((struct syb_context *)(frp->app_ptr))->sql, "%s %x\n/\n",
                   op_name, cursor_handle);
    }
    else
    {
#ifdef VERBOSE
        fprintf(frp->ofp, "%s %s\n/\n", op_name, cp->cursor_name);
#endif
        strcpy(((struct syb_context *)(frp->app_ptr))->sql, cp->sql_text);
    }
    return;
}
/**************************************************************************
 * Deal with the SYBASE OpenClient TCP Stream
 *
 * First cut, with little idea of the detailed structure, we just marked:
 * - Packet boundaries (in the calling routine)
 * - Apparently binary details (output in blocks of hex)
 * - Recognisable stretches of ASCII.
 *
 * We can now see there is a layered structure. In the top routine, we strip
 * the 'transport' headers.
 *
 * Finally, having established the format of the data, and how the file
 * is constructed, output the seed scripts.
 *
 * The messages give every appearance of being an arbitrary sequence of
 * fragment types and fragments whose internal structure depends on the
 * fragment type. Thus, the following is structured as a loop to process the
 * entire buffer.
 */
static void mess_handle(frp, hold_buf,top,out)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * top;
int out;
{
unsigned char * x = hold_buf;
unsigned char * x1;
struct syb_context * sybp = (struct syb_context *) frp->app_ptr;
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
 * We are only interested in the return data if we need to identify a cursor
 * handle
 */
    if (!out && !sybp->incomp_flag)
        return;
    while (x < top)
    {
        switch (*x)
        {
        case 0:
            if (x != hold_buf)
            {
                fputs("Lost synchronisation in mess_handle()\n",
                       cur_frame->ofp);
                x++;
                break;
            }
            if (x < (top - 31))
            {
#ifdef VERBOSE
                fprintf(frp->ofp, "\\C:%d:login:%s\\\n", out, x + 31);
#endif
                strncpy(frp->label,x + 31, sizeof(frp->label) - 1);
                frp->label[sizeof(frp->label) - 1] = '\0';
            }
#ifdef DEBUG
            gen_handle(frp->ofp, x+1,top,out);
            fflush(frp->ofp);
#endif
            x += 568;
            break;
/*
 * Various elements of uncertain purpose and variable lengths
 */
        case 0xad:                   /* Login ACK */
            x += (*x + 1) + 2;
            break;
        case 0xe2:                   /* Capability */
            x += (*x + 1) + 3;
            break;
        case 0xe3:                   /* Environment Change */
            x += (5 + *(x + 4));
            x += (1 + *x);
            break;
        case 0xe5:                   /* EED Error  */
            fprintf(frp->ofp, "\\C:%d:messages\\\n", out);
            fflush(frp->ofp);
            if ((x1 = error_locate(x,top, &j)) != (unsigned char *) NULL)
            {
                fwrite(x1, sizeof(char), j, frp->ofp);
                x = x1 + j + 4;
            }
            else
                x = top;
            break;
        case 0xec:
            x = do_binds(frp, x, top);
            break;
        case 0xee:                   /* Results */
#ifdef DEBUG
            fprintf(frp->ofp, "\\C:%d:response_rows\\\n", out);
            gen_handle(frp->ofp, x+1,top,out);
            fflush(frp->ofp);
#endif
            x = get_types(x,top,&(sybp->tcnt), sybp->dts);
            break;
        case 0xfd:                   /* Done */
#ifdef DEBUG
            fprintf(frp->ofp, "\\C:%d:response_status\\\n", out);
            gen_handle(frp->ofp, x+1,top,out);
            fflush(frp->ofp);
#endif
            x += 9; 
            break;
        case 0xff:                   /* Done */
#ifdef DEBUG
            fprintf(frp->ofp, "\\C:%d:transaction_status\\\n", out);
            gen_handle(frp->ofp, x+1,top,out);
            fflush(frp->ofp);
#endif
            x = top;
            break;
        case 0x71:                   /* Close */
            fprintf(frp->ofp, "\\C:%d:logout\\\n", out);
#ifdef DEBUG
            gen_handle(frp->ofp, x+1,top,out);
            fflush(frp->ofp);
#endif
            x = top;
            break;
/*
 * Cursor messages
 */
        case 0x86:      /* Declare */
            x += 3;
            j = (*(x + 4 + *x) << 8) + *(x + 3 + *x);
            if (j >= (sizeof(sybp->sql) - 32)
             || *x > 31
             || (x + j + *x + 5) >= top)
            {
                fprintf(frp->ofp, "LOGIC ERROR: SQL Statement is %d bytes\n",
                               j);
            }
            else
            {
                (void) new_cursor(sybp, *x, x + 1, j, x + 5 + *x);
#ifdef VERBOSE
            fprintf(frp->ofp,
                 "declare %*.*s cursor for\n%*.*s\n/\n",
                 *x, *x, x+1, j, j, x + 5 + *x);
#endif
                memcpy(sybp->sql, x + 5 + *x, j);
                sybp->sql[j] = '\0';
            }
            x += 6 + *x + j;
            break;
        case 0x84:      /* Open  */
        case 0x82:      /* Fetch */
        case 0x80:      /* Close */
            out_cursor(frp, x);
            x += 3 + *(x + 1);
            break;
        case 0x83:      /* Cursor operation response status */
#ifdef DEBUG
            fprintf(frp->ofp, "\\C:%d:cursor_response_status\\\n", out);
            gen_handle(frp->ofp, x+1,top,out);
            fflush(frp->ofp);
#endif
            if (sybp->incomp_flag)
                update_cursor(sybp, get_syb_long(x + 3));
            x += 3 + *(x + 1);
            break;
        case 0xd1:      /* Row Marker */
#ifdef DEBUG
            fprintf(frp->ofp, "\\C:%d:cursor_row_data\\\n", out);
            x++;
            if (sybp->tcnt)
                x = do_data_types(frp, x, top);
            else
                x = do_data(frp, x, top);
            fflush(frp->ofp);
#else
            x = top;
#endif
            break;
        case 0xd7:
            x++;
            offset = 0;
            for (j = 0; x < top && j < sybp->tcnt; j++)
            {
#ifdef VERBOSE
                offset = bind_out(frp->ofp, x, sybp->dts[j], offset, 
                                     ((j == (sybp->tcnt - 1)) ? 1: 0));
#endif
                x += *x + 1;
            }
            break;
        case 0x21:
/*
 * Normal SQL statement
 */
            x++;
            x = do_sql(frp, hold_buf, x, top);
            break;
        case 0xe7:
/*
 * Execute immediate sort of statement?
 */
            x++;
            x = do_simple(frp, hold_buf, x, top);
            break;
        case 0xe6:
/*
 * Remote Procedure Invocation
 */
            x++;
            x = do_remote_procedure(frp, hold_buf, x, top);
            break;
        case 0xd3:             /* Compute Row marker */
        case 0xac:             /* Remote Procedure Result */
        case 0xa6:             /* Option setting?    */
        default:
            fprintf(frp->ofp, "\\C:%d:%x:unknown:%d\\\n", out, *x, top - x);
            (void) gen_handle(frp->ofp, x,top,1);
            x = top;
            break;
        }
    }
#ifdef DEBUG
    fflush(frp->ofp);
#endif
    return;
}

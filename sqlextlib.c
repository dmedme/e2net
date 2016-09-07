/*
 * Scan a snoop file and pull out the ORACLE SQL*NET V.2 elements.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#define DEBUG
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
#include "tabdiff.h"
#include "e2conv.h"
#include "e2net.h"
struct sess_con * con = NULL;
/*
 * Structure allocated when a session is started that holds per-cursor
 * statistics plus session state. A better solution would be to use structures
 * in e2sqllib.c, but to truly populate them the responses from the host would
 * need to be analysed, since sometimes the messages assume that the recipient
 * knows how many there will be.
 *
 * This code handles multiple parallel sessions, but may not handle
 * asynchronous SQL calls.
 */
struct or_context {
int more_flag;
int incomplete_flag;
int fixed_flag;
int funny;
int last_curs;
int last_op;
int stat_len;
int curs;
int btype_cnt;
int b_cnt;
int d_cnt;
int f_arrlen;
int e_arrlen;
int plsql_flag;
int op_flag;                      /* This is the key to what is present
                                   * 0x0001   -   There is a statement to parse
                                   * 0x0002   -   Please describe the results
                                   * 0x0008   -   Bind (types) are present
                                   * 0x0010   -   Please Fetch
                                   * 0x0020   -   Please Execute
                                   * 0x0040   -   Describe types are present
                                   * 0x0400   -   This is PL/SQL
                                   * 0x8000   -   Not sure yet. Do not cancel?
                                   *              Defines?
                                   */
int to_do_cnt;
unsigned char * bind_types[512];  /* Up to 512 cursors catered for */
unsigned char * bind_flags[512];  /* Up to 512 cursors catered for */
unsigned char * bind_lengths[512];/* Up to 512 cursors catered for */
int desc_cnt[512];  /* Up to 512 cursors catered for */
};
static void tns_handle();
static void do_sqlnetv2();
short int ora_field();
static struct frame_con * cur_frame;
static int err_dump;
int scram_cnt;                /* Count of to-be-scrambled strings */
char * scram_cand[MAX_SCRAM]; /* Candidate scramble patterns */
char * tbuf;
char * tlook;
int tlen;
enum tok_id look_tok;
enum look_status look_status;
/***********************************************************************
 * The following logic ties together sessions where the port number is
 * changed during the login sequence.
 *
 * Do we want these sessions?
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */
static struct frame_con * prv_frame[100];
                             /* Corresponding frame control structures */

static int match_cnt;              /* Number of ports in the list    */
static void ora_match_add(port)
int port;
{
    if (match_cnt < 100)
    {
       match_port[match_cnt] = port;
       prv_frame[match_cnt] = cur_frame;
       match_cnt++;
    }
    return;
}
/*
 * Allow extra listener ports to be specified in the environment
 */
static void extend_listen_list()
{
char * x;
int i;
    extend_listen_flag = 1;
    if ((x = getenv("E2_TNS_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
                ora_match_add(i);
        }
    }
    return;
}
static struct frame_con * ora_match_true(from,to)
int from;
int to;
{
int i;
struct frame_con * ret_ptr;
#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif
    for (i = 0; i < match_cnt; i++)
    {
        if (match_port[i] == from || match_port[i] == to)
        {
            ret_ptr = prv_frame[i];
            match_port[i] = 0;         /* Mark the entry as free. There is no */
                                       /* such thing as a zero port number.   */
            if (i == (match_cnt - 1))
            {
/*
 * Reclaim the list entries if possible.
 */
                do
                {
                    match_cnt--;
                    i--;
                }
                while (i > -1 && match_port[i] == 0);
            }
            return ret_ptr;
        }
    }
    return (struct frame_con *) NULL;
}
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
int i, j;
register struct or_context * rop = (struct or_context *) frp->app_ptr;
struct frame_con *xfrp;
    if (rop != (struct or_context *) NULL)
    {
        for (i = 0; i < 512; i++)
            if (rop->bind_types[i] != (char *) NULL)
            {
                free(rop->bind_types[i]);
                free(rop->bind_flags[i]);
                free(rop->bind_lengths[i]);
            }
        for (i = 0; i < match_cnt; i++)
            if (frp == prv_frame[i])
            {
                xfrp = (struct frame_con *) malloc(sizeof(struct frame_con));
                *xfrp = *frp;
                fflush(xfrp->ofp);
                j = dup(fileno(xfrp->ofp));
                xfrp->ofp = fdopen(j,"ab");
                fseek(xfrp->ofp,0,2);
                prv_frame[i] = xfrp;
            }
        free((char *) rop);
    }
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int ora_app_recognise(frp)
struct frame_con *frp;
{
static int sess_cnt = 0;
char fname[32];
    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is the listener (1521, 1525 or thereabouts, usually)
 * -  The port is identified in the list of interesting ports, managed
 *    with ora_match_add() and ora_match_true()
 */
    if (extend_listen_flag == 0)
        extend_listen_list();
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;
    struct frame_con * prv_ptr;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if (((from > 1520 && from < 1531)
         || (to > 1520 && to < 1531))
        || ((from  == 4060) || (to == 4060)))
        {
            sprintf(fname,"ora_%d.sql", sess_cnt++);
#ifndef PACKDUMP
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
#endif
                frp->ofp = stdout;   /* Out of file descriptors */
            frp->off_flag = 0;
            frp->gap = 0;           /* Anything over 10 seconds is slow */
            frp->len_len = 2;
            frp->big_little = 0;
            frp->fix_size = 2;
            frp->fix_mult = 0;
            if ((from > 1520 && from < 1531) || (from  == 4060))
                frp->reverse_sense = 1;
            frp->do_mess = do_sqlnetv2;
            frp->cleanup = do_cleanup;
            frp->app_ptr = calloc(sizeof(struct or_context),1);
#ifdef WE_KNOW
            ((struct or_context *) (frp->app_ptr))->fixed_flag = 0;
            ((struct or_context *) (frp->app_ptr))->funny = 1;
#else
           ((struct or_context *) (frp->app_ptr))->fixed_flag = -1;
#endif
            return 1;
        }
        else
        if ((prv_ptr = ora_match_true(from, to)) != (struct frame_con *) NULL
          && (( !hcntstrcmp(prv_ptr->net_from,frp->net_from)
              && !hcntstrcmp(prv_ptr->net_to,frp->net_to))
          || ( !hcntstrcmp(prv_ptr->net_from,frp->net_to)
              && !hcntstrcmp(prv_ptr->net_to,frp->net_from))))
        {
            frp->ofp = prv_ptr->ofp;
            if (frp->ofp == (FILE *) NULL)
            {
#ifndef PACKDUMP
                sprintf(fname,"sql_%d.sql", sess_cnt++);
                frp->ofp = fopen(fname, "wb");
                if (frp->ofp == (FILE *) NULL)
#endif
                    frp->ofp = stdout;   /* Out of file descriptors */
            }
            frp->app_ptr = calloc(sizeof(struct or_context),1);
            frp->off_flag = 0;
            frp->len_len = 2;
            frp->fix_size = 2;
            frp->fix_mult = 0;
            frp->do_mess = do_sqlnetv2;
            frp->cleanup = do_cleanup;
#ifdef WE_KNOW
            ((struct or_context *) (frp->app_ptr))->fixed_flag = 0;
            ((struct or_context *) (frp->app_ptr))->funny = 1;
#else
           ((struct or_context *) (frp->app_ptr))->fixed_flag = -1;
#endif
            return 1;
        }
    }
    return 0;
}
/*
 * Test a 4 byte flag
 */
static int funny_test(p)
char ** p;
{
union {
    char c[4];
    int l;
} l;
    l.c[0] = *((*p)++);
    l.c[1] = *((*p)++);
    l.c[2] = *((*p)++);
    l.c[3] = *((*p)++);
    return l.l;
}
/*
 * Read in an optional value. Return if it was there or not
 */
int opti_get(pp, pv)
char ** pp;
int *pv;
{
int ret = 0;
    if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
    {
        if (funny_test(pp))
        {
            ret = 1;
            *pv = counted_int(*pp,1);
            *pp += **pp + 1;
        }
    }
    else
    if (**pp)
    {
        ret = 1;
        (*pp)++;
        *pv = counted_int(*pp,1);
        *pp += **pp + 1;
    }
    else
    {
        (*pp)++;
        *pv = 0;
    }
    if (*pv > 255)
        *pv = 0;
    return ret;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum()
 */
static void do_sqlnetv2(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
int i;

    cur_frame = frp;
#ifdef VERBOSE
    if (!(dir_flag) ^ frp->reverse_sense)
    {
        output_response(frp, dir_flag); /* The last response */
        frp->tran_start = frp->last_t[dir_flag];
        for (i = 0; i < 2; i++)
        {
            frp->tran_cnt[i] = frp->cnt[i];
            frp->tran_len[i] = frp->len[i];
            frp->tran_cs_tim[i] = frp->cs_tim[i];
            frp->tran_nt_tim[i] = frp->nt_tim[i];
        }
    }
#endif
    tns_handle(frp->ofp,frp->top[dir_flag] - frp->hold_buf[dir_flag],
               frp->hold_buf[dir_flag],  !(dir_flag) ^ frp->reverse_sense);
    return;
}
/*
 * Routine that is needed for deciphering the SQL*NET V.2 from Windows 95
 * and NT clients. The numbers may be big-endian or little endian; we work
 * it out by heuristics. Ideally, we would move to a version of the code
 * that knew the fields, and called a single routine that read fixed and
 * variable length fields, but this is difficult without the protocol
 * information.
 */
static int get_ora_big_endian(p)
unsigned char * p;
{
    return (int) (*(p + 3) + (*(p + 2) << 8) +(*(p + 1) << 16) + (*(p) << 24));
} 
static int get_ora_little_endian(p)
unsigned char * p;
{
    return (int) (*p + (*(p + 1) << 8) +(*(p + 2) << 16) + (*(p+3) << 24));
} 
/******************************************************************************
 * Decide whether this is a big or little endian system based on the first
 * non-zero value we encounter
 */
static int get_ora_fixed(fp, p)
FILE * fp;
unsigned char * p;
{
static int big_little;
int ret_value;
    switch (big_little)
    {
    case 1:
        ret_value = get_ora_big_endian(p);
        break;
    case -1:
        ret_value = get_ora_little_endian(p);
        break;
    default:
        if (*p > 0)
        {
            big_little = -1;
            ret_value = get_ora_little_endian(p);
        }
        else
        if (*p == 0
         && ( *(p + 1) != 0 || *(p + 2) != 0 || *(p + 3) != 0))
        {
            big_little = 1;
            ret_value = get_ora_big_endian(p);
        }
        else
            ret_value = 0;
        break;
    }
#ifdef DEBUG
    fprintf(fp,  "    Fixed_Field: %d\n", ret_value);
    fflush(fp);
#endif
    return ret_value;
} 
static unsigned char * chew_zero(fp, p,len)
FILE *fp;
unsigned char *p;
int len;
{
    if (p >= cur_frame->top[0]
     && p >= cur_frame->top[1])
    {
        fputs("Invalid pointer passed to chew_zero\n", fp);
        return p;
    }
    if ((p < cur_frame->top[0]
       && p >= cur_frame->hold_buf[0]
       && p + len >= cur_frame->top[0])
     || (p < cur_frame->top[1]
       && p >= cur_frame->hold_buf[1]
       && p + len >= cur_frame->top[1]))
    {
        fputs("Chew Zero would run out of record\n", fp);
        return p;
    }
    while (len > 0)
    {
        if (*p)
        {
            fprintf(fp, "Unexpected chars 0x%x 0x%x\n", *p,*(p+1));
            err_dump = 1;
        }
        p++;
        len--;
    }
    return p;
}
int chew_len(fp, x)
FILE * fp;
char *x;
{
short int w;
    memcpy((char *) &w, x, sizeof(short int));
    w = ntohs(w);
#ifdef DEBUG
    fprintf(fp, "e2len %d\n", w);
#endif
    return w;
}
/**************************************************************************
 * Deal with the SQL*NET V.2 TCP Stream
 *
 * First cut, with little idea of the detailed structure, we just marked:
 * - Packet boundaries (in the calling routine)
 * - Apparently binary details (output in blocks of hex)
 * - Recognisable stretches of ASCII.
 *
 * Finally, having established the format of the data, and how the file
 * is constructed, output the seed scripts.
 */
/*
 * Handle login messages
 */
static char * connect_handle(fp, x,top,out)
FILE * fp;
char * x;
char * top;
int out;
{
#ifdef DEBUG
/*
 * Three bytes zero
 */
    x = chew_zero(fp, x,3);
    x = gen_handle(fp, x,top,out);
#endif
    fprintf(fp, "\\C:LOGIN:%u\\\n", out);
#ifdef TAS_ONLY
/*
 * Suppress non-TAS sessions
 */
    if ((x +35) < top)
    {
        *(top - 1) = '\0';
        if ((x = memchr(x + 35, '(', top - x - 35)) != ( char *) NULL)
        {
            if ((x = strstr(x,"(SID=TAS")) == (char *) NULL)
                cur_frame->do_mess = NULL;
        }
    }
#endif
    return top;
}
/*
 * Handle setup messages
 */
static char * reconnect_handle(fp, x,top,out)
FILE * fp;
char * x;
char * top;
int out;
{
char * y;
/*
 * Three bytes zero
 */
    x = chew_zero(fp, x,4);
    out = (int) *x;
#ifdef DEBUG
    fprintf(fp, "e2len %d\n", out);
#endif
    x++;
    if (x + out >= top)
        *(top - 1) = '\0';
    else
        *(x + out) = '\0';
    if ((y = strstr(x,"PORT=")) != (char *) NULL)
    {
        y += 5;
        ora_match_add(atoi(y));
        fprintf(fp, "\\CONNECT:%u\\\n", atoi(y));
    }
#ifdef DEBUG
    fprintf(fp, "%*.*s\n",out,out,x);
#endif
    return top;
}
unsigned char * e2skipone(fp, p, top)
FILE * fp;
unsigned char * p;
unsigned char * top;
{
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
        p += 16;
    else
    {
        p += 4;
        if (p < top)
            p += *p + 1;
        p += 2;
    }
    if (p > top)
        return top;
    else
        return p;
}
/*
 * Function to skip over return value defines. Only call this function if
 * the Operation flag includes 0x8000.
 */ 
unsigned char * e2skipdefs(fp, p, top, d_cnt)
FILE * fp;
unsigned char * p;
unsigned char * top;
int d_cnt;
{
#ifdef DEBUG
    fprintf(fp, "e2skipdefs(%d)\n", d_cnt);
    gen_handle(fp, p,top,1);
#endif
    if (d_cnt > 0)
    {
       while (d_cnt > 0 && p < top)
       {
           p =  e2skipone(fp, p, top);
           d_cnt--;
       }
       if (d_cnt > 0 || p >= top) 
       {
           ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
#ifdef DEBUG
           fputs("e2skipdefs() Ran out of record\n", fp);
#endif
       }
    }
    else
/*
 * We do not know how many of them there are
 */
    while (p < top)
    {
        p =  e2skipone(fp, p, top);
        if (*p == 7)
            break;
    }
    return p;
}
/*
 * Handle a parse request
 */
int e2parse(fp, p, top)
FILE * fp;
unsigned char * p;
unsigned char * top;
{
int curs;
int len;
    p++;      /* Skip the sequence */
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag == 0)
    {
        curs = counted_int(p,1);
        p += *p + 2;
        if (*p > 2)
           p += 3;
        len = counted_int(p,1);
        fprintf(fp, "\\PARSE:%u\\\n", curs);
        if (len < 65536)
            ((struct or_context *)(cur_frame->app_ptr))->desc_cnt[curs] =
                    wrapsql(fp, len,(p+*p+1), top,
                   &((struct or_context *)(cur_frame->app_ptr))->more_flag);
    }
    else
    {
/*
 * Fixed length 4 byte fields, most significant byte first!?
 */
        curs = get_ora_fixed(fp, p);
        p += 8;
        len = get_ora_fixed(fp, p);
        p += 4;
        fprintf(fp, "\\PARSE:%u\\\n", curs);
        if (len < 65536)
            ((struct or_context *)(cur_frame->app_ptr))->desc_cnt[curs] =
                   wrapsql(fp, len,p, top,
                      &((struct or_context *)(cur_frame->app_ptr))->more_flag);
    }
    if (((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] !=
                    (unsigned char *) NULL)
    {
        free(((struct or_context *)(cur_frame->app_ptr))->bind_types[curs]);
        free(((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs]);
        free(((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs]);
        ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] = (unsigned char *) NULL;
    }
    if (((struct or_context *)(cur_frame->app_ptr))->more_flag)
        ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
    return curs;
}
#ifdef DEBUG
static void dump_bind_types(fp, curs)
FILE * fp;
int curs;
{
int btype_cnt;
char * x;
char * y;
char * z;
    if (((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] ==
             (char *) NULL)
    {
        fprintf(fp, "cursor: %d has no columns?\n",curs);
        return;
    }
    btype_cnt = (int) *(((struct or_context *)(cur_frame->app_ptr))->bind_types[curs]);
    fprintf(fp, "cursor: %d columns: %d ",curs,btype_cnt);
    for (x = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] + 1,
         y = ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] + 1,
         z = ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] + 1;
             btype_cnt; btype_cnt--, x++, y++, z++)
        fprintf(fp, " %d:%x:%d", (int) *x, (int) *y, (int) *z);
    fputc('\n', fp);
    return;
}
#endif
char * e2bindtypes(fp, curs,btype_cnt, p, top)
FILE * fp;
int curs;
int btype_cnt;
char * p;
char * top;
{
static int to_do_cnt;
static unsigned char * x;
static unsigned char * y;
static unsigned char * z;
int sanity_check;
#ifdef DEBUG
    fprintf(fp, "e2bindtypes incomplete_flag:%d\n",
              ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag);
#endif
    if (btype_cnt > 255)
    {
       err_dump = 1;
       return top;
    }
    if (!((struct or_context *)(cur_frame->app_ptr))->incomplete_flag)
    {
        to_do_cnt = btype_cnt;
        if (((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] ==
                          (unsigned char *) NULL)
        {
            ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] =
                          (unsigned char *) malloc(btype_cnt + 1);
            ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] =
                          (unsigned char *) malloc(btype_cnt + 1);
            ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] =
                          (unsigned char *) malloc(btype_cnt + 1);
        }
        else
        {
            ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] =
                   (unsigned char *) realloc(((struct or_context *)
                      (cur_frame->app_ptr))->bind_types[curs], btype_cnt + 1);
            ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] =
                   (unsigned char *) realloc(((struct or_context *)
                      (cur_frame->app_ptr))->bind_flags[curs], btype_cnt + 1);
            ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] =
                   (unsigned char *) realloc(((struct or_context *)
                      (cur_frame->app_ptr))->bind_lengths[curs], btype_cnt + 1);
        }
        x = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs];
        y = ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs];
        z = ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs];
        *x++ = btype_cnt;
        *y++ = btype_cnt;
        *z++ = btype_cnt; 
    }
    else
    if (((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] ==
                          (unsigned char *) NULL)
    {
        fputs("Incomplete with bind variables but none seen\n", fp);
        return top;
    }
    sanity_check = z -
          ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] - 1;
    if (sanity_check + to_do_cnt
      > *(((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs]) )
    {
        fputs("Sanity check Failed\n", fp);
        return p;
    }
    for ( ;to_do_cnt; to_do_cnt--)
    {
         if (p > top - 8)
         {
             to_do_cnt--;
#ifdef DEBUG
             fputs("e2bindtypes() Ran out of record\n", fp);
#endif
             if (to_do_cnt > 1)
                 ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag
                                    = 1;
             else
                 ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag
                                    = 0;
             return top;
         }
         *x = *p;
/*
 * *(p + 1) is some kind of flag value, associated with whether or not there
 * is a value in the bind variable list. However, we are using the length
 * field to achieve this at present.
 */
         *y = *(p + 1);
#ifdef DEBUG
         fprintf(fp, "dir flag:%x\n", (int) *(y));
#endif
         y++;
         x++;
         p += 4;
         if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
         {
             *z = get_ora_fixed(fp, p);
             p += 12;
         }
         else
         {
             *z = counted_int(p,1); 
             p += *p +1;
             p += *p +1;             /* Two more fields, meaning uncertain */
             p += *p +1;
         }
         z++;
    }
    ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
    return p;
}
unsigned char * e2bindvars(fp, curs, p,top, e_arrlen)
FILE * fp;
int curs;
unsigned char * p;
unsigned char * top;
int e_arrlen;
{
static int len;
static unsigned char * x;
static unsigned char * y;
static unsigned char * z;
static unsigned char * null_field="";
short int offset = 0;
unsigned int tab_len;
unsigned int arr_flag;
#ifdef DEBUG
    fprintf(fp, "e2bindvars incomplete_flag:%d\n",
         ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag);
#endif
    p++;
    if (p >= top && !e_arrlen)
        return p;
#ifdef DEBUG
    fputs("e2bindvars   ", fp);
    dump_bind_types(fp, curs);
    fflush(fp);
#endif
    if (!((struct or_context *)(cur_frame->app_ptr))->incomplete_flag)
    {
        x = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs];
        if (x == (unsigned char *) NULL)
            return top;
        y = ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] + 1;
        z = ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] + 1;
        len=((unsigned) *x++);
    }
#ifdef DEBUG
    fprintf(fp, "Known descriptors: %d\n",
              ((struct or_context *)(cur_frame->app_ptr))->desc_cnt[curs]);
#endif
    for (; len > 0; len--, x++, y++, z++)
    {
#ifdef DEBUG
        fprintf(fp, "\nbind_flag: %x length: %d\n",(int) *y, (int) *z);
#endif
/*
 * I think this value probably applies for input, and 0x40 for output. However,
 * we are only really interested in input.
 *
 * The following syntax is not yet supported by sqldrive.
 *
 * The code doesn't work properly if the bind variables are spread over
 * multiple SQL*Net blocks.
 */
        arr_flag = 0;
        if (*y & 0x4)
        {
            tab_len = counted_int(p, 1);
            p += *p + 1;
            if (tab_len > 100)
                tab_len = 1;
            else
            if (tab_len > 1)
            {
                fputc('{' ,fp);
                arr_flag = 1;
            }
        }
        else
            tab_len = 1;
        
        for (;tab_len > 0; tab_len--)
        {
            if (
                p >= top  ||
                (*p != 253 && *p != 254 && (
               ((*y & 0x8) && !(*z)) ||
               (*x == ORA_VARCHAR2 && *z < *p
                       && (*z != 0 ) || (*z == 0 && *y != 0x10)) ||
               (*x == ORA_VARCHAR2 && *(p + 1) > 127) ||
               (*x == ORA_DATE && (*p != 7 || *(p + 1) < 100)) ||
               (*x == ORA_NUMBER && *(p + 1) < 128)
              )))
            {
                offset = ora_field(fp,ORA_VARCHAR2, null_field, offset,
                           (!(len - 1) || (arr_flag && (tab_len == 1))),
                           null_field+1);
                continue;           /* Field does not need binding */
            }
            if ((offset = ora_field(fp,((unsigned int) *x), p, offset,
                           (!(len - 1) || (arr_flag && (tab_len == 1))),top))
                          < 0)
            {
                fputs("Bind Types Corrupt?\n", fp);
                return top;
            }
            if (*x == ORA_VARCHAR2)
            {
                if (*p == 1 && *(p + 1) == *(p + 2))
                {
                    p += *p + 3;
                    continue;
                }
                else
                if (*p == 2 && *(p + 3) == 0xff)
                {
                    p += counted_int(p,1) + 4;
                    continue;
                }
                else
                if (*p == 2 && *(p + 3) == 0xfe)
                {
                    p += 3;
                }
            }
            if (*p == 253)
                p += 2;
            else
            if (*p == 254)
            {
                p = ((char *) memchr(p,0,top - p + 1)) + 1;
                if (p == (char *) 1)
                    p = top;
            }
            else
                p += ((unsigned) *p) + 1;
            if (p > top)
            {
                p = top;
#ifdef DEBUG
                fputs("e2bindvars() Ran out of record\n", fp);
#endif
                break;
            }
        }
        if (arr_flag)
        {
            fputc('}' ,fp);
            if ((len - 1))
                fputc(',' ,fp);
        }
    }
    return p;
}
unsigned char * e2allbinds(fp, curs, p,top, e_arrlen)
FILE * fp;
int curs;
unsigned char * p;
unsigned char * top;
int e_arrlen;
{
    if (curs < 0 || curs > 511)
    {
        fprintf(fp, "e2allbinds():Cursor %d is out of range\n", curs);
        return top;
    }
    while (p < top)
    {
        while (*p != 7 && p < top)
            p++;
        p = e2bindvars(fp, curs, p, top, e_arrlen);
        ((struct or_context *)(cur_frame->app_ptr))->to_do_cnt--;
    }
    return p;
}
/*
 * Adjust the bind flags if appropriate.
 */
unsigned char * e2bind_variable_return(fp, curs, p,top)
FILE *fp;
int curs;
unsigned char * p;
unsigned char * top;
{
int len;
unsigned char * y;
short int offset = 0;
#ifdef DEBUG
    fputs("e2bind_variable_return....\n", fp);
#endif
    p += 8;                   /* Skip to the start of the list of flags */
    if (p >= top)
        return p;
    if (curs < 0 || curs > 511)
    {
        fprintf(fp, "e2bind_variable_return(): Cursor %d is out of range\n",
                     curs);
        return top;
    }
    y = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs];
    if (y == (unsigned char *) NULL)
        return top;
    for (len = *y,
         y = ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] + 1;
             p < top && len > 0;
                 len--, y++,p++)
    {
#ifdef DEBUG
         fprintf(fp, "Flag sent: %x returned: %x\n", *y, *p);
#endif
        *y |= *p;
    }
#ifdef DEBUG
    dump_bind_types(fp, curs);
#endif
    return p;
}
/*
 * Handle a fetch request.
 */
int e2fetch(fp, p,top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
int curs = counted_int(p+1,1);
    if (curs == 0)
        curs = get_ora_fixed(fp, p+1);
    fprintf(fp, "\\FETCH:%u\\\n", curs );
    return curs;
}
int e2defer_parse_bind(fp, p, top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
int curs;
int stat_len;
int dummy;
    p++;          /* Skip the sequence */
    if (!((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
    {
        ((struct or_context *)(cur_frame->app_ptr))->op_flag =
                 counted_int(p, 1);
        p += *p + 1;
        curs = counted_int(p,1);
        p += *p + 1;
        if ((((struct or_context *)(cur_frame->app_ptr))->op_flag  & 1))
        {
            if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
                (void) funny_test(&p);
            else
                p++;
            stat_len = counted_int(p,1);
            p += *p + 1;
        }
        else
        {
            if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
                (void) funny_test(&p);
            else
                p++;
            stat_len = 0;
        }
#ifdef DEBUG
        fprintf(fp, "e2defer_parse_bind(stat_len=%d)\n",stat_len);
#endif
        if (!opti_get(&p, &dummy))
            p++;
        if (!opti_get(&p, &dummy))
            p++;
        if (((struct or_context *)(cur_frame->app_ptr))->funny)
            p = chew_zero(fp,p, 19);
        else
            p++;
    }
    else
    {
        p += 4;
        curs = get_ora_fixed(fp, p);
        p += 8;
        stat_len = get_ora_fixed(fp, p);
        p += 48;
    }
    if (stat_len > 65536)
        stat_len =  0;
    fprintf(fp, "\\PARSE:%u\\\n",curs);
        ((struct or_context *)(cur_frame->app_ptr))->desc_cnt[curs] =
               wrapsql(fp, stat_len,p, top,
                     &((struct or_context *)(cur_frame->app_ptr))->more_flag);
    if (((struct or_context *)(cur_frame->app_ptr))->more_flag)
        ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
    return curs;
}
int  e2defer_parse_exec_fetch(fp, p, top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
int curs;
int i;
int stat_len;
int dummy;
    p++;          /* Skip the sequence */
#ifdef DEBUG
    fputs("e2defer_parse_exec_fetch()\n", fp);
    gen_handle(fp, p,top,1);
    fflush(fp);
    fflush(stderr);
#endif
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
    {
        ((struct or_context *)(cur_frame->app_ptr))->op_flag =
                get_ora_fixed(fp, p);
        p += 4;
        curs = get_ora_fixed(fp, p);
        p += 8;
        stat_len = get_ora_fixed(fp, p);
        p += 124;
    }
    else
    {
        ((struct or_context *)(cur_frame->app_ptr))->op_flag =
                 counted_int(p, 1);
#ifdef DEBUG
        fprintf(fp, "Operations flag:%x\n",
                 ((struct or_context *)(cur_frame->app_ptr))->op_flag );
#endif
        p += *p + 1;
        curs = counted_int(p,1);
        p += *p + 1;
        if ((((struct or_context *)(cur_frame->app_ptr))->op_flag  & 1))
        {
            if (((struct or_context *)(cur_frame->app_ptr))->funny)
                (void) funny_test(&p);
            else
                p++;
            stat_len = counted_int(p,1);
            p += *p + 1;
        }
        else
        {
            if (((struct or_context *)(cur_frame->app_ptr))->funny)
                (void) funny_test(&p);
            else
                p++;
            stat_len = 0;
        }
#ifdef DEBUG
        fprintf(fp, "Statement length:%d\n",stat_len);
#endif
        if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
        {
            (void) funny_test(&p);
            if (funny_test(&p))
                p += *p + 1;
            (void) funny_test(&p);
            if (funny_test(&p))
                p += *p + 1;
            (void) funny_test(&p);
            p = chew_zero(fp,p,33);
        }
        else
        {
            for (i = 5; i > 0; i--)
                p += *p + 1;
            p = chew_zero(fp,p,12);
        }
        p += *p + 1;
        p += *p + 1;
        opti_get(&p, &dummy);
        opti_get(&p, &dummy);
        if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
            p = chew_zero(fp,p,11);
        else
            p = chew_zero(fp,p,4);
        for (i = 2; i > 0; i--)
            p += *p + 1;
    }
    ((struct or_context *)(cur_frame->app_ptr))->curs = curs;
    if (stat_len > 65536)
        stat_len =  0;
    if (stat_len)
    {
        fprintf(fp, "\\PARSE:%u\\\n",curs);
        ((struct or_context *)(cur_frame->app_ptr))->desc_cnt[curs] =
              wrapsql(fp, stat_len,p, top,
                      &((struct or_context *)(cur_frame->app_ptr))->more_flag);
    }
    if (((struct or_context *)(cur_frame->app_ptr))->more_flag)
        ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
    else
    {
        if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x40)
            p = e2skipdefs(fp, p, top, 0);
        if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x20
          && !((struct or_context *)(cur_frame->app_ptr))->more_flag)
             fprintf(fp, "\\EXEC:%u\\\n",
                       ((struct or_context *)(cur_frame->app_ptr))->curs);
        p = e2allbinds(fp,((struct or_context *)(cur_frame->app_ptr))->curs,
                     p, top, 0);
        if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x10
          && !((struct or_context *)(cur_frame->app_ptr))->more_flag)
            fprintf(fp, "\\FETCH:%u\\\n",
                   ((struct or_context *)(cur_frame->app_ptr))->curs);
    }
    return curs;
}
/*
 * Handles the fixed length field format
 */
int e2universal_fixed(fp, pp, top, btype_cnt, b_cnt, d_cnt, f_arrlen, e_arrlen,
                      plsql_flag)
FILE *fp;
unsigned char ** pp;
unsigned char * top;
int * btype_cnt;
int * b_cnt;
int * d_cnt;
int * f_arrlen;
int * e_arrlen;
int * plsql_flag;
{
unsigned char * p = *pp;
int stat_len, curs;
    ((struct or_context *)(cur_frame->app_ptr))->op_flag = get_ora_fixed(fp, p);
#ifdef DEBUG
    fprintf(fp, "Operations flag:%x\n",
                 ((struct or_context *)(cur_frame->app_ptr))->op_flag);
#endif
    p += 4;          /* Skip the first field */
    curs = get_ora_fixed(fp, p);
    ((struct or_context *)(cur_frame->app_ptr))->curs = curs;
    p += 8;
/*
 * Is there going to be a statement?
 */
    stat_len = get_ora_fixed(fp, p);
    p += 36;
    *d_cnt = get_ora_fixed(fp, p);
    p += 8; 
    *btype_cnt = get_ora_fixed(fp, p);
    *b_cnt = *btype_cnt;
    p += 4;
    if ( stat_len && (stat_len < 65536))
    {
        fprintf(fp, "\\PARSE:%u\\\n",curs);
        *plsql_flag = wrapsql(fp, stat_len,p, top,
              &((struct or_context *)(cur_frame->app_ptr))->more_flag);
        if (((struct or_context *)(cur_frame->app_ptr))->more_flag)
        {
            ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
            return curs;
        }
    }
    p += stat_len;
/*
 * The EXEC array length
 */
    *e_arrlen = get_ora_fixed(fp, p);
    p += 4;
/*
 * The FETCH array length
 */
    *f_arrlen = get_ora_fixed(fp, p);
    p += 4;
#ifdef DEBUG
    fprintf(fp, "e2universal_fixed(stat_len=%d d_cnt=%d btype_cnt=%d b_cnt=%d f_arrlen=%d e_arrlen = %d)\n",
               stat_len,*d_cnt,*btype_cnt,*b_cnt,*f_arrlen, *e_arrlen);
#endif
    if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x20)
         fprintf(fp, "\\EXEC:%u\\\n",
                   ((struct or_context *)(cur_frame->app_ptr))->curs);
    p += 20;                       /* Skip 5 fields */
    *pp = p;
    return curs;
}
int e2universal(fp, p, top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
int dummy;
unsigned char * base_p = p - 1;
#ifdef DEBUG
    fprintf(fp, "incomplete_flag:%d\n",
          ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag);
#endif
    if (!((struct or_context *)(cur_frame->app_ptr))->incomplete_flag)
    {
        p++;          /* Skip the sequence */
        if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag == 1)
        {
            ((struct or_context *)(cur_frame->app_ptr))->curs =
               e2universal_fixed(fp, &p,top,
                 &((struct or_context *)(cur_frame->app_ptr))->btype_cnt,
                 &((struct or_context *)(cur_frame->app_ptr))->b_cnt,
                 &((struct or_context *)(cur_frame->app_ptr))->d_cnt,
                 &((struct or_context *)(cur_frame->app_ptr))->f_arrlen,
                 &((struct or_context *)(cur_frame->app_ptr))->e_arrlen,
                 &((struct or_context *)(cur_frame->app_ptr))->plsql_flag);
            if (((struct or_context *)(cur_frame->app_ptr))->more_flag)
                return ((struct or_context *)(cur_frame->app_ptr))->curs;
        }
        else
        {
            ((struct or_context *)(cur_frame->app_ptr))->op_flag =
                               counted_int(p,1);
#ifdef DEBUG
            fprintf(fp, "Operations flag:%x\n", counted_int(p,1));
#endif
            if (*p > 8)
            {
                fprintf(fp, "Dubious Op length:%u\n", (unsigned int) (*p));
                p++;
            }
            else
                p += *p + 1;
            ((struct or_context *)(cur_frame->app_ptr))->curs =
                   counted_int(p,1);
            if (*p > 8)
            {
                fprintf(fp, "Dubious Cursor length:%u\n", (unsigned int) (*p));
                p++;
            }
            else
                p += *p + 1;
/*
 * Is there going to be a statement?
 */
            if (!(((struct or_context *)(cur_frame->app_ptr))->op_flag  & 1))
            {
                ((struct or_context *)(cur_frame->app_ptr))->stat_len = 0;
                if (((struct or_context *)(cur_frame->app_ptr))->funny)
                    p = chew_zero(fp, p,6);
                p = chew_zero(fp, p,4);
            }
            else
            {
                if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
                    (void) funny_test(&p);
                else
                    p++;
                ((struct or_context *)(cur_frame->app_ptr))->stat_len =
                           counted_int(p,1);
                p += *p + 1;
                if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
                    p = chew_zero(fp, p,5);
                else
                    p = chew_zero(fp, p,2);
            }
/*
 * The patterns here change between different ORACLE versions. Amazingly, 
 * the version is coded in eg. 010107010102 for ORACLE 7.2. In funny mode, the
 * second flag seems to be ignored; assume it must be present.
 */
            opti_get(&p, &dummy);
            opti_get(&p, &dummy);
/*
 * Not sure if a counted int is really here.
 */
            if ( ((struct or_context *)(cur_frame->app_ptr))->funny)
                p += 4;
            else
                p++;
/*
 * Are there returned values?
 */
            if (!opti_get(&p,
                    &(((struct or_context *)(cur_frame->app_ptr))->d_cnt)))
                p++;
/*
 * Bind Variables
 */
            if (!opti_get(&p,
                    &(((struct or_context *)(cur_frame->app_ptr))->b_cnt)))
                p++;
/*
 * Bind Variable Types
 * The p++ change may have rendered this obsolete
 * VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
            if (((struct or_context *)(cur_frame->app_ptr))->b_cnt == 0)
                opti_get(&p,
                    &(((struct or_context *)(cur_frame->app_ptr))->btype_cnt));
            else
 */
                ((struct or_context *)(cur_frame->app_ptr))->btype_cnt =
                  ((struct or_context *)(cur_frame->app_ptr))->b_cnt;
            if (p > top)
            {
                fputs( "Lost Synchronisation in e2universal():2\n", fp);
                fflush(fp);
                err_dump = 1;
                return ((struct or_context *)(cur_frame->app_ptr))->curs;
            }
            if (((struct or_context *)(cur_frame->app_ptr))->stat_len)
            {
                while (p < top && !*p)
                    p++;
                if (((struct or_context *)(cur_frame->app_ptr))->stat_len
                        < 65536)
                {
#ifdef DEBUG_FULL
                    if (!strncmp(p,"INSERT",6))
                        puts(p);
#endif
                    fprintf(fp, "\\PARSE:%u\\\n",
                          ((struct or_context *)(cur_frame->app_ptr))->curs);
                    ((struct or_context *)(cur_frame->app_ptr))->plsql_flag =
                        wrapsql(fp,
                         ((struct or_context *)(cur_frame->app_ptr))->stat_len,
                         p, top,
                       &((struct or_context *)(cur_frame->app_ptr))->more_flag);
                    if (((struct or_context *)(cur_frame->app_ptr))->
                                   more_flag)
                    {
                        ((struct or_context *)(cur_frame->app_ptr))->
                               incomplete_flag = 1;
                        return ((struct or_context *)(cur_frame->app_ptr))->curs;
                    }
                }
                p += ((struct or_context *)(cur_frame->app_ptr))->stat_len;
            }
            if (((struct or_context *)(cur_frame->app_ptr))->curs == 21)
                puts("Interesting");
            if (p >= top)
            {
                if (((struct or_context *)(cur_frame->app_ptr))->d_cnt > 0
                 || ((struct or_context *)(cur_frame->app_ptr))->btype_cnt > 0)
                {
                    ((struct or_context *)(cur_frame->app_ptr))->
                               incomplete_flag = 1;
                }
                else
                {
                    if (((struct or_context *)(cur_frame->app_ptr))->op_flag
                           & 0x20)
                        fprintf(fp, "\\EXEC:%u\\\n",
                           ((struct or_context *)(cur_frame->app_ptr))->curs);
                    if (((struct or_context *)(cur_frame->app_ptr))->op_flag
                           & 0x10)
                        fprintf(fp, "\\FETCH:%u\\\n",
                           ((struct or_context *)(cur_frame->app_ptr))->curs);
                }
                return ((struct or_context *)(cur_frame->app_ptr))->curs;
            }
/*
 * The EXEC array length
 */
            ((struct or_context *)(cur_frame->app_ptr))->e_arrlen =
                      counted_int(p,1);
            p += *p + 1;
/*
 * The FETCH array length
 */
            ((struct or_context *)(cur_frame->app_ptr))->f_arrlen =
                      counted_int(p,1);
            p += *p + 1;
#ifdef DEBUG
        fprintf(fp, "e2universal(stat_len=%d d_cnt=%d btype_cnt=%d b_cnt=%d f_arrlen=%d e_arrlen = %d)\n",
                   ((struct or_context *)(cur_frame->app_ptr))->stat_len,
                   ((struct or_context *)(cur_frame->app_ptr))->d_cnt,
                   ((struct or_context *)(cur_frame->app_ptr))->btype_cnt,
                   ((struct or_context *)(cur_frame->app_ptr))->b_cnt,
                   ((struct or_context *)(cur_frame->app_ptr))->f_arrlen,
                   ((struct or_context *)(cur_frame->app_ptr))->e_arrlen);
#endif
            if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x20)
                fprintf(fp, "\\EXEC:%u\\\n",
                   ((struct or_context *)(cur_frame->app_ptr))->curs);
            chew_zero(fp, p,5);
            p += 5;
        }
        ((struct or_context *)(cur_frame->app_ptr))->to_do_cnt =
                ((struct or_context *)(cur_frame->app_ptr))->f_arrlen;
    }
    else
        ((struct or_context *)(cur_frame->app_ptr))->curs =
            ((struct or_context *)(cur_frame->app_ptr))->last_curs;
/*
 * Hop over the defines if there are any
 */
    if (((((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x40)
     || (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x8000))
     && ((struct or_context *)(cur_frame->app_ptr))->d_cnt != 0)
        p = e2skipdefs(fp,p,top,
                   ((struct or_context *)(cur_frame->app_ptr))->d_cnt);
/*
 * If there are bind type details
 */
    if (((struct or_context *)(cur_frame->app_ptr))->curs > 511)
    {
        fprintf(stderr, "struct or_context only supports 512 cursors; this is\n\
cursor number %d. Edit sqlextlib.c and recompile\n",
               ((struct or_context *)(cur_frame->app_ptr))->curs);
        return ((struct or_context *)(cur_frame->app_ptr))->curs;
    }
    if (((struct or_context *)(cur_frame->app_ptr))->d_cnt > 0
       && !((struct or_context *)(cur_frame->app_ptr))->incomplete_flag)
        ((struct or_context *)(cur_frame->app_ptr))->
             desc_cnt[((struct or_context *)(cur_frame->app_ptr))->curs] =
            ((struct or_context *)(cur_frame->app_ptr))->d_cnt;
    else
        ((struct or_context *)(cur_frame->app_ptr))->
             desc_cnt[((struct or_context *)(cur_frame->app_ptr))->curs] =
            ((struct or_context *)(cur_frame->app_ptr))->plsql_flag;
#ifdef UNRELIABLE
    if (((struct or_context *)(cur_frame->app_ptr))->d_cnt > 0
      && ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag)
        return ((struct or_context *)(cur_frame->app_ptr))->curs;
    else
#else
    if (((struct or_context *)(cur_frame->app_ptr))->d_cnt > 0)
#endif
        ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
/*
 * Mark the descriptors as done
 */
    ((struct or_context *)(cur_frame->app_ptr))->d_cnt = 0;
    if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x08)
    {
        while (*p == 0 && p < top)
            p++;
        p = e2bindtypes(fp, ((struct or_context *)(cur_frame->app_ptr))->curs,
                ((struct or_context *)(cur_frame->app_ptr))->btype_cnt,p, top);
        if (p >= top)
            return ((struct or_context *)(cur_frame->app_ptr))->curs;
    }
    else
        ((struct or_context *)(cur_frame->app_ptr))->to_do_cnt = 0;
/*
 * If there are bind variables, write them out.
 */
    if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x20)
    {
        p = e2allbinds(fp,((struct or_context *)(cur_frame->app_ptr))->curs,
                     p, top,
                 !(((struct or_context *)(cur_frame->app_ptr))->e_arrlen)? 1 :
                 ((struct or_context *)(cur_frame->app_ptr))->e_arrlen);

        if (((struct or_context *)(cur_frame->app_ptr))->to_do_cnt > 0
         && ((struct or_context *)(cur_frame->app_ptr))->e_arrlen > 0)
        {
            ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
            return ((struct or_context *)(cur_frame->app_ptr))->curs;
        }
    }
    if (((struct or_context *)(cur_frame->app_ptr))->op_flag & 0x10)
        fprintf(fp, "\\FETCH:%u\\\n",
               ((struct or_context *)(cur_frame->app_ptr))->curs);
    ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
    return ((struct or_context *)(cur_frame->app_ptr))->curs;
}
/*
 * Handle what appears to be a remote procedure call from an ORACLE Forms
 * PL/SQL engine to a stored procedure in the database. At present we do not
 * handle this straddling SQL*NET packets.
 */
int e2call_plsql(fp, p, top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
static unsigned char * null_field="";
short int offset = 0;
int ftyp;
static int to_do_cnt;
int curs;
int btype_cnt;
static unsigned char * x;
static unsigned char * y;
static unsigned char * z;
int flg;
int stat_len;
unsigned char * stat_ptr;
unsigned char * tp;
/*
 * This call does not appear to use a conventional cursor, but we need one,
 * should the data get fragmented. We return 1 (which is what we actually
 * find where the cursor is usually located).
 *
 * The layout for the fixed and non-funny cases is entirely conjectural.
 */
    p++;                            /* Skip the sequence */
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
    {
        curs = get_ora_fixed(fp, p);
        p += 4;
    }
    else
    {
        curs = counted_int(p,1);
        p += *p + 1;
    }
    ((struct or_context *)(cur_frame->app_ptr))->curs = curs; 
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
        p += 4;
    else
        p += *p + 1;    /* Skip a zero byte */
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag
      || ((struct or_context *)(cur_frame->app_ptr))->funny)
        p += 4;      /* Skip some unknown flag */
    else
        p++;
/*
 * We are now at the statement length
 */
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
    {
        stat_len = get_ora_fixed(fp, p);
        p += 4;
    }
    else
    {
        stat_len = counted_int(p,1);
        p += *p + 1;
    }
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag
      || ((struct or_context *)(cur_frame->app_ptr))->funny)
        p += 4;      /* Skip some unknown flag */
    else
        p++;
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
        p += 4;
    else
        p += *p + 1;             /* Skip a zero byte */
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag
      || ((struct or_context *)(cur_frame->app_ptr))->funny)
        p += 4;      /* Skip some unknown flag */
    else
        p++;
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
        p += 4;
    else
        p += *p + 1;             /* Skip some counted int (a count?) */
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag
      || ((struct or_context *)(cur_frame->app_ptr))->funny)
        p += 4;      /* Skip some unknown flag */
    else
        p++;
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
        p += 4;
    else
        p += *p + 1;             /* Skip some counted int (a count?) */
/*
 *  The next 4 bytes are always f459d401!?
 */
    if (*p != (unsigned char) 0xf4)
       fprintf(fp, "Error: expected 0xf4, found %x", (unsigned int) *p); 
    p++;
    if (*p != (unsigned char) 0x59)
       fprintf(fp, "Error: expected 0x59, found %x", (unsigned int) *p); 
    p++;
    if (*p != (unsigned char) 0xd4)
       fprintf(fp, "Error: expected 0xd4, found %x", (unsigned int) *p); 
    p++;
    if (*p != (unsigned char) 0x01)
       fprintf(fp, "Error: expected 0x01, found %x", (unsigned int) *p); 
    p++;
    chew_zero(fp,p,10);            /* Purpose unknown */
    p += 10;
/*
 * We are now at the details
 */
    stat_ptr = p;
    p += stat_len;
 
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
        p += 16;
    else
    {
        p += *p + 1;
        p += *p + 1;
        p += *p + 1;
        p += *p + 1;
    }
    chew_zero(fp, p, 7);
    p += 7;
    if (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
    {
        p += 12;
        to_do_cnt =  get_ora_fixed(fp, p);
        p += 4;
    }
    else
    {
        p += *p + 1;
        p += *p + 1;
        p += *p + 1;    /* Looks to be an interesting count */
        to_do_cnt = counted_int(p,1); 
        p += *p + 1;
    }
    btype_cnt = to_do_cnt;
    ((struct or_context *)(cur_frame->app_ptr))->btype_cnt =
                         to_do_cnt;
/*
 * The following is lifted from e2bindtypes(). The problem is that these
 * do not have any lengths.
 */
    if (((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] ==
                      (unsigned char *) NULL)
    {
        ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] =
                      (unsigned char *) malloc(btype_cnt + 1);
        ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] =
                      (unsigned char *) malloc(btype_cnt + 1);
        ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] =
                      (unsigned char *) malloc(btype_cnt + 1);
    }
    else
    {
        ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] =
               (unsigned char *) realloc(((struct or_context *)
                  (cur_frame->app_ptr))->bind_types[curs], btype_cnt + 1);
        ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] =
               (unsigned char *) realloc(((struct or_context *)
                  (cur_frame->app_ptr))->bind_flags[curs], btype_cnt + 1);
        ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs] =
               (unsigned char *) realloc(((struct or_context *)
                  (cur_frame->app_ptr))->bind_lengths[curs], btype_cnt + 1);
    }
    x = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs];
    y = ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs];
    z = ((struct or_context *)(cur_frame->app_ptr))->bind_lengths[curs];
    *x++ = btype_cnt;
    *y++ = btype_cnt;
    *z++ = btype_cnt; 
/*
 * They actually look like counted ints! We need to stop the count at the
 * first ORA_INTEGER type.
 */
    flg = 0;
    for (to_do_cnt = 0; to_do_cnt < btype_cnt; to_do_cnt++, x++, y++, z++)
    {
        *x = *(p + 1);      /* Data Type */
        *y = *(p + 4);      /* Bind Type */
        p += *p + 1;
        if (*y & 1)         /* Input variable, or in/out */
        {
            *z = (unsigned char) 80; 
            if (*x == ORA_INTEGER && flg == 0)
                flg = to_do_cnt;
        }
        else
            *z = 0;
        if (p >= top)
             break;
    }
    if (flg != 0)
        btype_cnt = flg;
    if (p < top)
    {
        ftyp = *p + 1;
        if (ftyp == 15)
            p += *p + 1;
    }
    else
        ftyp = (unsigned char) 6;   /* Make it a procedure by default */
/*
 * We can now write out our anonymous PL/SQL block
 */
    stat_len = (p - stat_ptr) - stat_len;
    fprintf(fp, "\\PARSE:%u\\\nbegin\n",
           ((struct or_context *)(cur_frame->app_ptr))->curs);
    if (ftyp == 15)
        fputs("    :ret_val := ",fp);
    tp = strtok(stat_ptr,"\"");
    if (tp == NULL)
    {
        fputs("Missing something!?\n", fp);
        return;
    }
    stat_ptr = tp;
    fputs(stat_ptr, fp);   /* Schema name */
    fputc('.', fp);
    tp = strtok(NULL,"\"");
    if (tp == NULL)
    {
        fputs("Missing something!?\n", fp);
        return;
    }
    stat_ptr = tp;
    fputs(stat_ptr, fp);   /* Package name or procedure or function */
    stat_ptr = strtok(NULL,"\"");
    if (stat_ptr != (unsigned char *) NULL && stat_ptr <= (p - stat_len))
    {
        fputc('.', fp);
        fputs(stat_ptr, fp);   /* Procedure or function */
    }
/*
 * Now write out the calling parameters, if there are any
 */
    if (btype_cnt > 0)
    {
        fputc('(', fp);

        x = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] + 1;
        switch ((int) *x)
        {
        case ORA_NUMBER:
        case ORA_INTEGER:
        case ORA_FLOAT:
        case ORA_VARNUM:
        case ORA_PACKED:
        case ORA_UNSIGNED:
        case ORA_DISPLAY:
            fputs(":bnd_num0", fp);
            break;

        case ORA_ROWID:
            fputs(":bnd_rowid0", fp);
            break;

        case ORA_DATE:
            fputs(":bnd_date0", fp);
            break;

        case ORA_RAW:
        case ORA_VARRAW:
        case ORA_LONG_VARRAW:
        case ORA_LONG_RAW:
        case ORA_MLSLABEL:
        case ORA_RAW_MLSLABEL:
            fputs(":bnd_raw0", fp);
            break;

        case ORA_VARCHAR2:
        case ORA_LONG_VARCHAR:
        case ORA_LONG:
        case ORA_CHAR:
        case ORA_VARCHAR:
        case ORA_CHARZ:
        case ORA_STRING:
        default:
            fputs(":bnd_char0", fp);
            break;
        }
        for (to_do_cnt = 1; to_do_cnt <  btype_cnt; to_do_cnt++)
        {
            x++;
            switch ((int) *x)
            {
            case ORA_NUMBER:
            case ORA_INTEGER:
            case ORA_FLOAT:
            case ORA_VARNUM:
            case ORA_PACKED:
            case ORA_UNSIGNED:
            case ORA_DISPLAY:
                fprintf(fp, ",\n:bnd_num%d", to_do_cnt);
                break;
    
            case ORA_ROWID:
                fprintf(fp, ",\n:bnd_rowid%d", to_do_cnt);
                break;
    
            case ORA_DATE:
                fprintf(fp, ",\n:bnd_date%d", to_do_cnt);
                break;
    
            case ORA_RAW:
            case ORA_VARRAW:
            case ORA_LONG_VARRAW:
            case ORA_LONG_RAW:
            case ORA_MLSLABEL:
            case ORA_RAW_MLSLABEL:
                fprintf(fp, ",\n:bnd_raw%d", to_do_cnt);
                break;

            case ORA_VARCHAR2:
            case ORA_LONG_VARCHAR:
            case ORA_LONG:
            case ORA_CHAR:
            case ORA_VARCHAR:
            case ORA_CHARZ:
            case ORA_STRING:
            default:
                fprintf(fp, ",\n:bnd_char%d", to_do_cnt);
                break;
            }
        }
        fputc(')', fp);
    }
    fputs(";\nend;\n/\n\\EXEC:1\\\n", fp);
/*
 * Finally, we write out the bind variables provided. sqldrive needs to
 * have values for all the bind variables, even the return-only ones.
 * We now use flg as a flag value for whether we have output one.
 */
    flg = 0;
    if (ftyp == 15)
    {
        fputs("''", fp);
        flg = 1;
    }
    x = ((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] + 1;
    y = ((struct or_context *)(cur_frame->app_ptr))->bind_flags[curs] + 1;
    if (p < top)
        p += *p + 1;
/*
 * The bind types are in the order declared for the function or procedure,
 * but there are extra values; one or two before we start (which we have already
 * skipped), and indicator variables after.
 *
 * The rules are:
 * -  Stop when we get to the indicator variables (type 3, ORA_INTEGER)
 * -  Ignore zero bytes encountered when we expect a field
 * -  If the type is numeric, check that the length is > 1; if it is not, and
 *    the next byte is not 80, output a NULL and advance to the next column
 */
#ifdef DEBUG
    fputs("Before the Bind", fp);
    gen_handle(fp, p,top,1);
#endif
    for (to_do_cnt = 0; to_do_cnt < btype_cnt ; to_do_cnt++, x++, y++)
    {
        if (flg)
        {
            fputc(',', fp);
            offset = 3;
            flg = 0;
        } 
/*
 * Output a NULL if the variable is output-only, or we have no more record
 */
        if (!(*y & 1) || p >= top )
        {
            offset = ora_field(fp,ORA_VARCHAR2, null_field,
                offset,(to_do_cnt == (btype_cnt  - 1)),null_field+1);
            continue;
        }
        if (*p == 0)
            p++;
/*
 * These look like missing values
 */
        if ((*x == ORA_VARCHAR2 && *(p + 1) > 127) ||
           (*x == ORA_DATE && (*p != 7 || *(p + 1) < 100)) ||
           (*x == ORA_NUMBER && *(p + 1) < 128))
        {
            offset = ora_field(fp,ORA_VARCHAR2, null_field,
                offset,(to_do_cnt == (btype_cnt  - 1)),null_field+1);
            continue;
        }
        if ((offset = ora_field(fp,((unsigned int) *x),p,
                offset,(to_do_cnt == (btype_cnt  - 1)),top)) < 0)
        {
            fputs("e2call_plsql:Bind Types Corrupt?\n", fp);
            p = top + 1;
            continue;
        }
        if (*x == ORA_VARCHAR2)
        {
            if (*p == 1 && *(p + 1) == *(p + 2))
            {
                p += *(p + 1) + 3;
                continue;
            }
            else
            if (*p == 2 && *(p + 3) == 0xff)
            {
                p += counted_int(p,1) + 4;
                continue;
            }
            else
            if (*p == 2 && *(p + 3) == 0xfe)
            {
                p += 3;
            }
        }
        if (*p == 253)
            p += 2;
        else
        if (*p == 254)
        {
            p = ((char *) memchr(p,0,top - p + 1)) + 1;
            if (p == (unsigned char *) 1)
                p = top;
        }
        else
            p += *p + 1;
        if (p > top)
        {
            p = top;
#ifdef DEBUG
            fputs("e2call_plsql() Ran out of record\n", fp);
#endif
        }
    }
    ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
    return curs;
}
/*
 * Handle an exec request
 */
int e2exec(fp, p, top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
int curs;
    p++;      /* Skip the sequence */
    if (!((struct or_context *)(cur_frame->app_ptr))->fixed_flag)
    {
        curs = counted_int(p,1);
        p += ((unsigned) *p) + 1;
        ((struct or_context *)(cur_frame->app_ptr))->e_arrlen =
               counted_int(p,1);
        p += ((unsigned) *p) + 1;
        p += ((unsigned) *p) + 1;
    }
    else
    {
/*
 * Apparently fixed length
 */
       curs = get_ora_fixed(fp, p);
       p += 4;
       ((struct or_context *)(cur_frame->app_ptr))->e_arrlen =
              get_ora_fixed(fp,p);
       p += 8;
    }
    ((struct or_context *)(cur_frame->app_ptr))->curs = curs;
    ((struct or_context *)(cur_frame->app_ptr))->to_do_cnt = 
           ((struct or_context *)(cur_frame->app_ptr))->e_arrlen;
    fprintf(fp, "\\EXEC:%u\\\n",curs);
    if (curs > 511)
    {
        fprintf(fp, "e2exec(): Cursor %d is out of range\n",
                     curs);
        curs = curs/65536;
    }
    if (((struct or_context *)(cur_frame->app_ptr))->bind_types[curs] !=
           (unsigned char *) NULL)
        p = e2allbinds(fp, curs,p, top, 
           ((struct or_context *)(cur_frame->app_ptr))->e_arrlen);
    return curs;
}
/*
 * Handle an exec request
 */
int e2exec_fetch(fp, p, top)
FILE *fp;
unsigned char * p;
unsigned char * top;
{
int curs =  e2exec(fp, p, top);
    fprintf(fp, "\\FETCH:%u\\\n",curs);
    return curs;
}
int e2immediate(fp, p, top)
FILE *fp;
unsigned char *p;
unsigned char * top;
{
int curs = e2parse(fp, p, top);
    (void) e2exec(fp, p, top);
    return curs;
}
/*
 * Handle sql-related messages
 */
static char * sync_handle(fp, x,top,out)
FILE *fp;
unsigned char * x;
unsigned char * top;
int out;
{
/*
 * Four bytes zero
 * I do not have samples of cancel.
 */
    chew_zero(fp, x,4);
    x += 4;
#ifdef DEBUG
    fprintf(fp, "e2zero %d (offset now 11)\n",(int) *x++);
#else
    x++;
#endif
    if (((struct or_context *)(cur_frame->app_ptr))->more_flag && out)
    {
    int hop = ((struct or_context *)(cur_frame->app_ptr))->more_flag;
        (void) wrapsql(fp,
                   ((struct or_context *)(cur_frame->app_ptr))->more_flag,x,
           top, &((struct or_context *)(cur_frame->app_ptr))->more_flag);
        if (((struct or_context *)(cur_frame->app_ptr))->more_flag)
        {
            ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 1;
            return top;
        }
        else
            x += hop;
    }
#ifndef UNRELIABLE
    if (((struct or_context *)(cur_frame->app_ptr))->incomplete_flag && !out)
        ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
#endif
    if (((struct or_context *)(cur_frame->app_ptr))->incomplete_flag
            && ((((struct or_context *)(cur_frame->app_ptr))->last_op == 0x47)
            || ((struct or_context *)(cur_frame->app_ptr))->last_op == 0x3e))
        ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                 e2universal(fp, x,top);
    else
    switch (*((unsigned char *)x))
    {
    case 0x01:
#ifdef DEBUG
        fputs("e2version(0x01)\n", fp);
#endif
        break;
    case 0x02:
#ifdef DEBUG
        fputs("e2charset_exch(0x02)\n", fp);
#endif
        break;
    case 0x03:
#ifdef DEBUG
        fputs("e2sql(0x03)\n", fp);
#endif
        x++;
        ((struct or_context *)(cur_frame->app_ptr))->last_op = (int) *x;
/*
 * Avoid problems with random selections
 */
        if ( ((struct or_context *)(cur_frame->app_ptr))->fixed_flag == -1
          && *x != 2)
            return top;
        switch (*x)
        {
        case 0x02:
#ifdef DEBUG
            fputs("e2cursor_open(0x02)\n", fp);
#endif
            if ( ((struct or_context *)(cur_frame->app_ptr))->fixed_flag == -1)
            {
                if (top - x > 7)
                    ((struct or_context *)(cur_frame->app_ptr))->fixed_flag = 1;
                else
                {
                    if (top - x > 4)
                        ((struct or_context *)(cur_frame->app_ptr))->funny = 1;
                    ((struct or_context *)(cur_frame->app_ptr))->fixed_flag = 0;
                }
            }
            break;
        case 0x03:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                         e2parse(fp, x+1,top);
            return top;
            break;
        case 0x04:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                        e2exec(fp, x+1,top);
            return top;
            break;
        case 0x05:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                        e2fetch(fp, x + 1,top);
            return top;
            break;
        case 0x07:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1);
            if (out)
                (void) e2bindvars(fp,
                     ((struct or_context *)(cur_frame->app_ptr))->last_curs,
                              x + (*x+2) +3, top, 0);
            return top;
            break;
        case 0x08:
#ifdef DEBUG
            fprintf(fp, "e2close(0x08) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x09:
#ifdef DEBUG
            fputs("e2disconnect(0x09)\n", fp);
#endif
            fprintf(fp, "\\C:LOGOUT:%u\\\n",out);
            break;
        case 0xa:
#ifdef DEBUG
            fputs("e2cancel(0x10)\n", fp);
#endif
            break;
        case 0x0e:
            fputs("\\PARSE:255\\\ncommit\n/\n\\EXEC:255\\\n", fp);
            break;
        case 0x0f:
            fputs("\\PARSE:255\\\nrollback\n/\n\\EXEC:255\\\n", fp);
            break;
        case 0x10:
#ifdef DEBUG
            fprintf(fp, "e2reopen_cursor(0x10) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x11:
#ifdef DEBUG
            fprintf(fp, "e2define(0x11) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x14:
#ifdef DEBUG
            fprintf(fp, "e2close_different(0x14) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x1f:
#ifdef DEBUG
            fprintf(fp, "e2how_many(0x1f) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x27:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                     e2immediate(fp, x+1, top);
            return top;
            break;
        case 0x2b:
#ifdef DEBUG
            fprintf(fp, "e2describe(0x2B) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x38:
#ifdef DEBUG
            fprintf(fp, "e2defer_parse(0x38) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x3b:
#ifdef DEBUG
            fprintf(fp, "e2session_options(0x3b) Cursor %d\n",
                     (((struct or_context *)(cur_frame->app_ptr))->fixed_flag)?
                     get_ora_fixed(fp,x + 2):
                     counted_int(x+2,1));
#endif
            break;
        case 0x3e:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                       e2defer_parse_exec_fetch(fp, x + 1,top);
            return top;
            break;
        case 0x47:
            ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                          e2universal(fp, x + 1,top);
            return top;
            break;
        case 0x4c:
            ((struct or_context *)(cur_frame->app_ptr))->incomplete_flag = 0;
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                          e2call_plsql(fp, x + 1,top);
            return top;
            break;
        case 0x48:
#ifdef DEBUG
            fputs("e2longpiece(0x48)?\n", fp);
#endif
            break;
        case 0x4a:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                       e2defer_parse_bind(fp, x + 1,top);
            return top;
            break;
        case 0x4e:
            ((struct or_context *)(cur_frame->app_ptr))->last_curs =
                       e2exec_fetch(fp, x + 1,top);
            return top;
            break;
        case 0x51:
#ifdef DEBUG
            fputs("e2login(0x51)\n", fp);
#endif
            fputs("\\C:NEW SESSION\\\n", fp);
            break;
        case 0x52:
#ifdef DEBUG
            fputs("e2who_am_i(0x52)\n", fp);
#endif
            break;
        case 0x54:
#ifdef DEBUG
            fputs("e2filestuff(0x54)?\n", fp);
#endif
            break;
        default:
            if (out)
            {
                fprintf(fp, "\\C:SQL:%d:e2unknown(0x%x)\\\n",out, *x);
                (void) gen_handle(fp, x,top,out);
            }
#ifdef DEBUG
            break;
#endif
            return top;
        }
        break;
    case 0x07:
        if (out)
            x =  e2allbinds(fp,
                    ((struct or_context *)(cur_frame->app_ptr))->last_curs,
                            x, top, 0);
        break;
    case 0x04:
#ifdef DEBUG
        fputs("e2error(0x04)\n", fp);
#endif
        break;
    case 0x06:
#ifdef DEBUG
        fputs("e2array_data(0x06)\n", fp);
        fprintf(fp, "\\FETCH:%u\\\n",
                   ((struct or_context *)(cur_frame->app_ptr))->last_curs );
#endif
        break;
    case 0x08:
#ifdef DEBUG
        fputs("e2status(0x08)\n", fp);
#endif
        break;
    case 0x09:
#ifdef DEBUG
        fputs("e2close_acknowledge(0x09)\n", fp);
#endif
        break;
    case 0x0b:
        x = e2bind_variable_return(fp,
                   ((struct or_context *)(cur_frame->app_ptr))->last_curs,x+1,
                                        top);
        break;
    case 0x28:
#ifdef DEBUG
        fputs("e2connect_details(0x28)\n", fp);
#endif
        break;
    case 0xde:
#ifdef DEBUG
        fputs("e2options(0xde)\n", fp);
#endif
        break;
    default:
        if (out)
        {
            fprintf(fp, "\\C:NET:%d:e2unknown(0x%x)\\\n",out, *x);
            (void) gen_handle(fp, x,top,out);
        }
        break;
    }
#ifdef DEBUG
    x++;
    x = gen_handle(fp, x,top,out);
    fflush(fp);
#endif
    return top;
}
#ifdef DEBUG
/*
 * Handle Error Messages
 */
static char * error_handle(fp, x,top,out)
FILE *fp;
unsigned char * x;
unsigned char * top;
int out;
{
#ifdef DEBUG
/*
 * Three bytes zero
 */
    chew_zero(fp, x,3);
    x += 3;
    x = gen_handle(fp, x,top,out);
#endif
    return top;
}
#endif
/*
 * Handle SQL*NET V.2 messages
 */
static void tns_handle(fp, len,hold_buf, out)
FILE *fp;
int len;
unsigned char * hold_buf;
int out;
{
unsigned char *top = hold_buf + len;
unsigned char * x = hold_buf;
#ifdef DEBUG
    (void) gen_handle(fp,hold_buf,hold_buf+len,1);
#endif
    err_dump = 0;
/*
 * Two bytes length
 */
    (void) chew_len(fp, x);
    x += sizeof(short int);
/*
 * Two bytes zero
 */
    chew_zero(fp, x,2);
    x += 2;
/*
 * 1 Byte Record Type
 */
    switch (*x)
    {
        case 1:
#ifdef DEBUG
            fputs("e2connect\n", fp);
#endif
            x++;
            (void) connect_handle(fp, x,top,out);
            break;
        case 2:
        case 5:
#ifdef DEBUG
            fputs("e2reconnect\n", fp);
#endif
            x++;
            (void) reconnect_handle(fp, x,top,out);
            break;
        case 6:
#ifdef DEBUG
            fputs("e2sync\n", fp);
#endif
            x++;
            (void) sync_handle(fp, x,top,out);
            break;
        case 11:
#ifdef DEBUG
            fputs("e2again\n", fp);
            x++;
            (void) gen_handle(fp, x,top,out);
#endif
            break;
        case 12:
#ifdef DEBUG
            fputs("e2error\n", fp);
            x++;
            (void) error_handle(fp, x,top,out);
#endif
            break;
        default:
            if (out)
            {
                fprintf(fp, "\\C:MESS:%d:e2unknown %d\\\n", out, (int) *x);
                (void) gen_handle(fp, x,top,out);
            }
#ifdef DEBUG
            x++;
            (void) gen_handle(fp, x,top,out);
#endif
            break;
    }
    if (err_dump && out)
    {
#ifndef DEBUG
        (void) gen_handle(fp,hold_buf,hold_buf+len,1);
#endif
#ifdef WE_KNOW
        ((struct or_context *)(cur_frame->app_ptr))->funny =
         !(((struct or_context *)(cur_frame->app_ptr))->funny);
#endif
    }
    fflush(fp);
    return;
}

/*
 * Scan a captured network packets and work out Application response times
 * 
 * The complexities in this file are to do with trying to make the descriptions
 * associated with the timings as meaningful as possible. To this end:
 * -  We allocate session structures (hashed on IP Address and session ID)
 * -  We tie the individual TCP connection to the session structures
 * -  We search for particular well-known variables that seem to
 *    have meaningful descriptions
 * -  We stamp the responses with these values inherited from the session.
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
static int sess_cnt;
static int verbose_flag;
/*
 * Table used for looking for interesting data
 */
static struct scan_con {
    unsigned char * match_key;
    struct bm_table * bp;
} scan_con[] =
{
#ifdef EMR
#ifndef COOKIE_AUTH
{ "Authorization: NTLM " },     /* Position 0 is known to be the cookie */
#else
{ "ASP.NET_SessionId=" },     /* Position 0 is known to be the cookie */
#endif
{ "method=" },
{ "<folderUrl>" },
{ "fname=" },
{ "flist=" },
{ "url=" },
{ "<pageUrl>" },
{ "<item>" },
#endif
{ "JSESSIONID=" },
{ "InfoViewPLATFORMSVC_COOKIE_USR=" },
{ (unsigned char *) NULL }};
/*
 * Table for choosing labels for URL's
 */
static struct url_classify {
    unsigned char * match_key;
    struct bm_table * bp;
    unsigned char * label;
} url_classify[]
={
{ ".gif", 0, "Graphic" },
{ ".ico", 0, "Graphic" },
{ ".jpg", 0, "Graphic" },
{ ".css", 0, "CSS" },
{ ".htm", 0, "Static" },
{ ".html", 0, "Static" },
#ifdef EMR
{ ".ashx", 0, "Trade2" },
{ ".asmx", 0, "Trade2" },
{ "citrix", 0, "CitrixPNA" },
{ ".aspx", 0, "Trade2" },
{ "-11.3", 0, "Coda" },
{ ".dll", 0, "CitrixPNA" },
{ "/sites/", 0, "Portal" },
{ "/_vti_bin/", 0, "WebService" },
{ "/ReportingWebService/", 0, "Reporting" },
#endif
{ "viewDocument.jsp", 0, "Load Report" },
{ "getImage.jsp", 0, "Load Graph" },
{ "viewDrillBar.jsp", 0, "Add Controls" },
{ "/BO/BI", 0, "BO" },
{ "InfoView", 0, "InfoView" },
{ "PlatformServices", 0, "PlatformServices" },
{ "Dashboard", 0, "Dashboard" },
{ "PerformanceManagement", 0, "PerformanceManagement" },
{ "AnalyticalReporting", 0, "AnalyticalReporting" },
{ "CrystalReports", 0, "CrystalReports" },
{ ".jsp", 0, "JSF (UI)" },
{ ".js", 0, "Javascript" },
{ (unsigned char *) NULL  }};

static char * url_classification(base, top)
unsigned char * base;
unsigned char * top;
{
struct url_classify * ucp;
unsigned char * p1;
int len;

    len = memcspn(base, top, 9, "?&; \r\n<>");
    for (ucp = &url_classify[0]; ucp->bp != (unsigned char *) NULL; ucp++)
        if (bm_match(ucp->bp, base, base + len))
            break;
    if (ucp->bp == (struct bm_table *) NULL)
        return "Other";
    return ucp->label;
}
/*
 * Structure allocated when a session is started that holds session state.
 *
 * This code handles multiple parallel sessions, but may not handle
 * asynchronous calls.
 */
struct web_context {
    unsigned char *session_key; /* Hashed */
    unsigned char * labels[10]; /* Current values of matched labels */
    struct web_context * wcp;   /* Parent; may not need this */ 
    int ref_cnt;                /* Reference Count; likewise */
    FILE * ofp;
};
static struct frame_con * cur_frame;
static HASH_CON *ht;                       /* The session hash table      */
/*
 * Session hash function
 */
static unsigned hash_func(x, modulo)
unsigned char * x;
int modulo;
{
    return(string_hh( ((struct web_context *) x)->session_key,
                             modulo) & (modulo-1));
}
/*
 * Session hash comparison function
 */
static int comp_func(x1, x2)
unsigned char * x1;
unsigned char * x2;
{
    return strcmp( ((struct web_context *) x1)->session_key,
              ((struct web_context *) x2)->session_key);
}
/*
 * Initialise the session structure
 */
static struct web_context * new_session( session_name )
unsigned char * session_name;
{
struct web_context * x;
int i;

    if ((x = (struct web_context *) malloc( sizeof(struct web_context)))
          == (struct web_context *) NULL)
        return x;
    x->session_key = strdup( session_name);
    for (i = 0; i < 10; i++)
        x->labels[i] = (unsigned char *) NULL;
    x-> wcp = (struct web_context *) NULL;   /* Parent; may not need this */ 
    x->ref_cnt = 1;                /* Reference Count; likewise */
    insert(ht,x,x);
    x->ofp = cur_frame->ofp;
    return x;
} 
static void first_write(frp)
struct frame_con *frp;
{
char fname[32];
register struct web_context * rop = (struct web_context *) frp->app_ptr;

    if (rop == NULL)
    {
        if (frp->ofp == NULL)
        {
            sprintf(fname,"web_%d.msg", sess_cnt++);
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
        }
    }
    else
    {
        if (rop->ofp == NULL)
        {
            if (frp->ofp == NULL)
            {
                sprintf(fname,"web_%d.msg", sess_cnt++);
                frp->ofp = fopen(fname, "wb");
                if (frp->ofp == (FILE *) NULL)
                    frp->ofp = stdout;   /* Out of file descriptors */
            }
            rop->ofp = frp->ofp;
        }
        else
            frp->ofp = rop->ofp;
    }
    fputs( "\\M:", frp->ofp);
    ip_dir_print(frp->ofp, frp, 0);
    fputs( "\\\n", frp->ofp);
    return;
}
static void shrink_escapes(x)
unsigned char * x;
{
unsigned char * x1 = x;
unsigned char * top = x + strlen(x);

    while (x1 < top)
    {
        if (*x1 < ' ' || *x1 > 126 )
        {                          /* Edit out extraneous characters */
            x1++;
            continue;
        }
        if (*x1 == '%')
        {
            x1 += 2;
            *x = '+';
        }
        else
        if (x != x1)
            *x = *x1;
        x++;
        x1++;
    }
    if (x != x1)
        *x = '\0';
    return;
}
/*
 * Update the session structure
 */
static void update_session(siebp, pos, narr, len)
struct web_context * siebp;
int pos;
unsigned char * narr;
int len;
{
    if (siebp->labels[pos] != (unsigned char *) NULL)
        free(siebp->labels[pos]);
    siebp->labels[pos] = (unsigned char *) strnsave( narr, len);
    shrink_escapes(siebp->labels[pos]);
    return;
}
/*
 * Look for opportunities to update the session data
 */
static int update_label_data(siebp, base, top)
struct web_context * siebp;
unsigned char * base;
unsigned char * top;
{
int i;
int len;
unsigned char * p1;
int done_flag = 0;

    for (i = 1; scan_con[i].match_key != (unsigned char *) NULL; i++)
    {
        if (p1 = bm_match(scan_con[i].bp, base, top))
        {
            p1 += scan_con[i].bp->match_len; 
            len = memcspn(p1, top, 9, "?&; \r\n<>");
            if (p1 + len > top)
                len = top - p1;
            update_session(siebp, i, p1, len);
            done_flag ++;
        }
        else
        if (done_flag)
        {
            free(siebp->labels[i]);
            siebp->labels[i] = (unsigned char *) NULL;
        }
    }
    return done_flag;
}
/*
 * Find a session structure, if possible
 */
static struct web_context * find_session(session_key)
unsigned char * session_key;
{
struct web_context x;
HIPT *h;

    x.session_key = session_key;
    if ((h = lookup(ht, (char *) &x)) != (HIPT *) NULL)
        return (struct web_context *) (h->body);
    else
        return (struct web_context *) NULL;
} 
/*
 * Hunt for the session cookie. This routine:
 * -  Scans for the session cookie.
 * -  If it finds it, looks to see if we already have it.
 * -  If we do, return the one found (and increment its reference count)
 * -  If not, create a new one, and return that.
 */
static struct web_context * hunt_session_cookie(base, top)
unsigned char * base;
unsigned char * top;
{
unsigned char * p1;
int len;
struct web_context * webp;

    if (p1 = bm_match(scan_con[0].bp, base, top))
    {
        p1 += scan_con[0].bp->match_len; 
        len = memcspn(p1, top, 7, "?&; \r\n");
        if (p1 + len > top)
            len = (top - p1);
        p1 = strnsave(p1,len);
        if ((webp =  find_session(p1)) == (struct web_context *) NULL)
        {
            webp = new_session(p1);
            update_session(webp, 0, p1, len);
        }
        free(p1);
        return webp;
    }
    return (struct web_context *) NULL;
}
/*
 * Don't know whether we will be able to free things rationally
 * So Memory-Leaks-R-Us for now.
 */
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */

static int match_cnt;              /* Number of ports in the list    */
static void web_match_add(port)
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
/*
 * One-time-only initialisation
 */
    if (scan_con[0].bp == (struct bm_table *) NULL)
    {
    struct scan_con * sp;
    struct url_classify * up;

        for (sp = &scan_con[0]; sp->match_key != (unsigned char *) NULL; sp++)
            sp->bp = bm_compile(sp->match_key);
        for (up = &url_classify[0]; up->match_key != (unsigned char *) NULL; up++)
            up->bp = bm_compile(up->match_key);
    }
    ht = hash(16384, hash_func, comp_func); /* Create the session hash table */
    extend_listen_flag = 1;
    if ((x = getenv("E2_WEB_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
                web_match_add(i);
        }
    }
    if ((x = getenv("E2_VERBOSE")) != (char *) NULL)
        verbose_flag = 1;
    return;
}
static int web_match_true(from,to)
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
 * Special version of the standard response output routine for flushing data
 * on session close, since we normally write when we see the first packet of
 * the next transaction.
 */
void closeoutput_response (f,dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval resp_time;
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
    tvdiff(&(f->ini_t[!dir_flag].tv_sec),
           &(f->ini_t[!dir_flag].tv_usec),
           &(f->tran_start.tv_sec),       /* The time when the previous       */
           &(f->tran_start.tv_usec),      /* transaction began                */
           &(resp_time.tv_sec),           /* The Response Time               */ 
           &(resp_time.tv_usec));
    if (f->corrupt_flag)
        f->corrupt_flag = 0;
/*    else */
    if (resp_time.tv_sec >= 0 && resp_time.tv_usec >= 0
     && f->tran_start.tv_sec >= 1000000 && f->tran_start.tv_usec >= 0)
    {
        if (f->ofp == NULL)
            first_write(f);
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
    f->tran_cnt[0] = f->cnt[0];
    f->tran_cnt[1] = f->cnt[1];
    f->tran_len[0] = f->len[0];
    f->tran_len[1] = f->len[1];
    return;
}
/*
 * Build up something meaningful for the label
 */
static void construct_long_label(frp)
struct frame_con * frp;
{
int i;
struct web_context * webp = ( struct web_context *) (frp->app_ptr);
int len;
char * x;

    len = strlen(frp->label) + 1;
    for (i = 1; i < 10; i++)
    {
        if (webp->labels[i] != (unsigned char *) NULL)
            len += strlen(webp->labels[i]) + 1;
    }
    if (frp->long_label != (char *) NULL)
        free(frp->long_label);
    frp->long_label = (char *) malloc(len);
    x = frp->long_label;
    x += sprintf(x, "%s", frp->label);
    for (i = 1; i < 10; i++)
    {
        if (webp->labels[i] != (unsigned char *) NULL)
            x += sprintf(x, " %s", webp->labels[i]);
    }
    return;
}
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
register struct web_context * rop = (struct web_context *) frp->app_ptr;

    closeoutput_response(frp, 0); /* Dir Flag = 0 Out (C->S), 1 = In (S->C) */
    if (rop != (struct web_context *) NULL)
    {
    int i;
/*
 * Free up the malloc()ed memory
 */
        if (rop->ref_cnt < 1)
        {
            if (rop->ofp != (FILE *) NULL && rop->ofp != stdout)
                fclose(rop->ofp);
            hremove(ht, rop);
            free(rop->session_key);
            for (i = 0; i < 10; i++)
                if (rop->labels[i] != (unsigned char *) NULL)
                    free(rop->labels[i]);
            if (rop->wcp != (struct web_contxt *) NULL)
                free((char *) rop->wcp);
            free((char *) rop);
        }
        else
            rop->ref_cnt--;
        frp->app_ptr = (char *) NULL;
    }
    else
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
        fclose(frp->ofp);
    return;
}
/*
 * Function that is called to process straight HTTP messages
 */
static void do_web(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
char * p;
struct web_context * webp = (struct web_context *) (frp->app_ptr);
char *x =frp->hold_buf[dir_flag];
char *top = frp->top[dir_flag];
int i = top - x;

    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
        output_response(frp, dir_flag);
        if (webp == (char *) NULL)
        {
            if ((webp =  hunt_session_cookie(x, top)) != NULL)
                webp->ref_cnt++;
            frp->app_ptr = (char *) webp;
        }
        if (webp != (char *) NULL)
            update_label_data( webp, x, top);
        if (i > 4
          && (p = memchr(x+3, ' ', 2)) != NULL
             && (p - x) < sizeof(frp->label) - 2)
        {
            sprintf(frp->label, "%.*s%.*s", (p - x) + 1, x,
                  (sizeof(frp->label) - (p - x) - 2), 
                  url_classification(p + 1, top));
            if (webp != (char *) NULL)
                construct_long_label(frp);
        }
/*
 * We just record what we have been given, in ASCII
 */
        if (frp->ofp == NULL)
            first_write(frp);
        fputs("\\D:B:", frp->ofp);
        ip_dir_print(frp->ofp, frp, !((!dir_flag) ^ frp->reverse_sense));
        fputs("\\\n", frp->ofp);
        fwrite(x,  sizeof(char), i, frp->ofp);
        fputc('\n', frp->ofp);
        fputs("\\D:E\\\n", frp->ofp);
    }
    else
    if (verbose_flag)
    {
        if (frp->ofp == NULL)
            first_write(frp);
        fputs("\\A:B:", frp->ofp);
        ip_dir_print(frp->ofp, frp, ((!dir_flag) ^ frp->reverse_sense));
        fputs("\\\n", frp->ofp);
        gen_handle(frp->ofp, x,  top, 1);
        fputs("\\A:E\\\n", frp->ofp);
    }
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int web_app_recognise(frp)
struct frame_con *frp;
{
int i;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is identified in the list of interesting ports, managed
 *    with web_match_add() and web_match_true()
 */
    if (extend_listen_flag == 0)
        extend_listen_list();
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if ((i = web_match_true(from, to)))
        {
            frp->ofp = (FILE *) NULL;
            if (i < 0)
                frp->reverse_sense = 1;
            frp->do_mess = do_web;
/*            frp->gap = 1;  /o Reduces record numbers */
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) NULL;
            return 1;
        }
    }
    return 0;
}

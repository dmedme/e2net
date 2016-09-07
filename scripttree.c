/*
 * Routines for tracking scripts as memory entities rather than as files.
 *
 * This file represents a new approach. Instead of dealing with the script
 * as a sequence of commands processed sequentially, we accumulate the whole
 * thing, and then write everything out at the end.
 *
 * The intention is to facilitate dynamic script construction and debugging.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <zlib.h>
#include "scripttree.h"
static struct script_element * create_script_element(head, foot)
unsigned char * head;
unsigned char * foot;
{
struct script_element * x;

    if ((x = (struct script_element *)
                 malloc(sizeof(struct script_element))) == NULL)
        return NULL;
#ifdef DEBUG
    fprintf(stderr, "CSE(%lx)\n", (long int) x);
#endif
    if (head == NULL)
        x->head = NULL;
    else
        x->head = strdup(head);
    x->body = NULL;
    x->body_len = 0;
    if (foot == NULL)
        x->foot = NULL;
    else
        x->foot = strdup(foot);
    x->next_track = NULL;
    x->prev_track = NULL;
    x->child_track = NULL;
    x->timestamp = 0.0;
    x->retry_cnt = 0;
    return x;
}
void zap_script_element(x)
struct script_element * x;
{
#ifdef DEBUG
    fprintf(stderr, "ZSE(%lx)\n", (long int) x);
#endif
    if (x->body != NULL)
        free(x->body);
    if (x->head != NULL)
        free(x->head);
    if (x->foot != NULL)
        free(x->foot);
    free(x);
    return;
}
/*
 * Resilient if it isn't actually hooked  (i.e. a child)
 */
void unhook_script_element(scp, sep)
struct script_control * scp;
struct script_element * sep;
{
    if (sep->prev_track == NULL)
    {
        if (scp->anchor == sep)
            scp->anchor = sep->next_track;
    }
    else
        sep->prev_track->next_track = sep->next_track;
    if (sep->next_track == NULL)
    {
        if (scp->last == sep)
            scp->last = sep->prev_track;
    }
    else
        sep->next_track->prev_track = sep->prev_track;
    sep->next_track = NULL;
    sep->prev_track = NULL;
    return;
}
/*
 * Unlink an element from the chain, and relink it as the first child of the
 * designated parent.
 */ 
void make_child(scp, par, sep)
struct script_control * scp;
struct script_element * par;
struct script_element * sep;
{
    unhook_script_element(scp, sep);
    sep->next_track = par->child_track; /* To allow for multiple responses */
    if (sep->next_track != NULL)
        sep->next_track->prev_track = sep;
    sep->prev_track = par;
    par->child_track = sep;
    return;
}
/*
 * Check that the script_element linked list is not corrupt and that
 * the nominated element is present.
 */
int check_integrity(scp, sep)
struct script_control * scp;
struct script_element * sep;
{
int seen_flag = 0;
struct script_element * xsep;

    if (sep == NULL)
        return 0;
    xsep = scp->anchor;
    if (xsep == NULL)
        return 0;
    if (xsep->prev_track != NULL)
        return 0;
    while (xsep->next_track != NULL)
    {
        if (xsep->prev_track == NULL
          && xsep != scp->anchor)
            return 0;
        if (xsep == sep)
            seen_flag = 1;
        xsep = xsep->next_track;
    }
    if (xsep != scp->last)
        return 0;
    if (xsep == sep)
        seen_flag = 1;
    return seen_flag;
}
void zap_children(sep)
struct script_element * sep;
{
struct script_element * xsep1;

    if (sep->child_track == NULL)
        return;
    xsep1 = sep->child_track;
    sep->child_track = NULL;
    while (xsep1 != NULL)
    {
        sep = xsep1;
        zap_children(sep);
        xsep1 = xsep1->next_track;
        zap_script_element(sep);
    }
    return;
}
/*
 * Get rid of a script element and its children from the chain
 * It works whether it is given a request or a response, and also handles
 * possible screw-ups in the chaining logic.
 */ 
void remove_se_subtree(scp, sep)
struct script_control * scp;
struct script_element * sep;
{
struct script_element * xsep1;

    if (sep->prev_track != NULL
     && sep->prev_track->child_track == sep)
        sep = sep->prev_track;          /* If response, substitute request */
    unhook_script_element(scp, sep);
    xsep1 = sep->child_track;
    if (xsep1 != NULL)
    {
        if (xsep1->prev_track != sep)
        {
            unhook_script_element(scp, xsep1);
            zap_script_element(xsep1);
        }
        else
            zap_children(sep);
    }
    zap_script_element(sep);
    return;
}
int head_match_len(head)
char * head;
{
char * x;

    if ((x = strchr(head + 5, ':')) == NULL)
        return strlen(head);
    x += strcspn(x + 1, "\\:") + 1;
    return (x - head);
}
/*
 * Find the previous send or receive for the current socket
 */
struct script_element * search_back(tp, head)
struct script_element * tp;
char * head;
{
int match_len = head_match_len(head);

    for (; tp != NULL
        && (strncmp(tp->head,head, match_len)
        || (*(tp->head + match_len) != ':'
           && (*(tp->head + match_len) != '\\'))); tp = tp->prev_track);
    return tp;
}
/*
 * Find the next send or receive for the current socket
 */
struct script_element * search_forw(tp, head)
struct script_element * tp;
char * head;
{
int match_len = head_match_len(head);

    for (; tp != NULL
        && (strncmp(tp->head, head, match_len)
        || (*(tp->head + match_len) != ':'
           && (*(tp->head + match_len) != '\\'))); tp = tp->next_track);
    return tp;
}
/*
 * Element that keeps tabs on stuff in the eventual output order, and puts
 * the new element at the tail.
 */
struct script_element * new_script_element(script_control, head, foot)
struct script_control * script_control;
unsigned char * head;
unsigned char * foot;
{
struct script_element * x = create_script_element(head, foot);

    if (x == NULL)
        return NULL;
    if (script_control->anchor == NULL)
    {
        script_control->anchor = x;
        script_control->last = x;
    }
    else
    {
        x->prev_track = script_control->last;
        script_control->last->next_track = x;
        script_control->last = x;
    }
    return x;
}
/*
 * Element that keeps tabs on stuff in the eventual output order, and
 * inserts the new element at the head of the linked list rather than the tail.
 */
struct script_element * head_script_element(script_control, head, foot)
struct script_control * script_control;
unsigned char * head;
unsigned char * foot;
{
struct script_element * x = create_script_element(head, foot);

    if (x == NULL)
        return NULL;
    if (script_control->anchor == NULL)
    {
        script_control->anchor = x;
        script_control->last = x;
    }
    else
    {
        x->next_track = script_control->anchor;
        script_control->anchor->prev_track = x;
        script_control->anchor = x;
    }
    return x;
}
/*
 * Start time
 */
static int event_id;
static char * event_desc;
static void open_event(scp)
struct script_control * scp;
{
char buf0[3];
char buf1[132];

    get_event_id(event_id, buf0);
    sprintf(buf1, "\\S%s:120:%-.120s \\\n", buf0, event_desc);
    new_script_element(scp, buf1, NULL);
    return;
}
/*
 * Take Time
 */
void close_event(scp)
struct script_control * scp;
{
char buf0[3];
char buf1[20];

    if (event_id != 0)
    {
        get_event_id(event_id, buf0);
        sprintf(buf1, "\\T%s:\\\n",buf0);
        new_script_element(scp, buf1, NULL);
    }
    return;
}
/*
 * Function that is called to process e2sync messages
 */
void do_e2sync(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned short int to;

    if ((!dir_flag) ^ frp->reverse_sense)
    {
        if (event_id != 0)
        {
            close_event(frp->app_ptr);
            event_id++;
        }
        else
            event_id = 1;
/*
 * This is one of our event definitions. Only pick up the ECHO packet
 * going in one direction, by specifying the Destination port. Note that
 * we expect PATHSYNC to put a trailing NULL on the message.
 */
        if (event_desc != (char *) NULL)
            free(event_desc);
        event_desc = strdup(frp->hold_buf[dir_flag]);
        open_event(frp->app_ptr);
    }
    return;
}
/*
 * Get the chunked length.
 */
int chunk_length(csp, bound, debug_level)
unsigned char ** csp;
unsigned char * bound;
int debug_level;
{
unsigned char * cp = *csp;
unsigned char * crp = NULL;
int i;
int r;
int loop_detect = 0;
/*
 * -  First we have to locate a carriage return.
 * -  We read more until we have a carriage return.
 * -  If we are actually pointing at a cr we must repeat.
 * -  The length is found by a hexadecimal scan of the current location.
 * -  The chunk starts after the carriage-return/line feed
 * -  Return 0 if we have an error (it could be a close)
 */
    if (debug_level > 3)
        fputs("chunk_length()\n", stderr);
/*
 * Skip over any carriage returns and line feeds
 */ 
    while(cp < bound && (*cp == '\n' || *cp == '\r'))
        cp++;
    if (cp >= bound)
    {
        fprintf(stderr, "chunk_length() Logic Error:cp =%x\n", (long) cp);
        return -1;
    }
    if (((crp = memchr(cp, '\r', bound - cp)) == NULL)
       || (memchr(crp, '\n', bound - crp) == NULL))
    {
        fprintf(stderr, "chunk_length() Logic Error:cp =%x, crp=%x\n",
                (long) crp,
                (long) cp);
        return -1;
    }
    if (sscanf(cp, "%x", &i) != 1 || i < 0 || i > 10000000)
    {
        fprintf(stderr, "Chunk size missing?(len=%d, left=%u)\n", i, bound-cp);
        gen_handle(stderr, cp, bound, 1);
        return -1;
    }
    *csp =  crp + 2;
    return i;
}
/***********************************************************************
 * Chunked data
 */
int dechunk(base, bound, debug_level)
unsigned char * base;
unsigned char * bound;
int debug_level;
{
int chunk_len;
unsigned char * xin;
unsigned char * xout;
/*
 * Loop - shuffle down the data a chunk at a time.
 */
    for (xin = base, xout = base;
          ((chunk_len =
              chunk_length(&xin, bound, debug_level)) > 0);
             xin += chunk_len + 2, xout += chunk_len)
        memmove(xout, xin, chunk_len);
    if (xin < bound)
    {
        memmove(xout, xin, (bound - xin));
        xout += (bound - xin);
    }
    return xout - base;
}
/***********************************************************************
 * Compressed data.
 */
int decomp(base, to_decompress, decoded, bound)
unsigned char *base;
int to_decompress;
unsigned char ** decoded;
unsigned char ** bound;
{
z_stream strm;
int len;
int declen;
int ret;
/*
 * If we have a gzip header, skip over it. Note that we are only testing the
 * first byte of the two ID bytes; we are not checking for the presence of
 * optional gzip header elements, nor are we determinining that the data when
 * we encounter it is going to be deflate data.
 */ 
    if ( *base == 0x1f)
    {
        base += 10;
        to_decompress -= 10;
    }
    if (to_decompress < 1)
        return 0;
/*
 * Allocate inflate state
 */ 
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    len = 0;
    if ((*base & 0xf) == Z_DEFLATED)
        inflateInit(&strm);
    else
        inflateInit2(&strm, -MAX_WBITS);
    strm.next_in = base;
    strm.avail_in = to_decompress;
    declen = *bound - *decoded;
    strm.avail_out = declen;
    strm.next_out = *decoded;
restart:
    ret = inflate(&strm, Z_NO_FLUSH);
    switch (ret)
    {
    case Z_NEED_DICT:
        ret = Z_DATA_ERROR;     /* and fall through */
    case Z_DATA_ERROR:
    case Z_MEM_ERROR:
        (void)inflateEnd(&strm);
        return -1;
    }
    if (strm.avail_out == 0 && strm.avail_in > 0)
    {
        fprintf(stderr, "Ran out of space for decompression, %d unprocessed\n",
                strm.avail_in);
        strm.avail_out = 20 * strm.avail_in;
        *decoded = realloc(*decoded, declen + strm.avail_out);
        strm.next_out = *decoded + declen;
        declen += strm.avail_out;
        *bound = *decoded + declen;
        goto restart;
    }
    len = declen - strm.avail_out;
    (void)inflateEnd(&strm);
    return len;
}
/*
 * Dump a chain of elements
 */
static void dump_chain(ofp, tp, debug_level)
FILE * ofp;
struct script_element *tp;
int debug_level;
{
static struct bm_table * abp;
int bothways = 0;

    if (abp == NULL)
        abp = bm_casecompile("\r\nAuthorization: ");
    for (; tp != NULL; tp = tp->next_track)
    {
        if (tp->head != NULL && (tp->foot == NULL || tp->body != NULL))
        {
            if (!bothways && tp->head[1] == 'A')
                bothways = 1;
/*
 * Ignore any authorisation requests or messages with no response
 * ***********************************************************************
 * There is a problem here if e2sync events intervene between the messages
 * and their responses.
 * ***********************************************************************
 */
            if (tp->body != NULL
             && !bothways
             && (bm_match(abp, tp->body, tp->body + tp->body_len)
              || (tp->child_track == NULL && (tp->next_track == NULL
                                           || tp->next_track->body == NULL))
              || (tp->child_track != NULL && tp->child_track->body == NULL)))
            {
                if (debug_level > 3)
                {
                    fputs("Discarding\n", stderr);
                    fputs(tp->head, stderr);
                    gen_handle_no_uni(stderr, tp->body, tp->body + tp->body_len,
                                       1);
                    if (tp->foot != NULL)
                        fputs(tp->foot, stderr);
                    if (bm_match(abp, tp->body, tp->body + tp->body_len))
                        fputs("Discard reason: Authorization\n", stderr);
                    else
                    if (tp->child_track == NULL && (tp->next_track == NULL
                                           || tp->next_track->body == NULL))
                        fputs("Discard Reason: No children and next has no body\n", stderr);
                    else
                    if (tp->child_track == NULL && (tp->next_track == NULL
                                           || tp->next_track->body == NULL))
                        fputs("Discard Reason: next has no body\n", stderr);
                        
                }
                continue;
            }
            fputs(tp->head, ofp);
            if (tp->body != NULL)
                gen_handle_no_uni(ofp, tp->body, tp->body + tp->body_len, 1);
            if (tp->foot != NULL)
                fputs(tp->foot, ofp);
        }
        if (tp->child_track != NULL)
            dump_chain(ofp, tp->child_track, debug_level);
    }
    return;
}
/*
 * Produce the generic script.
 */
void dump_script(tp, fname, debug_level)
struct script_element * tp;
char * fname;
int debug_level;
{
FILE * ofp;

    if (fname == NULL 
     || (ofp = (!strcmp(fname, "-")) ? stdout :
                  fopen(fname, "wb")) == NULL)
        return;
    dump_chain(ofp, tp, debug_level);
    fclose(ofp);
    return;
}
/*
 * Only create the End Point if it doesn't exist already; furthermore, it
 * goes at the beginning of the list
 */
static struct script_element * add_end_point(scp, ep)
struct script_control * scp;
END_POINT * ep;
{
char buf[256];
struct script_element * sep;

    sprintf(buf, "\\E:%s:%d:%s:%d:%c%s%s\\\n",
        ep->host,
        ep->port_id,
        ep->host,
        ep->port_id,
        ep->con_flag,
        ep->ssl_spec_ref[0] == '\0' ? "" : ":",
        ep->ssl_spec_ref);

    for (sep = scp->anchor;
            sep != NULL && sep->head[1] != 'M';
                        /* All E's should appear before any M's */
                sep = sep->next_track)
        if (!strcmp(sep->head, buf))
            return NULL;
    return head_script_element(scp, buf, NULL);
}
/*
 * Routines used by the proxy code to build up a script
 */
struct script_element * add_open(scp, lp)
struct script_control * scp;
LINK * lp;
{
char buf[256];

    (void) add_end_point(scp, lp->from_ep);
    (void) add_end_point(scp, lp->to_ep);
    sprintf(buf, "\\M:%s;%d:%s;%d\\\n",
         lp->from_ep->host,
         lp->from_ep->port_id,
         lp->to_ep->host,
         lp->to_ep->port_id);
    return new_script_element(scp, buf, NULL);
}
struct script_element * add_message(scp, lp)
struct script_control * scp;
LINK * lp;
{
char buf[256];

    sprintf(buf, "\\D:B:%s;%d:%s;%d\\\n",
         lp->from_ep->host,
         lp->from_ep->port_id,
         lp->to_ep->host,
         lp->to_ep->port_id);
    return new_script_element(scp, buf, "\\D:E\\\n");
}
struct script_element * add_think_time(scp, think)
struct script_control * scp;
double think;
{
char buf[256];

    sprintf(buf, "\\W%.23g\\\n", think);
    return new_script_element(scp, buf, NULL);
}
struct script_element * add_pause(scp, pause_time)
struct script_control * scp;
double pause_time;
{
char buf[256];

    sprintf(buf, "\\P%.23g\\\n", pause_time);
    return new_script_element(scp, buf, NULL);
}
struct script_element * add_answer(scp, lp)
struct script_control * scp;
LINK * lp;
{
char buf[256];

    sprintf(buf, "\\A:B:%s;%d:%s;%d\\\n",
         lp->from_ep->host,
         lp->from_ep->port_id,
         lp->to_ep->host,
         lp->to_ep->port_id);
    return new_script_element(scp, buf, "\\A:E\\\n");
}
struct script_element * add_close(scp, lp)
struct script_control * scp;
LINK * lp;
{
char buf[256];

    sprintf(buf, "\\X:%s;%d:%s;%d\\\n",
         lp->from_ep->host,
         lp->from_ep->port_id,
         lp->to_ep->host,
         lp->to_ep->port_id);
    return new_script_element(scp, buf, NULL);
}
#ifdef USE_SSL
struct script_element * add_ssl_spec(scp, ssp)
struct script_control * scp;
SSL_SPEC * ssp;
{
char buf[256];

    sprintf(buf, "\\H:%s:%s:%s\\\n",
         ssp->ssl_spec_ref,
         ssp->key_file,
         ssp->passwd);
    return head_script_element(scp, buf, NULL);
}
#endif
/*
 * Function that is called to process proxy comments
 */
void proxy_e2sync(scp, desc)
struct script_control * scp;
char * desc;
{
int len;

    if (event_id != 0)
    {
        close_event(scp);
        event_id++;
    }
    else
        event_id = 1;
    if (event_desc != (char *) NULL)
       free(event_desc);
    len = url_unescape(desc, strlen(desc));
    desc[len] = '\0';
    event_desc = strdup(desc);
    open_event(scp);
    return;
}

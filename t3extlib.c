/*
 * Scan a snoop file and pull out the Web Logic Server elements
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "matchlib.h"
#include "e2conv.h"
#include "e2net.h"
static struct frame_con * cur_frame;
static void do_web();
static void do_log();
static FILE * ofp;
static int both_ways;
static int verbose;
static unsigned char * t3_property();
static unsigned char * outstr();
unsigned char * t3_handle();
/*
 * Structure allocated when a session is started that holds Web session state.
 *
 * At the moment, we do not have any.
 */
struct t3_sess {
    int len[2];
    unsigned char * kept_msg[2];
};
/***************************************************************************
 * Object Stream Class Flags
 */
#define  SC_BLOCK_DATA  0x08;
/*
 * Bit mask for ObjectStreamClass flag. Indicates class is Serializable.
 */
#define  SC_SERIALIZABLE  0x02;
/*
 * Bit mask for ObjectStreamClass flag. Indicates class is Externalizable.
 */
#define  SC_EXTERNALIZABLE  0x04;

static struct or_obj_id {
int id;
char * name;
} or_obj_id[] = {
{0,"CMD_UNDEFINED"},
{1,"CMD_IDENTIFY_REQUEST"},
{9,"CMD_NO_ROUTE_IDENTIFY_REQUEST"},
{2,"CMD_IDENTIFY_RESPONSE"},
{10,"CMD_TRANSLATED_IDENTIFY_RESPONSE"},
{11,"CMD_REQUEST_CLOSE"},
{3,"CMD_PEER_GONE"},
{4,"CMD_ONE_WAY"},
{5,"CMD_REQUEST"},
{6,"CMD_RESPONSE"},
{7,"CMD_ERROR_RESPONSE"},
{8,"CMD_INTERNAL"},
{0x70,"TC_NULL"},
{0x71,"TC_REFERENCE"},
{0x72,"TC_CLASSDESC"},
{0x73,"TC_OBJECT"},
{0x74,"TC_STRING"},
{0x75,"TC_ARRAY"},
{0x76,"TC_CLASS"},
{0x77,"TC_BLOCKDATA"},
{0x78,"TC_ENDBLOCKDATA"},
{0x79,"TC_RESET"},
{0x7A,"TC_BLOCKDATALONG"},
{0x7B,"TC_EXCEPTION"},
{0x7C,"TC_LONGSTRING"},
{0x7D,"TC_PROXYCLASSDESC"},
{0x7E,"HANDLE"},
{0xaced0005,"STREAM_MAGIC_VERSION"}};
static char* find_name(match_id)
int match_id;
{
struct or_obj_id*guess;
struct or_obj_id* low = &or_obj_id[0];
struct or_obj_id* high =
            &or_obj_id[sizeof(or_obj_id)/sizeof(struct or_obj_id) - 1];

    while (low <= high)
    {
        guess = low + ((high - low) >> 1);
        if ( guess->id == match_id)
            return guess->name;
        else
        if ( guess->id < match_id)
            low = guess + 1;
        else
            high = guess - 1;
    }
    return "(unknown)";
}
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */
static int match_cnt;              /* Number of ports in the list    */
static int t3_port[100];    /* List of ports to match against          */
static int t3_cnt;              /* Number of ports in the list    */
static void web_match_add(arr, cnt, port)
int * arr;
int * cnt;
int port;
{
    if (*cnt < 100)
    {
       arr[*cnt] = port;
       (*cnt)++;
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
    if ((x = getenv("E2_WEB_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
                web_match_add(match_port, &match_cnt, i);
        }
    }
    if ((x = getenv("E2_T3_WEB_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
            {
                web_match_add(match_port, &match_cnt, i);
                web_match_add(t3_port, &t3_cnt, i);
            }
        }
    }
    if ((x = getenv("E2_BOTH")) != (char *) NULL)
        both_ways = 1;
    if ((x = getenv("E2_VERBOSE")) != (char *) NULL)
        verbose = 1;
    return;
}
static int web_match_true(arr, cnt, from, to)
int *arr;
int cnt;
int from;
int to;
{
int i;

#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif
    for (i = 0; i < cnt; i++)
    {
       if (arr[i] == from || arr[i] == to)
       {
           if (arr[i] == to)
               return  1;         /* Flag which end is the client */
           else
               return -1;
       }
    }
    return 0;
}
/*
 * Discard dynamically allocated session structures. Empty for now. But stops
 * the script file being closed on session close.
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
    if (frp->app_ptr != (char *) NULL)
        free(frp->app_ptr);
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
unsigned short int from, to;

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
/*        if (!(frp->tcp_flags & TH_SYN))
            return 0; */
        memcpy((char *) &to, &(frp->port_to[1]), 2);
        memcpy((char *) &from, &(frp->port_from[1]), 2);
        if (from == 80 || from == 8080)
            i = -1;
        else
        if ( to == 80 || to == 8080)
            i = 1;
        else
            i = web_match_true(match_port, match_cnt, from, to);
        if (i)
        {
            if (ofp == (FILE *) NULL)
                ofp = fopen("web_script.msg", "wb");
            frp->ofp = ofp;
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            fputs( "\\M:", ofp);
            ip_dir_print(ofp, frp, 0);
            fputs( "\\\n", ofp);
            if (i == -1)
                frp->reverse_sense = 1;
            frp->do_mess = do_web;
            frp->cleanup = do_cleanup;
            if (web_match_true(t3_port, t3_cnt, from, to))
            {
                frp->app_ptr = (struct t3_sess *) malloc(sizeof(struct
                                   t3_sess));
                ((struct t3_sess *)(frp->app_ptr))->len[0] = 0;
                ((struct t3_sess *)(frp->app_ptr))->len[1] = 0;
                ((struct t3_sess *)(frp->app_ptr))->kept_msg[0] =
                            (unsigned char *) NULL;
                ((struct t3_sess *)(frp->app_ptr))->kept_msg[1] =
                            (unsigned char *) NULL;
            }
            else
                frp->app_ptr = (char *) NULL;
            return 1;
        }
    }
    else
    if (frp->prot == E2_UDP )
    {
        memcpy((char *) &to, &(frp->port_to[1]), 2);
        memcpy((char *) &from, &(frp->port_from[1]), 2);
        if (from == 7 || to == 7)
        {
            if (ofp == (FILE *) NULL)
                ofp = fopen("web_script.msg", "wb");
            frp->ofp = ofp;
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            if (from == 7)
                frp->reverse_sense = 1;
            frp->do_mess = do_log;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) NULL;
            return 1;
        }
    }
    return 0;
}
/*
 * Deal with a fragment of WebLogic forms traffic
 */
static void t3_dispose(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * x;
unsigned char * top;
struct t3_sess * ap = (struct t3_sess *) (frp->app_ptr);

    if (ap->len[dir_flag])
    {
        ap->kept_msg[dir_flag] = (unsigned char *)
                      realloc(ap->kept_msg[dir_flag],
                              ap->len[dir_flag] +
                                (frp->top[dir_flag] - frp->hold_buf[dir_flag]));
        memcpy(ap->kept_msg[dir_flag] + ap->len[dir_flag],
                frp->hold_buf[dir_flag],
                        (frp->top[dir_flag] - frp->hold_buf[dir_flag]));
        ap->len[dir_flag] += (frp->top[dir_flag] - frp->hold_buf[dir_flag]);
        x = ap->kept_msg[dir_flag];
        top =  x + ap->len[dir_flag];
    }
    else
    {
        x = frp->hold_buf[dir_flag];
        top = frp->top[dir_flag];
    }
    if (*x != '\0'
     || x + x[3] + (x[2] << 8) + (x[1] << 16) + (x[0] << 24) == top)
    {
        fprintf(frp->ofp, "\\%c:B:",
           ((!dir_flag) ^ frp->reverse_sense) ? 'D' : 'A');
        ip_dir_print(frp->ofp, frp, dir_flag);
        fputs("\\\n", frp->ofp);
        while  (x < top)
            x = t3_handle(frp->ofp, x, top, 1);
        fprintf(frp->ofp, "\\%c:E\\\n",
           ((!dir_flag) ^ frp->reverse_sense) ? 'D' : 'A');
        if (top != frp->top[dir_flag])
        {
            free(ap->kept_msg[dir_flag]);
            ap->len[dir_flag] = 0;
        }
    }
    else
    if (top == frp->top[dir_flag])
    {
        ap->kept_msg[dir_flag] = (unsigned char *)
                      malloc( (frp->top[dir_flag] - frp->hold_buf[dir_flag]));
        memcpy(ap->kept_msg[dir_flag],
                frp->hold_buf[dir_flag],
                        (frp->top[dir_flag] - frp->hold_buf[dir_flag]));
        ap->len[dir_flag] = (frp->top[dir_flag] - frp->hold_buf[dir_flag]);
    }
    return;
}
/*
 * Function that is called to process messages
 */
static void do_web(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{

    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
/*
 * We just record what we have been given, in ASCII
 */
        if (frp->app_ptr == NULL)
        {
            fputs("\\D:B:", frp->ofp);
            ip_dir_print(frp->ofp, frp, dir_flag);
            fputs("\\\n", frp->ofp);
/*
 *          fwrite(frp->hold_buf[dir_flag], sizeof(char), 
 *                  frp->top[dir_flag] - frp->hold_buf[dir_flag],
 *                    frp->ofp);
 *          if (*(frp->top[dir_flag] - 1) != '\n')
 *              fputc('\n', frp->ofp);
 */
            (void) gen_handle_no_uni(frp->ofp, frp->hold_buf[dir_flag],
                              frp->top[dir_flag], 1);
            fputs("\\D:E\\\n", frp->ofp);
        }
        else
            t3_dispose(frp, dir_flag);
    }
    else
    if (both_ways)
    {
        if (frp->app_ptr == NULL)
        {
            fputs("\\A:B:", frp->ofp);
            ip_dir_print(frp->ofp, frp, dir_flag);
            fputs("\\\n", frp->ofp);
            (void) gen_handle_no_uni(frp->ofp, frp->hold_buf[dir_flag],
                              frp->top[dir_flag], 1);
            fputs("\\A:E\\\n", frp->ofp);
        }
        else
            t3_dispose(frp, dir_flag);
    }
    return;
}
static int event_id;
static char * event_desc;
static void open_event()
{
char buf[3];

    get_event_id(event_id, buf);
    if (ofp !=  NULL)
        fprintf(ofp, "\\S%s:120:%s \\\n", buf, event_desc);
    return;
}
static void close_event()
{
char buf[3];

    if (ofp !=  NULL && event_id != 0)
    {
        get_event_id(event_id, buf);
        fprintf(ofp, "\\T%s:\\\n",buf);
    }
    return;
}
/*
 * Function that is called to process log messages
 */
static void do_log(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned short int to;

    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
        if (event_id != 0)
        {
            close_event();
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
        open_event();
    }
    return;
}
/*
 * Dump out a human-readable rendition of the WebLogic forms messages
 * - Messages consist of:
 *   - A 4 byte length
 *   - A 19 byte JVMessage header
 *   - Optional JVM ID's
 *   - Remote execution or distributed garbage collection data
 */
unsigned char * t3_handle(ofp, base, top, out_flag)
FILE *ofp;
unsigned char * base;
unsigned char * top;
int out_flag;
{
    return gen_handle_no_uni(ofp, base, top, out_flag);
}

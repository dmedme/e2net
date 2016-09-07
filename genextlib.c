/*
 * Scan a snoop file and create a generic PATH script.
 *
 * This file represents a new approach. Instead of outputting the script as
 * we go, we accumulate the whole thing, and then write everything out at the
 * end. The intention is to avoid difficulties with responses happening in
 * parallel, messages being broken into multiple packets, etc. etc..
 *
 * We use this file in order to:
 * -   Leave genconv.c and e2net.c alone.
 * -   Make use of the fact that genconv.c has dealt with retransmissions and
 *     packet drops for us.
 *
 * We maintain a tree representing the order in which we want to output things.
 *
 * At the moment we assume that the traffic is simply request/response pairs.
 * We don't cater for one way or unsolicited messages.
 *
 * We output the whole thing at the end.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include "scripttree.h"
#include "matchlib.h"
#include "e2conv.h"
static struct frame_con * cur_frame;
static void do_mess();
static FILE * ofp;
static int both_ways;
static int verbose;
static struct script_control script_control;
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */
static int match_cnt;            /* Number of ports in the list    */
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
char buf[80];
/*
 * Allocate a message close
 */
    buf[0] = '\\';
    buf[1] = 'X';
    buf[2] = ':';
    ip_dir_copy(&buf[3], frp, 0);
    strcat(&buf[23], "\\\n"); /* Cannot be less than 20 long */
    (void) new_script_element(&script_control, buf, NULL);
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
char buf[80];

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
/*
 *      if (!(frp->tcp_flags & TH_SYN))
 *          return 0;
 */
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
        struct script_element * x;

            if (ofp == (FILE *) NULL)
                ofp = fopen("notes.txt", "wb");
            frp->ofp = ofp;
            if (frp->ofp == (FILE *) NULL)
            {
                perror("web_script.msg fopen() failed");
                frp->ofp = stdout;   /* Out of file descriptors */
            }
/*
 * Allocate a message open
 */
            buf[0] = '\\';
            buf[1] = 'M';
            buf[2] = ':';
            ip_dir_copy(&buf[3], frp, 0);
            strcat(&buf[23], "\\\n"); /* Cannot be less than 20 long */
            (void) new_script_element(&script_control, buf, NULL);
/*
 * Now set up the request/response tracking 
 */
            if (i == -1)
                frp->reverse_sense = 1;
            frp->do_mess = do_mess;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (unsigned char *) malloc(sizeof(struct script_sess));
            ((struct script_sess *)(frp->app_ptr))->send_tracker = NULL;
            ((struct script_sess *)(frp->app_ptr))->recv_tracker = NULL;
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
            frp->do_mess = do_e2sync;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) &script_control;
            return 1;
        }
    }
    return 0;
}
void init_send_recv(ap, frp, dir_flag)
struct script_sess * ap;
struct frame_con * frp;
int dir_flag;
{
char head_buf[80];

    head_buf[0] = '\\';
    head_buf[1] = 'D';
    head_buf[2] = ':';
    head_buf[3] = 'B';
    head_buf[4] = ':';
    ip_dir_copy(&head_buf[5], frp, dir_flag);
    strcat(&head_buf[25],"\\\n");
    ap->send_tracker = new_script_element(&script_control, head_buf,
                                                          "\\D:E\\\n");
    head_buf[1] = 'A';
    ap->recv_tracker = new_script_element(&script_control,
                                (both_ways)?head_buf: NULL, "\\A:E\\\n");
    return;
}
/*
 * Function that is called to process messages
 */
static void do_mess(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct script_sess * ap = (struct script_sess *) (frp->app_ptr);
int sav_len;

    if (frp->top[dir_flag] == frp->hold_buf[dir_flag])
        return;           /* Ignore it if there is no data */
    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
/*
 * A send
 */
        if (ap->send_tracker == NULL            /* First time */
         || (ap->recv_tracker != NULL           /* New message */
           &&  ap->recv_tracker->body != NULL))
            init_send_recv(ap, frp, dir_flag);
        sav_len = ap->send_tracker->body_len;
        ap->send_tracker->body_len += (frp->top[dir_flag] -
                                      frp->hold_buf[dir_flag]);
        if (ap->send_tracker->body == NULL)
            ap->send_tracker->body = (unsigned char *) malloc(
                 ap->send_tracker->body_len);
        else
            ap->send_tracker->body = (unsigned char *) realloc(
                 ap->send_tracker->body, ap->send_tracker->body_len);
        memcpy(ap->send_tracker->body + sav_len, frp->hold_buf[dir_flag],
                 ap->send_tracker->body_len - sav_len);
    }
    else
    if (ap->recv_tracker != NULL)
    {
/*
 * A receive that we want
 */
        sav_len = ap->recv_tracker->body_len;
        ap->recv_tracker->body_len += (frp->top[dir_flag] -
                                      frp->hold_buf[dir_flag]);
        if (ap->recv_tracker->body == NULL)
        {
#ifdef EXCLUDE_401
            if (ap->recv_tracker->head == NULL
             && ( !strncmp(frp->hold_buf[dir_flag],"HTTP/1.1 401", 12)
             || !strncmp(frp->hold_buf[dir_flag],"HTTP/1.0 401", 12)))
            {
                free(ap->send_tracker->head);   /* Inhibit messages with 401 */
                ap->send_tracker->head = NULL;
            }
#endif
            ap->recv_tracker->body = (unsigned char *) malloc(
                 ap->recv_tracker->body_len);
        }
        else
            ap->recv_tracker->body = (unsigned char *) realloc(
                 ap->recv_tracker->body, ap->recv_tracker->body_len);
        memcpy(ap->recv_tracker->body + sav_len, frp->hold_buf[dir_flag],
                 ap->recv_tracker->body_len - sav_len);
    }
    return;
}
/*
 * Produce the generic script.
 */
void output_script()
{
struct script_element * tp;
struct bm_table * abp = bm_casecompile("\r\nAuthorization: ");

    if (ofp != NULL)
        fclose(ofp);
    ofp = NULL;
    dump_script(script_control.anchor, "web_script.msg", 0);
    return;
}

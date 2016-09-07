/*
 *    ipdrive.c - Program to drive and collect timings for packets.
 *
 *    Copyright (C) E2 Systems 1995
 *
 * This program is the heart of the E2 Systems Traffic Generator. Its purpose
 * is to determine response times for packets propagated through the network.
 *
 * Any number of incarnations of these programs may be started in a network.
 * They take their instructions from a control file.
 * The instructions define a set of actors in the traffic, and then a
 * flow of messages between them.
 * Each program started knows which actor it is.
 * The program that represents the end user, and transaction initiator, is
 * actor zero.
 * Each program processes the actions prescribed for itself, and ignores the
 * others. 
 * Every packet sent has a unique ID, that identifies its place in the traffic.
 * Each program logs occurrences, and also elapsed times.
 * Every process handling a transaction stream processes the same stream.
 * (This is clearer than keeping separate streams for each actor)
 * Each process knows which actor it is (command line argument)
 * Actor 0 processes stdin immediately.
 * Other actors wait for kick-off, after encountering their listen
 * addresses.
 * Each process handles its own messages, and skips others.
 * When it encounters a receive, it waits until it has got what it is
 * looking for.
 * When it encounters a send, it searches its table to see if it has a
 * connexion; if not, it calls it up.
 * An actor can handle more than one protocol; this means there may be
 * more than one communication end point set up.
 *
 * An implicit design goal was to have multiple threads started on the primary
 * host, and spawn others on the secondaries as needed. However, the question arises,
 * what about unique sockets? Is it only a problem for senders of datagrams?
 *
 * Arguments
 * =========
 *   - arg 1 = name of file to output timestamps to
 *   - arg 2 = Id of fdriver
 *   - arg 3 = Id of bundle
 *   - arg 4 = i number within 'rope'
 *   - arg 5 = Input command file
 *   - arg 6 = Actor
 *
 * Signal handling
 * ===============
 * SIGTERM - terminate request
 *
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (C) E2 Systems Limited 1995";
#ifdef MINGW32
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SLEEP_FACTOR 1000
#define sleep _sleep
#else
#define closesocket close
#define SLEEP_FACTOR 1
#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>
#ifdef V32
#include <time.h>
#else
#include <sys/time.h>
#endif
#ifdef SEQ
#include <fcntl.h>
#include <time.h>
#else
#ifdef ULTRIX
#include <fcntl.h>
#else
#ifdef AIX
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#endif
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#ifndef MINGW32
#ifdef NT4
#define W_IN_SYS
#else
#ifdef AIX
#define W_IN_SYS
#else
#ifdef SCO
#ifndef V4
#define W_IN_SYS
#endif
#endif
#endif
#endif
#ifdef W_IN_SYS
#include <sys/wait.h>
#else
#include <wait.h>
#endif
#include <sys/socket.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#ifdef PYR
#include <strings.h>
#endif
#endif
#include "ansi.h"
#include "e2conv.h"
#ifndef MINGW32
#include "e2net.h"
#else
#define E2NET_H
#endif
#include "hashlib.h"
#include "ipdrive.h"
#include "circlib.h"
#include "matchlib.h"
#include "natregex.h"
#ifdef MINGW32
#include <winsock.h>
#endif
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif
#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 8
#endif
double floor();
/*
 * Message handling routines
 */
static void do_end_point();
static void do_delay();
static void do_start_timer();
static void do_take_time();
#ifndef MINGW32
static void do_send_file();
#endif
static void do_send_receive();
static void icmp_send();
#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif
/***********************************************************************
 *
 * Functions in this file
 */

static int io_event=0;
static struct timeval nohang = {10,0};  /* wait 10 seconds timeval structure */
#ifndef MINGW32
static long alarm_save;                 /* What's in the alarm clock; timer */
static void (*prev_alrm)();             /* Whatever is previously installed
                                           (either rem_time() or nothing) */

void alarm_preempt();        /* Put in a read timeout, in place of whatever is
                              * currently in the alarm clock
                              */
void alarm_restore();       /* Restore the previous clock value */
#endif
static void do_things(); /* process requests whilst things are still alive */
static void pre_scan();  /* Assign parents for child sessions */
void die();             /* catch terminate signal */
void scarper();         /* exit, tidying up */
void chld_sig();        /* catch the death of a child */
void io_sig();          /* catch a communications event */
static void proc_args();       /* process arguments */
int enable_file_io();   /* Associate FILE's with fd's */
static void ipdrive_listen();
                        /* Set up the socket that listens for link connect
                           requests */
static void ftp_spawn();/* Initiate an ftp, and return a sensible exit status */
static void child_sig_clear();
                        /* Clear unwanted signal handlers in forked children */
static int do_sock_close();
                        /* Execute a socket close */
static void ftp_spawn();/* Initiate an ftp, and return a sensible exit status */
static void child_sig_clear();
static void do_end_point();
static void sock_ready();
static void log_sock_bind();
static LINK * link_find();
static void ipdrive_connect();
static void ipdrive_peer();
static void do_send_file();
static unsigned short inet_checksum();
static int smart_read();
static void do_send_receive();
static void icmp_send();
static void do_start_timer();
static void do_take_time();
static void do_delay();
static FILE * ctl_read; /* Control file channel */
static FILE  *control_open ANSIARGS(( char *f, char *mode, long offset));
static void  ipdlog ANSIARGS((int argc, char **argv));
static void ipdrive_connect ANSIARGS((LINK * link));
static void ipdrive_listen ANSIARGS((LINK * link));
static void ipdrive_peer ANSIARGS((LINK * link));
static union {
    char rb[16384];
    long rl[4096];
} rbuf;
static char sbuf[16384];  /* Buffer used to give variation to sent messages */

static LINK link_det[MAXLINKS], *link_hw;
                             /* list of links in the input file */

static END_POINT end_point_det[MAXENDPOINTS];
                             /* list of links in the input file */
static int rec_cnt;
static int child_cnt;
static int listen_fd;
static struct sockaddr_in listen_sock;

/*
 * Hash the key fields. The intention is that this hash function does not
 * depend on the ordering of the from and to fields.
 */
int shash_key (utp,modulo)
struct con_con * utp;
int modulo;
{
    return (utp->from_end_id ^ utp->to_end_id) & (modulo - 1); 
}
/*
 * Compare pairs of key fields for the session hash table. Ordering is not
 * significant, so we just return 0 or 1.
 */
int scomp_key(utp1,  utp2)
struct con_con * utp1;
struct con_con * utp2;
{
int i;

    if ((utp1->from_end_id == utp2->from_end_id
      && utp1->to_end_id == utp2->to_end_id)
     || (utp1->from_end_id == utp2->to_end_id
      && utp1->to_end_id == utp2->from_end_id))
        return 0;
    else
        return 1;
}
/*
 * Create a new session record
 */
struct con_con * smatch_add(known_con,  ccp)
HASH_CON * known_con;
struct con_con * ccp;
{
struct con_con * un = (struct con_con *) malloc(sizeof(struct con_con));

    *un = *ccp;
    insert(known_con,un,un);
    if (end_point_det[ccp->from_end_id].iactor_id == ipdrive_base.actor_id)
        un->parent_flag = 0;
    else
        un->parent_flag = 1;
    un->parent = (struct con_con *) NULL;
    return un;
}
/*
 * Remove a session record
 */
void smatch_remove(known_con, ccp)
HASH_CON * known_con;
struct con_con * ccp;
{
/*
 * Remove the hash pointer
 */
    hremove(known_con,ccp);
    free(ccp);
    return;
}
/*
 * Search for an existing session record
 */
struct con_con * smatch_true(known_con, from)
HASH_CON * known_con;
struct con_con * from;
{
HIPT * h;
    if ((h = lookup(known_con, (char *) from)) != (HIPT *) NULL)
        return (struct con_con *) (h->body);
    else
        return (struct con_con *)  NULL ;
}
/***********************************************************************
 * Main Program Starts Here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
int main(argc,argv,envp)
int argc;
char * argv[];
char * envp[];
{
int i;
#ifdef MINGW32
WORD wVersionRequested;
WSADATA wsaData;
wVersionRequested = 0x0101;

    if ( WSAStartup( wVersionRequested, &wsaData ))
    {
        fprintf(stderr, "WSAStartup error: %d", errno);
        exit(1);
    }
/* #ifdef LCC
 *  tick_calibrate();
 * #endif
 */
#endif
/****************************************************
 *    Initialise
 */
    child_cnt = 0;
    ipd_init();
    link_hw = &link_det[0];
    for (i = 0; i < MAXENDPOINTS; i++)
        end_point_det[i].iactor_id = -1;
                               /* Prevent missing end points hanging actor 0 */
    proc_args(argc,argv);
/*
 * Process the input file
 */
    do_things();
    pg.seqX = rec_cnt;
    event_record("F", (struct event_con *) NULL); /* announce the finish */
    exit(0);
}
/*****************************************************************
 * Service Shutdown Requests
 */
void die()
{
#ifdef MINGW32
    WSACleanup();
#endif
    exit(0);                 /* No point in hanging around */
}
/*****************************************************************************
 * Handle unexpected errors
 */
void unexpected(file_name,line,message)
char * file_name;
int line;
char * message;
{
    (void) fprintf(stderr,"Unexpected Error %s,line %d\n",
                   file_name,line);
    perror(message);
    (void) fprintf(stderr,"UNIX Error Code %d\n", errno);
    (void) fflush(stderr);
    return;
}

extern struct event_con * curr_event; /* the event we are looking for; used as
                                         a flag to see if scanning or not */
#undef select
/*******************
 * Global data
 */
struct ptydrive_glob pg;
static double saved_time;
void siggoaway ()
{
    exit(1);
}
/*
 * Process arguments
 */
static void proc_args(argc,argv)
int argc;
char ** argv;
{
int c;
char * start_event;
/*
 * Set up the hash table for events
 */
    pg.poss_events = hash(MAX_EVENT,long_hh,icomp);

/****************************************************
 * Initialise.
 */
    pg.curr_event = (struct event_con *) NULL;
    pg.abort_event = (struct event_con *) NULL;
    pg.see_through=0;
    pg.esc_comm_flag=0;
    pg.log_output = stdout;
    start_event = (char *) NULL;
    pg.frag_size = 65536;
    pg.cur_in_file = stdin;
    ipdrive_base.verbosity = 0;
    pg.seqX = 0;                              /* timestamp sequencer       */
    while ( ( c = getopt ( argc, argv, "hd:v" ) ) != EOF )
    {
        switch ( c )
        {
        case 'h' :
            (void) fputs("ipdrive: E2 Systems Traffic Generator\n\
Options:\n\
 -h prints this message on stderr\n\
 -v sets verbose mode (all packets are timestamped and logged)\n\
 -d set the debug level (between 0 and 4)\n\
Arguments: Output File, Run ID, Bundle ID, Rope, Input File, Actor\n" ,stderr);
            fflush(stderr);
            break;
        case 'd' :
            ipdrive_base.debug_level = atoi(optarg);
            break;
        case 'v' :
            ipdrive_base.verbosity = 1;
            break;
        default:
        case '?' : /* Default - invalid opt.*/
            (void) fprintf(stderr,"Invalid argument; try -h\n");
            exit(1);
        } 
    }
    if ((argc - optind) < 6)
    {
        fprintf(stderr,"Insufficient Arguments Supplied; try -h\n");
        exit(1);
    } 
    pg.logfile=argv[optind++];
    pg.fdriver_seq=argv[optind++];            /* Details needed by event   */
    pg.bundle_seq=argv[optind++];             /* recording                 */
    pg.rope_seq=argv[optind++]; 
    ipdrive_base.control_file = argv[optind++];
    if (control_open(ipdrive_base.control_file,"rb", 0L) == (FILE *) NULL)
    {
        unexpected(__FILE__, __LINE__,"Failed to open control file");
        exit(1);
    }
    ipdrive_base.actor_id = atoi(argv[optind++]);
/*
 * If the actor is not zero, we need to carry out a pre-scan of the input
 * file.
 */
    if (ipdrive_base.actor_id != 0 )
        pre_scan();
    event_record("S", (struct event_con *) NULL); /* announce the start */
    (void) sigset(SIGINT,SIG_IGN);
#ifndef MINGW32
#ifdef AIX
#ifndef ANDROID
    (void) sigset(SIGDANGER,SIG_IGN);
#endif
#endif
#ifndef V32
    (void) sigset(SIGTTOU,SIG_IGN);
                             /* Ignore silly stops */
    (void) sigset(SIGTTIN,SIG_IGN);
                             /* Ignore silly stops */
    (void) sigset(SIGTSTP,SIG_IGN);
                             /* Ignore silly stops */
#endif
    (void) sigset(SIGCLD,SIG_DFL);
#endif
    (void) sigset(SIGTERM,siggoaway);
                            /* Initialise the termination signal catcher */
    (void) sigset(SIGHUP,siggoaway);
                             /* Treat hangups as instructions to go away */
    (void) sigset(SIGUSR1,die);       /* in order to exit */
#ifndef LCC
    (void) sigset(SIGPIPE,SIG_IGN);   /* So we don't crash out */
#endif
    (void) sigset(SIGHUP,SIG_IGN);    /* So we don't crash out */

/*******************************************************************
 * Variables used to control main loop processing
 */
    pg.think_time = PATH_THINK;           /* default think time */
    saved_time = timestamp();
    srand((long int) (floor(saved_time/65536.0) * 65536.0));
    for (c = 0; c < 4096; c++)
        rbuf.rl[c] = rand();
    
    if (ipdrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"proc_args()\n");
        (void) fflush(stderr);
        ipdlog(argc,argv);
    }
    return;
}
/*
 * chld_catcher(); reap children as and when
 * PYRAMID Problems:
 * - waitpid() doesn't work at all
 * - wait3() doesn't like being called when the child signal handler is
 *   installed; be sure that the signal handler has gone off before
 *   calling (and we will still disable it).
 */
void chld_catcher(hang_state)
int hang_state;
{
#ifndef MINGW32
    int pid;
#ifdef POSIX
    int
#else
    union wait
#endif
    pidstatus;

    if (ipdrive_base.debug_level > 1)
        (void) fprintf(stderr,"chld_catcher(); Looking for Children....\n");
    while ((pid=wait3(&pidstatus, hang_state, 0)) > 0)
        if (ipdrive_base.debug_level > 1)
            (void) fprintf(stderr,"Child %u exited\n", pid);
#endif
    return;
}
/*
 * read_timeout(); interrupt a network read that is taking too long
 */
void read_timeout()
{
    return;
}
/*
 * io_sig(); interrupt the select() or whatever.
 */
void io_sig()
{
    io_event++;
    return;
}
/*
 * Manage a chain of potential parent sessions
 */
struct parent_con {
    struct con_con * ccp;
    struct parent_con * pprev;
};
/*
 *  Add the session to the list if it is not already the top.
 */
struct parent_con *new_pce(parent_chain, ccp)
struct parent_con * parent_chain;
struct con_con *ccp;
{
struct parent_con * pcp;

    if ((parent_chain != (struct parent_con *) NULL
     && parent_chain->ccp == ccp)
     || !strcmp(end_point_det[ccp->from_end_id].protocol,"udp"))
        return parent_chain;
    if ((pcp = (struct parent_con *) malloc(sizeof(struct parent_con)))
                 == (struct parent_con *) NULL)
        return parent_chain;
    pcp->ccp = ccp;
    pcp->pprev = parent_chain;
    return pcp;
}
/*
 *  Remove a closed session from the list, wherever it occurs.
 */
struct parent_con *clean_pce(parent_chain, ccp)
struct parent_con * parent_chain;
struct con_con *ccp;
{
struct parent_con * pcp, *top, *prior;

    top = parent_chain;
    for (pcp = top, prior= (struct parent_con *) NULL;
            pcp != (struct parent_con *) NULL;)
    {
        if (pcp->ccp == ccp)
        {
            if (prior == (struct parent_con *) NULL)
            {
                top = pcp->pprev;
                free((char *) pcp);
                pcp = top;
            }
            else
            {
                prior->pprev = pcp->pprev;
                free((char *) pcp);
                pcp = prior->pprev;
            }
        }
        else
        {
            prior = pcp;
            pcp = pcp->pprev;
        }
    }
    return top;
}
/*
 * Function to assign parent threads to child sessions. 
 */
static void pre_scan()
{
union all_records in_buf;
struct ipd_rec * dmp;
struct con_con cc, *ccp;
struct parent_con * parent_chain;

    parent_chain = (struct parent_con *) NULL;
    ipdrive_base.known_con = hash(MAXLINKS,shash_key,scomp_key);
    while ((dmp = ipdinrec(ctl_read,&in_buf)) != (struct ipd_rec *) NULL)
    {
        switch(dmp->mess_id)
        {
        case END_POINT_TYPE:
/*
 * Add the end point to the array
 * Go and set up the end-point, depending on whether we are:
 * - The matching actor
 * - Other actors
 */
            do_end_point(&in_buf);
            break;
/*
 * These types are not intersting during a pre-scan.
 */
        case THINK_TYPE:
        case SEND_FILE_TYPE:
        case START_TIMER_TYPE:
        case TAKE_TIME_TYPE:
        case DELAY_TYPE:
            break;
        case SEND_RECEIVE_TYPE:
/*
 * See if this message applies to us.
 */          
            if (end_point_det[in_buf.send_receive.ifrom_end_point_id].
                   iactor_id == ipdrive_base.actor_id ||
                end_point_det[in_buf.send_receive.ito_end_point_id].
                   iactor_id == ipdrive_base.actor_id)
            {
/*
 * If the message applies to us:
 * -  See if we have already seen it.
 *    -  If we have seen it, and it is eligible to be a parent session, add it
 *       to the parent chain  
 *    -  If we have not, we set it up.
 *       -  If it is a child session (we are the Connect end) give it our
 *          current parent
 *       -  Otherwise, it becomes the current parent
 */
                cc.from_end_id = in_buf.send_receive.ifrom_end_point_id;
                cc.to_end_id = in_buf.send_receive.ito_end_point_id;
                if ((ccp = smatch_true(ipdrive_base.known_con, &cc))
                                     != (struct con_con *) NULL)
                {
                    if (ccp->parent_flag)
                    {
                        if (ipdrive_base.debug_level > 3)
                            (void) fprintf(stderr,
                            "Adding known session(%d,%d) to parent chain\n",
                               ccp->from_end_id, ccp->to_end_id);
                        parent_chain = new_pce(parent_chain, ccp);
                    }
                    else
                    if (parent_chain != (struct parent_con *) NULL
                      && ccp->parent == (struct con_con *) NULL)
                    {
                        if (ipdrive_base.debug_level > 3)
                            (void) fprintf(stderr,
                            "Adding known session(%d,%d) to parent (%d,%d)\n",
                               ccp->from_end_id, ccp->to_end_id,
                               parent_chain->ccp->from_end_id,
                               parent_chain->ccp->to_end_id);
                        ccp->parent = parent_chain->ccp;
                    }
                    else
                    if (ipdrive_base.debug_level > 3)
                       (void) fprintf(stderr,
                            "No parent for session(%d,%d)\n",
                               ccp->from_end_id, ccp->to_end_id);
                }
                else
                {
                    ccp = smatch_add(ipdrive_base.known_con, &cc);
                    if (ccp->parent_flag)
                    {
                        if (ipdrive_base.debug_level > 3)
                            (void) fprintf(stderr,
                            "Adding new session(%d,%d) to parent chain\n",
                               cc.from_end_id, cc.to_end_id);
                        parent_chain = new_pce(parent_chain, ccp);
                    }
                    else
                    if (parent_chain != (struct parent_con *) NULL)
                    {
                        if (ipdrive_base.debug_level > 3)
                            (void) fprintf(stderr,
                            "Adding new session(%d,%d) to parent (%d,%d)\n",
                               ccp->from_end_id, ccp->to_end_id,
                               parent_chain->ccp->from_end_id,
                               parent_chain->ccp->to_end_id);
                        ccp->parent = parent_chain->ccp;
                    }
                    else
                    if (ipdrive_base.debug_level > 3)
                       (void) fprintf(stderr,
                            "No parent for session(%d,%d)\n",
                               ccp->from_end_id, ccp->to_end_id);
                }
            }
            break;
        case SOCK_CLOSE_TYPE:
            if (end_point_det[in_buf.sock_close.ifrom_end_point_id].
                   iactor_id == ipdrive_base.actor_id ||
                end_point_det[in_buf.sock_close.ito_end_point_id].
                   iactor_id == ipdrive_base.actor_id)
            {
/*
 * If the closed session is a parent session, it must be removed from our
 * parent chain.
 */
                cc.from_end_id = in_buf.sock_close.ifrom_end_point_id;
                cc.to_end_id = in_buf.sock_close.ito_end_point_id;
                if ((ccp = smatch_true(ipdrive_base.known_con, &cc))
                                     != (struct con_con *) NULL
                  && ccp->parent_flag)
                {
                    if (ipdrive_base.debug_level > 3)
                       (void) fprintf(stderr,"parent_clean(%d,%d)\n",
                               cc.from_end_id, cc.to_end_id);
                    parent_chain = clean_pce(parent_chain, ccp);
                }
            }
            break;
        default:
            fprintf(stderr,"Garbage in the input file\n\
Record Type (%s) around position %u\n", dmp->mess_name, ftell(ctl_read));
            break;
        }
        if (ipdrive_base.debug_level)
            fflush(stderr);
    }
    fseek(ctl_read,0,0);
    return;
}
/*
 * Function to handle control file data.
 */
static void do_things()
{
union all_records in_buf;
struct ipd_rec * dmp;

    while ((dmp = ipdinrec(ctl_read,&in_buf)) != (struct ipd_rec *) NULL)
    {
        rec_cnt++;
        if (ipdrive_base.debug_level > 2)
        {
            (void) fprintf(stderr,"Control File Service Loop\n");
            (void) fprintf(stderr,"=========================\n");
            fprintf(stderr,"Line: %d Pos: %u Record Type: %s",
                   rec_cnt, ftell(ctl_read), dmp->mess_name);
            if (ipdrive_base.parent != (struct con_con *) NULL)
                fprintf(stderr," (Thread: %d|%d)\n",
                                   ipdrive_base.parent->from_end_id,
                                   ipdrive_base.parent->to_end_id);
            else
                fputc('\n', stderr);
 
        }
        switch(dmp->mess_id)
        {
        case END_POINT_TYPE:
/*
 * Add the end point to the array
 * Go and set up the end-point, depending on whether we are:
 * - The matching actor
 * - Other actors
 * If the actor is not zero, we did this in pre_scan() 
 */
            if (ipdrive_base.actor_id == 0)
                do_end_point(&in_buf);
            break;
        case THINK_TYPE:
/*
 * Save the new value for the think time
 */
            pg.think_time = in_buf.think.ithink;
            break;
        case SEND_RECEIVE_TYPE:
/*
 * See if this message applies to us.
 * If it does not, increment the event counter
 * Otherwise,
 * If we are the send, send the message,
 * If we are the receive, receive the message
 */          
            if (end_point_det[in_buf.send_receive.ifrom_end_point_id].
                   iactor_id == ipdrive_base.actor_id ||
                end_point_det[in_buf.send_receive.ito_end_point_id].
                   iactor_id == ipdrive_base.actor_id)
                do_send_receive(&in_buf);
            break;
        case SOCK_CLOSE_TYPE:
/*
 * See if this message applies to us.
 * If it does not, increment the event counter
 * Otherwise,
 * If we are the send or the receive, close the connection.
 */          
            if (end_point_det[in_buf.send_receive.ifrom_end_point_id].
                   iactor_id == ipdrive_base.actor_id ||
                end_point_det[in_buf.send_receive.ito_end_point_id].
                   iactor_id == ipdrive_base.actor_id)
            {
/*
 * We finish if this is the last thing we have to do.
 */
                if (do_sock_close(&in_buf)
                 && ipdrive_base.actor_id != 0
                 && ipdrive_base.open_sess_cnt == 0)
                {
                    if (ipdrive_base.debug_level > 2)
                    {
                        if (ipdrive_base.parent != (struct con_con *) NULL)
                            fprintf(stderr,"Last close (Thread: %d|%d)\n",
                                   ipdrive_base.parent->from_end_id,
                                   ipdrive_base.parent->to_end_id);
                        fflush(stderr);
                    }
                    return;
                }
            }
            break;
#ifndef MINGW32
        case  SEND_FILE_TYPE:
/*
 * See if this message applies to us.
 * If it does not, increment the event counter
 * Otherwise, send the file,
 */          
            if (in_buf.send_file.iactor_id == ipdrive_base.actor_id)
                do_send_file(&in_buf);
            break;
#endif
        case START_TIMER_TYPE:
/*
 * See if this message applies to us.
 * If it does not, increment the event counter
 * Otherwise, set up the timer,
 */          
            if (in_buf.start_timer.iactor_id == ipdrive_base.actor_id)
                do_start_timer(&in_buf);
            break;
        case TAKE_TIME_TYPE:
/*
 * See if this message applies to us.
 * If it does not, increment the event counter
 * Otherwise, record the time,
 */          
            if (in_buf.take_time.iactor_id == ipdrive_base.actor_id)
                do_take_time(&in_buf);
            break;
        case DELAY_TYPE:
/*
 * Increment the event counter
 * See if this message applies to us.
 * if so, wait the allotted span.
 */          
            if (in_buf.delay.iactor_id == ipdrive_base.actor_id)
                do_delay(&in_buf);
            break;
        default:
            fprintf(stderr,"Garbage in the input file\n\
Record Type %s around position %u\n", dmp->mess_name, ftell(ctl_read));
            break;
        }
        if (ipdrive_base.debug_level)
            fflush(stderr);
    }
    if (ipdrive_base.debug_level > 2)
    {
        if (ipdrive_base.parent != (struct con_con *) NULL)
        {
            fprintf(stderr,"End of File (Thread: %d|%d)\n",
                       ipdrive_base.parent->from_end_id,
                       ipdrive_base.parent->to_end_id);
            fflush(stderr);
        }
    }
    return;
}
static void do_end_point(a)
union all_records * a;
{
/*
 * Add the end point to the array
 * Go and set up the end-point, depending on what it is.
 */
 int ep;
    if ((ep = a->end_point.iend_point_id) < 0 || ep > MAXENDPOINTS)
                       /* Ignore if out of range */
        return;
    end_point_det[ep] = a->end_point;
    if (a->end_point.iactor_id != ipdrive_base.actor_id)
                       /* Ignore if an other actor */
        return;
    if (a->end_point.iaddress_family != AF_INET)
        fprintf(stderr,"Address Family %u not supported\n",
                 a->end_point.iaddress_family);
    return;
}
#ifndef MINGW32
/*
 * Routine to temporarily pre-empt the normal clock handling
 */
void alarm_preempt()
{
    prev_alrm = sigset(SIGALRM,read_timeout);
    alarm_save = alarm(nohang.tv_sec);
    return;
}
/*
 * Routine to restore it
 */
void alarm_restore()
{
    alarm(0);
    (void) sigset(SIGALRM,prev_alrm);
    (void) alarm(alarm_save);
    return;
}
#endif
/*
 * Routine to set up a socket address
 */
static void sock_ready(host,port, out_sock)
char * host;
int port;
struct sockaddr_in * out_sock;
{
#ifdef NT4
long num_host;
struct hostent num_ent;
long * phost; 
#endif
struct hostent  *connect_host;

    if (ipdrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"sock_ready(%s,%d)\n", host, port);
        (void) fflush(stderr);
    }
#ifdef NT4
/*
 * Because NT4 gethostbyname() is so useless
 */
    if ((num_host = inet_addr(host)) != -1)
    {
        num_ent.h_addrtype = AF_INET;
        num_ent.h_addr_list = &phost;
        num_ent.h_addr = (char *) &num_host;
        num_ent.h_length = sizeof(num_host);
        connect_host = &num_ent;
    }
    else
#endif
        connect_host=gethostbyname(host);
    if (connect_host == (struct hostent *) NULL)
    { 
        static char * x[2] = {"Logic Error; no such host\n",""};
        x[1]=host;
        ipdlog(2,x);
        return;
    }
    else
    {
/*
 *    Set up the socket address
 */
         memset(out_sock,0,sizeof(*out_sock));
#ifdef OSF
         out_sock->sin_len = connect_host->h_length+sizeof(out_sock->sin_port);
#endif
         out_sock->sin_family = (unsigned char) connect_host->h_addrtype;
         out_sock->sin_port   = htons((unsigned short) port);
         memcpy((char *) &(out_sock->sin_addr.s_addr),
                (char *) connect_host->h_addr, 
                    connect_host->h_length);
    }
    return;
}
static void log_sock_bind(fd)
int fd;
{
struct sockaddr_in check;
int len = sizeof(check);
    if (!getsockname(fd,(struct sockaddr *) (&check),&len))
    {
        (void) fprintf(stderr,"Socket %d bound as %x:%d\n",
                                fd, check.sin_addr.s_addr,
                                 ntohs(check.sin_port));
        (void) fflush(stderr);
    }
    else
    { 
        char * x = "getsockname() failed\n"; 
        ipdlog(1,&x);
        perror("getsockname() failed"); 
    }
    return;
}
/************************************************************************
 * Listen set up
 */
static void ipdrive_listen(link)
LINK * link;
{
/*
 * struct protoent *ipdrive_prot;
 */
int child_pid;
long adlen;

    if (ipdrive_base.debug_level > 1)
        (void) fprintf(stderr,"ipdrive_listen(%s,%s,%s)\n",
          link->to_ep->address,link->to_ep->protocol,link->to_ep->port_id);
/*
 * We only use TCP
 *
    ipdrive_prot=getprotobyname(link->to_ep->protocol);
    if ( ipdrive_prot == (struct protoent *) NULL)
    { 
        char * x = "Logic Error; no protocol!\n";
        ipdlog(1,&x);
        return;
    }
 */
    sock_ready(link->to_ep->address,atoi(link->to_ep->port_id), &listen_sock);
    listen_sock.sin_addr.s_addr = INADDR_ANY;
/*
 *    Now create the socket to listen on
 */
    if ((listen_fd=
        socket(AF_INET,SOCK_STREAM, IPPROTO_TCP))<0)
    { 
        char * x = "Listen socket create failed\n" ;
        ipdlog(1,&x);
        perror("Listen socket create failed"); 
        link->link_id = -1;          /* Mark it to be ignored */
        return;
    }
/*
 * Bind its name to it
 */
    if (bind(listen_fd,(struct sockaddr *) (&listen_sock),sizeof(listen_sock)))
    { 
        char * x = "Listen bind failed\n"; 
        ipdlog(1,&x);
        perror("Listen bind failed"); 
        closesocket(listen_fd);
        link->link_id = -1;          /* Mark it to be ignored */
        (void) fprintf(stderr,"ipdrive_listen(%s,%s,%s)\n",
          link->to_ep->address,link->to_ep->protocol,link->to_ep->port_id);
        return;
    }
    else
    if (ipdrive_base.debug_level > 1)
        log_sock_bind(listen_fd);
/*
 *    Declare it ready to accept calls
 */
    if (listen(listen_fd, MAXLINKS))
    { 
        char * x = "Listen() failed\n"; 
        ipdlog(1,&x);
        perror("listen() failed"); 
        fflush(stderr);
        link->link_id = -1;          /* Mark it to be ignored */
        closesocket(listen_fd);
        return;
    }
    for (adlen = sizeof(link->connect_sock);;adlen = sizeof(link->connect_sock))
    {
        if ((link->connect_fd = accept(listen_fd, &(link->connect_sock),
            &adlen)) < 0)
        {
            if (errno == EINTR)
                continue;
            closesocket(listen_fd);
            break;
        }
        if (ipdrive_base.debug_level > 1)
        {
            (void) fprintf(stderr, "record: %d pos: %u accept() from %x:%d\n",
                                rec_cnt, ftell(ctl_read),
                                 link->connect_sock.sin_addr.s_addr,
                                 ntohs(link->connect_sock.sin_port));
            fflush(stderr);
        }
#ifndef MINGW32
        if ((child_pid = fork()) == 0)
#endif
        {
/*
 * Child
 */
        static  char buf[256];
        int on;

            (void) control_open(ipdrive_base.control_file,"rb",ftell(ctl_read));
            closesocket(listen_fd);
            (void) close(fileno(pg.fo));         /* Do not keep parent's log
                                                  * file open                 */
            pg.fo = (FILE *) NULL;               /* The child will probably
                                                  * not log anything          */
            (void) sprintf(buf,"%s_%d",pg.logfile,getpid());
            pg.logfile = buf;
            on = 1;
#ifdef SOLAR
            if ((setsockopt(link->connect_fd,SOL_SOCKET, SO_KEEPALIVE,&on,
                        sizeof(on))) < 0)
                perror("Failed to enable TCP Keepalive");
#else
            if ((setsockopt(link->connect_fd,IPPROTO_TCP, TCP_KEEPALIVE,&on,
                        sizeof(on))) < 0)
                perror("Failed to enable TCP Keepalive");
#endif
            if ((setsockopt(link->connect_fd,IPPROTO_TCP, TCP_NODELAY,&on,
                        sizeof(on))) < 0)
                perror("Failed to disable TCP Nagle Algorithm");
/*
 * Record the other end for possible future reference
 */ 
            sock_ready(link->from_ep->address,atoi(link->from_ep->port_id),
                  &(link->connect_sock));
            return;
        }
#ifndef MINGW32
        else
        if (child_pid < 0)
        {
            perror("fork() failed");
            fflush(stderr);
        }
        else
        if (ipdrive_base.debug_level > 3)
        {
            (void) fprintf(stderr, "fork() created new process: %d\n",
                                child_pid);
            fflush(stderr);
        }
#endif
        closesocket(link->connect_fd);
#ifndef MINGW32
        chld_catcher(WNOHANG);
#endif
    }
    perror("accept() failed"); 
    exit(1);
}
/************************************************************************
 * Find the link, given the from and to
 */
static LINK * link_find(ifrom_end_point_id, ito_end_point_id)
int ifrom_end_point_id;
int ito_end_point_id;
{
LINK * cur_link;

    if (ipdrive_base.debug_level > 3)
        (void) fprintf(stderr,"link_find(%d,%d)\n",
                    ifrom_end_point_id, ito_end_point_id);
    for (cur_link = link_det; cur_link < link_hw; cur_link++)
        if ((cur_link->from_ep->iend_point_id ==  ifrom_end_point_id
          && cur_link->to_ep->iend_point_id == ito_end_point_id)
         || (cur_link->from_ep->iend_point_id ==  ito_end_point_id
          && cur_link->to_ep->iend_point_id == ifrom_end_point_id))
            break;
    if (ipdrive_base.debug_level > 1)
    {
        if (cur_link == link_hw)
            (void) fprintf(stderr,"link_find(%d,%d) new link\n",
                    ifrom_end_point_id, ito_end_point_id);
        else
            (void) fprintf(stderr,"link_find(%d,%d) matched %d\n",
                    ifrom_end_point_id, ito_end_point_id,
                    (cur_link - &link_det[0]));
        fflush(stderr);
    }
    return cur_link;
}
/************************************************************************
 * Establish a connexion
 * - Fills in the socket stuff.
 * - Sets up a calling socket if it is allowed to.
 */
static void ipdrive_connect(link)
LINK * link;
{
/*
 *    Initialise - use input parameters to set up listen port, and
 *        address of port to connect to
 *       -    Data Definitions
struct protoent *ipdrive_prot;
 */
int on;

    if (link == (LINK *) NULL)
    {
        char * x = "Logic Error: ipdrive_connect() called with NULL link";
        ipdlog(1,&x);
        return;
    }
    if (ipdrive_base.debug_level > 1)
        (void) fprintf(stderr,"ipdrive_connect(%d,%d)\n",
            link->from_ep->iend_point_id, link->to_ep->iend_point_id);

/*
 * The only connection-oriented protocol we support is TCP
 *
 *  ipdrive_prot=getprotobyname(link->from_ep->protocol);
 */

    link->connect_fd = -1;
    sock_ready(link->to_ep->address,atoi(link->to_ep->port_id),
                  &(link->connect_sock));
        /*    Now create the socket to output on    */
    for (;;)
    {
        if ((link->connect_fd =
              socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
        {
            char * x = "Output create failed\n";
            ipdlog(1,&x);
            perror("Output create failed");
            fflush(stderr);
            sleep (5*SLEEP_FACTOR);
            continue;
        }
        else
        {
/*
 * Connect to the destination. Leave as blocking
 */
            if (connect(link->connect_fd,
               &link->connect_sock,sizeof(link->connect_sock)))
            {
            char * x = "Initial connect() failure\n";

                ipdlog(1,&x);
                perror("connect() failed");
                fflush(stderr);
                sleep (5*SLEEP_FACTOR);
                closesocket(link->connect_fd);
                continue;
            }
            else
            { 
                if (!strcmp(link->from_ep->protocol, "tcp"))
                {
#ifdef SOLAR
                    if ((setsockopt(link->connect_fd,
                          SOL_SOCKET, SO_KEEPALIVE,&on,
                                   sizeof(on))) < 0)
                        perror("Failed to enable TCP Keepalive");
#else
                    if ((setsockopt(link->connect_fd,IPPROTO_TCP,
                             TCP_KEEPALIVE,&on, sizeof(on))) < 0)
                        perror("Failed to enable TCP Keepalive");
#endif
                    if ((setsockopt(link->connect_fd,IPPROTO_TCP,
                             TCP_NODELAY,&on, sizeof(on))) < 0)
                        perror("Failed to disable TCP Nagle Algorithm");
                }
                return;
            }
        }
    }
}
/************************************************************************
 * Non-connexion socket set-up.
 */
static void ipdrive_peer(link)
LINK * link;
{
/*
 *    Initialise - use input parameters to set up listen port, and
 *        address of port to connect to
 *       -    Data Definitions
struct protoent *ipdrive_prot;
 */
int socktype;
int protono;

    if (link == (LINK *) NULL)
    {
        char * x = "Logic Error: ipdrive_peer() called with NULL link";
        ipdlog(1,&x);
        return;
    }
    if (ipdrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"ipdrive_peer(%d,%d)\n",
            link->from_ep->iend_point_id, link->to_ep->iend_point_id);
        fflush(stderr);
    }
/*
 * Can only be udp or icmp ...
 *
 *  ipdrive_prot=getprotobyname(link->from_ep->protocol);
 */

    link->connect_fd = -1;
    if (link->from_ep->iactor_id == ipdrive_base.actor_id)
        sock_ready(link->from_ep->address,
              atoi(link->from_ep->port_id),&(link->connect_sock));
    else
        sock_ready(link->to_ep->address,
              atoi(link->to_ep->port_id),&(link->connect_sock));
        /*    Now create the socket to output on    */
    if (!strcmp(link->from_ep->protocol,"udp"))
    {
        socktype = SOCK_DGRAM;
        protono = IPPROTO_UDP;
    }
    else
    {
        socktype = SOCK_RAW;
        protono = IPPROTO_ICMP;
    }
    if ((link->connect_fd =
          socket(AF_INET,socktype,protono)) < 0)
    {
        char * x = "Output create failed\n";
        ipdlog(1,&x);
        perror("Output create failed");
        return;
    }
    else
/*
 * Bind the name to the socket
 */
    if (bind(link->connect_fd,(struct sockaddr *) &(link->connect_sock),
                   sizeof(link->connect_sock)))
    {
        char * x = "Output bind failed\n";
        ipdlog(1,&x);
        perror("bind() failed");
        closesocket(link->connect_fd);
    }
    else
/*
 * Set up peer details for the other socket.
 */
    {
        if (ipdrive_base.debug_level > 1)
            log_sock_bind(link->connect_fd);
        if (link->from_ep->iactor_id == ipdrive_base.actor_id)
            sock_ready(link->to_ep->address,
                  atoi(link->to_ep->port_id),&(link->connect_sock));
        else
            sock_ready(link->from_ep->address,
                  atoi(link->from_ep->port_id),&(link->connect_sock));
        if (connect(link->connect_fd,
           &link->connect_sock,sizeof(link->connect_sock)))
        {
             char * x = "DGRAM connect() failure\n";
             ipdlog(1,&x);
             perror("connect() failed");
             fflush(stderr);
             closesocket(link->connect_fd);
        }
    } 
    return;
}
#ifndef MINGW32
/*
 * Send a file using ftp.
 */
static void do_send_file(msg)
union all_records * msg;
{
char buf[BUFSIZ];
int i;

    if (ipdrive_base.debug_level > 1)
        (void) fprintf(stderr,
                       "Processing SEND_FILE Sequence %d\n",
                        pg.seqX);
    if ((i=fork()) == 0)
    {
/*
 * CHILD
 */
        child_sig_clear();
/*
 * Step one; want to copy the file.
 */
        ftp_spawn(msg);     /* Should not return */
        exit(1);   /* exec() failed: Should not happen */
    }
    else
/*
 * PARENT
 */
    if (i<0)
    {
        char * x = "Fork to process ftp failed\n";
        perror("Fork to process msg failed");
        ipdlog(1,&x);
    }
    else
        (void) wait(0);
    return;
}
/*
 * Run an ftp and return a proper exit status
 */
static void ftp_spawn(msg)
union all_records * msg;
{
int inp[2];
int ftp_pid;
char buf[BUFSIZ];

    if (pipe(inp) == -1)
    {
        char * x ="Cannot open ftp input pipe\n";
        perror("ftp input pipe() Failed");
        ipdlog(1,&x);
        exit(1);      /* Does not return */
    }
    if ((ftp_pid = fork()) > 0)
    {      /* PARENT success */
    static char * x[2] = {"ftp command returned:",""};
    int pid_status;
    int len;
    int i,j;

        (void) dup2(inp[1],1);
        (void) dup2(inp[1],2);
        (void) close(0);
        (void) close(inp[0]);
        (void) close(inp[1]);
        (void) sigset(SIGPIPE,read_timeout); /* ie catch harmlessly */
        len = sprintf(buf, "user %s %s\n\
binary\n\
put %s %s\n\
quit\n",
              msg->send_file.dest_ftp_user_id,
              msg->send_file.dest_ftp_pass, 
              msg->send_file.send_file_name,
              msg->send_file.send_file_name);
        x[1] = buf;
        if (ipdrive_base.debug_level > 0)
        {
            buf[len] = '\0';
            ipdlog(2,x);
        }
        for (i = 0, j = 0; i < len && j > -1; i += j)
            j = write(1,buf+i,len -i);
        (void) close(1);
        (void) close(2);
        ftp_pid = wait(&pid_status);
        if (ipdrive_base.debug_level > 2)
        {
            sprintf(buf,"After wait(): errno: %d ftp_pid: %d pid_status %x",
                  errno,ftp_pid,
                  (long)(*((long *)(&pid_status))));
            x[1] = buf;
            ipdlog(2,x);
        }
        if (WIFEXITED(pid_status))
        {
            if (ipdrive_base.debug_level > 2)
            {
                sprintf(buf,"Before exit(): errno: %d w_retcode %d",
                      errno,WEXITSTATUS(pid_status));
                x[1] = buf;
                ipdlog(2,x);
            }
            if (WEXITSTATUS(pid_status))
                exit(WEXITSTATUS(pid_status));
            else
                exit(0);
        }
        else /* Terminated by signal */
        {

            if (ipdrive_base.debug_level > 0)
            {
                (void) sprintf(buf,
                    "Killed by a signal: ftp_pid: %d errno: %d pid_status %lx",
                      ftp_pid,errno, (long)(*((long *)(&pid_status))));
                x[1] = buf;
                ipdlog(2,x);
            }
            exit(1);
        }
    }
    else if (ftp_pid < 0)
    {      /* Parent Failed */
    char * x ="Cannot fork() ftp child\n";

        perror("Cannot fork() ftp child\n");
        ipdlog(1,&x);
        exit(1);      /* Does not return */
    }
    else
    {      /* CHILD success */
    char * x ="Cannot exec() ftp child\n";
    char *argv[5];
    int t;

        argv[0] = "ftp";
        argv[1] = "-n";
        argv[2] = msg->send_file.host_name;
        argv[3] = (char *) NULL;
        ipdlog(3,argv);
        (void) dup2(inp[0],0);
        if ((t = open("/dev/null",O_WRONLY,0755)) > -1)
        {
            (void) dup2(t,1);
            (void) dup2(t,2);
        }
        else
        {
            perror("ftp log file open failed");
            x = buf;
            ipdlog(1,&x);
        }
        (void) close(inp[0]);
        (void) close(inp[1]);
        (void) close(t);
#ifdef SCO
        (void) setsid();
#else
#ifdef NT4
        (void) setsid();
#else
        if ((t = open("/dev/tty",O_RDWR)) > -1)
        {           /* Stop ftp outputting to the control terminal */
            (void) ioctl(t,TIOCNOTTY,0);
            (void) close(t);
        }
#endif
#endif
        if (execvp(argv[0],argv))
            perror("Command exec failed");
        ipdlog(1,&x);
        exit(1);
    }
}
/*
 * Make sure that any forked process won't execute anything that it
 * shouldn't
 */
void child_sig_clear()
{
LINK * cur_link;

    if (ipdrive_base.debug_level > 1)
        (void) fprintf(stderr,"chld_sig_clear()\n");
    for (cur_link = link_det;
                cur_link->link_id != 0;
                     cur_link++)
        if (cur_link->connect_fd != -1)
            (void) closesocket(cur_link->connect_fd);
    (void) sigset(SIGHUP,SIG_IGN);  
    (void) sigset(SIGINT,SIG_IGN);
    (void) sigset(SIGUSR1,SIG_DFL);
    (void) sigset(SIGQUIT,SIG_IGN);
    (void) sigset(SIGTERM,SIG_DFL);
    (void) sigset(SIGCLD,SIG_DFL);
    (void) sigset(SIGPIPE,io_event);
    return;
}
#endif
/*
 * Compute an internet checksum
 */
static unsigned short inet_checksum (start,count)
unsigned short * start;
int count;
{
register long r;
register unsigned short *rp;
register unsigned short low;
register unsigned short high;
register short int rc;

    for (r = 0,
         rp = start,
         rc = count;
             rc;
                r +=  (long) (*rp++),
                rc--);
    low = r & 0xffff;
    high = r >> 0x10;
    r = low + high;
    low = r & 0xffff;
    high = r >> 0x10;
    r = low + high;
    return (unsigned short) ~r;
}
/*
 * Function to get known incoming
 */
static int smart_read(f,buf,len)
int f;
char * buf;
int len;
{
int so_far = 0;
int r;
    do
    {
        r = recvfrom(f, buf, len, 0,0,0);
        if (r <= 0)
            return r;
        so_far += r;
        len -= r;
        buf+=r;
    }
    while (len > 0);
    return so_far;
}
/***********************************************************************
 * Process messages. This routine is only called if there is something
 * to do.
 */
static void do_send_receive(msg)
union all_records * msg;
{
LINK * cur_link;
LINK * new_link;
static unsigned char x[16384];
static char * b_ptr;
int len;
int new_ep;
int done;
int socket_flags = 0;
int first_flag;            /* Needed to be able to direct the receiver to the
                            * correct location in the control file            */
long resync_loc;

    first_flag = 0;        /* Ignore the message contents */
    if (b_ptr == (char *) NULL)
        b_ptr = &(rbuf.rb[0]);
    pg.seqX = rec_cnt;
    if (ipdrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,
        "Processing Send Receive Message Sequence %d\n",
                   pg.seqX);
        fflush(stderr);
    }
/*
 * See if we have already encountered this link. If we have not done
 * so, initialise it.
 */
    cur_link = link_find(msg->send_receive.ifrom_end_point_id,
                         msg->send_receive.ito_end_point_id);
    if (cur_link->link_id == -1)
        return;                      /* For our actor, but not our thread */
    if (cur_link->link_id == 0)
    {
/*
 * Needs initialising
 */
        cur_link->from_ep =
                        &end_point_det[msg->send_receive.ifrom_end_point_id];
        cur_link->to_ep = &end_point_det[msg->send_receive.ito_end_point_id];
        if (cur_link == link_hw && link_hw < &(link_det[MAXLINKS - 1]))
            link_hw++;
        if (ipdrive_base.actor_id != 0 && ipdrive_base.parent != NULL)
        {
        struct con_con cc, *pcp;

            cc.from_end_id = msg->send_receive.ifrom_end_point_id;
            cc.to_end_id = msg->send_receive.ito_end_point_id;
            if ((pcp = smatch_true(ipdrive_base.known_con, &cc))
                        != (struct con_con *) NULL)
            {
                if (( !pcp->parent_flag
                    && pcp->parent != ipdrive_base.parent)
                  || (pcp->parent_flag))
                {
/*
 * It belongs to a different thread; mark it to be ignored
 *
 * New rule; do not allow non-base threads to listen
 */
                    cur_link->link_id == -1;
                    return;
                }
            }
        }
        cur_link->link_id = 1;
        cur_link->from_ep =
                        &end_point_det[msg->send_receive.ifrom_end_point_id];
        cur_link->to_ep = &end_point_det[msg->send_receive.ito_end_point_id];
        if (cur_link == link_hw && link_hw < &(link_det[MAXLINKS - 1]))
            link_hw++;
        if (!strcmp(cur_link->from_ep->con_orient,EPEER))
            ipdrive_peer(cur_link);
        else
        if (cur_link->from_ep->iactor_id == ipdrive_base.actor_id
          && !strcmp(cur_link->from_ep->con_orient,ECONNECT))
        {
            ipdrive_connect(cur_link);
            first_flag = 1;
            ipdrive_base.open_sess_cnt++;
        }
        else
        if (cur_link->to_ep->iactor_id == ipdrive_base.actor_id
          && !strcmp(cur_link->to_ep->con_orient,ELISTEN))
        {
/*
 * ipdrive_listen() might well fail, if another process has already got to
 * this listen point. However, our client must still service whatever messages
 * there are on its own connection, so it needs to mark this link to be
 * ignored. However, we do not want every single process to go reading on to
 * the end of the file before deciding it has nothing further to do, so we make
 * a rule that a process exits if it processes the listening end of a close.
 */ 
            ipdrive_listen(cur_link);
            if (cur_link->link_id == -1)
                return;
            first_flag = -1;
        }
        else
        {
/****************************************************************************
 * "Message from a listen end before a send." Originally, I did not think that
 * this should happen, but a client-directed seek can jump over the first
 * message. Also, after a connection, might not the first data flow from the
 * server to the client? For the seek that jumps, we actually want the message
 * picked up by a different thread, so we should ignore it. Which means that
 * we will not process the second case correctly. Our difficulties come about
 * because we are allowing multiple independent threads to follow the input
 * file. We do not have the information available to know the extent to which
 * the order of messages for different sessions in the capture reflects thread
 * flow of control or random factors. For now, mark the session as to be
 * ignored.
 */
            cur_link->to_ep =
                        &end_point_det[msg->send_receive.ito_end_point_id];
            cur_link->from_ep =
                        &end_point_det[msg->send_receive.ifrom_end_point_id];
            cur_link->link_id = -1;
            cur_link->connect_fd = -1;

            if (ipdrive_base.debug_level > 1)
            {
                fprintf (stderr, "Wrong thread - Process: %d pos:%u link_id:%d fd:%d From act:%d addr:%s(%s) To act:%d addr:%s(%s)\n",
                    getpid(),
                    ftell(ctl_read),
                    cur_link->link_id,
                    cur_link->connect_fd,
                    cur_link->from_ep->iactor_id,
                    cur_link->from_ep->address,
                    cur_link->from_ep->port_id,
                    cur_link->to_ep->iactor_id,
                    cur_link->to_ep->address,
                    cur_link->to_ep->port_id);
                fflush(stderr);
            }
            return;
        }
    }
    if (first_flag == -1 ||  msg->send_receive.imessage_len < 8)
        len = 8;
    else
        len = msg->send_receive.imessage_len;
    if (end_point_det[msg->send_receive.ito_end_point_id].iactor_id
              == ipdrive_base.actor_id)
    {
    char * mess="Problem with receive";
/*
 * Receive
 */        
    long adlen;

        if (!strcmp(cur_link->from_ep->con_orient,EPEER))
            adlen =  sizeof(cur_link->connect_sock);
        else
            adlen = 0;
#ifdef RECVFROM_ATOMIC
        if ((done = recvfrom(cur_link->connect_fd,x,len,socket_flags,
                            &(cur_link->connect_sock), &adlen)) < len)
#else
        if ((done = smart_read(cur_link->connect_fd,x,len)) < len)
#endif
        {
            perror("recvfrom()");
            (void) fprintf(stderr,
           "Initially under received: len %d read %d\n",len,done);
            ipdlog(1,&mess);
        }
        if (first_flag)
        {
        struct con_con cc;
/*
 * Get the location we need to re-read the control file from, and the end
 * point this thread is now going to service.
 */
            resync_loc = (x[0] << 24) + (x[1] << 16) + (x[2] << 8) + x[3];
            len = (x[4] << 8) + x[5] - 8;
            new_ep = (x[6] << 8) + x[7];
            fseek(ctl_read,resync_loc,0);
            if (len > 0)
            {
#ifdef RECVFROM_ATOMIC
                if ((done = recvfrom(cur_link->connect_fd,x,len,socket_flags,
                            &(cur_link->connect_sock), &adlen)) < len)
#else
                if ((done = smart_read(cur_link->connect_fd,x,len)) < len)
#endif
                {
                    perror("recvfrom()");
                    (void) fprintf(stderr,
               "Transfered under received: len %d read %d\n",len,done);
                    ipdlog(1,&mess);
                }
            }
            new_link = link_find(new_ep,
                         msg->send_receive.ito_end_point_id);
            if (new_link != cur_link)
            {
                new_link->connect_fd = cur_link->connect_fd;
                cur_link->connect_fd = -1;
                cur_link->link_id = -1;   /* Mark the current link as not
                                             belonging to this thread */
                if (ipdrive_base.debug_level > 1)
                    (void) fprintf(stderr,
                     "do_send_receive() - swapping to new End Point %u\n",
                              new_ep);
                if (new_link->link_id == 0)
                {
/*
 * Needs initialising
 */
                    new_link->link_id = 1;
                    new_link->from_ep =
                        &end_point_det[new_ep];
                    new_link->to_ep = cur_link->to_ep;
                    if (new_link == link_hw
                     && link_hw < &(link_det[MAXLINKS - 1]))
                        link_hw++;
                }
                cur_link = new_link;
            }
            else
            if (ipdrive_base.debug_level > 3)
                (void) fputs("do_send_receive() - End Point unchanged\n",
                              stderr);
/*
 * Make sure we only start sessions for which this thread is the parent
 */
            cc.from_end_id = (cur_link->from_ep - &(end_point_det[0]));
            cc.to_end_id =  (cur_link->to_ep - &(end_point_det[0]));
            ipdrive_base.parent = smatch_true(ipdrive_base.known_con, &cc);
            if (ipdrive_base.debug_level > 3)
                (void) fprintf(stderr,
                  "do_send_receive() - reposition to %u\n",resync_loc);
            ipdrive_base.open_sess_cnt = 1;        /* Initialise the count */
        }
        if (ipdrive_base.debug_level > 3)
        {
            (void) fprintf(stderr,
                  "do_send_receive() - len %d read %d\n",len,done);
            fflush(stderr);
        }
        if (ipdrive_base.verbosity)
            event_record("R", (struct event_con *) NULL); /* Note the message */
    }
    else
    {
    char * mess="Problem with transmit";
/*
 * Send
 */
        if (ipdrive_base.verbosity)
            event_record("T", (struct event_con *) NULL); /* Note the message */
#ifndef MINGW32
        if (!strcmp(cur_link->from_ep->con_orient,EPEER) &&
            !strcmp(cur_link->from_ep->protocol,"icmp"))
                icmp_send(cur_link,len);
        else
#endif
        if (first_flag)
        {
/*
 * Pass the location in the file, and the length of message to read, to the
 * server end
 */
            resync_loc = ftell(ctl_read);
            x[0] = (resync_loc >> 24) & 0xff;
            x[1] = (resync_loc >> 16) & 0xff;
            x[2] = (resync_loc >> 8) & 0xff;
            x[3] = resync_loc & 0xff;
            x[4] =  (len >> 8) & 0xff;
            x[5] =  len & 0xff;
            x[6] =  (cur_link->from_ep->iend_point_id >> 8) & 0xff;
            x[7] =  cur_link->from_ep->iend_point_id & 0xff;
            b_ptr = &x[0];
            if (ipdrive_base.debug_level > 1)
                (void) fprintf(stderr,
                  "do_send_receive() - sending command to reposition to %u\n",
			resync_loc);
        }
        else
        if (b_ptr > ((&(rbuf.rb[16383]) + len)))
            b_ptr = &(rbuf.rb[0]);
        if ((done =  sendto(cur_link->connect_fd,
                  b_ptr,len, socket_flags, 0 , 0)) < len)
        {
            perror("Error from do_send_receive sendto()");
            ipdlog(1,&mess);
        }
        if (first_flag)
            b_ptr = (char *) NULL;
        else
            b_ptr += len;
        if (ipdrive_base.debug_level > 3)
        {
            (void) fprintf(stderr,
                  "do_send_receive() - len %d written %d\n",len,done);
            fflush(stderr);
        }
    }
    (void) fflush(stderr);
    return;
}
/***********************************************************************
 * Process messages. This routine is only called if there is something
 * to do.
 */
static int do_sock_close(msg)
union all_records * msg;
{
LINK * cur_link;

    pg.seqX = rec_cnt;
    if (ipdrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,
        "Processing Socket Close Message Sequence %d\n",
                   pg.seqX);
        fflush(stderr);
    }
/*
 * Find the link and set it to de-allocated.
 */
    cur_link = link_find(msg->send_receive.ifrom_end_point_id,
                         msg->send_receive.ito_end_point_id);
    if (cur_link->link_id != 1)
        return 0;
    cur_link->link_id = 0;
    if (cur_link->connect_fd != -1)
    {
        closesocket(cur_link->connect_fd);
        cur_link->connect_fd = -1;
        ipdrive_base.open_sess_cnt--;          /* Decrement the session count */
        return 1;
    }
    return 0;                                  /* Another thread owns it */
}
#ifndef MINGW32
/*****************************************************************
 *   Routine to send an ICMP packet.
 */
static void icmp_send (link,len)
LINK * link;
int len;
{
/*
 *   Initialise - use input parameters to set up raw port, and
 *   details of port to get killed off.
 */
    int socket_flags = 0;
    union buf {
        char c[BUFLEN];
        struct icmp icmp;
    } buf;
    struct tcphdr *tpp;
/*
 * Construct the ICMP message
 */
    buf.icmp.icmp_type = ICMP_UNREACH;      /* dest unreachable */
    buf.icmp.icmp_code = ICMP_UNREACH_PORT; /* bad port */
    buf.icmp.icmp_cksum = 0; 
    buf.icmp.icmp_hun.ih_void = 0; 
#ifdef ANDROID
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_v = IPVERSION;
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_hl = 5;
#else
#ifdef AIX
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_vhl = 0x45;
#else
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_v = IPVERSION;
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_hl = 5;
#endif
#endif
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_tos = 0;
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_len = 40; /* IP header plus TCP Header */
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_id = 149; /* Random number */
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_off = 0;  /* No fragments */
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_ttl = 23; /* Random Number */
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_sum = 0;  /* Check sum */
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_p = 6;  /* TCP */
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_src = link->connect_sock.sin_addr;
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_dst = link->connect_sock.sin_addr;
    tpp = (struct tcphdr *) (&buf.icmp.icmp_dun.id_ip.idi_ip.ip_dst + 1);
    tpp->th_sport = link->connect_sock.sin_port; /* source port */
    tpp->th_dport = link->connect_sock.sin_port;  /* destination port */
    tpp->th_seq  = 149;         /* sequence number */
    tpp->th_ack  = 149;         /* acknowledgement number */
#ifdef ANDROID
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_v = IPVERSION;
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_hl = 5;
#else
#ifdef AIX
    tpp->ip_vhl = 0x50;
    tpp->ip_tos = TH_FIN;
#else
    tpp->th_off = 5;
    tpp->th_x2 = 0;
    tpp->th_flags = TH_FIN;
#endif
#endif
    buf.icmp.icmp_dun.id_ip.idi_ip.ip_sum = inet_checksum ((unsigned short *)
       &buf.icmp.icmp_dun.id_ip.idi_ip,
       sizeof(struct ip)/sizeof(unsigned short));  /* IP Header Check sum */
    buf.icmp.icmp_cksum = inet_checksum ((unsigned short *) &buf.icmp,
                          (sizeof(struct icmp) + 8)/sizeof(unsigned short));
                                              /* ICMP Check sum */
    if (sendto(link->connect_fd,buf.c,sizeof(struct icmp)+8,socket_flags,
                &(link->connect_sock), sizeof(link->connect_sock)) < 0)
        perror("Error from icmp Send To");
    return;
}    /* End of function */
#endif
/*
 *  Log the arguments to the global log file.
 */
extern char * ctime();
static void
ipdlog(argc, argv)
int argc;
char    **argv;
{
char    buf[BUFSIZ];
char    *cp;
long    t;
int i;

    if (ipdrive_base.debug_level > 3)
        (void) fprintf(stderr, "ipdlog()\n");
    (void) time(&t);
    cp = ctime(&t);
    cp[24] = 0;
    (void) sprintf(buf, "ipdrive, %s, %d, pos:%u, ", cp,getpid(),
                       ftell(ctl_read));
    for (i = 0 ; i < argc ; i++)
    {
        (void) strcat(buf, argv[i]);
        (void) strcat(buf, " ");
    }
    (void) strcat(buf, "\n");
    (void) fwrite(buf,sizeof(char),strlen(buf), stderr);
    (void) fflush(stderr);
    return;
}
/*
 *  Open the control file, positioning to the same place as we
 *  were in the parent process.
 */
static FILE * control_open(d, mode, offset)
char    *d;
char    *mode;
long int offset;
{
long fd = 1;

    if (ctl_read != (FILE *) NULL)
        (void) fclose(ctl_read);
    else
        fd = 0;
    if (ipdrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "control_open(%s) to read %d\n",
                        d, rec_cnt);
        fflush(stderr);
    }
    if ((ctl_read = fopen(d,mode)) != (FILE *) NULL && fd) 
    {
        int i;
        union all_records in_buf;
        setvbuf(ctl_read, &sbuf[0], _IOFBF, sizeof(sbuf));
#ifdef BROKEN
        for (i = 0; i < rec_cnt; i++)
            (void) ipdinrec(ctl_read,&in_buf);
#else
        if (offset)
            fseek(ctl_read, offset, 0);
#endif
    }
    return ctl_read; 
}
/*
 * Start the timer running
 */
static void do_start_timer(a)
union all_records *a;
{
char cur_pos[BUFLEN];
short int x;
HIPT * h;
pg.seqX = rec_cnt;

    if (ipdrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_start_timer(%s)\n",
                        a->start_timer.timer_id);
        fflush(stderr);
    }
    (void) sprintf(cur_pos,"%s:3600:.::%s",a->start_timer.timer_id,
                            a->start_timer.timer_description);
    stamp_declare(cur_pos);
    x = (((int) (*cur_pos)) << 8) + ((int) *(cur_pos+1));
    if ((h = lookup(pg.poss_events, (char *) x)) == (HIPT *) NULL)
    {
        (void) fprintf(stderr,"Error, event define failed for %s\n",
                       cur_pos);
        return;       /* Crash out here */
    }
    pg.curr_event = (struct event_con *) (h->body);
    pg.curr_event->time_int = timestamp();
    return;
}
/*
 * Take a time stamp
 */
static void do_take_time(a)
union all_records *a;
{
HIPT * h;
int think_left;
short int event_id;

    if (ipdrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_take_time(%s)\n", a->take_time.timer_id);
        fflush(stderr);
    }
    event_id = (((int) (a->take_time.timer_id[0])) << 8)
             + ((int) (a->take_time.timer_id[1]));
    if ((h = lookup(pg.poss_events,(char *) event_id)) ==
           (HIPT *) NULL)
    {
        (void) fprintf(stderr,"Error, undefined event %*.*s\n",
                       sizeof(event_id),sizeof(event_id),
                       (char *) &event_id);
        return;       /* Crash out here */
    }
    pg.curr_event = (struct event_con *) (h->body);
    if (pg.curr_event  != (struct event_con *) NULL)
    {
        pg.seqX = rec_cnt;
        event_record(pg.curr_event->event_id, pg.curr_event);
        think_left = (int) (pg.curr_event->min_delay
                    - pg.curr_event->time_int/100.0);
        if (think_left > 0)
        {                       /* sleep time in progress */
            sleep(think_left * SLEEP_FACTOR);
        }
        pg.curr_event = (struct event_con *) NULL;
    }
    return;
}
extern double floor();
/*
 * Use select() to give a high resolution timer
 */
static void do_delay(a)
union all_records *a;
{
struct timeval nap_time;
double delta;
#ifdef OSF
fd_set dummy;

    FD_ZERO(&dummy);
    FD_SET(0, &dummy);
#endif
    if (ipdrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_delay(%13.6f)\n", a->delay.fdelta);
        fflush(stderr);
    }
    delta =   a->delay.fdelta;
    nap_time.tv_sec = (long) floor(delta);
    nap_time.tv_usec = (long) (1000000.0 *
                       (delta - ((double) nap_time.tv_sec)));
#ifdef OSF
    (void) select (1, NULL, NULL, &dummy, &nap_time);
#else
    (void) select (0, NULL, NULL, NULL, &nap_time);
#endif
    return;
}
/**************************************************************************
 * Duplicated function to ensure that only timestamp.o is pulled in from the
 * pathatlib.a library
 */
void match_out (curr_word)
struct word_con * curr_word;
{
    if (curr_word != (struct word_con *) NULL)
        int_out(curr_word->words);
    return;
}

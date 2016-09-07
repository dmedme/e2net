/*
 *    coddrive.c - Program to drive and collect timings from coda stream
 *
 *    Copyright (C) E2 Systems 1993
 *
 *    Timestamps are written when the appropriate events are spotted.
 *
 * Arguments
 * =========
 *   - arg 1 = name of file to output timestamps to
 *   - arg 2 = pid of fdriver
 *   - arg 3 = pid of bundle
 *   - arg 4 = i number within 'rope'
 *   - arg 5 = initial quaumentum contact details.
 *
 * Signal handling
 * ===============
 * SIGTERM - terminate request
 * SIGBUS  - should not happen (evidence of machine stress)
 * SIGALRM - used to control typing rate
 * SIGCHLD - watching for death of process
 * SIGINT  - Toggle between See Through and Terminal Independent input modes
 * SIGQUIT - Force an event after the next keystroke
 *
 * Arguments
 * =========
 *   - arg 1 = name of file to output timestamps to
 *   - arg 2 = Id of fdriver
 *   - arg 3 = Id of bundle
 *   - arg 4 = i number within 'rope'
 *   - arg 5 = Input command file
 *
 * Signal handling
 * ===============
 * SIGTERM - terminate request
 *
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (C) E2 Systems Limited 1995";
#ifndef MINGW32
#include <sys/param.h>
#endif
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
#define NEED_SMART_READ
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#endif
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef NT4
#include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#ifdef PYR
#include <strings.h>
#endif
#include "hashlib.h"
#include "e2net.h"
#include "circlib.h"
#include "matchlib.h"
#include "coddrive.h"

extern int errno;
#ifdef HP7
#define NEED_SMART_READ
#endif
/***********************************************************************
 * Functions in this file
 *
 * Message handling routines
 */
unsigned char * codasc_handle();
void do_end_point();
void do_delay();
void do_start_timer();
void do_take_time();
void do_link();
void do_close();
void do_send_receive();
END_POINT * ep_find();
LINK * link_find();
static enum tok_id get_tok();
static int child_death=0;
static int io_event=0;
static struct timeval nohang = {10,0};  /* wait 10 seconds timeval structure */
static long alarm_save;                 /* What's in the alarm clock; timer */
static void (*prev_alrm)();             /* Whatever is previously installed
                                           (either rem_time() or nothing) */
#ifdef NT4
void * (*sigset)();
#endif

void alarm_preempt();   /* Put in a read timeout, in place of whatever is
                         * currently in the alarm clock
                         */
void alarm_restore();   /* Restore the previous clock value */
void do_things();       /* process requests whilst things are still alive */
void die();             /* catch terminate signal */
void scarper();         /* exit, tidying up */
void chld_sig();        /* catch the death of a child */
void io_sig();          /* catch a communications event */
void proc_args();       /* process arguments */
int enable_file_io();   /* Associate FILE's with fd's */
void coddrive_listen();  /* Set up the socket that listens for link connect
                           requests */
void ftp_spawn();       /* Initiate an ftp, and return a sensible exit status */
void child_sig_clear(); /* Clear unwanted signal handlers in forked children */

static LINK link_det[MAXLINKS];
                             /* list of links in the input file */

static END_POINT end_point_det[MAXENDPOINTS],
                             /* list of links in the input file */
         * ep_cur_ptr = end_point_det,
         * ep_max_ptr = &end_point_det[MAXENDPOINTS-1];

 
static int rec_cnt;
static int child_cnt;

static struct named_token {
char * tok_str;
enum tok_id tok_id;
} known_toks[] = {
{"", E2STR}};

static char * tbuf;
static char * tlook;
static char * sav_tlook;
static enum look_status look_status;
/***********************************************************************
 * Main Program Starts Here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
int main(argc,argv,envp)
int argc;
char * argv[];
char * envp[];
{
/****************************************************
 *    Initialise
 */
    child_cnt = 0;
    proc_args(argc,argv);
    do_things();                /* process the input file */
    pg.seqX = rec_cnt;
    event_record("F", (struct event_con *) NULL); /* announce the finish */
    exit(0);
}
/*****************************************************************
 * Service Shutdown Requests
 */
void die()
{
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
extern int errno;
extern struct event_con * curr_event; /* the event we are looking for; used as
                                         a flag to see if scanning or not */
#undef select
/*******************
 * Global data
 */
struct ptydrive_glob pg;
void siggoaway ()
{
    event_record("F", (struct event_con *) NULL); /* Mark the end */
    exit(1);
}
/*
 * Process arguments
 */
void proc_args(argc,argv)
int argc;
char ** argv;
{
    int c;
/*
 * Process the arguments
 */
    char * start_event;
    int ch;
/*
 * Set up the hash table for events
 */
    pg.poss_events = hash(MAX_EVENT,long_hh,icomp);

/****************************************************
 * Initialise.
 *
 */
    pg.curr_event = (struct event_con *) NULL;
    pg.abort_event = (struct event_con *) NULL;
    pg.log_output = stdout;
    start_event = (char *) NULL;
    pg.frag_size = 65536;
    coddrive_base.verbosity = 0;
    coddrive_base.msg_seq = 1;                /* request sequencer         */
    pg.seqX = 0;                              /* timestamp sequencer       */
    while ( ( c = getopt ( argc, argv, "hd:v" ) ) != EOF )
    {
        switch ( c )
        {
        case 'h' :
            (void) fprintf(stderr,"coddrive: E2 Systems Delphi Driver\n\
Options:\n\
 -h prints this message on stderr\n\
 -v sets verbose mode (all packets are timestamped and logged)\n\
 -d set the debug level (between 0 and 4)\n\
Arguments: Output File, Run ID, Bundle ID, Rope, Input File\n");
            fflush(stderr);
            break;
        case 'd' :
            coddrive_base.debug_level = atoi(optarg);
            break;
        case 'v' :
            coddrive_base.verbosity = 1;
            break;
        default:
        case '?' : /* Default - invalid opt.*/
            (void) fprintf(stderr,"Invalid argument; try -h\n");
            exit(1);
        } 
    }
    if ((argc - optind) < 5)
    {
        fprintf(stderr,"Insufficient Arguments Supplied; try -h\n");
        exit(1);
    } 
    pg.logfile=argv[optind++];
    pg.fdriver_seq=argv[optind++];            /* Details needed by event   */
    pg.bundle_seq=argv[optind++];             /* recording                 */
    pg.rope_seq=argv[optind++]; 
    coddrive_base.control_file = argv[optind++];
    if ((pg.cur_in_file = fopen(coddrive_base.control_file,"r"))
                 == (FILE *) NULL)
    {
        unexpected(__FILE__, __LINE__,"Failed to open control file");
        exit(1);
    }
    event_record("S", (struct event_con *) NULL); /* announce the start */
    (void) sigset(SIGINT,SIG_IGN);
#ifdef AIX
    (void) sigset(SIGDANGER,SIG_IGN);
#endif
    (void) sigset(SIGUSR1,siggoaway);
    (void) sigset(SIGTERM,siggoaway);
                            /* Initialise the termination signal catcher */
#ifndef V32
#ifndef MINGW32
    (void) sigset(SIGTTOU,SIG_IGN);
                             /* Ignore silly stops */
    (void) sigset(SIGTTIN,SIG_IGN);
                             /* Ignore silly stops */
    (void) sigset(SIGTSTP,SIG_IGN);
                             /* Ignore silly stops */
#endif
#endif
    (void) sigset(SIGUSR1,die);       /* in order to exit */
#ifndef MINGW32
    (void) sigset(SIGCLD,SIG_DFL);
#endif
    (void) sigset(SIGPIPE,SIG_IGN);   /* So we don't crash out */
    (void) sigset(SIGHUP,SIG_IGN);    /* So we don't crash out */

/*******************************************************************
 * Variables used to control main loop processing
 */
    pg.think_time = PATH_THINK;           /* default think time */
    
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"proc_args()\n");
        (void) fflush(stderr);
        codlog(argc,argv);
    }
    return;
}
/*
 * chld_sig(); interrupt the select() or whatever.
 */
void chld_sig()
{
    child_death++;
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
void scarper(fname,ln,text)
char * fname;
int ln;
char * text;
{
    fprintf(stderr, "%s:%d UNIX error code %d\n\
%s\n",fname,ln,errno, text);
    exit(1);       /* Does not Return */
}
void syntax_err(fname,ln,text)
char * fname;
int ln;
char * text;
{
    fprintf(stderr, "Syntax error in control file %s:\n\
%s%s\n\
unexpected around byte offset %d\n",
        coddrive_base.control_file,
        tbuf, (look_status == CLEAR) ?"": tlook, ftell(pg.cur_in_file));
    scarper(fname,ln,text);       /* Does not Return */
}
/*********************************************************************
 * Recognise the PATH directives in the file
 *
 * End Points (\E) are used to allow replay of scripts captured on
 * one machine with one set of parameters, on another machine with another
 * set.
 *
 * The end_points are:
 * Original Host:Capture Port:Host for Test:Port for Test:Connection Flag
 *
 * The con_flag is 'C' for connect() and 'L' for listen() behaviour.
 */
void recognise_end_point(a)
union all_records *a;
{
    a->end_point.end_point_id = coddrive_base.ep_cnt++;
    STRCPY(a->end_point.address,nextfield(tlook,':'));
    a->end_point.cap_port_id = atoi(nextfield(NULL,':'));
    STRCPY(a->end_point.host,nextfield(NULL,':'));
    a->end_point.port_id = atoi(nextfield(NULL,':'));
    a->end_point.con_flag = *(nextfield(NULL,':'));
    return;
}
/*
 * Start Time (\S) records are:
 * id:number (ignored):description
 */
void recognise_start_timer(a)
union all_records *a;
{
    STRCPY(a->start_timer.timer_id,nextfield(tlook,':'));
    (void) nextfield(NULL,':');
    STRCPY(a->start_timer.timer_description,nextfield(NULL,':'));
    return;
}
/*
 * Take Time (\T) records are:
 * id:
 */
void recognise_take_time(a)
union all_records *a;
{
    STRCPY(a->take_time.timer_id,nextfield(tlook,':'));
    return;
}
/*
 * Delay (\W) records are:
 * delay time (floating point number)
 */
void recognise_delay(a)
union all_records *a;
{
    a->delay.delta = strtod(tlook,(char **) NULL);
    return;
}
/*
 * Link messages are Link (\M) and Close (\X).
 * They contain:
 * from_host; from_port: to_host;to_port
 */
void recognise_link(a)
union all_records *a;
{
    char address[HOST_NAME_LEN];
    int port_id;
    strcpy(&address[0], nextfield(tlook, ';'));
    port_id = atoi(nextfield((char *) NULL, ':'));
    if ((a->link.from_ep = ep_find(address,port_id)) ==
        (END_POINT *) NULL)
        syntax_err(__FILE__,__LINE__,"Missing End Point");
    strcpy(&address[0], nextfield((char *) NULL, ';'));
    port_id = atoi(nextfield((char *) NULL, ':'));
    if ((a->link.to_ep = ep_find(address,port_id)) ==
        (END_POINT *) NULL)
        syntax_err(__FILE__,__LINE__,"Missing End Point");
    a->link.connect_fd = -1;
    memset((char *) &(a->link.connect_sock),0,sizeof(a->link.connect_sock));
    memset((char *) &(a->link.in_det),0,sizeof(a->link.in_det));
    memset((char *) &(a->link.out_det),0,sizeof(a->link.out_det));
    return;
}
/*
 * Take an incoming message in ASCII and make it binary
 */
enum tok_id recognise_message(a)
union all_records *a;
{
static union all_records msg;
int mess_len;
    if ((mess_len = codinrec(pg.cur_in_file,tlook,IN)) == 0)
        syntax_err(__FILE__,__LINE__,
              "Invalid format coda record");
    else
        memcpy(&(msg.buf[0]), tlook, mess_len);
    a->send_receive.record_type = SEND_RECEIVE_TYPE;
    a->send_receive.msg = &msg;
    look_status = CLEAR;
    return SEND_RECEIVE_TYPE;
}
/*
 * Assemble records for processing by the main loop
 */
enum tok_id codread(a)
union all_records *a;
{
enum tok_id tok_id;
/*
 * Skip White Space and Comments
 */
    for (;;)
    {
        tok_id = get_tok(pg.cur_in_file);
        if (tok_id == E2EOF)
            return tok_id;
        else
        if (tok_id == E2COMMENT)
        {
            if (coddrive_base.verbosity)
            {
                fputs(tbuf,stderr);
                if (look_status != CLEAR)
                    fputs(tlook,stderr);
            }
            look_status = CLEAR;
        }
        else
            break;
    }
    if (look_status == CLEAR)
        syntax_err(__FILE__,__LINE__,"There should be a look-ahead token");
    a->end_point.record_type = tok_id;  /* It's in the same position in every
                                         record */
    switch(tok_id)
    {
    case  END_POINT_TYPE:
        recognise_end_point(a);
        break;
    case  E2STR:
        tok_id = recognise_message(a);
        break;
    case  LINK_TYPE:
    case  CLOSE_TYPE:
        recognise_link(a);
        break;
    case  START_TIMER_TYPE:
        recognise_start_timer(a);
        break;
    case  TAKE_TIME_TYPE:
        recognise_take_time(a);
        break;
    case  DELAY_TYPE:
        recognise_delay(a);
        break;
    default:
          fprintf(stderr,"Token: %d\n", (int) tok_id);
          syntax_err(__FILE__,__LINE__,"Invalid control file format");
    }
    if (look_status != KNOWN)
        look_status = CLEAR;
    return tok_id;
}
/*
 * Function to handle control file data.
 */
void do_things()
{
union all_records in_buf;
enum tok_id rec_type;
    tbuf = malloc(WORKSPACE);
    sav_tlook = malloc(WORKSPACE);
    tlook = sav_tlook;
    look_status = CLEAR;
    while ((rec_type = codread(&in_buf)) != E2EOF)
    {
        rec_cnt++;
        if (coddrive_base.debug_level > 2)
        {
            (void) fprintf(stderr,"Control File Service Loop\n");
            (void) fprintf(stderr,"=========================\n");
            fprintf(stderr,"Line: %d Record Type: %d\n", rec_cnt,
                         (int) rec_type);
        }
        switch (rec_type)
        {
        case END_POINT_TYPE:
/*
 * Add the end point to the array
 */
            do_end_point(&in_buf);
            break;
        case SEND_RECEIVE_TYPE:
/*
 * Send the message and receive the response.
 */          
            do_send_receive(&in_buf);
            break;
        case SEND_FILE_TYPE:
/*
 * Send the file.
 */          
            break;
        case START_TIMER_TYPE:
/*
 * Set up the timer.
 */          
            do_start_timer(&in_buf);
            break;
        case TAKE_TIME_TYPE:
/*
 * Record the time.
 */          
            do_take_time(&in_buf);
            break;
        case DELAY_TYPE:
/*
 * Wait the allotted span.
 */          
            do_delay(&in_buf);
            break;
        case CLOSE_TYPE:
/*
 * Connect a link if this is new.
 */          
            do_close(&in_buf);
            break;
        case LINK_TYPE:
/*
 * Connect a link if this is new.
 */          
            do_link(&in_buf);
            break;
        default:
            syntax_err(__FILE__,__LINE__,"this token invalid at this point");
            break;
        }
    }
    free(tbuf);
    free(sav_tlook);
    return;
}
void do_link(a)
union all_records * a;
{
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"do_link(%s;%d => %s;%d)\n",
            a->link.from_ep->host,
            a->link.from_ep->port_id,
            a->link.to_ep->host,
            a->link.to_ep->port_id);
        fflush(stderr);
    }
    coddrive_base.cur_link = link_find(a->link.from_ep, a->link.to_ep);
/*
 * See if we have already encountered this link. If we have not done
 * so, initialise it.
 */
    if (coddrive_base.cur_link->link_id != LINK_TYPE)
    {
/*
 * Needs initialising
 */
        *(coddrive_base.cur_link) = a->link; 
        if (a->link.from_ep->con_flag == 'C')
            coddrive_connect(coddrive_base.cur_link);
        else
            coddrive_listen(coddrive_base.cur_link);
    }
    return;
}
void do_close(a)
union all_records * a;
{
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"do_close(%s;%d => %s;%d)\n",
            a->link.from_ep->host,
            a->link.from_ep->port_id,
            a->link.to_ep->host,
            a->link.to_ep->port_id);
        fflush(stderr);
    }
    coddrive_base.cur_link = link_find(a->link.from_ep, a->link.to_ep);
/*
 * See if we have already encountered this link. If we have not done
 * so, initialise it.
 */
    if (coddrive_base.cur_link->connect_fd == -1)
        fprintf(stderr, "Logic Error: closing a non-open connexion\n");
    else
    {
        if (a->link.from_ep->con_flag == 'C')
        {
            shutdown(coddrive_base.cur_link->connect_fd, 2);
            close(coddrive_base.cur_link->connect_fd);
            coddrive_base.cur_link->connect_fd = -1;
            coddrive_base.cur_link->link_id = CLOSE_TYPE;
        }
        else
            exit(0);
    }
    return;
}
void do_end_point(a)
union all_records * a;
{
/*
 * Add the end point to the array
 * Go and set up the end-point, depending on what it is.
 */
 int ep;
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"do_end_point(%d, %s;%d (%s;%d))\n",
            a->end_point.end_point_id,
            a->end_point.address,
            a->end_point.cap_port_id,
            a->end_point.host,
            a->end_point.port_id);
        fflush(stderr);
    }
    if ((ep = a->end_point.end_point_id) < 0 || ep > MAXENDPOINTS)
                       /* Ignore if out of range */
        return;
    end_point_det[ep] = a->end_point;
    return;
}
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
/*
 * Routine to set up a socket address
 */
static void sock_ready(host,port, out_sock)
char * host;
int port;
struct sockaddr_in * out_sock;
{
struct hostent  *connect_host;
long addr;
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"sock_ready(%s,%d)\n", host, port);
        (void) fflush(stderr);
    }
    connect_host=gethostbyname(host);
    if (connect_host == (struct hostent *) NULL)
        addr = inet_addr(host); /* Assume numeric arguments */
    else
        memcpy((char *) &addr, (char *) connect_host->h_addr_list[0], 
                    (connect_host->h_length < sizeof(addr)) ?
                        connect_host->h_length :sizeof(addr));
/*
 *    Set up the socket address
 */
     memset(out_sock,0,sizeof(*out_sock));
#ifdef OSF
     out_sock->sin_len = connect_host->h_length+sizeof(out_sock->sin_port);
#endif
     out_sock->sin_family = AF_INET;
     out_sock->sin_port   = htons((unsigned short) port);
     memcpy((char *) &(out_sock->sin_addr.s_addr),
            (char *) &addr,(sizeof(out_sock->sin_addr.s_addr) < sizeof(addr)) ?
                                 sizeof(out_sock->sin_addr.s_addr) :
                                 sizeof(addr));
    return;
}
void log_sock_bind(fd)
int fd;
{
struct sockaddr_in check;
int len = sizeof(check);
    if (!getsockname(fd,(struct sockaddr *) (&check),&len))
    {
        (void) fprintf(stderr,"Socket %d bound as %x:%d\n",
                                fd, check.sin_addr.s_addr, check.sin_port);
        (void) fflush(stderr);
    }
    else
    { 
        char * x = "getsockname() failed\n"; 
        codlog(1,&x);
        perror("getsockname() failed"); 
    }
    return;
}
/************************************************************************
 * Find the end point, given the host and port
 */
END_POINT * ep_find(address, cap_port_id)
char * address;
int cap_port_id;
{
END_POINT * cur_ep;
    if (coddrive_base.debug_level > 1)
        (void) fprintf(stderr,"ep_find(%s,%d)\n", address, cap_port_id);
    for (cur_ep = end_point_det;
            cur_ep->record_type == END_POINT_TYPE &&
            (strcmp(cur_ep->address,address) ||
            cur_ep->cap_port_id != cap_port_id);
                     cur_ep++);
    if (cur_ep->record_type != END_POINT_TYPE)
        return (END_POINT *) NULL;
    else
        return cur_ep;
}
/************************************************************************
 * Find the link, given the from and to
 */
LINK * link_find(from_ep, to_ep)
END_POINT * from_ep;
END_POINT * to_ep;
{
    LINK * cur_link;
    if (coddrive_base.debug_level > 1)
        (void) fprintf(stderr,"link_find(%s:%d => %s:%d)\n",
                    from_ep->host,
                    from_ep->port_id,
                    to_ep->host,
                    to_ep->port_id);
    for (cur_link = link_det;
                cur_link->link_id != 0;
                     cur_link++)
        if ((cur_link->from_ep ==  from_ep
          && cur_link->to_ep == to_ep)
         || (cur_link->from_ep ==  to_ep
          && cur_link->to_ep == from_ep))
            break;
    return cur_link;
}
/************************************************************************
 * Establish a connexion
 * - Fills in the socket stuff.
 * - Sets up a calling socket if it is allowed to.
 */
void coddrive_connect(link)
LINK * link;
{
/*
 *    Initialise - use input parameters to set up listen port, and
 *        address of port to connect to
 *       -    Data Definitions
 */
struct protoent *coddrive_prot;

    if (link == (LINK *) NULL)
    {
        char * x = "Logic Error: coddrive_connect() called with NULL link";
        codlog(1,&x);
        return;
    }
    if (coddrive_base.debug_level > 1)
        (void) fprintf(stderr,"coddrive_connect(%s;%d => %s;%d)\n",
            link->from_ep->host,
            link->from_ep->port_id,
            link->to_ep->host,
            link->to_ep->port_id);

    coddrive_prot=getprotobyname("tcp");

    link->connect_fd = -1;
    sock_ready(link->to_ep->host, link->to_ep->port_id,
                  &(link->connect_sock));
/*
 *    Now create the socket to output on
 */
    for (;;)
    {
        if ((link->connect_fd =
              socket(AF_INET,SOCK_STREAM,coddrive_prot->p_proto)) < 0)
        {
            char * x = "Output create failed\n";
            codlog(1,&x);
            perror("Output create failed");
            fflush(stderr);
            sleep (5);
            continue;
        }
        else
        {
/*
 * If we need to bind names, use a variation on the following code
 *
 *          for( i = 1050; i < 1489; i++)
 *          {
 *             sock_ready("glaxo1",i,&b);
 *             if (!bind(link->connect_fd, &b, sizeof(b)))
 *                 break;
 *          }
 *
 * Connect to the destination. Leave as blocking
 */
            if (connect(link->connect_fd,
            (struct sockaddr *) &link->connect_sock,sizeof(link->connect_sock)))
            {
                 char * x = "Initial connect() failure\n";
                 codlog(1,&x);
                 perror("connect() failed");
                 fflush(stderr);
                 close(coddrive_base.cur_link->connect_fd);
                 coddrive_base.cur_link->connect_fd = -1;
                 sleep (5);
                 continue;
            }
            else
            {
                coddrive_base.cur_link->cfpr =
                    fdopen(coddrive_base.cur_link->connect_fd,"r");
                coddrive_base.cur_link->cfpw =
                    fdopen(coddrive_base.cur_link->connect_fd,"w");
                setbuf( coddrive_base.cur_link->cfpr, NULL);
                setbuf( coddrive_base.cur_link->cfpw, NULL);
                return;
            }
        }
    }
}
/************************************************************************
 * Listen set up - needed to drive the rendition scripts. We still
 * emulate the PC, but this time the host initiates.
 * Note that the source is still the from_ep.
 */
void coddrive_listen(link)
LINK * link;
{
static char nseq[10];
struct protoent *coddrive_prot;
unsigned long adlen;
int listen_fd;
struct sockaddr_in listen_sock;

    if (coddrive_base.debug_level > 1)
        (void) fprintf(stderr,"coddrive_listen(%s,%d)\n",
          link->from_ep->host,link->from_ep->port_id);
    coddrive_prot=getprotobyname("tcp");
    if ( coddrive_prot == (struct protoent *) NULL)
    { 
        char * x = "Logic Error; no host or protocol!\n";
        codlog(1,&x);
        return;
    }
/*
 *    Construct the Socket Address
 */
    sock_ready(link->from_ep->host, link->from_ep->port_id, &listen_sock);
    listen_sock.sin_addr.s_addr = INADDR_ANY;
/*
 *    Now create the socket to listen on
 */
    if ((listen_fd=
         socket(AF_INET,SOCK_STREAM,coddrive_prot->p_proto))<0)
    { 
        char * x = "Listen socket create failed\n" ;
        codlog(1,&x);
        perror("Listen socket create failed"); 
    }
/*
 * Bind its name to it
 */
    if (bind(listen_fd,(struct sockaddr *) (&listen_sock),sizeof(listen_sock)))
    { 
        char * x = "Listen bind failed\n"; 
        codlog(1,&x);
        perror("Listen bind failed"); 
    }
    else
    if (coddrive_base.debug_level > 1)
        log_sock_bind(listen_fd);
/*
 *    Declare it ready to accept calls
 */
    if (listen(listen_fd, MAXLINKS))
    { 
        char * x = "Listen() failed\n"; 
        codlog(1,&x);
        perror("listen() failed"); 
        fflush(stderr);
    }
    for (adlen = sizeof(link->connect_sock);
            (link->connect_fd = accept(listen_fd, (struct sockaddr *)
                          &(link->connect_sock), &adlen)) >= 0;
                adlen = sizeof(link->connect_sock))
    {
        if (fork() == 0)
        {
/*
 * Child. One shot. There has to be one file per transaction,
 * because the listener never advances past the listening point..
 */
        char buf[128];
            fclose(pg.cur_in_file);
            (void) sprintf(buf,"%s_%s",coddrive_base.control_file,
                               pg.rope_seq);
            close(listen_fd);
            if ((pg.cur_in_file = fopen(buf,"r")) == (FILE *) NULL)
            {
                fprintf(stderr, "No script %s available!\n", buf); 
                exit(1);
            }
            (void) sprintf(buf,"%s_%s",pg.logfile,pg.rope_seq);
            pg.fo = fopen(buf,"w");
            link->cfpr = fdopen(link->connect_fd,"r");
            link->cfpw = fdopen(link->connect_fd,"w");
            setbuf( coddrive_base.cur_link->cfpr, NULL);
            setbuf( coddrive_base.cur_link->cfpw, NULL);
/*
 * Record the other end for possible future reference
 */ 
            sock_ready(link->to_ep->host,link->to_ep->port_id,
                  &(link->connect_sock));
            return;
        }
/*
 * Give the next child a new rope number
 */
        sprintf(nseq,"%d",atoi(pg.rope_seq)+1);
        pg.rope_seq = nseq;
    }
    perror("accept() failed"); 
    exit(1);
}
/***********************************************************************
 * Process messages. This routine is only called if there is something
 * to do.
 *
 * Delphi-specific code is included here. The general solution would
 * provide hooks into which any TCP/IP based message passing scheme could
 * be attached.
 */
void do_send_receive(msg)
union all_records * msg;
{
int len;
int socket_flags = 0;
struct cod_mess * ret_val;
union all_records ret_msg;
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,
        "Processing Send Receive Message Sequence %d\n",
                   pg.seqX);
        fflush(stderr);
    }
resend:
/*
 * Send - Message has been assembled in msg.
 */
    if (( codoutrec(coddrive_base.cur_link->cfpw,msg->send_receive.msg,OUT))
               == 0)
    {
        perror("Error from do_send_receive codoutrec()");
        fflush(stderr);
        exit(1);     /* Abandon. Closes the files. */
    }
    if (coddrive_base.verbosity)
        event_record("T", (struct event_con *) NULL); /* Note the message */
/*
 * Receive
 */
    if ( codinrec(coddrive_base.cur_link->cfpr,&ret_msg, OUT) == 0)
        return;
/*
 * Now do whatever processing is necessary on the received message:
 * - find its type:
 * - depending on the type, extract the bits that we need
 */
    if (coddrive_base.verbosity)
    {
        event_record("R", (struct event_con *) NULL); /* Note the message */
    }
/*
 * Take any special action based on the message just processed....
 */
    return;
}
/*
 *  Log the arguments to the global log file.
 */
extern char * ctime();
void
codlog(argc, argv)
int argc;
char    **argv;
{
char    buf[BUFSIZ];
char    *cp;
time_t    t;
int i;
    if (coddrive_base.debug_level > 3)
        (void) fprintf(stderr, "codlog()\n");
    (void) fflush(stderr);

    (void) time(&t);
    cp = ctime(&t);
    cp[24] = 0;
    (void) sprintf(buf, "coddrive, %s, %d, ", cp,getpid());
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
 * Start the timer running
 */
void do_start_timer(a)
union all_records *a;
{
char cur_pos[BUFLEN];
short int x;
HIPT * h;
pg.seqX = rec_cnt;
    if (coddrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_start_timer(%s)\n",
                        a->start_timer.timer_id);
        fflush(stderr);
    }
    strcpy(cur_pos,a->start_timer.timer_id);
    strcat(cur_pos, ":120:");
    strcat(cur_pos, a->start_timer.timer_description);
    stamp_declare(cur_pos);
    x = (short int) (((int) (*cur_pos)) << 8) + ((int) *(cur_pos+1));
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
void do_take_time(a)
union all_records *a;
{
    HIPT * h;
    long int event_id;
    if (coddrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_take_time(%s)\n", a->take_time.timer_id);
        fflush(stderr);
    }
    event_id = (((int) (a->take_time.timer_id[0])) << 8)
             + ((int) (a->take_time.timer_id[1]));
    if ((h = lookup(pg.poss_events,(char *) event_id)) ==
           (HIPT *) NULL)
    {
        (void) fprintf(stderr,"Error, undefined event 0x%x\n",
                        event_id);
        return;       /* Crash out here */
    }
    pg.curr_event = (struct event_con *) (h->body);
    if (pg.curr_event  != (struct event_con *) NULL)
    {
    int sleep_left;
        pg.seqX = rec_cnt;
        event_record(pg.curr_event->event_id, pg.curr_event);
        sleep_left = (int) (((double) pg.think_time)
                          - pg.curr_event->time_int/100.0);
        if (sleep_left > 0)
            sleep(sleep_left);
        pg.curr_event = (struct event_con *) NULL;
    }
    return;
}
extern double floor();
extern double strtod();
/*
 * Use select() to give a high resolution timer
 */
void do_delay(a)
union all_records *a;
{
struct timeval nap_time;
#ifdef OSF
#ifndef AIX
fd_set dummy;

    FD_ZERO(&dummy);
    FD_SET(0, &dummy);
#endif
#endif
    if (coddrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_delay(%f)\n", a->delay.delta);
        fflush(stderr);
    }
    nap_time.tv_sec = (long) floor(a->delay.delta);
    nap_time.tv_usec = (long) (1000000.0 *
                       (a->delay.delta - ((double) nap_time.tv_sec)));
    pg.think_time = (short int) nap_time.tv_sec;
    if (
#ifdef AIX
             select (0, NULL, NULL, NULL, &nap_time)
#else
#ifdef OSF
             select (1, NULL, NULL, &dummy, &nap_time)
#else
             select (0, NULL, NULL, NULL, &nap_time)
#endif
#endif
                  != 0)
    {
        perror("select() failed");
        fprintf(stderr,"Trying to sleep %d.%06d seconds\n",
                  nap_time.tv_sec, nap_time.tv_usec);
        fflush(stderr);
    }    
    return;
}
/*
 * Read in up to a new line, and terminate with a null character
 * In case getc() doesn't inter-work with fseek()
 */
int getc_seek ( fp)
FILE * fp;
{
unsigned char buf;
    if (fread(&buf,sizeof(char),1,fp) == 0)
        return EOF;
    else
        return (int) buf;
}
/*
 * Read in a line to tbuf, dropping escaped newlines.
 */
static int getescline(fp)
FILE * fp;
{
int p; 
char * cur_pos = sav_tlook;
skip_blank:
    tlook = sav_tlook;
    look_status = PRESENT;
    p = getc(fp);
/*
 * Scarper if all done
 */
    if ( p == EOF )
        return p;
    else
    if (p == '\\')
    {
        *cur_pos++ = (char) p;
        fgets(cur_pos, 32767, fp);
        return strlen(cur_pos);
    }
    else
/*
 * Pick up the next line, stripping out escapes
 */
    {
        for (;;)
        {
            if (p == (int) '\\')
            {
                p = getc(fp);
                if ( p == EOF )
                    break;
                else
                if (p == '\n')
                    p = getc(fp);
                else
                    *cur_pos++ = '\\';
            }
            *cur_pos++ = p;
            if (p == (int) '\n')
            {
                if (cur_pos == sav_tlook + 1)
                {
                    cur_pos = sav_tlook;
                    goto skip_blank;
                }
                break;
            }
            p = getc(fp);
            if ( p == EOF )
                p = '\n';
        }
        *cur_pos = '\0';
        return (cur_pos - sav_tlook);
    }
}
/*
 * Move things from the look-ahead to the live buffer
 */
void mv_look_buf(len)
int len;
{
    memcpy(tbuf, tlook, len);
    *(tbuf + len) = '\0';
    tlook += len;
    if (*tlook == '\0' || *tlook == '\n')
        look_status = CLEAR;
    return;
}
/*
 * Convert a MSB/LSB ordered hexadecimal string into an integer
 */
int hex_to_int(x1, len)
char * x1;
int len;
{
long x;
int x2;
for (x = (unsigned long) (*x1++ - (char) 48), x = (x > 9)?(x - 7):x, len -= 1;
             len; len--, x1++)
    {
        x2 = *x1 - (char) 48;
        if (x2 >  9)
            x2 -=  7;
        x = x*16 + x2;
    }
    return x;
}
/*
 * Read the next token
 * -  There are at most two tokens a line
 * -  Read a full line, taking care of escape characters
 * -  Search to see what the cat brought in
 * -  Be very careful with respect to empty second tokens
 * -  Return  
 */
static enum tok_id get_tok(fp)
FILE * fp;
{
static enum look_status last_look;
static enum tok_id last_tok;
    int len;
/*
 * If no look-ahead present, refresh it
 */
    if (look_status == KNOWN)
    {
        look_status = last_look;
        return last_tok;
    }
    if (look_status != PRESENT)
    {
        if ((len = getescline(fp)) == EOF)
            return E2EOF;            /* Return EOF if no more */
/*
 * Commands are only allowed at the start of a line
 */
        if (coddrive_base.debug_level > 3)
            fprintf(stderr,"Input Line: %s",tlook);
        last_look = look_status;
        if (*tlook == '\\')
        {        /* Possible PATH Command */
        char c = *(tlook + 1);
            switch (c)
            {
            case 'C':
                 if (*(tlook + 2) != ':')
                     goto notnewline;
                 *tbuf = '\0';
                 last_tok = E2COMMENT;
                 break;
            case 'M':
            case 'E':
            case 'X':
                 if (*(tlook + 2) != ':')
                     goto notnewline;
                 *tbuf = '\\';
                 *(tbuf+1) = c;
                 *(tbuf+2) = ':';
                 *(tbuf+3) = '\0';
                 tlook += 3;
                 if (c == 'M')
                     last_tok = LINK_TYPE;
                 else
                 if (c == 'E')
                     last_tok = END_POINT_TYPE;
                 else
                     last_tok = CLOSE_TYPE;
                 break;
            case 'W':
                 tlook += 2;
                 last_tok = DELAY_TYPE;
                 break;
            case 'S':
                 *(tlook + len - 2) = '\0';
                 tlook += 2;
                 last_tok = START_TIMER_TYPE;
                 break;
            case 'T':
                 tlook += 2;
                 last_tok = TAKE_TIME_TYPE;
                 break;
            }
            if (coddrive_base.debug_level > 2)
                fprintf(stderr,"Token: %d\n",(int) last_tok);
            return last_tok;
        }
    }
notnewline:
    last_tok = E2STR;
/*
 * Push back the whole line, without any escapes in it now, excluding the
 * final new-line character
 *
 * What on earth is this? Preserved here in case some light dawns.
 *
    fseek(fp,-(len),1);
 */
    if (coddrive_base.debug_level > 2)
        fprintf(stderr,"Token: %d\n",(int) last_tok);
    return last_tok;
}
/*****************************************************************************
 * - Routines that read or write one of the valid record types
 *   off a FILE.
 *
 * codinrec()
 *   - Sets up the record in a buffer that is passed to it
 *   - Returns the record type found
 *
 * codoutrec()
 *   - Fills a static buffer with the data that is passed to it
 *   - Returns 1 if successful, 0 if not.
 *
 * Code to generate binary from a mixed buffer of ASCII and hexadecimal
 */ 
int get_bin(tbuf, tlook, cnt)
unsigned char * tbuf;
unsigned char * tlook;
int cnt;
{
unsigned char * cur_pos;
unsigned char * sav_tbuf = tbuf;
int len;
notnewline:
    while (cnt > 0)
/*
 * Is this a length of hexadecimal?
 */
    {
        if (*tlook == '\''
          && (cur_pos = strchr(tlook+1,'\'')) > (tlook + 1)
          && strspn(tlook+1,"0123456789ABCDEFabcdef") ==
                          (len = (cur_pos - tlook - 1)))
        {
            cnt -= (3 + len);
            tlook++;
            *(tlook + len) = (unsigned char) 0;
            tbuf = hex_in_out(tbuf, tlook);
            tlook = cur_pos + 1;
        }
/*
 * Is this a run of characters?
 */
        else
        if ((len = strcspn(tlook,"'")))
        {
            memcpy(tbuf,tlook,len);
            tlook += len;
            tbuf += len;
            cnt -= len;
        }
/*
 * Otherwise, we have a stray "'"
 */
        else
        {
            *tbuf++ = *tlook++;
            cnt--;
        }
    }
    return tbuf - sav_tbuf;
}
/*********************************************************************
 * codinrec - read a record off the input stream
 * - read the record type
 * - return (char *) NULL if can't get the full thing
 * - strip any trailing space
 * - find out which record it is
 * - switch on the record type
 * - copy the record type
 * - read each field in turn into the buffer, null terminate it
 * - any error, return (char *) NULL
 * - if ultimately successful,
 * - return the record type originally read
 *
 * IN means that the data is in ASCII. 
 * OUT means that the data is in binary.
 *
 * The buffer contents are always binary.
 */
#ifdef NEED_SMART_READ
int smart_read(f,buf,len)
int f;
char * buf;
int len;
{
int so_far = 0;
int r;
    do
    {
        r = read(f, buf, len);
        if (r <= 0)
            return r;
        so_far += r;
        len -= r;
        buf+=r;
    }
    while (len > 0);
    return so_far;
}
#endif
int codinrec(fp, b, in_out)
FILE * fp;
unsigned char * b;
enum direction_id in_out;
{
int eof_check;
static unsigned char buf[8192];
char * x;
int read_cnt;
int i;
static unsigned char data_header[16];
HIPT *h;
int mess_id;
int mess_len;
    if ((fp == (FILE *) NULL) || b == (unsigned char *) NULL)
    {
        (void) fprintf(stderr,
               "Logic Error: codinrec() called with NULL parameter(s)\n");
        return 0;
    }
    if (in_out == IN)
    {
/*
 * The record has already been read, and is in ASCII format in b. Convert it
 * in place.
 */
        if (coddrive_base.debug_level > 2)
            fputs(b,stderr);
        mess_len = get_bin(&buf[0], b, strlen(b));
        memcpy(&b[0], &buf[0],mess_len);
    }
    else
    {
#ifdef NEED_SMART_READ
        eof_check = smart_read(fileno(fp), data_header,sizeof(data_header));
#else
        eof_check = fread(data_header,sizeof(char),sizeof(data_header),fp);
#endif
        if (eof_check != sizeof(data_header))
        {
            if (eof_check)
            {
                (void) fputs("Format failure: data_header read failed\n",
                             stderr);
                if (eof_check > 0)
                {
                    gen_handle(stdout, &data_header[0],&data_header[eof_check],1);
                }
                else
                     perror("Unexpected Read Failure");
            }
            return 0;
        }
        mess_len = data_header[14]*256 + data_header[15];
/*
 * Read the record
 */
#ifdef NEED_SMART_READ
        if ((eof_check = smart_read(fileno(fp), &buf[0],mess_len)) != mess_len)
#else
        if ((eof_check = fread(buf,sizeof(char),mess_len,fp)) != mess_len)
#endif
        {
            (void) fputs( "Format failure: record read failed\n", stderr);
            if (!eof_check)
                (void) fputs( "EOF on communications channel\n", stderr);
            return 0;
        }
        memcpy(b,&data_header[0], 16);
        memcpy(b+16,&buf[0],mess_len);
    }
    if (coddrive_base.debug_level > 2)
    {
        fprintf(stderr, "Read Message Length: %d\n", mess_len);
        (void) codoutrec(stderr, b, IN);
        fflush(stderr);
    }
    return mess_len;
}
/**************************************************************************
 * Output clear text when we encounter it, otherwise decoded CODA stuff.
 */
unsigned char * cod_handle(ofp, p, top, write_flag)
FILE *ofp;
unsigned char *p;
unsigned char *top;
int write_flag;
{
    while ((p = codasc_handle(ofp, p,top,write_flag)) < top) 
        p = asc_handle(ofp, p,top,write_flag);
    fputc((int) '\n', ofp);
    return top;
}
/**************************************************************************
 * Output non-clear text as blocks of characters.
 */
unsigned char * codasc_handle(ofp, p,top,write_flag)
FILE *ofp;
unsigned char *p;
unsigned char *top;
int write_flag;
{
unsigned char tran;
unsigned     char *la;
int i;
    for (la = p; la < top; la++)
    {
        tran = asc_ind(*la);
        if ((tran == (unsigned char) '\t'
             || tran == (unsigned char) '\n'
             || tran ==  (unsigned char) '\r'
             || (tran > (unsigned char) 31 && tran < (unsigned char) 127))
             && ((asc_handle(ofp, la, top, 0) - la) > 3))
            break;
    }
    if (write_flag && (la - p))
    {
        fputc('\'', ofp);
        i = 0;
        while( p < la)
        {
           if ((*p) & 0x80 && *(p+1) == 0)
           {
               fputc((*p) & 0x7f, ofp);
               fputc('.', ofp);
               p += 2;
           }
           else
           if (*p <= 0x40 && *p >= 0x20) 
           {
               fputc((*p) , ofp);
               p++;
           }
           else
           {
               hex_out(ofp, p, p + 1);
               p++;
           }
           i++;
           if (i > 40)
           {
               fputs("'\\\n'", ofp);
               i = 0;
           }
        }
        fputs("'\\\n", ofp);
    }
    return la;
}
/***************************************************************
 * codoutrec() - write out a record
 *
 * The input data is always in binary format. If IN, it is written out
 * out in ASCII; if OUT, it is written out in binary.
 */
int codoutrec(fp, b, in_out)
FILE * fp;
unsigned char * b;
enum direction_id in_out;
{
char * x;
int buf_len;
int i;
int mess_len;

    if (fp == (FILE *) NULL 
      || b == (unsigned char *) NULL)
    {
         (void) fprintf(stderr,
          "Logic Error: codoutrec(%x, %x, %d) called with NULL parameter(s)\n",
                  (unsigned long int) fp,
                  (unsigned long int) b,(unsigned long int) in_out);
        return 0;
    }
    mess_len = b[14]*256 + b[15];
    if (in_out == OUT)
    {
        buf_len = mess_len + 16;
        buf_len = fwrite(b,sizeof(char),buf_len,fp);
        if (coddrive_base.debug_level > 1)
             (void) fprintf(stderr,
                   "Message Length %d Sent with return code: %d\n",
                          mess_len + 16, buf_len);
        if (coddrive_base.debug_level > 2)
            (void) codoutrec(stderr, b, IN);
    }
    else
    {
/*
 * Convert the record from binary
 */
        gen_handle(fp, b, b + 16, 1);
        cod_handle(fp, b + 16, b + mess_len + 16, 1);
        buf_len = 1;
    }
    if (coddrive_base.debug_level > 2)
        (void) fprintf(stderr,"codoutrec() File Descriptor: %d\n",
                       fileno(fp));
    return buf_len;
}

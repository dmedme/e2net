/*
 * ipdrive.h - Structures corresponding to the records
 *             used by the E2 Systems Traffic Generator
 *
 *           - Include a load of pointers, in case we want to use
 *             them for sorting etc.
 * @(#) $Name$ $Id$
 * Copyright (c) E2 Systems, 1995
 *
 ****************************************************************************
 *
 *
 * Any number of incarnations of these programs may be started in a network.
 * They take their instructions from stdin.
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
 * The command stream.
 * ==================
 * - Communication End Point (for waiting, and for knowing who to call)
 *   -  Actor
 *   -  End Point ID
 *   -  Address Family
 *   -  Address
 *   -  Protocol
 *   -  Connexion Oriented?
 *   -  Port number
 * - Send/Receive Message
 *   -  From End Point
 *   -  To End Point
 *   -  Length
 * - Delay
 *   -  Actor
 *   -  Interval (microseconds)
 * - Start timer
 *   -  Actor
 *   -  ID
 *   -  Description
 * - Close
 *   -  From End Point
 *   -  To End Point
 * - Take Time
 *   -  Actor
 *   -  ID
 * - Think Time
 *   -  Actor
 *   -  ID
 *********************************************
 * Useful macros
 */
#ifndef IPDRIVE_H
#define IPDRIVE_H

#ifdef PRODUCT
#define ERROR(fn, ln, ex, fmt, s1, s2) { \
        (void) fprintf(stderr, fmt, s1, s2); \
        (void) fputc('\n', stderr); \
        if (ex) \
                exit(ex); \
}
#else
#define ERROR(fn, ln, ex, fmt, s1, s2) { \
        (void) fprintf(stderr, "\"%s\" Line %d: ", fn, ln); \
        (void) fprintf(stderr, fmt, s1, s2); \
        (void) fputc('\n', stderr); \
        if (ex) \
                exit(ex); \
}
#endif /* !PRODUCT */

#define NEWARRAY(type, ptr, nel) \
        if ((ptr = (type *) calloc((unsigned) nel, sizeof(type))) == (type *) NULL) \
                ERROR(__FILE__, __LINE__, 1, "can't calloc %d bytes", (nel * sizeof(type)), (char *) NULL)

#define RENEW(type, ptr, nel) \
        if ((ptr = (type *) realloc((char *)ptr, (unsigned)(sizeof(type) * (nel)))) == (type *) NULL) \
                ERROR(__FILE__, __LINE__, 1, "can't realloc %d bytes", (nel * sizeof(type)), (char *) NULL)

#define NEW(type, ptr)  NEWARRAY(type, ptr, 1)

#define FREE(s)         (void) free((char *) s)

#define ZAP(type, s)    (FREE(s), s = (type *) NULL)

#ifndef MAX
#define MAX(a, b)       (((a) > (b)) ? (a) : (b))
#endif /* !MAX */

#ifndef MIN
#define MIN(a, b)       (((a) < (b)) ? (a) : (b))
#endif /* !MIN */

#define PREV(i, n)      (((i) - 1) % (n))
#define THIS(i, n)      ((i) % (n))
#define NEXT(i, n)      (((i) + 1) % (n))
/********************************************************************
 * Communications Control Data
 *
 */
#define MAXUSERNAME     32
#define MAXFILENAME     BUFSIZ

#define BUFLEN      2048
#define MAXLINKS 2048
                   /* default number of possible links */
/*
 * Data on Set Up
 */
typedef struct _ipdrive_base {
int actor_id;
char *control_file;
int debug_level;
int verbosity;
int excel_flag;
HASH_CON * nmt;            /* Hash of Traffic Message Names      */ 
HASH_CON * known_con;      /* Look up child sessions to see if we want them */
struct con_con * parent;
char * event_desc;         /* Current Event Description         */
int open_sess_cnt;         /* Used to track when a thread can exit */
} IPDRIVE_BASE;
/*
 *  Session tracking for thread assignment purposes
 */
struct con_con {
    struct con_con * parent;
    int from_end_id;
    int to_end_id;
    int parent_flag;
};
/*
 * Structure used to batch timings data
 */
struct timbuc {
 int buc_cnt;
 double duration[32];
 struct timbuc * next_buc;
};
/*
 * Structure used to collect timing data
 */
struct collcon {
     int glob_cnt;
     double glob_tot;
     double glob_tot2;
     double glob_min;
     double glob_max;
     int cnt;
     double tot;
     double tot2;
     double min;
     double max;
     struct timbuc * first_buc;
};
/*
 * Valid Message Types
 */
#define MAXENDPOINTS 4096
typedef struct link_det {
int link_id;            /* Actually a flag */
struct _end_point * from_ep;
struct _end_point * to_ep;
char allowed_to_call;
int max_simul;
int cur_simul;
char link_up_y_or_n;
char in_out;       /* Direction the connexion was established in */
int connect_fd;
struct sockaddr_in connect_sock;
char desc[132];
struct collcon in_det;
struct collcon out_det;
struct collcon event_det;
FILE * read_connect_file;
FILE * write_connect_file;
} LINK;
/*
 * Values for con_orient
 */
#define ELISTEN "L"
#define ECONNECT "C"
#define EPEER   "P"

/* So that malloc's aren't done all the time */
#define CHUNK           32
enum tok_id {
 SEND_FILE_TYPE,
 SEND_RECEIVE_TYPE,
 START_TIMER_TYPE,
 TAKE_TIME_TYPE,
 END_POINT_TYPE,
 DELAY_TYPE,
 LINK_TYPE,
 SOCK_CLOSE_TYPE,
 THINK_TYPE,
 E2COMMENT,
 E2STR,
 E2EOF
};
struct ipd_rec {
    enum tok_id mess_id;
    char *mess_name;
    char *mess_form;
    struct iocon * mess_io;
    int mess_len;
};
/*********************************************************************
 * Control Record Field Lengths
 *
 */
#define RECORD_TYPE_LEN 2
#define ADDRESS_LEN 32
#define PROTOCOL_LEN 10
#define MESSAGE_LEN_LEN 10
#define CON_ORIENT_LEN 1
#define PORT_ID_LEN 10
#define TIMER_ID_LEN 2
#define TIMER_DESCRIPTION_LEN 80
#define END_POINT_ID_LEN 10
#define MAX_SIMUL_LEN 10
#define DELTA_LEN 15
#define STATUS_LEN 1
#define SEND_FILE_NAME_LEN 106
#define SUCCESS_LEN 1
#define HOST_NAME_LEN 32
#define FTP_USER_ID_LEN 14
#define FTP_PASS_LEN 9
/*********************************************************************
 * Record Definitions
 * - Communication End Point (for waiting, and for knowing who to call)
 *   -  Actor
 *   -  End Point ID
 *   -  Address Family
 *   -  Address
 *   -  Protocol
 *   -  Connexion Oriented?
 *   -  Port number
 * - Send/Receive Message
 *   -  From End Point
 *   -  To End Point
 *   -  Length
 * - Send File
 *   -  Actor
 *   -  Host
 *   -  User
 *   -  Password
 *   -  File Name
 * - Delay
 *   -  Actor
 *   -  Interval (microseconds)
 * - Start timer
 *   -  Actor
 *   -  ID
 *   -  Description
 * - Take Time
 *   -  Actor
 *   -  ID
 *********************************************************************/
#define END_POINT_NAME "EP"
typedef struct _end_point {
char record_type[RECORD_TYPE_LEN+1];
int iactor_id;
int iend_point_id;
int iaddress_family;
char address[ADDRESS_LEN+1];
char protocol[PROTOCOL_LEN+1];
char con_orient[CON_ORIENT_LEN+1];
char port_id[PORT_ID_LEN+1];
} END_POINT;
/*********************************************************************/
#define SEND_RECEIVE_NAME "SR"
typedef struct _send_receive {
char record_type[RECORD_TYPE_LEN+1];
int ifrom_end_point_id;
int ito_end_point_id;
int imessage_len;
} SEND_RECEIVE;
/*********************************************************************/
#define SOCK_CLOSE_NAME "SC"
typedef struct _sock_close {
char record_type[RECORD_TYPE_LEN+1];
int ifrom_end_point_id;
int ito_end_point_id;
} SOCK_CLOSE;
/*********************************************************************/
#define SEND_FILE_NAME "SF"
typedef struct _send_file {
char record_type[RECORD_TYPE_LEN+1];
int iactor_id;
char host_name[HOST_NAME_LEN+1];
char send_file_name[SEND_FILE_NAME_LEN+1];
char dest_ftp_user_id[FTP_USER_ID_LEN+1];
char dest_ftp_pass[FTP_PASS_LEN+1];
} SEND_FILE;
/*********************************************************************/
#define DELAY_NAME "DT"
typedef struct _delay {
char record_type[RECORD_TYPE_LEN+1];
int iactor_id;
double fdelta;
} DELAY;
/*********************************************************************/
#define THINK_NAME "TH"
typedef struct _think {
char record_type[RECORD_TYPE_LEN+1];
int ithink;
} THINK;
/*********************************************************************/
#define START_TIMER_NAME "ST"
typedef struct _start_timer {
char record_type[RECORD_TYPE_LEN+1];
int iactor_id;
char timer_id[TIMER_ID_LEN+1];
char timer_description[TIMER_DESCRIPTION_LEN+1];
} START_TIMER;
/*********************************************************************/
#define TAKE_TIME_NAME "TT"
typedef struct _take_time {
char record_type[RECORD_TYPE_LEN+1];
int iactor_id;
char timer_id[TIMER_ID_LEN+1];
} TAKE_TIME;
/*
 * Definition of a buffer that can take all the incoming records known
 */
union all_records {
END_POINT end_point;
SEND_RECEIVE send_receive;
SOCK_CLOSE sock_close;
SEND_FILE send_file;
DELAY delay;
THINK think;
START_TIMER start_timer;
TAKE_TIME take_time;
};

/*****************************************************************************
 * Prototypes for functions in ipdinrec.c
 */
struct ipd_rec * ipdinrec ANSIARGS((FILE * fp, union all_records * b));
                                              /* routine for reading records */
int ipdoutrec ANSIARGS((FILE * fp, union all_records * b));
                                              /* routine for writing records */
void trail_space_strip ANSIARGS((char * ptr, int len));
                                              /* routine for stripping fields */

IPDRIVE_BASE ipdrive_base;      /* Global configuration information */
#ifdef RAW
void hexvartobin ANSIARGS((struct {short int len; char arr[1];} * hexvar,
                           union all_records *ptr));
void bintohexvar ANSIARGS((union all_records * ptr,
                           struct {short int len; char arr[1];} * hexvar,
                           int len));
#endif
/*
 * Message details
 */
struct mess_rec {
     int in_use;
     int link_seq;
     int from_ep;
     double mess_size;
     double mess_time;
};
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
#endif

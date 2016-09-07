/************************************************************************
 * webdrive.h - Header for webdrive
 *
@(#) $Name$ $Id$
*/
#ifndef WEBDRIVE_H
#define WEBDRIVE_H

#include <sys/types.h>
#ifndef MINGW32
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include <ctype.h>
#include "hashlib.h"
/*****************************************************************
 * The data for processing the statement files
 */
#ifndef PATHSIZE
#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif
#define PATHSIZE MAXPATHLEN
#endif
#define WORKSPACE 1048576

enum look_status {CLEAR, PRESENT, KNOWN};

/******************************************************************
 * Parser data
 */
enum tok_id {
 SEND_FILE_TYPE,
 SEND_RECEIVE_TYPE,
 START_TIMER_TYPE,
 TAKE_TIME_TYPE,
 END_POINT_TYPE,
 DELAY_TYPE,
 LINK_TYPE,
 CLOSE_TYPE,
 E2COMMENT,
 E2BEGIN,
 E2END,
 E2ABEGIN,
 E2AEND,
 E2RESET,
 E2COOKIES,
 E2HEAD,
 E2T3,
 E2STR,
 E2EOF
};
/*
 * Functions that must be defined by the user of codlib.c
 */
void scarper();
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

/************************************************************
 * Macros to get ansi-standard source through various
 * non-ansi compilers
 */
#ifndef ANSI_H
#define ANSI_H

#ifdef __STDC__
#define ANSIARGS(x)     x
#define VOID            void
#endif /* __STDC__ */

#ifdef __ZTC__
#define ANSIARGS(x)     x
#define VOID            void
#endif /* __ZTC__ */

#ifdef __MSC__
#define ANSIARGS(x)     x
#define VOID            void
#endif /* __MSC__ */

#ifndef ANSIARGS
#define ANSIARGS(x)     ()
#define VOID            char
#endif /* !ANSIARGS */
#endif /* !ANSI_H */

/********************************************************************
 * Communications Control Data
 *
 */
#define MAXUSERNAME     32
#define MAXFILENAME     BUFSIZ

#define BUFLEN      2048
#define MAXLINKS 512
                   /* default number of possible links */
/*
 * Data on Set Up
 */
typedef struct _webdrive_base {
char *control_file;
int debug_level;
int verbosity;
struct link_det * cur_link;
int ep_cnt;
int msg_seq;
int sav_seq;
/*
 * Things that will need to be recognised in the input packets and
 * substituted back; may come up with a more general solution in
 * future
 */
long sess_handle1;    /* 8 bytes hexadecimal session handle */
long sess_handle2;
long new_handle;      /* New object handle                  */
int sav_i_vstamp;
int gd_i_vstamp;
int cookie_cnt;
int head_flag;
struct bm_table * ebp;          /* Encrypted Token */
struct bm_table * rbp;          /* Remote Reference Marker */
struct bm_table * sbp;          /* Substitute Remote Reference */
struct bm_table * erp;          /* EJB Exception */
int except_flag;                /* EJB Exception present */
char * encrypted_token;
char * remote_ref;
char * cookies[100];       /* New handles by tag value           */      
} WEBDRIVE_BASE;
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
#define MAXENDPOINTS 512
typedef struct link_det {
enum tok_id link_id;            /* Actually used as a flag */
struct _end_point * from_ep;
struct _end_point * to_ep;
int connect_fd;
struct sockaddr_in connect_sock;
struct collcon in_det;
struct collcon out_det;
int pair_seq;
char * remote_handle;
int t3_flag;  /* Whether this link is talking HTTP or Weblogic T3 */
} LINK;
/* prototypes for library functions */
void    weblog          ANSIARGS((int argc, char **argv));
void webdrive_connect ANSIARGS((LINK * link));
/* So that malloc's aren't done all the time */
#define CHUNK           32
/*********************************************************************
 * Control Record Field Lengths
 *
 */
#define TIMER_ID_LEN 2
#define TIMER_DESCRIPTION_LEN 32
#define SEND_FILE_NAME_LEN 106
#define HOST_NAME_LEN 32
#define ADDRESS_LEN 30
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
typedef struct _end_point {
enum tok_id record_type;
int end_point_id;
char address[ADDRESS_LEN+1];
int cap_port_id;
char host[HOST_NAME_LEN+1];
int port_id;
char con_flag;       /* Whether we listen or connect             */
int ora_forms_flag;  /* Whether this is an ORACLE Web Forms port */
} END_POINT;
/*********************************************************************/
typedef struct _send_receive {
enum tok_id record_type;
int message_len;
union all_records * msg;
int fun;
} SEND_RECEIVE;
/*********************************************************************/
typedef struct _send_file {
enum tok_id record_type;
char send_file_name[SEND_FILE_NAME_LEN+1];
char * msg;
FILE * sfp;
} SEND_FILE;
/*********************************************************************/
typedef struct _delay {
enum tok_id record_type;
double delta;
} DELAY;
/*********************************************************************/
typedef struct _start_timer {
enum tok_id record_type;
char timer_id[TIMER_ID_LEN+1];
char timer_description[TIMER_DESCRIPTION_LEN+1];
} START_TIMER;
/*********************************************************************/
typedef struct _take_time {
enum tok_id record_type;
char timer_id[TIMER_ID_LEN+1];
} TAKE_TIME;
/*
 * Definition of a buffer that can take all the incoming records known
 */
union all_records {
END_POINT end_point;
LINK link;
SEND_RECEIVE send_receive;
SEND_FILE send_file;
DELAY delay;
START_TIMER start_timer;
TAKE_TIME take_time;
char buf[WORKSPACE];
};
WEBDRIVE_BASE webdrive_base;      /* Global configuration information */
#ifdef RAW
void hexvartobin ANSIARGS((struct {short int len; char arr[1];} * hexvar, union all_records *ptr));
void bintohexvar ANSIARGS((union all_records * ptr, struct {short int len; char arr[1];} * hexvar, int len));
#endif
#ifdef IN
#undef IN
#endif
#ifdef OUT
#undef OUT
#endif
enum direction_id {IN, OUT, ORAIN, ORAOUT};
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

#define STRCPY(x,y) {strncpy((x),(y),sizeof(x)-1);*((x)+sizeof(x)-1)='\0';}
int webinrec();
int weboutrec();
enum tok_id webread();
char * forms60_handle();
#endif

/*
 * Whole script management
 *
 * Structure allocated when a session is started that holds session state.
 * @(#) $Name$ $Id$ Copyright (c) E2 Systems 2009
 */
#ifndef SCRIPTTREE_H
#define SCRIPTTREE_H
#ifdef MINGW32
#ifdef LCC
int _debuglevel;
#endif
typedef unsigned int in_addr_t; 
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "w32pthread.h"
#define sleep _sleep
#define SLEEP_FACTOR 1000
#ifdef perror
#undef perror
#endif
#define perror(x) fprintf(stderr,"%s: error: %x\n",x,GetLastError())
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <string.h>
#ifdef PYR
#include <strings.h>
#endif
#endif
#include "submalloc.h"
#include "hashlib.h"
#include "csexe.h"
#ifdef MINGW32
/***********************************************************************
 * For reasons that I have not been bothered to sort out, under some
 * circumstances you cannot include both the windows headers AND e2net.h
 * The stuff here are the things that the files that include scripttree.h
 * need from e2net.h under all circumstances.
 ***********************************************************************
 * Structure for managing remembered packets. Holds a circular buffer of
 * non-descript pointers. Handles wrap by discarding the element encountered.
 * Should not be where it normally is ...
 */
#define E2_TCP 1
#define E2_UDP 2
struct circbuf {
volatile int buf_cnt;
volatile char ** head;
volatile char ** tail;
    char ** base;
    char ** top;
    void (*get_rid)();
};
struct circbuf * circbuf_cre ANSIARGS((int nelems, void (*get_rid)()));
void circbuf_des ANSIARGS((struct circbuf * buf));
int circbuf_add ANSIARGS(( struct circbuf * buf, char* x));
int circbuf_take ANSIARGS((struct circbuf * buf, char ** x));
#include "bmmatch.h"
/************************************************************************
 * Structure for tracking application message fragments
 */
struct frame_con {
/*
 * Session Identifiers - these are counted binary values, and are hashed
 * The hash function produces the same number regardless of the direction
 * of the packet, so we only need to store one hash entry for each session.
 */
int prot;                     /* The protocol - as per the above define    */
unsigned char phys_from[10];  /* Length plus address (eg. Ethernet)        */
unsigned char phys_to[10];    /* Length plus address (eg. Ethernet)        */
unsigned char net_from[10];   /* Length plus address (eg. IP Host)         */
unsigned char net_to[10];     /* Length plus address (eg. IP Host)         */
unsigned char port_from[10];  /* Length plus address (eg. IP port)         */
unsigned char port_to[10];    /* Length plus address (eg. IP port)         */
char label[40];
char * long_label;
int reverse_sense;            /* Flag which is client, which server.       */
/*
 * Remembered packets
 */
struct circbuf * pack_ring;
/*
 * Details of the current packet.
 */
int pack_no;
struct timeval this_time;          /* The current packet time           */
int pack_len;
int tcp_flags;                     /* Avoid stray application sessions  */
/*
 * TCP-specific information.
 */
unsigned int seq[2];              /* TCP protocol handling       */
unsigned int ack[2];              /* TCP protocol handling       */
unsigned short win[2];             /* TCP protocol handling       */
int fin_cnt;                       /* Number of TCP FIN's seen    */
int last_out;                      /* The direction of the last message */
int cnt[2];                        /* Numbers of packets used     */
int len[2];                        /* Network Length of packets seen    */
int retrans[2];                   /* Count of retransmissions          */
struct timeval last_t[2];          /* Last time stamp             */
struct timeval cs_tim[2];          /* Time on client/server       */
struct timeval nt_tim[2];          /* Time on network             */
/*
 * Application protocol details
 */
int last_app_out;                  /* For the last APPLICATION message  */
int fix_size;                      /* Header Fixed Length               */
int fix_mult;                      /* Whether the header counts         */
int off_flag;                      /* Offset to length                  */
int len_len;                       /* Length of length                  */
int big_little;                    /* Big (0)/Little (1) Endian flag    */
char reserve[2][32];               /* In case we haven't read the fixed */
int res_len[2];                    /* length yet                        */
int left[2];                       /* The number of bytes held          */
unsigned char * hold_buf[2];       /* Where the messages are            */
unsigned char * top[2];            /* Pointers to end of messages       */
struct timeval ini_t[2];           /* First time stamp                  */
int gap;                           /* Size of gap for timing purposes   */
struct timeval tran_start;         /* Gap begin time                    */
int tran_cnt[2];                   /* Numbers of packets used           */
int tran_len[2];                   /* Application Length of packets used */
struct timeval tran_cs_tim[2];     /* Used to work out client/server time */
struct timeval tran_nt_tim[2];     /* Used to work out time on network    */
struct timeval up_to;              /* Last time apportioned             */
void (*do_mess)();                 /* Application message function      */
void (*cleanup)();                 /* Application cleanup function      */
FILE * ofp;                        /* Where to dump the output to       */
struct frame_con * prev_frame_con;
struct frame_con * next_frame_con;
char * app_ptr;                    /* Pointer to application-private data */
int event_id;                      /* Current script event, if applicable */
int corrupt_flag;                  /* Flag to prevent spurious response logs */
};
#else
#include "e2net.h"
#endif
#include "hpack.h"
#include "matchlib.h"
#ifdef TDSDRIVE
#include "tds.h"
#endif
#ifdef USE_SSL
#ifdef ANDROID
#define ROOT_CERTS "/data/local/ssl/certs/root.pem"
#else
#define ROOT_CERTS "/etc/ssl/certs/root.pem"
#endif
#include <openssl/ssl.h>
BIO * ssl_bio_error;
#endif
struct script_sess {
    struct script_element * send_tracker;
    struct script_element * recv_tracker;
};
struct script_element {
    unsigned char * head; /* ASCII */
    volatile unsigned char * body; /* Binary */
    int body_len;
    unsigned char * foot; /* ASCII */
    volatile struct script_element * prev_track;
    volatile struct script_element * next_track;
    volatile struct script_element * child_track;
    double timestamp;
    int retry_cnt;
};
struct script_control {
    volatile struct script_element * anchor;
    volatile struct script_element * last;
};
#define MAX_PATTERN_SPECS 10
struct script_element * new_script_element();
void do_e2sync();
#ifndef WORKSPACE
#ifdef TDSDRIVE
#define WORKSPACE 16384
#else
#ifdef T3_DECODE
#define WORKSPACE 1048576
#else
/* #define WORKSPACE 262144 */
/* #define WORKSPACE 131072 */
/* #define WORKSPACE 2097152 */
/* #define WORKSPACE 8388608 */
#define WORKSPACE 65536
#endif
#endif
#endif
#define MAX_GOTOS 6
/******************************************************************
 * Parser data
 */
enum look_status {CLEAR, PRESENT, KNOWN};
enum tok_id {
 START_TIMER_TYPE=100,
 TAKE_TIME_TYPE,
 DELAY_TYPE,
 PAUSE_TYPE,
 QUIESCENT_TYPE,
 E2COMMENT,
 E2SCANSPECS,
 E2LABEL,
 E2GOTO,
 E2INCLUDE,
#ifdef TDSDRIVE
 SQLLINK_TYPE,
 E2M_TDS_RPC,
 E2M_TDS_SQLBATCH,
 E2T_TDS_BIGCHAR,
 E2T_TDS_BIGVARCHAR,
 E2T_TDS_BITN,
 E2T_TDS_DATETIMEN,
 E2T_TDS_FLTN,
 E2T_TDS_INTN,
 E2T_TDS_MONEYN,
#else
 SEND_FILE_TYPE,
 SCAN_SPEC_TYPE,
 SEND_RECEIVE_TYPE,
 END_POINT_TYPE,
 SSL_SPEC_TYPE,
 LINK_TYPE,
 E2BEGIN,
 E2END,
 E2ABEGIN,
 E2AEND,
 E2COOKIES,
 E2PRAGMA,
 E2CONTENT,
 E2COMPRESS,
 E2TRANSFER,
 E2HEAD,
 E2T3,
#endif
 CLOSE_TYPE,
 E2RESET,
 E2STR,
 E2EOS,
 E2EOF
};
#define MAX_NESTING 20
#define ADDRESS_LEN 256
struct script_seg {
FILE * ifp;
long offset;
};
/*
 * Status tracking for our script parser. Split out to make it easier to use
 * the parse routines in single threaded environments.
 */
typedef struct _parser_con {
    char * tbuf;
    int tbuf_len;
    char * tlook;
    int tlook_len;
    char * sav_tlook;
    enum look_status look_status;
    enum look_status last_look;
    enum tok_id last_tok;
    int break_flag;
/*
 * Data used by event recording and input tracking
 */
    struct ptydrive_glob pg;
/*
 * Include file support
 */
    struct script_seg stack_file[MAX_NESTING]; /* Allow nesting 20 deep */
    int next_in;    /* Index to list */
/*
 * Expression evaluation support
 */
    struct csmacro csmacro;         /* Global symbol table */
} PARSER_CON;
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
#ifdef TDSDRIVE
typedef struct link_det {
enum tok_id record_type;
int from_port_id;  /* Outgoing database connection port ID */
struct link_det * cur_link;
TDSSOCKET *tds;
TDSLOGIN *login;
TDSCONTEXT *context;
TDSCONNECTION *connection;
char *mybuf;
int bufsz;
int mess_len;
union all_records * msg;
int fun;
} SQLLINK;
#else
typedef struct link_det {
enum tok_id link_id;            /* Actually used as a flag */
struct _end_point * from_ep;
struct _end_point * to_ep;
long int connect_fd;     /* Must be the same size as a pointer */
struct sockaddr_in connect_sock;
struct collcon in_det;
struct collcon out_det;
int pair_seq;
char * remote_handle;
#ifdef USE_SSL
int ssl_spec_id;
SSL * ssl;
BIO * bio;
#endif
int t3_flag;  /* Is this link talking HTTP, Weblogic T3 or something else? */
struct http2_stream * h2sp;
} LINK;

#endif
#define TIMER_ID_LEN 2
#define TIMER_DESCRIPTION_LEN 64
#define HOST_NAME_LEN 32
#ifndef TDSDRIVE
#define SEND_FILE_NAME_LEN 128
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
char ssl_spec_ref[TIMER_ID_LEN+1];
#ifdef USE_SSL
int ssl_spec_id;
SSL_SESSION * ssl_sess;
#endif
int port_id;
char con_flag;       /* Whether we listen or connect             */
int proto_flag;  /* Whether this is an ORACLE Web Forms port */
/*
 * Add material for HTTP2 management
 */
struct http2_con * h2cp; 
struct _webdrive_base * iwdbp;
struct _webdrive_base * owdbp;
pthread_mutex_t rights;
int thread_cnt;
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
#endif
typedef struct _pattern_spec {
int cnt;
int curr;
struct bm_table * bmp[MAX_PATTERN_SPECS];
struct bm_frag * bfp[MAX_PATTERN_SPECS];
} PATTERN_SPEC;
typedef struct _scan_spec {
enum tok_id record_type;
char scan_key[HOST_NAME_LEN+1];
char c_e_r_o_flag[2];   /*
                         * C for a cookie
                         * E for an exception marker
                         * O the out_marker is updated
                         * U the out_marker is URL-encoded
                         */  
int i_offset;
int i_len;
unsigned char i_cust[9];
PATTERN_SPEC ebp;   /* In-coming markers */
int o_offset;
int o_len;
unsigned char o_cust[9];
PATTERN_SPEC rbp;    /* Out-going markers */
char * encrypted_token;   /* Value to substitute    */
int frozen;          /* 1 - Frozen ; 0 - Thawed */
} SCAN_SPEC;
/*********************************************************************/
typedef struct _delay {
enum tok_id record_type;
double delta;
} DELAY;
#ifdef USE_SSL
typedef struct _ssl_spec {
enum tok_id record_type;
int ssl_spec_id;
char ssl_spec_ref[TIMER_ID_LEN+1];
char key_file[SEND_FILE_NAME_LEN+1];
char passwd[HOST_NAME_LEN+1];
SSL_METHOD * ssl_meth;
SSL_CTX * ssl_ctx;
} SSL_SPEC;
#endif
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
DELAY delay;
START_TIMER start_timer;
TAKE_TIME take_time;
#ifdef TDSDRIVE
SQLLINK link;
#else
END_POINT end_point;
LINK link;
SEND_RECEIVE send_receive;
SEND_FILE send_file;
#ifdef USE_SSL
SSL_SPEC ssl_spec;
#endif
#endif
char buf[WORKSPACE];
};
void update_target();
void do_goto();
struct script_element * load_script();
void dump_script();
struct script_element * add_open();
struct script_element * add_message();
struct script_element * add_think_time();
struct script_element * add_pause();
struct script_element * add_answer();
struct script_element * add_close();
struct script_element * add_ssl_spec();
void close_event();
void proxy_e2sync();
struct script_element * search_back();
struct script_element * search_forw();
void zap_script_element();
void zap_children();
void remove_se_subtree();
void do_ora_forms();
void make_child();
void unhook_script_element();
int check_integrity();
#endif

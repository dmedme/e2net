/*
 *    opldrive.pc - Program to drive and collect timings through a pty device.
 *
 *    Copyright (C) E2 Systems 1993
 *
 *    It loops through the stdin, the pty and standard output.
 *
 *    Timestamps are written when the appropriate events are spotted.
 *
 * Arguments
 * =========
 *   - arg 1 = name of file to output timestamps to
 *   - arg 2 = pid of fdriver
 *   - arg 3 = pid of bundle
 *   - arg 4 = i number within 'rope'
 *   - arg 5 = Connection String
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
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (C) E2 Systems Limited 1993";
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
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
#include <errno.h>
#include "circlib.h"
#include "matchlib.h"
/* #include "natregex.h" */
int in_arr_size;            /* For array processing                */
int ret_arr_size;           /* For array processing                */
/*
 * We only ever execute a statement once, otherwise we would need
 * several of these. We could of course use the OCI, but this may be
 * portable to other systems?
 */
#include "libudbc.h"
#include "opldrive.h"

/**********************************************************************
 * Initialise a dynamic statement control block
 */
struct dyn_con * dyn_init()
{
    struct dyn_con * d;
    if ((d = (struct dyn_con *) malloc(sizeof(*d))) == (struct dyn_con *) NULL)
        return d;

    d->statement = (char *) NULL;
                            /* Text of SQL Statement               */
    d->sb_map = (short int *) NULL;
                            /* Select/Bind Mapping                 */
    d->bd_size = 64;        /* Default number of Bind variables    */
    d->bv_size = 32;        /* Max no of chars in Bind Var name    */
    d->sd_size = 64;        /* Default number of Select variables  */
    d->sv_size = 32;        /* Max no chars in Select List colnames*/
    d->ind_size= 0;         /* Max no chars in indicator variable name.
                               This has been set to zero because it would
                               appear that indicator variable names are
                               illegal in dynamic SQL */
/*
 * Allocate a bind descriptor
 */
    d->bdp = (char *) NULL;
/*
 * Allocate a select list descriptor
 */
    d->sdp = (char *) NULL;

    d->sdt = (short *) NULL;    /* -> arr of original DESCRIBE'd types */
    d->scram_flags = (char *) NULL;
                                /* -> arr of original DESCRIBE'd types */
    d->sdtl = 0;                /* nr of entries in sdt[]              */
    d->sb_map = (short int *) NULL;  /* select/bind map                     */
    d->sv_widths = (short int *) NULL;     /* Widths */
    d->sv_types = (short int *) NULL;      /* Types */
    d->sv_precs = (short int *) NULL;      /* Precisions */
    d->sv_nulls = (short int *) NULL;      /* Nulls */
    d->chars_read = 0;               /* Count of characters read by selects */
    d->chars_sent = 0;               /* Length of SQL Statements            */
    d->rows_read = 0;                /* Count of rows processed             */
    d->rows_sent = 0;                /* Count of rows processed             */
    d->fields_read = 0;              /* Count of fields read                */
    d->fields_sent = 0;              /* Count of fields sent                */
    return d;
}
/************************************************************************
 * Destroy a dynamic statement control block
 */
void dyn_kill(d)
struct dyn_con * d;
{
    if (d->statement != (char *) NULL)
        free(d->statement);          /* Saved select descriptors             */
    if (d->sv_widths != (short *) NULL)
        free(d->sv_widths);         /* Saved select descriptors             */
    if (d->sv_types != (short *) NULL)
        free(d->sv_types);         /* Saved select descriptors             */
    if (d->sv_nulls != (short *) NULL)
        free(d->sv_nulls);         /* Saved select descriptors             */
    if (d->sv_precs != (short *) NULL)
        free(d->sv_precs);         /* Saved select descriptors             */
    if (d->scram_flags != (char *) NULL)
        free(d->scram_flags);    /* Scramble flags for the select stuff  */
    free(d);                     /* Free the structure                   */
    return;
}

/*
 *  Connect to the datasource
 *
 *  The connect string can have the following parts and they refer to
 *  the values in the odbc.ini file
 *
 *    DSN=<data source name>        [mandatory]
 *    HOST=<server host name>        [optional - value of Host]
 *    SVT=<database server type>    [optional - value of ServerType]
 *    DATABASE=<database path>    [optional - value of Database]
 *    OPTIONS=<db specific opts>    [optional - value of Options]
 *    UID=<user name>            [optional - value of LastUser]
 *    PWD=<password>            [optional]
 *    READONLY=<N|Y>            [optional - value of ReadOnly]
 *    FBS=<fetch buffer size>        [optional - value of FetchBufferSize]
 *
 *   Examples:
 *
 *    HOST=star;SVT=Informix 5;UID=demo;PWD=demo;DATABASE=stores5
 *
 *    DSN=stores5_informix;PWD=demo
 */
int
oplconnect (struct dyn_con * d, char *connect_str)
{
  short buflen;
  char buf[257];

  if (SQLAllocEnv (&(d->henv)) != SQL_SUCCESS)
    return 0;

  if (SQLAllocConnect (d->henv, &(d->hdbc)) != SQL_SUCCESS)
    return 0;

  if (SQLDriverConnect (d->hdbc, 0, (UCHAR *) connect_str, SQL_NTS, (UCHAR *) buf,
       sizeof (buf), &buflen, SQL_DRIVER_COMPLETE) != SQL_SUCCESS)
    return 0;

  if (SQLAllocStmt ((d->hdbc), &(d->hstmt)) != SQL_SUCCESS)
    return 0;

  return 1;
}
/*
 *  Disconnect from the database
 */
int
opldisconnect (struct dyn_con *d)
{
    if (d->hstmt)
        SQLFreeStmt (d->hstmt, SQL_DROP);
    SQLDisconnect (d->hdbc);
    if (d->hdbc)
        SQLFreeConnect (d->hdbc);
    if (d->henv)
        SQLFreeEnv (d->henv);
    return 0;
}

/*
 *  This is the message handler for the communications layer.
 *
 *  The messages received here are not passed through SQLError,
 *  because they might occur when no connection is established.
 *
 *  Typically, Rejections from oplrqb are trapped here, and
 *  also RPC errors.
 *
 *  When no message handler is installed, the messages are output to stderr
 */
void
oplinternalerror (char *reason)
{
    fprintf (stderr, "OPENLINK Internal Error: %s\n", reason);
    return;
}
/*
 *  Show all the error information that is available
 */
int
oplerrors (struct dyn_con * d, char *where)
{
    unsigned char buf[250];
    unsigned char sqlstate[15];
    if (d->statement != (char *) NULL)
        (void) fprintf(stderr, "\nCall: %s Statement:\n%s\n",
           where,d->statement);
/*
 *  Get statement errors
 */
    while (SQLError (d->henv, d->hdbc, d->hstmt, sqlstate, NULL,
            buf, sizeof(buf), NULL) == SQL_SUCCESS)
        fprintf (stderr, "SQL Error: %s, SQLSTATE=%s\n", buf, sqlstate);

  /*
   *  Get connection errors
   */
    while (SQLError (d->henv, d->hdbc, SQL_NULL_HSTMT, sqlstate, NULL,
              buf, sizeof(buf), NULL) == SQL_SUCCESS)
        fprintf (stderr, "Connection Error: %s, SQLSTATE=%s\n", buf, sqlstate);
  /*
   *  Get environmental errors
   */
    while (SQLError (d->henv, SQL_NULL_HDBC, SQL_NULL_HSTMT, sqlstate, NULL,
        buf, sizeof(buf), NULL) == SQL_SUCCESS)
        fprintf (stderr, "Environmental Error: %s, SQLSTATE=%s\n",
                 buf, sqlstate);
    return 0;
}

int
exec_sql(struct dyn_con *d)
{
  char fetch_buf[2048];
  short display_width;
  short col_num;
  char col_name[50];
  short col_type;
  UDWORD col_prec;
  SDWORD colIndicator;
  short colScale;
  short colNullable;
  short int fields_this;
  int i;
/*
 *  Prepare & Execute the statement
 */
    if (SQLPrepare (d->hstmt, (UCHAR *) d->statement, SQL_NTS) != SQL_SUCCESS)
    {
        oplerrors (d,"SQLPrepare");
        return;
    }
    if (SQLExecute (d->hstmt) != SQL_SUCCESS)
    {
        oplerrors (d,"SQLExecute");
        return;
    }
    d->chars_sent += strlen(d->statement);
    d->rows_sent++;    /* Actually a count of statements validly executed */
/*
 *  Get the number of result columns for this cursor.
 *  If it is not 0, then the statement was probably a select
 */
    if (SQLNumResultCols (d->hstmt, &(fields_this)) != SQL_SUCCESS)
    {
        oplerrors (d, "SQLNumResultCols");
        goto close_cursor;
    }
    if (fields_this < 0)
        fields_this = 32767;
    if (fields_this == 0)
        goto close_cursor;
    if (d->sv_widths != (short int *) NULL)
         free(d->sv_widths);
    d->sv_widths = (short int *) malloc(fields_this * sizeof(short int));
    if (d->sv_types != (short int *) NULL)
        free(d->sv_types);
    d->sv_types = (short int *) malloc(fields_this * sizeof(short int));
    if (d->sv_precs != (short int *) NULL)
        free(d->sv_precs);
    d->sv_precs = (short int *) malloc(fields_this * sizeof(short int));
    if (d->sv_nulls != (short int *) NULL)
        free(d->sv_nulls);
    d->sv_nulls = (short int *) malloc(fields_this * sizeof(short int));
    if (d->sv_widths != (short int *) NULL)
        free(d->sv_widths);
    d->sv_widths = (short int *) malloc(fields_this * sizeof(short int));
    
    if (fields_this > d->sd_size)
        d->sd_size = fields_this;
/*
 *  Get the details of the columns.
 */
    for (col_num = 1; col_num <= fields_this;  col_num++)
    {
/*
 *  Get the name and other type information
 */
         if (SQLDescribeCol (d->hstmt, col_num, (UCHAR *) col_name,
                 sizeof (col_name), NULL, &col_type, &col_prec,
             &colScale, &colNullable) != SQL_SUCCESS)
         {
              oplerrors (d, "SQLDescribeCol");
              fields_this = col_num -1;
              break;
         }
/*
 *  Calculate the display width for the column
 */
        switch (col_type)
        {
        case SQL_VARCHAR:
        case SQL_CHAR:
            display_width = (short) col_prec;
            break;
        case SQL_BIT:
            display_width = 1;
            break;
        case SQL_TINYINT:
        case SQL_SMALLINT:
        case SQL_INTEGER:
            display_width = col_prec + 1;    /* sign */
            break;
        case SQL_DOUBLE:
        case SQL_DECIMAL:
        case SQL_NUMERIC:
        case SQL_FLOAT:
            display_width = col_prec + 2;  /* sign, comma */
            break;
        default:
            d->sv_widths[col_num-1] = 20;    /* skip other data types */
            break;
        }
        d->sv_widths[col_num-1] = display_width; 
    }
/*
 *  Read all the fields
 */
    for(;;)
    {
    int sts = SQLFetch (d->hstmt);

        if (sts == SQL_NO_DATA_FOUND)
            break;

        if (sts != SQL_SUCCESS)
        {
            oplerrors (d, "Fetch");
            break;
        }
        for (col_num = 1; col_num <= fields_this; col_num++)
        {
/*
 *  Fetch this column as character
 */
            if (SQLGetData (d->hstmt, col_num, SQL_CHAR, fetch_buf,
                  sizeof (fetch_buf), &colIndicator) != SQL_SUCCESS)
            {
                oplerrors (d, "SQLGetData");
                goto close_cursor;
            }
/*
 *  Show NULL fields as ****
 *         (colIndicator == SQL_NULL_DATA)
 */
            d->chars_read += strlen(fetch_buf);
        }
        d->rows_read++;
        d->fields_read += fields_this;
    }
close_cursor:
    SQLFreeStmt (d->hstmt, SQL_CLOSE);
    return 1;
}

struct dyn_con * opldrive_init();
enum tok_id opldrive_process();
void opldrive_quit();
/*****************************************************************
 * The data for processing the statement files
 */
char * tbuf;
char * tlook;
enum tok_id look_tok;
enum look_status look_status;
/************************************************************************
 * Dummies; opldrive doesn't use this functionality
 */
int char_long = 80;
int scram_cnt = 0;                /* Count of to-be-scrambled strings */
char * scram_cand[1];             /* Candidate scramble patterns */
char * scramble( to_scram, scram_len)
char * to_scram;
int scram_len;
{
    return to_scram;
}
/*****************************************************************************
 * Handle unexpected errors
 */
extern int errno;
void scarper(file_name,line,message)
char * file_name;
int line;
char * message;
{
    (void) fprintf(stderr,"Unexpected Error %s,line %d\n",
                   file_name,line);
    perror(message);
    (void) fprintf(stderr,"UNIX Error Code %d\n", errno);
    return;
}

/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
extern int errno;
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
    opldrive_quit();
    exit(1);
}
/***********************************************************************
 * Main program starts here
 */
int main (argc,argv)
    int argc;
    char* argv[];
{
    char * ttn;         /* Terminal to use for User Dialogue */
    short int bufleft;
    char * read_ptr;
    char * start_event;
    enum tok_id tok_id;
    struct timeval long_stop;
    char * force_time;
    char * term;
    int read_count;
    int ch;
    char c;
    int no_cache_flag = 0;
    char * com_ex;
/*
 * Set up the hash table for events
 */
    pg.poss_events = hash(MAX_EVENT,long_hh,icomp);
/*
 * Allocate the circular buffers
 */
    for (ch = 0; ch < BUF_CNT; ch++)
        pg.circ_buf[ch] = (struct circ_buf *) NULL;

/****************************************************
 *    Initialise
 */
    pg.curr_event = (struct event_con *) NULL;
    pg.abort_event = (struct event_con *) NULL;
    com_ex = (char *) 0;
    pg.see_through=0;
    pg.esc_comm_flag=0;
    pg.log_output = stdout;
    start_event = (char *) NULL;
    pg.frag_size = 65536;
    pg.cur_in_file = stdin;
    pg.seqX = 0;                              /* timestamp sequencer */
    while ( ( ch = getopt ( argc, argv, "hn" ) ) != EOF )
    {
        switch ( ch )
        {
                case 'n' :
                    no_cache_flag = 1;
                    break;
                case 'h' :
                    (void) printf("opldrive: Openlink SQL Script Driver\n\
  You can specify:\n\
  -n to switch off session cursor caching\n\
  -h to get this message.\n\
  Arguments are:\n\
  1 - output log file name\n\
  2 - run id (pid)\n\
  3 - rope (bundle)\n\
  4 - thread (g)\n\
  5 - Openlink Database Connect String (eg. DSN=;UID=PIMS;PWD=PIMS)\n\
\n");
                    exit(0);
                default:
                case '?' : /* Default - invalid opt.*/
                       (void) fprintf(stderr,"Invalid argument; try -h\n");
                       exit(1);
                    break;
        }
    }
    if ((argc -optind) < 5)
    {
        fprintf(stderr,"Insufficient Arguments Supplied\n");
        fprintf(stderr,"Arguments (all compulsory) must be\n\
   - arg 1 = name of file to output timestamps to\n\
   - arg 2 = pid of fdriver\n\
   - arg 3 = pid of bundle\n\
   - arg 4 = i number within 'rope'\n\
   - arg 5 = Connection String, made up of the following elements\n\
        DSN=<data source name>     [mandatory; null value selects default]\n\
        HOST=<server host name>    [optional - value of Host]\n\
        SVT=<database server type> [optional - value of ServerType]\n\
        DATABASE=<database path>   [optional - value of Database]\n\
        OPTIONS=<db specific opts> [optional - value of Options]\n\
        UID=<user name>            [optional - value of LastUser]\n\
        PWD=<password>             [optional]\n\
        READONLY=<N|Y>             [optional - value of ReadOnly]\n\
        FBS=<fetch buffer size>    [optional - value of FetchBufferSize]\n");
        exit(1);
    } 
    pg.logfile=argv[optind];
    pg.fdriver_seq=argv[optind+1];  /* Details needed by event   */
    pg.bundle_seq=argv[optind+2];   /* recording                 */
    pg.rope_seq=argv[optind+3]; 

    event_record("S", (struct event_con *) NULL); /* announce the start */
    if (opldrive_init(argv[optind+4]) == (struct dyn_con *) NULL)
        exit(1);
    (void) sigset(SIGINT,SIG_IGN);
#ifdef AIX
#ifdef SIGDANGER
    (void) sigset(SIGDANGER,SIG_IGN);
#endif
#endif
    (void) sigset(SIGTERM,siggoaway);
                            /* Initialise the termination signal catcher */
#ifndef V32
     (void) sigset(SIGTTOU,SIG_IGN);
                             /* Ignore silly stops */
     (void) sigset(SIGTTIN,SIG_IGN);
                             /* Ignore silly stops */
     (void) sigset(SIGTSTP,SIG_IGN);
                             /* Ignore silly stops */
#endif
     (void) sigset(SIGHUP,siggoaway);
                             /* Treat hangups as instructions to go away */
     (void) sigset(SIGALRM,SIG_IGN);

/*******************************************************************
 * Variables used to control main loop processing
 */
    pg.think_time = PATH_THINK;           /* default think time */
    long_stop.tv_sec = PATH_TIMEOUT;      /* give up after 20 minutes */
    long_stop.tv_usec = 0;   /* give up after 20 minutes */
    saved_time = timestamp();
/*******************************************************************
 *  Main Loop;
 *  - feed information from stdin to ORACLE
 *
 *  Terminate when signal arrives (termination request SIGTERM or child death)
 *
 * Get the data types and lengths needed for the data to be processed
 * Cannot do this; interesting. 
    get_cols(dyn,tab);
 */
/*
 * Process the file of statements and data with a simple parser
 */
    tbuf = malloc(WORKSPACE);
    tlook = malloc(WORKSPACE);
    look_status = CLEAR;
    dyn->statement = (char *) NULL;
    if (no_cache_flag)
    {
        tok_id = SQL;
        strcpy(tbuf,"ALTER SESSION SET CLOSE_CACHED_OPEN_CURSORS=TRUE\n");
    }
    else
        tok_id = get_tok(stdin);
    while (tok_id != PEOF)
    {
        switch(tok_id)
        {
        case SQL:
            tok_id = opldrive_process(dyn);
            break;
        default:
            scarper(__FILE__, __LINE__,  "Syntax error in input stream");
            printf("TOKEN: %d   Value: %s\n",tok_id,tbuf);
            tok_id = get_tok(stdin);
        }
    }
    if (dyn->statement != (char *) NULL)
    {
        free(dyn->statement);
        dyn->statement = (char *) NULL;
    }
    free(tbuf);
    free(tlook);
    (void) fflush(stderr);
    (void) fflush(stdout);
    event_record("F", (struct event_con *) NULL);
    opldrive_quit();
    _exit(0);                                 /* scarper */
}    /* End of Main program */
/***********************************************************************
 * Main Program Starts Here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
struct dyn_con * opldrive_init(arg1)
char      *arg1;
{
    in_arr_size = 10;           /* For array processing                */
    ret_arr_size = 10;          /* For array processing                */
/*
 *  Install our own message handler
 */
     _UDBC_SetMessageHandler (oplinternalerror);

    if ((dyn = dyn_init()) == (struct dyn_con *) NULL)
        scarper(__FILE__,__LINE__,"Control Structure Allocation Failed");
    else
    if (!oplconnect(dyn, arg1))
    {
        oplerrors(dyn, "Sign-on Failed");
        return (struct dyn_con *) NULL; 
    }
    else
        return dyn;
}
/*
 * Process a statement
 */
enum tok_id opldrive_process(dyn)
struct dyn_con *dyn;
{
    enum tok_id tok_id;
    long t;
    char *x;
    int i;
    short int y;
    if (dyn->statement != (char *) NULL)
        free(dyn->statement);
    dyn->statement = malloc(strlen(tbuf) +1);
    strcpy(dyn->statement,tbuf);
#ifdef DEBUG
    t = time(0);
    printf("%s\n%s\n",ctime(&t),dyn->statement);
#endif
    exec_sql(dyn);
    return get_tok(stdin);
}
/************************************************************************
 * Closedown
 */
void opldrive_quit()
{
    dyn_kill(dyn);
    opldisconnect(dyn);
    return;
}
/**********************************************************************
 * Handle premature EOF
 */
enum tok_id prem_eof(cur_pos, cur_tok)
char * cur_pos;
enum tok_id cur_tok;
{            /* Allow the last string to be unterminated */
    *tlook = '\0';
    *cur_pos = '\0';
    look_status = PRESENT;
    switch (cur_tok)
    {
    case FIELD:
        look_tok = EOR; 
        break;
    case SQL:
    case EOR:
        look_tok = PEOF;
        break;
    }
    return cur_tok;
}
void sort_out(struct dyn_con * d)
{
    SQLTransact(d->henv, d->hdbc,SQL_COMMIT);
    return;
}
/**********************************************************************
 * Set up to log the traffic statistics with the events
 */
static struct word_con * traff_log()
{
register char *x;
register short int * y;
static char buf[BUFLEN];
static short int ibuf[BUFLEN];
static struct word_con w;
w.words = &ibuf[0];
w.tail = &ibuf[0];
w.head = &ibuf[0];
    sprintf(&buf[0],"%d:%d:%d:%d:%d:%d",
             dyn->chars_read,     /* Count of characters read by selects */
             dyn->chars_sent,     /* Length of SQL Statements   */
             dyn->rows_read,      /* Count of rows processed    */
             dyn->rows_sent,      /* Count of rows processed    */
             dyn->fields_read,    /* Count of fields read       */
             dyn->fields_sent);    /* Count of fields sent      */
    for (x = &buf[0], y = &ibuf[0]; *x != (char) 0; *y++ = (short int) *x++); 
    *y = 0;
    w.state = y;
    w.head = y;
    dyn->chars_read = 0;
    dyn->chars_sent = 0;
    dyn->rows_read = 0;
    dyn->rows_sent = 0;
    dyn->fields_read = 0;
    dyn->fields_sent = 0;
    return &w;
} 
/**********************************************************************
 * Read the next token
 */
enum tok_id get_tok(fp)
FILE * fp;
{
    int p;
    char * cur_pos;
/*
 * If look-ahead present, return it
 *
 * This code also processes PATH timing commands.
 * These are not returned, but are edited out, like comments.
 */
restart:
    if (look_status == PRESENT)
    {
        strcpy(tbuf,tlook);
        look_status = CLEAR;
        return look_tok;
    }
    else
        cur_pos = tbuf; 
    while ((p = getc(fp)) == (int) '\n'); /* skip any blank lines */
/*
 * Scarper if all done
 */
    if ( p == EOF )
        return PEOF;
/*
 * Pick up the next token, stripping off the wrapper for fields.
 */
    else
    if (p == (int) '\'')
    {      /* This is a FIELD; search for the end of the string
            * Strings are returned unstuffed, and without wrapping quotes
            */
        for(;;)
        {
            p = getc(fp);
            if (p == EOF)
                return (prem_eof(cur_pos,FIELD));
            else
            if (p == (int) '\'')
            {            /* Have we come to the end? */
                 int pn;
                 pn = getc(fp);
                 if (pn != (int) '\'')
                 {   /* End of String */
                    *cur_pos = '\0';
                    if (pn != (int) ',')
                    {    /* End of record */
                        *tlook = '\0';
                        look_status = PRESENT;
                        look_tok = EOR; 
                    }
                    return FIELD;
                }
            }
            *cur_pos++ = (char) p;
        }
    }
    else
    if (p == (int) '\\')
    {        /* Command string; start timing, end timing or delay */
         *(cur_pos++) = (signed char) getc(stdin);
         if (*cur_pos == (signed char) EOF)
             return PEOF; /*ignore empty non-terminated command*/
         if (*cur_pos == '\\')
             goto restart;      /* ignore empty command */
         for (*cur_pos = (signed char) getc(stdin);
                  *cur_pos != (signed char) EOF;
                       cur_pos++,
                       *cur_pos = (signed char) getc(stdin))
                              /* advance to end of string,
                               * treating '\\' as an escape character
                               * storing it in cur_pos_buf
                               */
              if (*cur_pos == (int) '\\')
              {
                  *cur_pos = (signed char) getc(stdin);
                  if (*cur_pos != (int) '\\')
                  {
                     (void) ungetc(*cur_pos,stdin);
                                   /* pop back this character */
                     break;        /* got the lot */
                  }
                  /* otherwise, we have stripped an escape character */
              }   
         *cur_pos = '\0';        /* terminate the string */
         cur_pos = tbuf;
         if (*cur_pos == 'S')
         {                 /* Start a timestamp */
             HIPT * h;
             short int event_id;
             short int j,k,l;
             short int x;
             l=0;
             cur_pos++;
             stamp_declare(cur_pos);
             x = (((int) (*cur_pos)) << 8) + ((int) *(cur_pos+1));
             if ((h = lookup(pg.poss_events,(char *) x)) == (HIPT *) NULL)
             {
             (void) fprintf(stderr,"Error, event define failed for %s\n",
                               cur_pos);
                goto restart;       /* Crash out here */
             }
             pg.curr_event = (struct event_con *) (h->body);
             pg.curr_event->time_int = timestamp();
             dyn->chars_read = 0;     /* Count of characters read by selects */
             dyn->chars_sent = 0;     /* Length of SQL Statements            */
             dyn->rows_read = 0;      /* Count of rows processed             */
             dyn->rows_sent = 0;      /* Count of rows processed             */
             dyn->fields_read = 0;    /* Count of fields read                */
             dyn->fields_sent = 0;    /* Count of fields sent                */
         }
         else
         if (*cur_pos == 'T')
         {                 /* Take a timestamp */
             HIPT * h;
             short int event_id;
             short int j,k,l;
             short int x;
             l=0;
             sort_out(dyn);
             cur_pos++;
             cur_pos = nextfield(cur_pos,':');
             x = (short int) (((int) (*cur_pos)) << 8) + ((int) *(cur_pos+1));
             if ((h = lookup(pg.poss_events, ((char *) (x)))) ==
                   (HIPT *) NULL)
             {
                (void) fprintf(stderr,"Error, undefined event %*.*s\n",
                               sizeof(event_id),sizeof(event_id),
                               (char *) &event_id);
                goto restart;       /* Crash out here */
             }
             pg.curr_event = (struct event_con *) (h->body);
             if (pg.curr_event  != (struct event_con *) NULL)
             {
                 int think_left;
                               /* record the time */
                 pg.curr_event->word_found = traff_log(); 
                 pg.force_flag = FORCE_DUE;  /* Switch on statistics logging */
                 event_record(pg.curr_event->event_id, pg.curr_event);
                 pg.force_flag = 0;    /* Switch it off again */
                 think_left = (int) (pg.curr_event->min_delay
                             - pg.curr_event->time_int/100.0);
                 if (think_left > 0)
                 {                       /* sleep time in progress */
                     sleep(think_left);
                 }
                 pg.curr_event = (struct event_con *) NULL;
             }
             goto restart;
         }
         else if  (*cur_pos == 'W')
         {                /* Sleep for some number of seconds */
             int thinks;
             cur_pos++;
             thinks = atoi(cur_pos);
             if (thinks > 0)
                 sleep(thinks);
             pg.think_time = thinks;
         }
         goto restart;       /* unrecognised command */
    }
    else   /* an SQL statement */
    {      /* Search for \n/\n */
        enum match_state { NOTHING, NEW_LINE, SLASH };
        enum match_state match_state;
        match_state = NEW_LINE;
        for(;;)
        {
            if (p == EOF)
                return (prem_eof(cur_pos,SQL));
            switch (match_state)
            {
            case NOTHING:
                if (p == (int) '\n')
                    match_state = NEW_LINE;
                else
                    *cur_pos++ = (char) p;
                break;
            case NEW_LINE:
                if (p == (int) '/')
                    match_state = SLASH;
                else
                {
                    *cur_pos++ = (char) '\n';
                    if (p != (int) '\n')
                    {
                        match_state = NOTHING;
                        *cur_pos++ = (char) p;
                    }
                }
                break;
            case SLASH:
                if (p == (int) '\n')
                {
                    *cur_pos = '\0';
                    return SQL;
                }
                else
                {
                    match_state = NOTHING;
                    *cur_pos++ = (char) '\n';
                    *cur_pos++ = (char) '/';
                    *cur_pos++ = (char) p;
                }
                break;
            }
            p = getc(fp);
        }
    }
}
/**************************************************************************
 * Dummy functions to ensure that only timestamp.o is pulled in from the
 * pathatlib.a library
 */
void match_out (curr_word)
struct word_con * curr_word;
{
    int_out(curr_word->words);
    return;
}
short int * match_comp()
{
    return (short int *) NULL;
}

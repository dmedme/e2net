/*
 *    coddump.c - Program to check a coda script
 *
 *    Copyright (C) E2 Systems 1993
 *
 * Arguments
 * =========
 *   - arg 1 = Input command file
 *
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (C) E2 Systems Limited 1995";
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include "hashlib.h"
#include "e2net.h"
#include "circlib.h"
#include "matchlib.h"
#include "coddrive.h"

extern int errno;
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
void do_things();       /* process requests whilst things are still alive */
void proc_args();       /* process arguments */

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
    exit(0);
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
    coddrive_base.verbosity = 1;
    coddrive_base.debug_level = 4;
    coddrive_base.msg_seq = 1;                /* request sequencer         */
    pg.seqX = 0;                              /* timestamp sequencer       */
    while ( ( c = getopt ( argc, argv, "h" ) ) != EOF )
    {
        switch ( c )
        {
        case 'h' :
            (void) fprintf(stderr,"coddump: E2 Systems CODA Script Checker\n\
Options:\n\
 -h prints this message on stderr\n\
Arguments: Input File\n");
            fflush(stderr);
            break;
        case '?' : /* Default - invalid opt.*/
            (void) fprintf(stderr,"Invalid argument; try -h\n");
            exit(1);
        } 
    }
    if ((argc - optind) < 1)
    {
        fprintf(stderr,"Insufficient Arguments Supplied; try -h\n");
        exit(1);
    } 
    coddrive_base.control_file = argv[optind++];
    if ((pg.cur_in_file = fopen(coddrive_base.control_file,"r"))
                 == (FILE *) NULL)
    {
        unexpected(__FILE__, __LINE__,"Failed to open control file");
        exit(1);
    }
    if (coddrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,"proc_args()\n");
        (void) fflush(stderr);
        codlog(argc,argv);
    }
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
 * Ready a timestamp for use.
 */
struct event_con * stamp_frig(parm)
signed char * parm;
{
HIPT * h;
int x;
struct event_con * slot;

    if (parm == (char *) NULL)
        return (struct event_con *) NULL;       /* cannot define nothing */
    fputs( "Declaring Timestamp ", stderr);
    fputs( parm, stderr);
    fputc( '\n', stderr);
    fflush(stderr);
    parm = nextfield(parm,':');
    if (parm == (char *) NULL)
    {
        fputs( "Timestamp identification Failed ", stderr);
        fputs( parm, stderr);
        fflush(stderr);
        return (struct event_con *) NULL;       /* cannot define nothing */
    }
    if (!strcmp(parm,"F") || !strcmp(parm,"S")  ||
        strcmp(parm, "A") <= 0|| strcmp(parm, "Z") >=0
        || (int) strlen(parm) > 2)
    {
        (void) fprintf(stderr,"Event %-2.2s is reserved or illegal\n",
                               parm);
        return (struct event_con *) NULL;       /* cannot define these */
    }
    x = (((int) (*parm)) << 8) + ((int) *(parm+1));
    h = lookup(pg.poss_events,(char *) (x));
    if (h != (HIPT *) NULL)
    {
        if ( (struct event_con *) h->body == pg.curr_event)
        {
            (void) fprintf(stderr,"Event %-2.2s is current; cannot change\n",
                               parm);
            return (struct event_con *) NULL;       /* cannot define these */
        }
        else
            event_con_destroy((struct event_con *) h->body);
           /* clear up the existing item */
    }
    else
    {
        h = insert(pg.poss_events,(char *)(x),(char *) NULL);
        if (h == (HIPT *) NULL)
        {
            (void) fprintf(stderr,"Hash Insert Failure\n");
            return (struct event_con *) NULL;
        }
    }
    slot = stamp_read(parm);
    return slot;
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
    stamp_frig(cur_pos);
    x = (short int) (((int) (*cur_pos)) << 8) + ((int) *(cur_pos+1));
    if ((h = lookup(pg.poss_events, (char *) x)) == (HIPT *) NULL)
    {
        (void) fprintf(stderr,"Error, event define failed for %s\n",
                       cur_pos);
        return;       /* Crash out here */
    }
    pg.curr_event = (struct event_con *) (h->body);
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
    return;
}
/*
 * Use select() to give a high resolution timer
 */
void do_delay(a)
union all_records *a;
{
struct timeval nap_time;
#ifdef OSF
#ifndef AIX
    int dummy = 1;
#endif
#endif
    if (coddrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_delay(%f)\n", a->delay.delta);
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

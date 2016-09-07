/*
 * Scan a snoop file and pull out .NET remote elements.
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
static void do_dotnet();
static void dotnet_prelim();
static void dotnet_header();
static void dotnet_body();
static void do_traffic();
static void do_log();
static FILE * ofp;
static int both_ways;
static int verbose;
static unsigned char * dotnet_property();
static unsigned char * outstr();
unsigned char * dotnet_handle();
enum dotnet_state { E2_PRELIM, E2_HEADER, E2_BODY };
/*
 * Structure allocated when a session is started that holds session state.
 */
struct dotnet_rem_sess {
    int len[2];
    unsigned char * kept_msg[2];
    enum dotnet_state dotnet_state[2];
    int plain_flag;
    int to_go[2];
};
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */
static int match_cnt;            /* Number of ports in the list    */
static int dotnet_rem_port[100];    /* List of ports to match against          */
static int dotnet_rem_cnt;          /* Number of ports in the list    */
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
    if ((x = getenv("E2_DOTNET_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
            {
                web_match_add(match_port, &match_cnt, i);
                web_match_add(dotnet_rem_port, &dotnet_rem_cnt, i);
            }
        }
    }
    if ((x = getenv("E2_BOTH")) != (char *) NULL)
        both_ways = 1;
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
int dotnet_app_recognise(frp)
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
        if (!(frp->tcp_flags & TH_SYN))
            return 0;
        memcpy((char *) &to, &(frp->port_to[1]), 2);
        memcpy((char *) &from, &(frp->port_from[1]), 2);
        i = web_match_true(match_port, match_cnt, from, to);
        if (i)
        {
            if (ofp == (FILE *) NULL)
                ofp = fopen("dotnet_script.msg", "wb");
            frp->ofp = ofp;
            if (frp->ofp == (FILE *) NULL)
            {
                perror("dotnet_script.msg fopen() failed");
                frp->ofp = stdout;   /* Out of file descriptors */
            }
            fputs( "\\M:", ofp);
            ip_dir_print(ofp, frp, 0);
            fputs( "\\\n", ofp);
            if (i == -1)
                frp->reverse_sense = 1;
            frp->do_mess = do_traffic;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (unsigned char *) malloc(sizeof(struct
                                   dotnet_rem_sess));
            ((struct dotnet_rem_sess *)(frp->app_ptr))->len[0] = 0;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->len[1] = 0;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->to_go[0] = 0;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->to_go[1] = 0;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->dotnet_state[0] = E2_PRELIM;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->dotnet_state[1] = E2_PRELIM;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->kept_msg[0] =
                        (unsigned char *) NULL;
            ((struct dotnet_rem_sess *)(frp->app_ptr))->kept_msg[1] =
                            (unsigned char *) NULL;
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
                ofp = fopen("dotnet_script.msg", "wb");
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
 * Adjust the buffer being used for to-be-processed message fragments
 */
static void adjust_buf(frp, dir_flag, x)
struct frame_con * frp;
int dir_flag;
unsigned char * x;
{
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

    if (ap->len[dir_flag])
    {
        ap->len[dir_flag] -=
               (x - ap->kept_msg[dir_flag]);
        if (ap->len[dir_flag] == 0)
        {
            free( ap->kept_msg[dir_flag] );
            ap->kept_msg[dir_flag]  = (unsigned char *) NULL;
            return;
        }
        memmove(ap->kept_msg[dir_flag], x, ap->len[dir_flag]);
        ap->kept_msg[dir_flag] = (unsigned char *)
                      realloc(ap->kept_msg[dir_flag],
                              ap->len[dir_flag]);
    }
    else
    {
        ap->len[dir_flag] = (frp->top[dir_flag] - x);

        ap->kept_msg[dir_flag] = (unsigned char *)
                      malloc( ap->len[dir_flag]);
        memcpy(ap->kept_msg[dir_flag], x, ap->len[dir_flag]);
        frp->top[dir_flag] = frp->hold_buf[dir_flag];
    }
    return;
}
static void reset_kept(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

    ap->dotnet_state[dir_flag] = E2_PRELIM;
    if ( ap->kept_msg[dir_flag] != NULL)
    {
         free(ap->kept_msg[dir_flag]);
         ap->kept_msg[dir_flag] = NULL;
         ap->to_go[dir_flag] = 0;
         ap->len[dir_flag] = 0;
    }
    return;
}
/*
 * Function that is called to process messages
 */
static void do_traffic(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

    cur_frame = frp;
    do_dotnet(frp, dir_flag);
    fflush(frp->ofp);
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
 * Dump out a human-readable rendition of the .NET messages
 * - Messages consist of:
 *   - A header (.NET \1 \0)
 *   - A header tag (0x0000 = request, 0x0100 = one way, 0x0200 = response)
 *   - Two bytes 0x0000
 *   - The data length (excluding headers; 4 bytes little-endian)
 *   - The headers:
 *     -  A collection of 'transport keys' and strings.
 *        The keys may be:
 *        -  URI transport key (0x04000101)
 *        -  Content-type transport key (0x06000101)
 *        -  Default transport key (0x010001)
 *        Strings are preceded by a 4 byte big-endian length
 *        The headers are terminated by 0x0000
 *   - The data.
 *
 * Function that is called to process .NET messages
 */
static void do_dotnet(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

    cur_frame = frp;
    if (ap->dotnet_state[dir_flag] == E2_PRELIM)
        dotnet_prelim(frp, dir_flag);
    else
    if (ap->dotnet_state[dir_flag] == E2_HEADER)
        dotnet_header(frp, dir_flag);
    else
        dotnet_body(frp, dir_flag);
    return;
}
/*
 * Process .NET headers
 */
static void dotnet_header(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * x;
unsigned char * x1;
unsigned char * x2;
unsigned char * top;
int out_flag;
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

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
        frp->top[dir_flag] = frp->hold_buf[dir_flag];
    }
    else
    {
        x = frp->hold_buf[dir_flag];
        top = frp->top[dir_flag];
    }
    x1 = x;
    out_flag = (((!dir_flag) ^ frp->reverse_sense) || both_ways) ? 1 : 0;
    for (;;)
    {
/*
 * Process all the whole strings
 * -   x tracks the data that is processed.
 * -   x1 tracks the beginnings of lines
 * -   x2 tracks the ends of header strings
 */
        if (x1 >= top - 1)
            goto reserve;
/*
 * End of Headers
 */
        if (*x1 == '\0' && *(x1 + 1) == '\0')
        {
/*
 * We have added these two to the body, so we do not skip over them
 */
            adjust_buf(frp, dir_flag, x1);
            ap->dotnet_state[dir_flag] = E2_BODY;
            dotnet_body(frp, dir_flag);
            return;
        }
        if (x1 >= top - 8)
            goto reserve;
/*
 * Ordinary string
 */
        if (*x1 == 1 && *(x1 + 1) == 0 && *(x1 + 2) == 1)
        {
            x2 = x1 + 7 + *(x1 + 3) +
               (*(x1 + 4) << 8) +
               (*(x1 + 5) << 16) +
               (*(x1 + 6) << 24);
    
            if (x2 >= top)
                goto reserve;
            (void) gen_handle_nolf(frp->ofp, x1, x2, out_flag);
        }
        else
/*
 * URI or Content type
 */
        if ((*x1 == 4 || *x1 == 6)
          && *(x1 + 1) == 0 && *(x1 + 2) == 1 && *(x1 + 3) == 1)
        {
            x2 = x1 + 8 + *(x1 + 4) +
               (*(x1 + 5) << 8) +
               (*(x1 + 6) << 16) +
               (*(x1 + 7) << 24);
            if (x2 >= top)
                goto reserve;
            (void) gen_handle_nolf(frp->ofp, x1, x2, out_flag);
        }
        else
        {
            fputs("\n*** Header Parse Failed ***\n", frp->ofp);
            (void) gen_handle(frp->ofp, x1, top, 1);
            reset_kept(frp, dir_flag);
            return;
        }
/*
 * Advance to the next line
 */
        x1 = x2;
    }
reserve:
    adjust_buf(frp, dir_flag, x1);
    return;
}
static unsigned int get_int_little_endian(p)
unsigned char * p;
{
    return (unsigned int) (*p + (*(p + 1) << 8) +(*(p + 2) << 16) + (*(p+3) << 24));
}
static unsigned int get_var_int_little_endian(pp)
unsigned char ** pp;
{
unsigned int ret;
int i;
unsigned char * p = *p;

    for(ret = 0, i = 0;;i += 8, p++)
    {
        ret += ((*p) << i);
        if (!(*p) & 0x80)
            break;
    }
    *pp = p;
    return ret;
}
/*
 * Decode .net binary data - just documentation at present
 */
void dotnet_decode(ofp, base, top, out_flag)
FILE * ofp;
unsigned char * base;
unsigned char * top;
int out_flag;
{
unsigned char * x = base;

    if (top - base < 17
    || *x++ != 0
    || *x++ != 1
    || *x++ != 0
    || *x++ != 0
    || *x++ != 0
    || *x++ != 255
    || *x++ != 255
    || *x++ != 255
    || *x++ != 255
    || *x++ != 1
    || *x++ != 0
    || *x++ != 0
    || *x++ != 0
    || *x++ != 0
    || *x++ != 0
    || *x++ != 0
    || *x++ != 0)
    {
        gen_handle(ofp, base, top, out_flag);
        return;
    }
    if (out_flag)
    {
        fputs("Binary Header: ", ofp);
        gen_handle(ofp, base, x, out_flag);
    }
/*
 * The layout is esentially type/name/value triplets, but stuff already
 * seen can be referenced by ID. So object type information doesn't get
 * written multiple times. Also, complex things have separate type dictionaries?
 * Don't worry about this for now.
 */
    while (x > top)
    {
    int len;

        switch(*x)
        {
        case 0:
            x++;
            if (out_flag)
            {
                fputs("Header: ", ofp);
            }
            break;
        case 1:
            x++;
            if (out_flag)
            {
                fputs("RefTypeObject: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
                fprintf(ofp, "Object ID: %u\n",
                              get_int_little_endian(x));
                x += 4;
            }
            else
                x += 8;
            break;
        case 2:
            x++;
            if (out_flag)
            {
                fputs("UntypedRuntimeObject: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
            }
            else
                x += 4;
            break;
        case 3:
            if (out_flag)
            {
                fputs("UntypedExternalObject: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
            }
            else
                x += 4;
            break;
        case 4:
            if (out_flag)
            {
                fputs("RuntimeObject: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
            }
            x += 4;
            len = get_var_int_little_endian(&x);
            if (out_flag)
                fprintf(ofp, "Type Length: %u String: %.*s\n", len, len, x);
            x += len;
            break;
        case 5:
            if (out_flag)
            {
                fputs("ExternalObject: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
            }
            x += 4;
            len = get_var_int_little_endian(&x);
            if (out_flag)
                fprintf(ofp, "Type Length: %u String: %.*s\n", len, len, x);
            x += len;
            break;
        case 6:
            x++;
            if (out_flag)
            {
                fputs("String: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
            }
            x += 4;
            len = get_var_int_little_endian(&x);
            if (out_flag)
                fprintf(ofp, "Length: %u String: %.*s\n", len, len, x);
            x += len;
            break;
        case 7:
            x++;
            if (out_flag)
            {
                fputs("GenericArray: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
                len = get_int_little_endian(x);
                fprintf(ofp, "Element Count: %u\n", len);
                x += 4;
            }
            else
                x += 8;
            break;
        case 8:
            x++;
            if (out_flag)
            {
                fputs("BoxedPrimitiveTypeValue: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
            }
            else
                x += 4;
            break;
        case 9:
            x++;
            if (out_flag)
            {
                fputs("ObjectReference: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
                fprintf(ofp, "Object ID: %u\n",
                              get_int_little_endian(x));
                x += 4;
            }
            else
                x += 8;
            break;
        case 10:
            x++;
            if (out_flag)
            {
                fputs("NullValue: ", ofp);
            }
            break;
        case 11:
            x++;
            if (out_flag)
            {
                fputs("End: ", ofp);
            }
            break;
        case 12:
            x++;
            if (out_flag)
            {
                fputs("Assembly: ", ofp);
                fprintf(ofp, "ID: %u\n", get_int_little_endian(x));
                x += 4;
            }
            else
                x += 4;
            break;
        case 13:
            x++;
            if (out_flag)
            {
                fputs("ArrayFiller8b: ", ofp);
                fprintf(ofp, "Null Count: %u\n", *x);
            }
            x++;
            break;
        case 14:
            x++;
            if (out_flag)
            {
                fputs("ArrayFiller32b: ", ofp);
            }
        break;
            case 15:
            x++;
            if (out_flag)
            {
                fputs("ArrayOfPrimitiveType: ", ofp);
            }
            break;
        case 16:
            x++;
            if (out_flag)
            {
                fputs("ArrayOfObject: ", ofp);
            }
            break;
        case 17:
            x++;
            if (out_flag)
            {
                fputs("ArrayOfString: ", ofp);
            }
            break;
        case 18:
            x++;
            if (out_flag)
            {
                fputs("Method: ", ofp);
            }
            break;
        case 19:
            x++;
            if (out_flag)
            {
                fputs("Type 19: ", ofp);
            }
            break;
        case 20:
            x++;
            if (out_flag)
            {
                fputs("Type 20: ", ofp);
            }
            break;
        case 21:
            x++;
            if (out_flag)
            {
                fputs("MethodCall: ", ofp);
            }
            break;
        case 22:
            x++;
            if (out_flag)
            {
                fputs("MethodResponse: ", ofp);
            }
            break;
        default:
            fprintf(ofp, "Lost Synchronisation: (%x) ", *x++);
            gen_handle(ofp, x, top, out_flag);
            return;
        }
    }
    return;
}
/*
 * The body
 */
void dotnet_body(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * x;
unsigned char * x2;
unsigned char * top;
int out_flag;
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

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
        frp->top[dir_flag] = frp->hold_buf[dir_flag];
    }
    else
    {
        x = frp->hold_buf[dir_flag];
        top = frp->top[dir_flag];
    }
    x2 = x;
/*
 * - Content length supplied; use it
 */
    if (ap->to_go[dir_flag] > 0)
    {
        x2 = x2 + ap->to_go[dir_flag];
        if (x2 > top)
        {
            adjust_buf(frp, dir_flag, x);
            return;
        }
        out_flag = (((!dir_flag) ^ frp->reverse_sense) || both_ways) ? 1 : 0;
        (void) gen_handle(frp->ofp, x, x2, out_flag);
    }
    else
    if (both_ways || ((!dir_flag) ^ frp->reverse_sense))
        fputc('\n',frp->ofp);
    ap->dotnet_state[dir_flag] = E2_PRELIM;
    ap->dotnet_state[!dir_flag] = E2_PRELIM;
    ap->to_go[dir_flag] = 0;
    adjust_buf(frp, dir_flag, x2);
    if ((!dir_flag) ^ frp->reverse_sense)
        fputs("\\D:E\\\n", frp->ofp);
    else
    if (both_ways)
        fputs("\\A:E\\\n", frp->ofp);
    return;
}
/*
 * Process the .NET Header
 */
static void dotnet_prelim(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * x;
unsigned char * x1;
unsigned char * top;
int out_flag;
struct dotnet_rem_sess * ap = (struct dotnet_rem_sess *) (frp->app_ptr);

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
        frp->top[dir_flag] = frp->hold_buf[dir_flag];
    }
    else
    {
        x = frp->hold_buf[dir_flag];
        top = frp->top[dir_flag];
    }
    ap->dotnet_state[!dir_flag] = E2_PRELIM;
    ap->to_go[!dir_flag] = 0;
    if (x >= top - 14)
        goto reserve;
/*
 * Check the .NET header
 */
    x1 = x;
    if (*x1++ != '.'
      || *x1++ != 'N'
      || *x1++ != 'E'
      || *x1++ != 'T'
      || *x1++ != 1
      || *x1++ != 0)
    {
         fputs("\n*** .NET Marker Parse Failed ***\n", frp->ofp);
         (void) gen_handle(frp->ofp, x, top, 1);
         reset_kept(frp, dir_flag);
         return;
    }
    if ((!dir_flag) ^ frp->reverse_sense)
    {
        fputs("\\D:B:", frp->ofp);
        ip_dir_print(frp->ofp, frp, dir_flag);
        fputs("\\\n", frp->ofp);
        out_flag = 1;
    }
    else
    if (both_ways)
    {
        fputs("\\A:B:", frp->ofp);
        ip_dir_print(frp->ofp, frp, dir_flag);
        fputs("\\\n", frp->ofp);
        out_flag = 1;
    }
    else
        out_flag = 0;
    x1 += 4;
    ap->to_go[dir_flag] = *(x1) +
               (*(x1 + 1) << 8) +
               (*(x1 + 2) << 16) +
               (*(x1 + 3) << 24) + 2; /* The 2 to allow for the header end */
    x1 += 4;
    (void) gen_handle_nolf(frp->ofp, x, x1, out_flag);
    adjust_buf(frp, dir_flag, x1);
    ap->dotnet_state[dir_flag] = E2_HEADER;
    dotnet_header(frp, dir_flag);
    return;
reserve:
    if (top == frp->top[dir_flag])
    {
        ap->kept_msg[dir_flag] = (unsigned char *)
                      malloc( (top - frp->hold_buf[dir_flag]));
        memcpy(ap->kept_msg[dir_flag],
                frp->hold_buf[dir_flag],
                        (top - frp->hold_buf[dir_flag]));
        ap->len[dir_flag] = (frp->top[dir_flag] - frp->hold_buf[dir_flag]);
        frp->top[dir_flag] = frp->hold_buf[dir_flag];
    }
    return;
}

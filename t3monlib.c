/*
 * Scan a captured network packets and work out Stellar response times
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";
#include <sys/types.h>
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#endif
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef LCC
#ifndef VCC2003
#include <unistd.h>
#endif
#endif
#include <errno.h>
#include <time.h>
#include "e2conv.h"
#include "e2net.h"
#include "hashlib.h"
static void mess_handle();
static void do_t3bubble();
/*
 * Structure allocated when a session is started that holds session state.
 *
 * This code handles multiple parallel sessions, but discards asynchronous
 * calls. The USER_MESSAGES are ignored.
 */
struct mess_frame {
    unsigned char *mess_id;
    unsigned char *label;
    int len;
    struct timeval tv;
    int in_use;
};
struct t3_context {
    unsigned char *hold_buf[2]; /* Place for assembling application messages */
    unsigned char * top[2];
    struct mess_frame mess[32];
    int hwm;
};
static struct frame_con * cur_frame;
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */
static int match_port[100];    /* List of ports to match against          */

static int match_cnt;              /* Number of ports in the list    */
static void t3_match_add(port)
int port;
{
    if (match_cnt < 100)
    {
       match_port[match_cnt] = port;
       match_cnt++;
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
    if ((x = getenv("E2_T3_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)
                t3_match_add(i);
        }
    }
    return;
}
static int t3_match_true(from,to)
int from;
int to;
{
int i;

#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif
    for (i = 0; i < match_cnt; i++)
    {
       if (match_port[i] == from || match_port[i] == to)
       {
           if (match_port[i] == to)
               return  1; /* Flag which end is the client */
           else
               return -1;
       }
    }
    return 0;
}
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
register struct t3_context * rop = (struct t3_context *) frp->app_ptr;

    if (rop != (struct t3_context *) NULL)
    {
/*
 * Free up the malloc()ed memory
 */
        free(rop->hold_buf[0]);
        free(rop->hold_buf[1]);
        free((char *) rop);
    }
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
        fclose(frp->ofp);
    return;
}
/*
 * Function to set up a WebLogic T3 stream decoder. Separated from
 * t3_app_recognise() so that it can be called when the protocol switches from
 * HTTP to T3.
 */
void t3_app_initialise(frp)
struct frame_con *frp;
{
struct t3_context * t3p;

    frp->app_ptr = calloc(sizeof(struct t3_context),1);
    t3p = (struct t3_context *) (frp->app_ptr);
    t3p->hold_buf[0] = (unsigned char *) malloc(32768);
    t3p->hold_buf[1] = (unsigned char *) malloc(32768);
    t3p->top[0] = t3p->hold_buf[0];
    t3p->top[1] = t3p->hold_buf[1];
    t3p->hwm = 0;
    frp->off_flag = 0;
    frp->len_len = 4;
    frp->big_little = 0;
    frp->fix_size = 23;
    frp->fix_mult = 0;
    frp->do_mess = do_t3bubble;
    frp->gap = 0;
    return;
}
/*
 * Function that is called to process messages before the protocol becomes T3
 */
static void do_web(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
    char *x =frp->hold_buf[dir_flag];
    int i = frp->top[dir_flag] -frp->hold_buf[dir_flag];
/*
 * We just record what we have been given, in ASCII, if it is normal HTTP.
 * The presence of a binary 0 in the first 8 characters signals we are looking
 * at T3. We don't bother about the proper sequence for switching protocol,
 * because we could be picking the session up anywhere.
 */
        i = (i > 8) ? 8 : i;
        while (i > 0)
        {
            if (*x == 0)
            {
                t3_app_initialise(frp);
                do_t3bubble(frp, dir_flag);
                return;
            }
            i--;
            x++;
        }
        fputs("\\D:B:", frp->ofp);
        ip_dir_print(frp->ofp, frp, dir_flag);
        fputs("\\\n", frp->ofp);
        fwrite(frp->hold_buf[dir_flag], sizeof(char),
                    frp->top[dir_flag] - frp->hold_buf[dir_flag],
                      frp->ofp);
        if (*(frp->top[dir_flag] - 1) != '\n')
            fputc('\n', frp->ofp);
        fputs("\\D:E\\\n", frp->ofp);
        if ((frp->top[dir_flag] - frp->hold_buf[dir_flag]) > 8
         && !memcmp("t3 6.1.", frp->hold_buf[dir_flag],7))
            t3_app_initialise(frp);
    }
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int t3_app_recognise(frp)
struct frame_con *frp;
{
char fname[32];
int i;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is identified in the list of interesting ports, managed
 *    with t3_match_add() and t3_match_true()
 */
    if (extend_listen_flag == 0)
        extend_listen_list();
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;
    struct t3_context * t3p;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if ((i = t3_match_true(from, to)))
        {
        static int sess_cnt = 0;

            sprintf(fname,"t3_%d.msg", sess_cnt++);
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            if (i < 0)
                frp->reverse_sense = 1;
            frp->do_mess = do_web;
            frp->cleanup = do_cleanup;
            fputs( "\\M:", frp->ofp);
            ip_dir_print(frp->ofp, frp, 0);
            fputs( "\\\n", frp->ofp);
            return 1;
        }
    }
    return 0;
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
    return gen_handle(ofp, base, top, out_flag);
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
struct t3_context * ap = (struct t3_context *) (frp->app_ptr);

    x = ap->hold_buf[dir_flag];
    top = ap->top[dir_flag];
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
    }
    return;
}
/*
 * Special version of the standard response output routine. This is needed
 * because we write on seeing the return packet, rather than on the next
 * request, as we normally do.
 */
void t3output_response (f,dir_flag, to_match)
struct frame_con * f;
int dir_flag;
int to_match;
{
struct timeval resp_time;
struct t3_context * t3p = (struct t3_context *) (f->app_ptr);
/*
 * We need to output a response record:
 * - Record Type
 * - Label
 * - Time Start
 * - Response
 * - Packets Out
 * - Packets In
 * - Bytes Out
 * - Bytes In
 */
    if (dir_flag == -1)
    {
        head_print(f->ofp, f);
        fprintf(f->ofp, "DROPPED|%.*s|%d.%06d|",
            t3p->mess[to_match].len,
            (t3p->mess[to_match].label == NULL)? "" :
            t3p->mess[to_match].label,
            (t3p->mess[to_match].tv.tv_sec),
            (t3p->mess[to_match].tv.tv_usec));
        date_out(f->ofp,
            (t3p->mess[to_match].tv.tv_sec),
            (t3p->mess[to_match].tv.tv_usec));
        fputc('\n', f->ofp);
        return;
    }
    tvdiff(&(f->last_t[dir_flag].tv_sec),
           &(f->last_t[dir_flag].tv_usec),
           &(t3p->mess[to_match].tv.tv_sec),
           &(t3p->mess[to_match].tv.tv_usec),
           &(resp_time.tv_sec),           /* The Response Time               */
           &(resp_time.tv_usec));
    head_print(f->ofp, f);
    fprintf(f->ofp, "RESPONSE|%.*s|%d.%06d|%d.%06d|%d|%d|%d|%d|",
            t3p->mess[to_match].len, 
            (t3p->mess[to_match].label == NULL)? "" :
            t3p->mess[to_match].label,
           (t3p->mess[to_match].tv.tv_sec),
           (t3p->mess[to_match].tv.tv_usec),
            resp_time.tv_sec, resp_time.tv_usec,
            f->cnt[!dir_flag] - f->tran_cnt[!dir_flag],
            f->cnt[dir_flag] - f->tran_cnt[dir_flag],
            f->len[!dir_flag] - f->tran_len[!dir_flag],
            f->len[dir_flag] - f->tran_len[dir_flag]);
    date_out(f->ofp,
            (t3p->mess[to_match].tv.tv_sec),
            (t3p->mess[to_match].tv.tv_usec));
    fputc('\n', f->ofp);
    f->tran_cnt[0] = f->cnt[0];
    f->tran_cnt[1] = f->cnt[1];
    f->tran_len[0] = f->len[0];
    f->tran_len[1] = f->len[1];
    f->label[0] = '\0';
    return;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum(), if we appear to be looking at T3.
 */
static void do_t3bubble(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * p;
unsigned char * p1;
int last_frag;
int tran_len;
int len;
int i;
struct t3_context * t3p;
static struct bm_table * bp;

    if (bp == (struct bm_table *) NULL)   /* Marker for the messsage type */
        bp = bm_compile_bin("DispActiont", 12);
    cur_frame = frp;
/*
 * First we have the Header to discard.
 */
    p = frp->hold_buf[dir_flag];
    len = frp->top[dir_flag] - p;
#ifdef DEBUG
    fprintf(frp->ofp, "do_t3bubble(%lx) = (%lx, %d)\n", (long) frp,
               p, len);
    fflush(frp->ofp);
#endif
/*
 * Ignore one-way messages and dross
 */
    if ((len < 23) || (p[0] == 0 && (p[4] == 4 || p[4] == 8)))
    {
#ifdef DEBUG
        fputs("do_t3bubble() one way message or dross?\n", frp->ofp);
        fflush(frp->ofp);
#endif
        return;
    }
    t3p = (struct t3_context *) (frp->app_ptr);
/*
 * Outgoing message - save the details.
 */
    if ((!dir_flag) ^ frp->reverse_sense)
    {
        if ((t3p->top[dir_flag]  - t3p->hold_buf[dir_flag]) + (len - 4) > 32768)
        {                         /* Too little buffer space */
            for (i = 0; i < t3p->hwm; i++)
            {
                if (t3p->mess[i].in_use)
                    t3output_response(frp, -1, i);
                         /* Record the drop */
            }
            t3p->top[dir_flag] = t3p->hold_buf[dir_flag];   /* Discard it all */
            t3p->hwm = 0;
            if ((len - 4) > 32768)
                return;
        }
/***********************************************************************
 * Manage a stack of messages
 */
        memcpy(t3p->top[dir_flag], p + 4, len - 4);
        for (i = 0; i < t3p->hwm; i++)
            if (t3p->mess[i].in_use == 0)
                break;
        t3p->mess[i].in_use = 1;
        t3p->mess[i].mess_id = t3p->top[dir_flag] + 3; /* Message Sequence */
/*
 * The Transaction label will only be in data from PC to the server
 */
        if ( (p1 = bm_match(bp, t3p->top[dir_flag], t3p->top[dir_flag] + len - 4)) != (unsigned char *) NULL)
        {
            t3p->mess[i].len = (*(p1 + 12) > 39) ? 39 : *(p1 + 12);
            t3p->mess[i].label = p1 + 13;
        }
        else
        {
            t3p->mess[i].len = 0;
            t3p->mess[i].label = NULL;
        }
        t3p->mess[i].tv = frp->last_t[dir_flag];     /* Time stamp */
        if (i >= t3p->hwm && i < 31)
            t3p->hwm++;
        t3p->top[dir_flag] += (len - 4);
#ifdef DEBUG
        fprintf(frp->ofp, "do_t3bubble(%lx)\nSaved\n", (long) frp);
        gen_handle(frp->ofp, t3p->hold_buf[dir_flag], t3p->top[dir_flag], 1);
        fflush(frp->ofp);
#endif
        mess_handle(frp, p + 4, p + len, (!dir_flag) ^ frp->reverse_sense);
    }
    else
    {
/*
 * See if the from and to tally
 */
        for (i = 0, len = 0; i < t3p->hwm; i++)
        {
            if (t3p->mess[i].in_use)
            {
                p1 = t3p->mess[i].mess_id;
                if (p1 + 3 < t3p->top[!dir_flag]
                 && p[10] == p1[3]
                 && p[9] == p1[2]
                 && p[8] == p1[1]
                 && p[7] == p1[0])
                    break;
                if (t3p->mess[i].tv.tv_sec < frp->last_t[dir_flag].tv_sec - 600)
                {
                    t3output_response(frp, -1, i);
                         /* Record the drop */
                    t3p->mess[i].in_use = 0;   /* Time out dropped stuff */
                }
                else
                    len++;
            }
        }
        if (i > t3p->hwm)
        {
#ifdef DEBUG
            fputs("do_t3bubble() response message does not correspond\n\
ONE\n", frp->ofp);
            gen_handle(frp->ofp, p, p + len, 1);
            fputs("OTHER\n",  frp->ofp);
            gen_handle(frp->ofp, t3p->hold_buf[!dir_flag],
                            t3p->top[!dir_flag], 1);
            fflush(frp->ofp);
#endif
            if (len == 0)
            {
                head_print(frp->ofp, frp);
                fprintf(frp->ofp, "DROPPED|Unknown|%d.%06d|",
                    (frp->last_t[dir_flag].tv_sec),
                    (frp->last_t[dir_flag].tv_usec));
                date_out(frp->ofp,
                    (frp->last_t[dir_flag].tv_sec),
                    (frp->last_t[dir_flag].tv_usec));
                fputc('\n', frp->ofp);
                t3p->top[!dir_flag] = t3p->hold_buf[!dir_flag];
                t3p->hwm = 0;
            }
            return;
        }
        t3_dispose(frp, !dir_flag);   /* Record the response */
        t3output_response(frp, dir_flag, i);   /* Record the response */
        t3p->mess[i].in_use = 0;
        if (i == t3p->hwm - 1)
        {
            do
            {
                t3p->hwm--;
                i--;
            }
            while (i >= 0 && t3p->mess[i].in_use == 0);
        }
        if ( t3p->hwm == 0)
            t3p->top[!dir_flag] = t3p->hold_buf[!dir_flag];
    }
    return;
}
/******************************************************************************
 * Decode sections of Java serialisation
 */
#define STREAM_MAGIC_1 0xac
#define STREAM_MAGIC_2 0xed
#define STREAM_VERSION  5
#define TC_NULL  0x70
#define TC_REFERENCE 0x71
#define TC_CLASSDESC 0x72
#define TC_OBJECT 0x73
#define TC_STRING 0x74
#define TC_ARRAY 0x75
#define TC_CLASS 0x76
#define TC_BLOCKDATA 0x77
#define TC_ENDBLOCKDATA 0x78
#define TC_RESET 0x79
#define TC_BLOCKDATALONG 0x7A
#define TC_EXCEPTION 0x7B
#define TC_LONGSTRING  0x7C
#define TC_PROXYCLASSDESC  0x7D
#define TC_BASEWIREHANDLE  0x7E
#define SC_WRITE_METHOD 0x01
#define SC_BLOCK_DATA  0x08
#define SC_SERIALIZABLE  0x02
#define SC_EXTERNALIZABLE  0x04
/*
 * Grammar
 *
stream:
    magic version contents

contents:
    content
    contents content

content:
    object
    blockdata

object:
    newObject
    newClass
    newArray
    newString
    newClassDesc
    prevObject
    nullReference
    exception
    TC_RESET

newClass:
    TC_CLASS classDesc newHandle

classDesc:
    newClassDesc
    nullReference
    (ClassDesc)prevObject      // an object required to be of type
                             // ClassDesc

superClassDesc:
    classDesc

newClassDesc:
    TC_CLASSDESC className serialVersionUID newHandle classDescInfo
    TC_PROXYCLASSDESC newHandle proxyClassDescInfo

classDescInfo:
  classDescFlags fields classAnnotation superClassDesc

className:
  (utf)

serialVersionUID:
  (long)

classDescFlags:
  (byte)                  // Defined in Terminal Symbols and
                            // Constants

proxyClassDescInfo:
  (int)    count     proxyInterfaceName[count] classAnnotation
      superClassDesc

proxyInterfaceName:
  (utf)

fields:
  (short)    count      fieldDesc[count]

fieldDesc:
  primitiveDesc
  objectDesc

primitiveDesc:
  prim_typecode fieldName

objectDesc:
  obj_typecode fieldName className1

fieldName:
  (utf)

className1:
  (String)object             // String containing the field's type,
                             // in field descriptor format

classAnnotation:
    endBlockData
    contents endBlockData      // contents written by annotateClass

prim_typecode:
  `B'   // byte
  `C'   // char
  `D'   // double
  `F'   // float
  `I'   // integer
  `J'   // long
  `S'   // short
  `Z'   // boolean

obj_typecode:
  `[`   // array
  `L'   // object

newArray:
    TC_ARRAY classDesc newHandle (int)    size     values[size]

newObject:
    TC_OBJECT classDesc newHandle classdata[]  // data for each class

classdata:
  nowrclass                 // SC_SERIALIZABLE & classDescFlag &&
                            // !(SC_WRITE_METHOD & classDescFlags)
  wrclass objectAnnotation  // SC_SERIALIZABLE & classDescFlag &&
                            // SC_WRITE_METHOD & classDescFlags
  externalContents          // SC_EXTERNALIZABLE & classDescFlag &&
                            // !(SC_BLOCKDATA  & classDescFlags
  objectAnnotation          // SC_EXTERNALIZABLE & classDescFlag&&
                            // SC_BLOCKDATA &amp; classDescFlags

nowrclass:
    values                    // fields in order of class descriptor

wrclass:
    nowrclass

objectAnnotation:
    endBlockData
    contents endBlockData     // contents written by writeObject
                            // or writeExternal PROTOCOL_VERSION_2.

blockdata:
    blockdatashort
    blockdatalong

blockdatashort:
    TC_BLOCKDATA (unsigned byte)    size     (byte)[size]

blockdatalong:
    TC_BLOCKDATALONG (int)    size     (byte)[size]


endBlockData    :
    TC_ENDBLOCKDATA


externalContent:          // Only parseable by readExternal
  ( bytes)                // primitive data
    object


externalContents:         // externalContent written by
    externalContent         // writeExternal in PROTOCOL_VERSION_1.
    externalContents externalContent

newString:
    TC_STRING newHandle (utf)
    TC_LONGSTRING newHandle (long-utf)

prevObject:
    TC_REFERENCE (int)handle

nullReference:
    TC_NULL


exception:
    TC_EXCEPTION reset (Throwable)object         reset

magic:
    STREAM_MAGIC

version
    STREAM_VERSION

values:          // The size and types are described by the
                 // classDesc for the current object

newHandle:       // The next number in sequence is assigned
                 // to the object being serialized or deserialized

reset:           // The set of known objects is discarded
                 // so the objects of the exception do not
                 // overlap with the previously sent objects
                 // or with objects that may be sent after
                 // the exception
 */
static void java_serial_handle(frp, hold_buf,top,out)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * top;
int out;
{
unsigned char * x = hold_buf;
unsigned char * x1;
struct t3_context * t3p = (struct t3_context *) frp->app_ptr;
int j;
int offset;

#ifdef DEBUG
    fprintf(frp->ofp, "java_serial_handle(%lx, %lx, %lx, %d)\n", (long) frp,
               (long) hold_buf, (long) top, out);
    fflush(frp->ofp);
    out = 1;
#endif
    if (top <= x)
    {
        fprintf(frp->ofp, "x: %lx top: %lx\n", (long) x, (long) top);
        fflush(frp->ofp);
        fflush(stdout);
        fflush(stderr);
        return;
    }
#ifdef DEBUG
    fflush(frp->ofp);
#endif
    return;
}
/**************************************************************************
 * Deal with the WebLogic T3 TCP Stream - the bubbling abbreviation stuff
 *
 * First cut, with little idea of the detailed structure, we just marked:
 * - Packet boundaries (in the calling routine)
 * - Apparently binary details (output in blocks of hex)
 * - Recognisable stretches of ASCII.
 *
 * We can now see there is a layered structure. In the top routine, we strip
 * the 'transport' headers.
 *
 * Finally, having established the format of the data, and how the file
 * is constructed, output the seed scripts.
 *
 * The messages give every appearance of being an arbitrary sequence of
 * fragment types and fragments whose internal structure depends on the
 * fragment type. Thus, the following is structured as a loop to process the
 * entire buffer.
 ****************************************************************************
 * Now do the necessary manipulations on the message that has been read in.
 ****************************************************************************
 * Messages consist of:
 * - A four byte inclusive length, sent MSB=>LSB (ie. Big-Endian) (gone here)
 * - A 19 byte JVMessage header, made up of:
 * - A command code:
 *   - 0 - CMD_UNDEFINED
 *   - 1 - CMD_IDENTIFY_REQUEST
 *   - 2 - CMD_IDENTIFY_RESPONSE
 *   - 3 - CMD_PEER_GONE
 *   - 4 - CMD_ONE_WAY
 *   - 5 - CMD_REQUEST
 *   - 6 - CMD_RESPONSE
 *   - 7 - CMD_ERROR_RESPONSE
 *   - 8 - CMD_INTERNAL
 *   - 9 - CMD_NO_ROUTE_IDENTIFY_REQUEST
 *   - 10 - CMD_TRANSLATED_IDENTIFY_RESPONSE
 *   - 11 - CMD_REQUEST_CLOSE
 * - A 1 byte QOS (always 101, 0x65)
 * - A 1 byte flag:
 *   - 1 - Message has JVMID's
 *   - 2 - Message has Transaction details
 * - A 4 byte request sequence (incremented on requests, matched on responses)
 * - A 4 byte invokable ID (same as request for responses, not understood in
 *   other cases
 * - A 4 byte abbrev offset. This always seems to be the end of the message
 *   for our message
 * - Then, a set of marshalled parameters.
 */
static void mess_handle(frp, hold_buf,top,out)
struct frame_con * frp;
unsigned char * hold_buf;
unsigned char * top;
int out;
{
unsigned char * x = hold_buf;
unsigned char * x1;
struct t3_context * t3p = (struct t3_context *) frp->app_ptr;
int j;
int offset;

#ifdef DEBUG
    fprintf(frp->ofp, "mess_handle(%lx, %lx, %lx, %d)\n", (long) frp,
               (long) hold_buf, (long) top, out);
    fflush(frp->ofp);
    out = 1;
#endif
/*
 * 1 Byte Record Type
 */
    if (top <= x)
    {
        fprintf(frp->ofp, "x: %lx top: %lx\n", (long) x, (long) top);
        fflush(frp->ofp);
        fflush(stdout);
        fflush(stderr);
        return;
    }
/*
 * We are never interested in the return data
 * handle
 */
    if (!out)
        return;
#ifdef DEBUG
    fflush(frp->ofp);
#endif
    return;
}

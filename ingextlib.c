/*
 * Scan a snoop file and pull out the Ingres OpenAPI GCA elements.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include "e2conv.h"
#include "e2net.h"
#include "hashlib.h"
static FILE * ofp;        /* All the output goes to a single file */
/*
 * GCA message Control
 */
struct ing_mess {
    int mess_id;
    char *mess_name;
    char *mess_form;
    int has_length;       /* Flag presence of a big-endian length */
    int length_at_end;    /* Flag presence of a little-endian trailing length */
    int length_after;     /* The final length */
    struct iocon * mess_io;
    int mess_len;
}
ing_mess[] = {
/*
 * Variable details. The data type (actually I4) is followed by ... what (I4)
 * and then a set of read/write flags, finishing with the field length.
 */
{ 0x2, "M_SQL", "1I4", 0 },
{ 0x3, "M_API_DTE_TYPE", "1I4 1I4", 0, 1 },
{ 0x5, "M_API_MNY_TYPE", "2I4 1H8 1I2", 0, 1 },
{ 0xa, "M_API_DEC_TYPE", "1I4 1I4", 0, 1 },
{ 0xb, "M_API_LOGKEY_TYPE", "2I4 1I2", 0, 1 },
{ 0xc, "M_API_TABKEY_TYPE", "2I4 1I2", 0, 1 },
{ 0x14, "M_API_CHA_TYPE", "1I4 1I4", 0, 1 },
{ 0x15, "M_API_VCH_TYPE", "2I4 1I2", 0, 1 },
{ 0x16, "M_API_LVCH_TYPE", "2I4 1I2", 0, 1 },
{ 0x17, "M_API_BYTE_TYPE", "1I4 1I4", 0, 1 },
{ 0x18, "M_API_VBYTE_TYPE", "2I4 1I2", 0, 1 },
{ 0x19, "M_API_LBYTE_TYPE", "1I4 1I4", 0, 1 },
{ 0x1a, "M_API_NCHA_TYPE", "1I4 1I4", 0, 1 },
{ 0x1b, "M_API_NVCH_TYPE", "2I4 1I2", 0, 1 },
{ 0x1c, "M_API_LNVCH_TYPE", "2I4 1I2", 0, 1 },
{ 0x1e, "M_API_INT_TYPE", "1I4 1I4", 0, 1 },
{ 0x1f, "M_API_FLT_TYPE", "2I4 1D8 1I2", 0, 0 },
{ 0x20, "M_API_CHR_TYPE", "1I4 1I4", 0, 1 },
{ 0x25, "M_API_TXT_TYPE", "2I4 1I2", 0, 1 },
{ 0x29, "M_API_LTXT_TYPE", "2I4 1I2", 0, 1 },
{ 0x33, "M_SQL_FRAG", "2I4", 0, 1 },
{ 0x114, "M_EXEC_RESPONSE", "2I1", 1 },
{ 0x115, "M_COLUMN_RESPONSE", "2I1", 1 },
{ 0x151, "M_COLUMN_DATA_151", "2I4 1I2", 1 },
{ 0x116, "M_COLUMN_DATA_116", "2I4 1I2", 1 },
{ 0x0303, "M_STATUS_REQ", 0, 1 },
{ 0x0203, "M_SESS_INFO", "1I4", 1 },
{ 0x0c03, "M_COMMIT", 0, 1 },
{ 0x2203, "M_ROLLBACK", 0, 1 },
{ 0x0d03, "M_PARSE_EXEC_FETCH", 0, 1 },
{ 0x0e00, "M_DEFINE", 0, 1 },
{ 0x0e03, "M_PARSE", 0, 1 },
{ 0x0f03, "M_EXEC_REPEAT", "2I4 1S64", 1, 0 },
{ 0x0503, "M_ROLLBACK", "1I4", 1 },
{ 0x1303, "M_CANCEL", "1I4", 1 },
{ 0x1b03, "M_EXEC_STATUS", 0, 1 },
{ 0x02c1, "M_CONNECT", 0, 0 },
{ 0xc104, "M_DISCONNECT", "1I2", 0 },
{ 0x0c01, "M_TERMINATE", "3I1", 0 },
{ 0x80c1, "M_LOGIN", 0, 0 },
{ 0xffe2, "M_LOGIN", "3I4 1I1", 0 },
{ 0x32c1, "M_LOGIN_OK", 0, 0 },
{ -1, "M_API_HNDL_TYPE", "2I4 1I2", 0, 1 },
{ 0 }};
static struct frame_con * cur_frame;
static void do_ingapi();
static void ingapi_handle();
/*
 * Structure allocated when a session is started that holds per-cursor
 * statistics plus session state.
 *
 * This code handles multiple parallel sessions.
 */
struct ing_sess {
    int out_len;      /* Length outstanding */
    char sql[65536];
    char *ptr;
};
/*
 * Hash function for Ingres message IDs
 */
unsigned mess_hh(w,modulo)
char * w;
int modulo;
{
long l = (long) w;
long maj = (l & 0xff00) >> 3;
    return(((int) ((l & 0xff) | maj)) & (modulo-1));
}
static HASH_CON * idt;
static HASH_CON * nmt;
/*
 * Initialise the control structures for the message recognition
 */
void ing_init()
{
struct ing_mess *dmp;

    idt = hash(256, mess_hh, icomp);
    nmt = hash(256, string_hh, strcmp);
    for (dmp = &ing_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(idt, (char *) dmp->mess_id, (char *) dmp);
        insert(nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    return;
}
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
int i;
register struct ing_sess * rop = (struct ing_sess *) frp->app_ptr;

    if (rop != (struct ing_sess *) NULL)
    {
        free((char *) rop);
    }
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout && frp->ofp != ofp)
    {
        fclose(frp->ofp);
        frp->ofp = (FILE *) NULL;
    }
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
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int ing_app_recognise(frp)
struct frame_con *frp;
{
static int sess_cnt = 0;
char fname[32];
unsigned short int from, to;
struct ing_sess * rop;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is the INGRES DB (2677?)
 */
    if (idt == NULL)
        ing_init();
    if (frp->prot == E2_TCP)
    {
        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if ((from >= 26700 && from <= 33779)
         || (to >= 26700 && to <= 33779))
        {
/*****************************************************************************
 * Multiple database connections ....
 *****************************************************************************
 *          sprintf(fname,"sql_%d.sql", sess_cnt++);
 *          frp->ofp = fopen(fname, "wb");
 *          if (frp->ofp == (FILE *) NULL)
 */
            if (ofp == (FILE *) NULL)
                ofp = fopen("ing_script.sql", "wb");
            frp->ofp = ofp;        /* Out of file descriptors      */
            if (from >= 26700 && from <= 33779)
                frp->reverse_sense = 1;   /* Flag which end is the client */
            frp->off_flag = 0;
            frp->len_len = 2;
            frp->big_little = 1;   /* A little-endian length */
            frp->fix_size = 9;
            frp->fix_mult = 0;
            frp->do_mess = do_ingapi;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) calloc(sizeof(struct ing_sess),1);
            rop = (struct ing_sess *) frp->app_ptr;
            rop->ptr = rop->sql;
            rop->out_len = 0;
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
                ofp = fopen("ing_script.sql", "wb");
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
/****************************************************************************
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum()
 ****************************************************************************
 * This is broken because the tcp_frame_accum may not pass entire application
 * messages. Usually it does so, though we have a frig to deal with the failed
 * cases.
 */
static void do_ingapi(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
    cur_frame = frp;
    (void) ingapi_handle(frp->ofp, frp->hold_buf[dir_flag], frp->top[dir_flag],
                (!dir_flag) ^ frp->reverse_sense);
    return;
}
static void ingapi_handle(fp, x,top,out)
FILE *fp;
unsigned char * x;
unsigned char * top;
int out;
{
int i, j;
unsigned char * x1;
int mess_id;
int mess_len;
HIPT * h;
struct fld_descrip * desc_arr;
struct ing_mess * dmp;
char buf[8192];
int len;
unsigned short int from;
struct ing_sess * rop;

    rop = (struct ing_sess *) cur_frame->app_ptr;
    if (out)
    {
#ifdef DEBUG
        fputs(">->->->->>\n", fp);
        (void) gen_handle(fp, x,top,1);
        fputs(">=>=>=>=>>\n", fp);
#endif
        if (cur_frame->reverse_sense)   /* Flag which end is the client */
            memcpy(&from, &(cur_frame->port_to[1]), 2);
        else
            memcpy(&from, &(cur_frame->port_from[1]), 2);
        if (rop->out_len == 0)
            fprintf(fp, "\n/\n\\I_PORT:%u\\\n", from);
        for (x1 = x + 9; x1 < top; )
        {
            mess_id = x1[1]*256 + x1[0];
            mess_len = x1[2]*256 + x1[3];
            if ((h = lookup(idt, mess_id)) == (HIPT *) NULL)
            {
                if (rop->out_len > 0)
                {
#ifdef DEBUG
                    if (rop->ptr != rop->sql)
                        fprintf(fp, "--Overspill-->\n%.*s\n====\n",rop->out_len,
                                        x1);
#endif
                    memcpy(rop->ptr,x1,rop->out_len);
                    rop->ptr += rop->out_len;
                    x1 += rop->out_len;
                    rop->out_len = 0;
                    if (*(rop->ptr - 1) == '\0')
                    {
                        fputs(rop->sql,fp);
                        rop->ptr = rop->sql;
                    }
                    continue;
                }
                else
                {
                    (void) fprintf(fp,
                "Format failure: submitted unknown message ID:%d length:%d\n", 
                            mess_id, mess_len);
#ifdef DEBUG
                    if (rop->ptr != rop->sql)
                        fprintf(fp, "--Reserved-->\n%.*s\n====\n",
                                     (rop->ptr - rop->sql),
                                          rop->sql);
#endif
                    if (x1 + 4 + mess_len > top)
                    {                
                        gen_handle(fp, x1 + 4, top, 1);
                        return;
                    }
                    else
                    {
                        x1 += 4;
                        gen_handle(fp, x1, (top > (x1 + mess_len))
                                     ? (x1 + mess_len) : top, 1);
                        x1 += mess_len;
                        continue;
                    }
                }
            }
            dmp = ((struct ing_mess *) (h->body));
/*
 * Convert the record
 */
            x1 += 4;
            fputs(dmp->mess_name, fp);
            fputc('|', fp);
            switch (mess_id)
            {
            case 0x02c1: /* CONNECT  */
            case 0x80c1: /* LOGIN    */
            case 0x32c1: /* LOGIN_OK */
            case 0x0203: /* SESS_INFO */
#ifdef DEBUG
                gen_handle(fp, x1 + 4, top, 1);
#else
                fputc('\n', fp);
#endif
                return;
            }
            i = e2rec_map_bin(&desc_arr, x1, &buf[0], dmp->mess_io, '|', '\\');
            if (i)
            {
                fputs(&buf[0], fp);
                x1 = desc_arr[i-1].fld +  desc_arr[i-1].len;
                if (x1 >= top)
                    continue;
                if (dmp->length_at_end)
                {
                    len = get_fld_int_le(&desc_arr[i-1]);
                    if (x1 + len > top)
                    {
                        memcpy(rop->ptr, x1, top - x1);
                        rop->ptr += (top - x1);
                        rop->out_len = len - (top - x1);
                        x1 = top;
                        continue;
                    }
                    switch( mess_id )
                    {
                    case 0x3:  /* API_DTE_TYPE */
                    case 0x5:  /* API_MNY_TYPE */
                    case 0xa:  /* API_DEC_TYPE */
                    case 0xb:  /* API_LOGKEY_TYPE */
                    case 0xc:  /* API_TABKEY_TYPE */
                    case 0x17:  /* API_BYTE_TYPE */
                    case 0x18:  /* API_VBYTE_TYPE */
                    case 0x19:  /* API_LBYTE_TYPE */
                    case 0x1e:  /* API_INT_TYPE */
                    case 0x1f:  /* API_FLT_TYPE */
                        fputs(hexin(x1, len), fp);
                        break;
                    case 0x33:  /* SQL Text */
                        memcpy(rop->ptr, x1, len);
                        rop->ptr += len;
                        if (*(rop->ptr - 1) == '\0')
                        {
                            fputs(rop->sql,fp);
                            rop->ptr = rop->sql;
                        }
                        break;
                    default:
                        fwrite(x1, sizeof(char), len, fp);
                        break;
                    }
                    x1 += len;
                }
            }
            fputc('\n', fp);
        }
    }
    else
    {
#ifdef DEBUG
        fputs("<-<-<-<-<<\n", fp);
        (void) gen_handle(fp, x,top,1);
        fputs("<=<=<=<=<<\n", fp);
#endif
        x1 = x + 9;
        if (x1[0] == 1 && x1[1] == 0x14 && x1[2] == 0 && x1[3] == 0x48)
        {
            h = lookup(idt, 0xf03);
            dmp = ((struct ing_mess *) (h->body));
/*
 * Convert the record
 */
            x1 += 4;
            fputs(dmp->mess_name, fp);
            fputc('|', fp);
            i = e2rec_map_bin(&desc_arr, x1, &buf[0], dmp->mess_io, '|', '\\');
            if (i)
                fputs(&buf[0], fp);
            fputc('\n', fp);
        }
    }
    return;
}

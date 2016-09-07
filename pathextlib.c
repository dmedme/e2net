/*
 * Scan a snoop file and pull out things that the E2 Systems dumb terminal
 * path capture utility can turn into scripts.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#ifndef VCC2003
#include <sys/time.h>
#endif
#include "e2conv.h"
#include "e2net.h"
/*
 * Structure allocated when a session is started that holds application-
 * specific session state.
 *
 * This code handles multiple parallel sessions.
 */
struct dumb_sess {
int ev_cnt;
unsigned char * last_output; 
unsigned char * last_input; 
FILE * logfp;
};
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
register struct dumb_sess * rop = (struct dumb_sess *) frp->app_ptr;

    if (rop != (struct dumb_sess *) NULL)
    {
        if (rop->last_output != (char *) NULL)
            free(rop->last_output);
        if (rop->last_input != (char *) NULL)
            free(rop->last_input);
#ifdef DEBUG
        if (rop->logfp != (FILE *) NULL && rop->logfp != stdout)
            fclose(rop->logfp);
#endif
        free((char *) rop);
    }
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
    {
        fclose(frp->ofp);
        frp->ofp = (FILE *) NULL;
    }
    return;
}
/*
 * Routines to pre-process information from incoming and outgoing
 * buffers so that it is valid ptydrive input
 */
static unsigned char * path_in_stuff(in, len)
unsigned char * in;
int len;
{
unsigned char buf[2048];
register unsigned char *x1=in, *x2=buf;
    while (len-- > 0)
    {
        if (*x1 == '`')
        {   /* In case back quotes appear in the input strings */
            *x2++ = '`';
            *x2++ = ' ';
            *x2++ = '\'';
            *x2++ = '`';
            *x2++ = '\'';
            *x2++ = ' ';
        }
        *x2++ = *x1++;
    }
    *x2 = '\0';
    return (unsigned char *) strdup((char *) (&buf[0]));
}
static unsigned char * path_out_stuff(in, len)
unsigned char * in;
int len;
{
unsigned char buf[2048];
register unsigned char *x1=in, *x2=buf;
    while (len-- > 0)
    {
        if (*x1 == (unsigned char) ':')
            *x2++ = (unsigned char) '\\';
        *x2++ = *x1++;
    }
    x2--;    /* Because the PATH match needs an extra character; bug! */
    if (x2 <= &buf[0])
        return (char *) NULL;
    else
    {
        *x2 = (unsigned char) '\0';
        return (unsigned char *) strdup((char *) (&buf[0]));
    }
}
/*
 * Generate PATH output.
 */
static void do_dumb(f, dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval el_diff;
int i;
unsigned char * p1;
static int done_flag;
static char buf1[64];
static char buf2[512];
static char buf3[64];
static char buf4[512];

    if (!done_flag)
    {
        re_comp("\033\\[1;1", buf1, (long int) sizeof(buf1));
#ifdef GECMF
        re_comp("G E Capital Woodchester      ", buf2, (long int) sizeof(buf2));
        re_comp("\033\\[23;1", buf3, (long int) sizeof(buf3));
        re_comp( "[A-Z0-9][A-Z0-9 -][A-Z0-9 -][A-Z0-9 -][A-Z0-9 -]\
[A-Z0-9 -][A-Z0-9 -][A-Z0-9 -]", buf4, (long int) sizeof(buf4));
#else
        re_comp( "[A-Z0-9][A-Z0-9 _][A-Z0-9 _][A-Z0-9 _][A-Z0-9 _]\
[A-Z0-9 _][A-Z0-9 _]", buf2, (long int) sizeof(buf2));
#endif
        done_flag = 1;
    }
    if ((!dir_flag) ^ f->reverse_sense) /* User Input */
    {
        if (((struct dumb_sess *)(f->app_ptr))->last_input !=
                  (unsigned char *) NULL)
        {
            if (((struct dumb_sess *)(f->app_ptr))->last_output !=
                  (unsigned char *) NULL)
            {
                strncpy(f->label + 30,
                      ((struct dumb_sess *)(f->app_ptr))->last_input, 9);
                f->label[39] = '\0';
                output_response(f, dir_flag); /* The last response */
                tvdiff(&(f->ini_t[dir_flag].tv_sec),&
                           (f->ini_t[dir_flag].tv_usec),
                   &(f->ini_t[!dir_flag].tv_sec),&(f->ini_t[!dir_flag].tv_usec),
                   &(el_diff.tv_sec), &(el_diff.tv_usec));
                if (el_diff.tv_sec > 2)
                    fprintf(f->ofp, "\n\\W%d\\",el_diff.tv_sec/2);
                if (((struct dumb_sess *)(f->app_ptr))->ev_cnt < 160
                  || ((struct dumb_sess *)(f->app_ptr))->ev_cnt > 255)
                    ((struct dumb_sess *)(f->app_ptr))->ev_cnt = 160;
                fprintf(f->ofp, "\n\\S%X:1200:%s::Event %X\\\n\\T%X:\\\n",
                        ((struct dumb_sess *)(f->app_ptr))->ev_cnt,
                 ((struct dumb_sess *)(f->app_ptr))->last_output,
                 ((struct dumb_sess *)(f->app_ptr))->ev_cnt,
                 ((struct dumb_sess *)(f->app_ptr))->ev_cnt);
                ((struct dumb_sess *)(f->app_ptr))->ev_cnt++;
                free(((struct dumb_sess *)(f->app_ptr))->last_output);
                ((struct dumb_sess *)(f->app_ptr))->last_output =
                     (unsigned char *) NULL;
            }
            else
                fputc('\n', f->ofp);
            fputc('`', f->ofp);
            fputs((char *) ((struct dumb_sess *)(f->app_ptr))->last_input,
                     f->ofp);
            fputc('`', f->ofp);
            fputc('\n', f->ofp);
            free(((struct dumb_sess *)(f->app_ptr))->last_input);
            ((struct dumb_sess *)(f->app_ptr))->last_input =
                     (unsigned char *) NULL;
        }
        if (f->top[dir_flag] != f->hold_buf[dir_flag])
            ((struct dumb_sess *)(f->app_ptr))->last_input =
                     path_in_stuff(f->hold_buf[dir_flag],
                          (f->top[dir_flag] - f->hold_buf[dir_flag]));
        f->tran_start = f->last_t[dir_flag];
        for (i = 0; i < 2; i++)
        {
            f->tran_cnt[i] = f->cnt[i];
            f->tran_len[i] = f->len[i];
            f->tran_cs_tim[i] = f->cs_tim[i];
            f->tran_nt_tim[i] = f->nt_tim[i];
        }
    }
    else
    {
/*
 * The Transaction label will only be in data from the server to the client
 */ 
        p1 = f->hold_buf[dir_flag];
#ifdef GECMF
        if (re_scan(&p1, buf1, (f->top[dir_flag] - p1))
          && (p1 += 6, re_scan(&p1, buf2, (f->top[dir_flag] - p1)))
          && p1 < f->top[dir_flag] - 60)
        {
             p1 += 30;
             while (p1 < f->top[dir_flag] - 30  && *p1 == ' ' )
                 p1++;
             if (*p1 != ' ')
             {
                 strncpy(f->label, p1, 22);
                 memset(&(f->label[22]), ' ', 8);
                 f->label[38] = '\0';
             }
        }
        else
        if (re_scan(&p1, buf3, (f->top[dir_flag] - p1))
          && (p1 += 7, re_scan(&p1, buf4, (f->top[dir_flag] - p1)))
          && p1 < f->top[dir_flag] - 8)
        {
             strncpy(f->label + 22, p1, 8);
             f->label[38] = '\0';
        }
#else
        if (re_scan(&p1, buf1, (f->top[dir_flag] - p1))
          && (p1 += 6, re_scan(&p1, buf2, (f->top[dir_flag] - p1)))
          && p1 < f->top[dir_flag] - 30)
        {
             memcpy(f->label,p1,30);
             f->label[39] = '\0';
        }
#endif
#ifdef DEBUG
        fwrite(f->hold_buf[dir_flag], sizeof(char), 
                          (f->top[dir_flag] - f->hold_buf[dir_flag]),
            ((struct dumb_sess *)(f->app_ptr))->logfp);
#endif
        if (((struct dumb_sess *)(f->app_ptr))->last_output
                     != (unsigned char *) NULL)
            free(((struct dumb_sess *)(f->app_ptr))->last_output);
        ((struct dumb_sess *)(f->app_ptr))->last_output =
                     path_out_stuff(f->hold_buf[dir_flag], 
                          (f->top[dir_flag] - f->hold_buf[dir_flag]));
    }
    return;
}
int telnet_app_recognise(frp)
struct frame_con * frp;
{
static int sess_seq;
char fname[28];

    if (frp->prot == E2_TCP)
    {
        unsigned short int from, to;
        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if (from == 23 || to == 23)
        {
            frp->do_mess = do_dumb;
            frp->cleanup = do_cleanup;
            if (from == 23)
                frp->reverse_sense = 1;
            frp->gap = 0;
            sprintf(fname,"path_%d",sess_seq++);
            if ((frp->ofp = fopen(fname,"wb")) == (FILE *) NULL)
                 frp->ofp = stdout;
            frp->app_ptr = (char *) calloc(sizeof(struct dumb_sess),1);
#ifdef DEBUG
            sprintf(fname,"screen_%d",sess_seq);
            if ((((struct dumb_sess *) (frp->app_ptr))->logfp =
                     fopen(fname,"wb")) == (FILE *) NULL)
                ((struct dumb_sess *) (frp->app_ptr))->logfp =stdout;
#endif
            return 1;
        }
    }
    return 0;
}

/*
 * Capture the user responses from the Glasgow OpenDoor Block Mode(?) terminal
 * emulation.
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
struct ps_sess {
unsigned char * last_input; 
unsigned char * last_output; 
FILE * logfp;
};
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
register struct ps_sess * rop = (struct ps_sess *) frp->app_ptr;

    if (rop != (struct ps_sess *) NULL)
    {
        if (rop->last_input != (char *) NULL)
            free(rop->last_input);
        if (rop->last_output != (char *) NULL)
            free(rop->last_output);
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
 * Routine to pre-process information from incoming and outgoing
 * buffers so that it can be parsed (stuff the |)
 */
static unsigned char * pipe_stuff(in, len)
unsigned char * in;
int len;
{
unsigned char buf[8192];                 /* Bigger than a single TCP message */
register unsigned char *x1=in, *x2=buf;

    while (len-- > 0)
    {
        if (*x1 == (unsigned char) '|')
            *x2++ = (unsigned char) '\\';
        *x2++ = *x1++;
    }
    if (x2 <= &buf[0])
        return (char *) NULL;
    else
    {
        *x2 = (unsigned char) '\0';
        return (unsigned char *) strdup((char *) (&buf[0]));
    }
}
/******************************************************************************
 * Extract response times from Glasgow OpenDoor Network Traces
 */
static void do_ps(f, dir_flag)
struct frame_con * f;
int dir_flag;
{
unsigned char * p1, * p2, *p3;
int i;
static struct bm_table * bp;

    if (bp == (struct bm_table *) NULL)
        bp = bm_compile("Screen name : ");
    if ((!dir_flag) ^ f->reverse_sense) /* User Input */
    {
        if (((struct ps_sess *)(f->app_ptr))->last_input !=
                  (unsigned char *) NULL)
        {
/*
 * Set uyp the response details
 */
            for (p1 = (unsigned char *) &f->label[0];
                      *p1 != '}' && *p1 != '\0';
                             p1++);
            if (*p1 == '\0')
                *p1 = '}';
            p1++;
            for (i = 10, p2 = ((struct ps_sess *)(f->app_ptr))->last_input;
                   i > 0 && *p2 != '\0';
                            p1++, p2++, i--)
                 *p1 = *p2;
            *p1 = '}';
            p1++;
            if (((struct ps_sess *)(f->app_ptr))->last_output !=
                  (unsigned char *) NULL)
            {
                for (i = 10, p2 = ((struct ps_sess *)(f->app_ptr))->last_output;
                       i > 0 && *p2 != '\0';
                            p1++, p2++, i--)
                     *p1 = *p2;
            }
            *p1 = '\0';
            output_response(f, dir_flag); /* The last response */
            free(((struct ps_sess *)(f->app_ptr))->last_input);
            ((struct ps_sess *)(f->app_ptr))->last_input =
                     (unsigned char *) NULL;
        }
        if (f->top[dir_flag] != f->hold_buf[dir_flag])
            ((struct ps_sess *)(f->app_ptr))->last_input =
                     pipe_stuff(f->hold_buf[dir_flag],
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
        if ((p1 = bm_match(bp,f->hold_buf[dir_flag], f->top[dir_flag]))
              != (unsigned char *) NULL)
        {
            p1 += 20;
            for (p2 = p1; p2 < f->top[dir_flag] && *p2 > 30; p2++);
            memcpy(f->label, p1, (p2 - p1));
            p2 = &(f->label[(p2 - p1)]);
            *p2 = '}';
            p2++;
            *p2 = '\0';
        }
        if ( ((struct ps_sess *)(f->app_ptr))->last_output != (char *) NULL)
             free(((struct ps_sess *)(f->app_ptr))->last_output);
        if (f->top[dir_flag] != f->hold_buf[dir_flag])
            ((struct ps_sess *)(f->app_ptr))->last_output =
                     pipe_stuff(f->hold_buf[dir_flag],
                          (f->top[dir_flag] - f->hold_buf[dir_flag]));
    }
    return;
}
int ps_app_recognise(frp)
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
            frp->do_mess = do_ps;
            frp->cleanup = do_cleanup;
            if (from == 23)
                frp->reverse_sense = 1;
            frp->gap = 0;
            sprintf(fname,"ps_%d",sess_seq++);
            if ((frp->ofp = fopen(fname,"wb")) == (FILE *) NULL)
                 frp->ofp = stdout;
            frp->app_ptr = (char *) calloc(sizeof(struct ps_sess),1);
            return 1;
        }
    }
    return 0;
}

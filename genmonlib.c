/*
 * Scan a network trace and naively calculate response times
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
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */
static int match_port[100];    /* List of ports to match against          */

static int match_cnt;              /* Number of ports in the list    */
static void gen_match_add(port)
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
    if ((x = getenv("E2_GEN_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)
                gen_match_add(i);
        }
    }
    return;
}
#ifdef USE_PORTS
static int gen_match_true(from,to)
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
#else
/*
 * From and to are IP addresses in network order; check for Rushden
 */
static int gen_match_true(from,to)
unsigned int from;
unsigned int to;
{
/* Bigendian     if ((from & 0x0a6e4100) == 0x0a6e4100) */
    if ((from & 0x416e0a) == 0x416e0a)
        return 1;
    else
/* Bigendian    if ((to & 0x0a6e4100) == 0x0a6e4100) */
    if ((to & 0x416e0a) == 0x416e0a)
        return -1;
    else
        return 0; /* Broadcast only? */
}
#endif
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
register struct dumb_sess * rop = (struct dumb_sess *) frp->app_ptr;

    if (rop != (struct dumb_sess *) NULL)
    {
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
 * Routines to prepare response label
 */
static unsigned char * in_human(frp, in, len)
struct frame_con * frp;
unsigned char * in;
int len;
{
unsigned char * ep;

    (void) hexin_r(in, (len < 16) ? len : 16, frp->label, frp->label + 39) ;
    return frp->label;
}
/*
 * Calculate response times
 */
static void do_dumb(f, dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval el_diff;
int i;
unsigned char * p1;

    if ((!dir_flag) ^ f->reverse_sense) /* User Input */
    {
        if (((struct dumb_sess *)(f->app_ptr))->last_input !=
                  (unsigned char *) NULL)
        {
            if (((struct dumb_sess *)(f->app_ptr))->last_output !=
                  (unsigned char *) NULL)
            {
                strncpy(f->label,
                      ((struct dumb_sess *)(f->app_ptr))->last_input,
                    sizeof(f->label) - 1);
                f->label[39] = '\0';
                output_response(f, dir_flag); /* The last response */
                tvdiff(&(f->ini_t[dir_flag].tv_sec),&
                           (f->ini_t[dir_flag].tv_usec),
                   &(f->ini_t[!dir_flag].tv_sec),&(f->ini_t[!dir_flag].tv_usec),
                   &(el_diff.tv_sec), &(el_diff.tv_usec));
            }
            ((struct dumb_sess *)(f->app_ptr))->last_input =
                     (unsigned char *) NULL;
        }
        if (f->top[dir_flag] != f->hold_buf[dir_flag])
            ((struct dumb_sess *)(f->app_ptr))->last_input =
                     in_human(f, f->hold_buf[dir_flag],
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
        ((struct dumb_sess *)(f->app_ptr))->last_output =
                     (char *) (f->hold_buf[dir_flag]);
    }
    return;
}
int gen_app_recognise(frp)
struct frame_con * frp;
{
int i;
char fname[28];

    if (extend_listen_flag == 0)
        extend_listen_list();
    if (frp->prot == E2_TCP)
    {
#ifdef USE_PORTS
    unsigned short int from, to;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
#else
    unsigned int from, to;

        memcpy(&to, &(frp->net_to[1]), 4);
        memcpy(&from, &(frp->net_from[1]), 4);
#endif
        if ((i = gen_match_true(from, to)))
        {
            frp->do_mess = do_dumb;
            frp->cleanup = do_cleanup;
            if (i < 0)
                frp->reverse_sense = 1;
            frp->gap = 0;
            frp->ofp = stdout;
            frp->app_ptr = (char *) calloc(sizeof(struct dumb_sess),1);
            return 1;
        }
    }
    return 0;
}

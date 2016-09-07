/*
 * Scan a snoop file and report the SMB elements.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 2001";
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
#include "smb.h"
static void mess_handle();
static void do_smb();
/*
 * Structure allocated when a session is started that holds session state.
 *
 * This code handles multiple parallel sessions, but may not handle
 * asynchronous SQL calls.
 */
struct smb_context {
    struct frame_con * syb_frame;  /* Place for assembling Sybase messages */
};
static struct frame_con * cur_frame;
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
struct smb_context * rop = (struct smb_context *) frp->app_ptr;

    if (rop != (struct smb_context *) NULL
     && rop->syb_frame != (struct frame_con *) NULL)
    {
        rop->syb_frame->cleanup(rop->syb_frame);
        free((char *) rop->syb_frame);
    }
    return;
}
/*
 * Set up the control structure for Sybase TDS embedded in SMB
 */
struct frame_con * smb_syb_setup(frp, reverse_flag)
struct frame_con * frp;
int reverse_flag;
{
struct frame_con * un = (struct frame_con *) malloc(sizeof(struct frame_con));

    *un = *frp;
    un->last_out = -1;    /* To trigger "not the same" processing first time */
    un->last_app_out = -1;
                          /* To trigger "not the same" processing first time */
    un->event_id = 0;
    un->corrupt_flag = 0;
    syb_app_initialise(un, reverse_flag, frp);
    return un;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int smb_app_recognise(frp)
struct frame_con *frp;
{
static int sess_cnt = 0;
char fname[32];
int i;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is 139
 */
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;
    struct smb_context * smbp;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if (to == 139 || from == 139)
        {
            sprintf(fname,"smb_%d.txt", sess_cnt++);
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            if (from == 139)
                frp->reverse_sense = 1;
            frp->app_ptr = calloc(sizeof(struct smb_context),1);
            smbp = (struct smb_context *) (frp->app_ptr);
            smbp->syb_frame = smb_syb_setup(frp, (from == 139) ? -1 : 1);
            frp->off_flag = 2;
            frp->len_len = 2;
            frp->big_little = 0;
            frp->fix_size = 4;
            frp->fix_mult = 1;
            frp->do_mess = do_smb;
            frp->cleanup = do_cleanup;
            frp->gap = 0;           /* Anything over 10 seconds is slow */
            return 1;
        }
    }
    return 0;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum()
 */
static void do_smb(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
unsigned char * p;
int last_frag;
int tran_len;
int len;
struct smb_context * smbp;
unsigned char * words;
unsigned char * data;
/*
 * SMB blocks are structured as:
 * - A 32 byte header
 * - A list of code words
 * - Corresponding blocks of data.
 *
 * We only want:
 * - Message types SMBwriteX and SMBreadX (although I am curious about the
 *   SMBopenX as well)
 * - Messages with useful data.
 * Everything else is ignored
 */
    p = frp->hold_buf[dir_flag];
    if ( frp->top[dir_flag] -  p  < 40)
        return;
    words = p  + 36;
    data = words + 1 + 2*(*words);
    if (data >= frp->top[dir_flag])
        return;
    cur_frame = frp;
    smbp = (struct smb_context *) (frp->app_ptr);
    switch(*(p + 8))
    {
    case '.':         /* SMBreadX */
    case '/':         /* SMBwriteX */
#ifdef DEBUG
        if (*p == '.')
            fputs("SMBreadX\n", frp->ofp);
        else
            fputs("SMBwriteX\n", frp->ofp);
        gen_handle(frp->ofp, data + 3, frp->top[dir_flag], 1);
#endif
/*
 * There is no logic to process the message if we have not at least got the
 * fixed size header. The assumption is that the message is not actually a
 * Sybase message if its data length is less than 8.
 */ 
        if (frp->top[dir_flag] > data + 9 )
        {
            if (*data == *(data + 5))
                data += 2;
            else
                data += 3;
            smbp->syb_frame->hold_buf[dir_flag] = data;
            smbp->syb_frame->top[dir_flag] = frp->top[dir_flag];
            smbp->syb_frame->last_t[dir_flag] = frp->last_t[dir_flag];
            smbp->syb_frame->cnt[dir_flag] = frp->cnt[dir_flag];
            smbp->syb_frame->len[dir_flag] = frp->len[dir_flag];
            smbp->syb_frame->do_mess(smbp->syb_frame, dir_flag);
        }
        break;
    default:
#ifdef DEBUG
        print_smb(frp->ofp,  p + 4, frp->top[dir_flag]); */
#endif
        break;
    }
    return;
}

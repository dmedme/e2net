/*
 * Scan a snoop file and pull out the CODA Client Server elements
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
#include <time.h>
#include "e2conv.h"
#include "e2net.h"
static struct frame_con * cur_frame;
static void do_coda();
static void coda_handle();
static void cod_match_add();
static int cod_match_true();
/*
 * Structure allocated when a session is started that holds CODA session state.
 *
 * At the moment, we do not have any.
 */
struct coda_sess {
    int out_curs;     /* We assume that there is only one outstanding at once */
    int out_len;      /* How big it is to be                                  */
    char * long_bind;
};
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
    {
        fclose(frp->ofp);
        frp->ofp = (FILE *) NULL;
    }
    return;
}
static int extend_listen_flag; /* Feed in extra listener ports            */ 
/*
 * Allow extra listener ports to be specified in the environment
 */
static void extend_listen_list()
{
char * x;
int i;
    extend_listen_flag = 1;
    if ((x = getenv("E2_COD_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
                cod_match_add(i);
        }
    }
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int cod_app_recognise(frp)
struct frame_con *frp;
{
static int sess_cnt = 0;
char fname[32];
struct frame_con * prv_ptr;
char * x1, * x2;
int i;

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is one of the listeners (6002 or whatever)
 * 3857 = 0x911E = 37150 = -28386
 * 4119 = 0x9720 = 38688 = -26848
 * 3949 = 0xED1E = 60702 = -4834
 * 4246 =
 * The algorithm appears to be:
 * - Clear the sign bit; the high byte is now the low order byte of the port.
 * - Shift the low order byte left 1, but do not lose the least significant bit
 *   if it is set. The result is the high order byte of the port. Is this real? 
 */
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;

        if (!extend_listen_flag)
        {
            extend_listen_list();
            cod_match_add(6002);
            cod_match_add(3857);
            cod_match_add(3949);
            cod_match_add(4119);
            cod_match_add(4246);
        }
        memcpy((char *) &to, &(frp->port_to[1]), 2);
        memcpy((char *) &from, &(frp->port_from[1]), 2);
        if (( i = cod_match_true(from, to)))
        {
        struct in_addr x3;

            memcpy((char *) &x3, &(frp->net_from[1]), sizeof(long));
            x1 = strdup(inet_ntoa(x3));
            memcpy((char *) &x3, &(frp->net_to[1]), sizeof(long));
            x2 = strdup(inet_ntoa(x3));
            sprintf(fname,"coda_%d.msg", sess_cnt++);
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            fprintf(frp->ofp, "\\M:%s;%d:%s;%d\\\n", x1, from,  x2, to);
            free(x1);
            free(x2);
            if (i < 0)
                frp->reverse_sense = 1; 
            frp->off_flag = 14;   /* The length is offset 14 bytes */
            frp->len_len = 2;     /* The length is two bytes */
            frp->big_little = 0;
            frp->fix_size = 16;   /* 16 byte message header  */
            frp->fix_mult = 1;    /* The header is not included in the length */
            frp->do_mess = do_coda;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) NULL;
            return 1;
        }
    }
    return 0;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum()
 */
static void do_coda(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
    cur_frame = frp;
    (void) coda_handle(frp->ofp,
               frp->hold_buf[dir_flag], frp->top[dir_flag],
                    (!dir_flag) ^ frp->reverse_sense);
    return;
}
static void coda_handle(fp, x,top,out)
FILE *fp;
unsigned char * x;
unsigned char * top;
int out;
{
int curs;
int op_code;
int i, j;
unsigned char * x1;
    if (cur_frame->port_from[1] == 0x17        
     && cur_frame->port_from[2] == 0x72 /* CODA listener port = 6002 */
     && *x == 0x02
     && *(x+14) == 0x0
     && *(x+15) == 0x11)
    {
/*
 * This is a message from the CODA listener, telling us the port to use for
 * our application server. The following calculation purports to give us the
 * actual port number.
 */
        i = (*(x+16) & 0x7f) + 256*((*(x+17)>>1) | ((*(x + 17) & 0x1)));
        cod_match_add(i);
    }
    (void) gen_handle(fp, x,top, out);
    return;
}
/***********************************************************************
 * The following logic lists sessions where the port number is identified as
 * a CODA listener
 */
static int match_port[100];  /* List of ports to match against            */

static int match_cnt;        /* Number of ports in the list               */
static void cod_match_add(port)
int port;
{
    if (match_cnt < 100)
    {
       match_port[match_cnt] = port;
       match_cnt++;
    }
    return;
}
int cod_match_true(from,to)
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
                return 1;
            else
                return -1;
        }
    }
    return 0;
}

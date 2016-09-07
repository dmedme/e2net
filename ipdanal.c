/*
 *    ipdanal.c - Program to generate tables from traffic definition files.
 *
 * There are many possible outputs:
 * 1 - A matrix showing traffic by link, in, out and both, packets and bytes:
 *     - either by second
 *     - or by event
 * 2 - Percentiles on packet sizes, in, out and combined.
 * 3 - If a network benchmark log file is provided
 *     - The events, in one file
 *     - The TR pairs, turned into events, in the other
 *     in both cases, optionally with a tag pre-pended to the run ID
 *
 *    Copyright (C) E2 Systems 1995
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (C) E2 Systems Limited 1995";
#include <sys/types.h>
#ifndef MINGW32
#include <sys/socket.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>
#include <string.h>
#ifdef PYR
#include <strings.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#ifdef PYR
#include <strings.h>
#endif
#include <math.h>
#include "e2net.h"
#include "hashlib.h"
#include "ipdrive.h"
extern char * nextasc();
extern double strtod();
/*
 * Message handling routines
 */
static void do_end_point();
static void add_result();
static void do_send_receive();
static void do_delay();
/*
 * Other functions defined here
 */
static void colcntres();
static void do_page();
static struct path_rec * do_trf_file();
static struct path_rec * get_next();
static void write_next();
static void output_traffic_summary();
static LINK * link_find();
static char *fname;
/*
 * Static data
 */
static double save_time;
static double cur_time;
static int page_no;
static int line_cnt = 100;

static LINK link_det[MAXLINKS];
                             /* list of links in the input file */

static END_POINT end_point_det[MAXENDPOINTS],
                             /* list of links in the input file */
         * ep_cur_ptr = end_point_det,
         * ep_max_ptr = &end_point_det[MAXENDPOINTS-1];

static struct ipdanal_base {
    char * extra;
    FILE * ifpl;           /* Network Benchmark input Log file             */
    FILE * ofpe;           /* Network Benchmark Output Event file          */
    FILE * ofpm;           /* Network Benchmark Output Message Timing file */
    int iactor_id;         /* Actor used for timing analysis               */
} ipdanal_base;
/***************************************************************
 * Routines that control the collection of timings.
 */

#define MAX_SESS 2048
 
static int rec_cnt;
static char fld_sep = ' ';

static int double_comp(i,j)
double *i;
double *j;
{
    if (*i == *j)
        return 0;
    else
    if (*i < *j)
        return -1;
    else
        return 1;
}
/*
 * Code for reading a benchmark results file
 */
struct path_rec {
    char *pid;       /* PID */
    int bundle;
    int g;
    int evseq;
    double timestamp;
    char evt[3];
    union {
        struct {
            double timing;
            char * seen;
        } result;
        struct {
            double timing;
            int pack_snt;
            int pack_rcvd;
            int byte_snt;
            int byte_rcvd;
            int pairs;
        } tr;
        struct {
           char evt[3];
           char desc[132];
        } evdef;
    } extra;
};
/*****************************************************************************
 * Read a record from a PATH log file created by the PATH Network Benchmark
 * kit. The record format is a sub-set of that created by dumb-terminal PATH
 * so we do not use the general purpose routines.
 */
static struct path_rec * get_next(ifp)
FILE * ifp;
{
static char buf[2048];
static char pid_buf[132];
static struct path_rec work_sess;
unsigned char * x, *parm;
int i;
/*
 * Come back to this point if corrupt records are encountered
 */
restart:
    if (fgets(buf,sizeof(buf), ifp) == (char *) NULL)
        return 0;
    i = strlen(buf);
    if (i < sizeof(buf))
        buf[i - 1] = '\0';
    memset((char *) &work_sess, 0, sizeof(work_sess));
    work_sess.pid = pid_buf;
    strcpy(pid_buf, nextasc(buf,':','\\'));
    if ((x = nextasc((signed char *) NULL,':','\\')) == (unsigned char *) NULL)
        goto restart; 
    work_sess.bundle = atoi(x); 
    if ((x = nextasc((signed char *) NULL,':','\\')) == (unsigned char *) NULL)
        goto restart; 
    work_sess.g = atoi(x); 
    if ((x = nextasc((signed char *) NULL,':','\\')) == (unsigned char *) NULL)
        goto restart; 
    work_sess.evseq = atoi(x); 
    if ((x = nextasc((signed char *) NULL,':','\\')) == (unsigned char *) NULL)
        goto restart; 
    work_sess.timestamp = strtod( x, (char **) NULL)/100.0; 
    if ((parm =  nextasc((char *) NULL,':','\\')) == (unsigned char *) NULL)
        goto restart;
    strncpy(work_sess.evt, parm, sizeof(work_sess.evt));
    if (!strcmp(work_sess.evt,"A") || !strcmp(work_sess.evt,"Z"))
    {
        if ((parm =  nextasc((char *) NULL,':','\\')) == (unsigned char *) NULL)
            goto restart;
        strncpy(work_sess.extra.evdef.evt, parm,
                             sizeof(work_sess.extra.evdef.evt));
        if ((parm =  nextasc((char *) NULL,':','\\')) == (unsigned char *) NULL)
            goto restart;       /* Timeout (dummy) */
        if ((parm =  nextasc((char *) NULL,':','\\')) == (unsigned char *) NULL)
            goto restart;       /* Look for string (dummy) */
        if ((parm =  nextasc((char *) NULL,':','\\')) == (unsigned char *) NULL)
            goto restart;       /* Response string (dummy) */
        if ((parm =  nextasc((char *) NULL,':','\\')) == (unsigned char *) NULL)
            goto restart;       /* Event description */
        strncpy(work_sess.extra.evdef.desc, parm,
                     sizeof(work_sess.extra.evdef.desc));
    }
    else
    if (strcmp(work_sess.evt,"S") && strcmp(work_sess.evt,"F")
     && strcmp(work_sess.evt,"R") && strcmp(work_sess.evt,"T"))
    {
        if ((x = nextasc((signed char *) NULL,':','\\'))
                         == (unsigned char *) NULL)
            goto restart; 
        work_sess.extra.result.timing = strtod( x, (char **) NULL)/100.0; 
        work_sess.extra.result.seen = nextasc((signed char *) NULL, ':', '\\');
    }
    return &work_sess;
}
/*
 * Write out a PATH log record
 */
static void write_next(ofp, p_rec)
FILE * ofp;
struct path_rec * p_rec;
{
    if (ipdanal_base.extra != (char *) NULL)
        fputs(ipdanal_base.extra, ofp);
    fprintf(ofp, "%s:%d:%d:%.05d:%f:%s",
                    p_rec->pid,
                    p_rec->bundle,
                    p_rec->g,
                    p_rec->evseq,
                    p_rec->timestamp * 100.0,
                    p_rec->evt);
    if (!strcmp(p_rec->evt,"F") || !strcmp(p_rec->evt,"S")
     || !strcmp(p_rec->evt,"R") || !strcmp(p_rec->evt,"T"))
        fputc('\n',ofp);
    else
    if (!strcmp(p_rec->evt,"A") || !strcmp(p_rec->evt,"Z"))
        fprintf(ofp, ":%s:3600:.::%s\n",
                    p_rec->extra.evdef.evt,
                    p_rec->extra.evdef.desc);
    else
    if (!strcmp(p_rec->evt,"TR"))
        fprintf(ofp, ":%f:%d:%d\n",
                    p_rec->extra.tr.timing * 100.0,
                    p_rec->extra.tr.pack_snt,
                    p_rec->extra.tr.pack_rcvd);
    else
        fprintf(ofp, ":%f:%d:%d:%d:%d:%d\n",
                    p_rec->extra.tr.timing * 100.0,
                    p_rec->extra.tr.pairs,
                    p_rec->extra.tr.pack_snt,
                    p_rec->extra.tr.pack_rcvd,
                    p_rec->extra.tr.byte_snt,
                    p_rec->extra.tr.byte_rcvd);
    return;
}
/***********************************************************************
 * Main Program Starts Here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 * The file is processed in sequence. Running time is calculated with
 * reference to the recorded time deltas. Messages are assumed to be
 * transmitted in zero time, since we are looking at DEMAND.
 * Input is on stdin unless a file name is provided; output is on stdout.
 */
int main(argc,argv,envp)
int argc;
char * argv[];
char * envp[];
{
int c;
FILE * ifp;
char buf[BUFSIZ];
struct path_rec *pr = (struct path_rec *) NULL;
/****************************************************
 *    Initialise
 */
    ipdrive_base.verbosity = 0;
    ipdrive_base.event_desc = (char *) NULL;
    ipd_init();
    ifp = (FILE *) NULL;
    ipdanal_base.ifpl = (FILE *) NULL;
    ipdanal_base.ofpe = (FILE *) NULL;
    ipdanal_base.ofpm = (FILE *) NULL;
    ipdanal_base.extra = (char *) NULL;
    ipdanal_base.iactor_id = 0;
    fname="STDIN";
    while ( ( c = getopt ( argc, argv, "hd:tsw:l:a:" ) ) != EOF )
    {
        switch ( c )
        {
        case 'h' :
            (void) fprintf(stderr,"ipdanal: E2 Systems Traffic Analyser\n\
Options:\n\
 -h prints this message on stderr\n\
 -s indicates group traffic by socket pair rather than host pair\n\
 -w logfile indicates a log file should be split into message timings and events\n\
 -l extra indicates that the extra tag should be pre-pended to run ID's\n\
 -a actor_id; analyse the log file from the point of view of this actor\n\
 -d set the debug level (between 0 and 4)\n\
 -t format output for easy import into Microsoft Office\n");
            fflush(stderr);
            break;
        case 'l' :
            ipdanal_base.extra = optarg;
            break;
        case 'w' :
            if ((ipdanal_base.ifpl = fopen(optarg, "rb")) != (FILE *) NULL)
            {
                sprintf(buf, "%s.evt", optarg);
                ipdanal_base.ofpe = fopen(buf, "wb");
                sprintf(buf, "%s.msr", optarg);
                ipdanal_base.ofpm = fopen(buf, "wb");
                if (ipdanal_base.ofpe == (FILE *) NULL
                 || ipdanal_base.ofpm == (FILE *) NULL
                 || (pr = get_next(ipdanal_base.ifpl))
                        == (struct path_rec *) NULL)
                {
                    fclose(ipdanal_base.ifpl);
                    ipdanal_base.ifpl = (FILE *) NULL;
                    if (ipdanal_base.ofpe != (FILE *) NULL)
                    {
                        fclose(ipdanal_base.ofpe);
                        ipdanal_base.ofpe = (FILE *) NULL;
                    }
                    if (ipdanal_base.ofpm != (FILE *) NULL)
                    {
                        fclose(ipdanal_base.ofpm);
                        ipdanal_base.ofpm = (FILE *) NULL;
                    }
                }
            }
            break;
        case 'd' :
            ipdrive_base.debug_level = atoi(optarg);
            break;
        case 's' :
            ipdrive_base.verbosity = 1;
            break;
        case 't' :
            ipdrive_base.excel_flag = 1;
            break;
        default:
        case '?' : /* Default - invalid opt.*/
            (void) fprintf(stderr,"Invalid argument; try -h\n");
            exit(1);
        } 
    }
    if (optind < argc)
        ifp = fopen(argv[optind], "rb");
    if (ifp == (FILE *) NULL)
        ifp = stdin;
    else
        fname = argv[optind];
/*
 * The following logic requires that the file starts as usual with an S.
 * The synchronisation is probably meaningless if it does not.
 */
    if (ipdanal_base.ifpl != (FILE *) NULL && !strcmp(pr->evt, "S"))
    {                 /* Deal with the 'S' record at the beginning */
        write_next(ipdanal_base.ofpe, pr);
        write_next(ipdanal_base.ofpm, pr);
        pr->evt[0] = 'A';
        strcpy(pr->extra.evdef.evt,"TR");
        strcpy(pr->extra.evdef.desc,"Send/Receive Pair");
        write_next(ipdanal_base.ofpm, pr);
        pr = get_next(ipdanal_base.ifpl);
    }
/*
 * Handle control file data.
 */
    while ((pr = do_trf_file(ifp, pr)) != (struct path_rec *) NULL)
    {
        fseek(ifp,0,0);
        while (pr != (struct path_rec *) NULL
          && (!strcmp(pr->evt, "F") || !strcmp(pr->evt, "S")))
            pr = get_next(ipdanal_base.ifpl);
    }
/*
 * Finished the file. Now output the results to stdout
 */
    output_traffic_summary(stdout);
    exit(0);
}
/*****************************************************************************
 * Make a cycle through a network script file. Only output the details the
 * first time through.
 */
struct path_rec * do_trf_file(ifp, pr)
FILE * ifp;
struct path_rec *  pr;
{
LINK * cur_link;
union all_records in_buf;
struct ipd_rec * rec_type;
struct path_rec t_rec;
struct path_rec a_rec;
static int not_first;             /* Flag to control .trf file output        */
int k;

    if (pr != (struct path_rec *) NULL)
        t_rec = *pr;
    else
        memset((char *) &t_rec, 0, sizeof(t_rec));
    memset((char *) &a_rec, 0, sizeof(a_rec));
    t_rec.extra.tr.pack_rcvd = 1;  /* Bootstrap flag value */
    t_rec.evt[0] = '\0';
    while ((rec_type = ipdinrec(ifp,&in_buf)) != (struct ipd_rec *) NULL)
    {
        rec_cnt++;
        if (ipdrive_base.debug_level > 2)
        {
            (void) fprintf(stderr,"Control File Service Loop\n");
            (void) fprintf(stderr,"=========================\n");
            fprintf(stderr,"Line: %d Record Type: %s\n",
                   rec_cnt, rec_type->mess_name);
            if (pr != (struct path_rec *) NULL)
                write_next(stderr,pr);
        }
        switch(rec_type->mess_id)
        {
        case END_POINT_TYPE:
/*
 * Add the end point to the array
 */
            if (!not_first)
                do_end_point(&in_buf);
            break;
        case SEND_RECEIVE_TYPE:
            if (pr != (struct path_rec *) NULL
     && (end_point_det[in_buf.send_receive.ifrom_end_point_id].iactor_id
                         == ipdanal_base.iactor_id
      || end_point_det[in_buf.send_receive.ito_end_point_id].iactor_id
                         == ipdanal_base.iactor_id))
            {
                if (!strcmp(pr->evt, "T"))
                {
                    if (t_rec.extra.tr.pack_rcvd)
                    {
                        if (t_rec.evt[0] == 'T')
                        {
                            write_next(ipdanal_base.ofpm, &t_rec);
                            a_rec.extra.tr.pairs++;
                            a_rec.extra.tr.pack_rcvd +=
                                t_rec.extra.tr.pack_rcvd;
                            a_rec.extra.tr.pack_snt +=
                                t_rec.extra.tr.pack_snt;
                            a_rec.extra.tr.byte_rcvd +=
                                t_rec.extra.tr.byte_rcvd;
                            a_rec.extra.tr.byte_snt +=
                                t_rec.extra.tr.byte_snt;
                        }
                        t_rec = *pr;
                        strcpy(t_rec.evt, "TR");
                    }
                    t_rec.extra.tr.byte_snt += in_buf.send_receive.imessage_len;
                    t_rec.extra.tr.pack_snt++;
                }
                else
                if (!strcmp(pr->evt, "R"))
                {
                    t_rec.extra.tr.byte_rcvd +=
                                 in_buf.send_receive.imessage_len;
                    t_rec.extra.tr.timing =pr->timestamp - t_rec.timestamp;
                    t_rec.extra.tr.pack_rcvd++;
                }
                pr = get_next(ipdanal_base.ifpl);
            }
            if (!not_first)
                do_send_receive(&in_buf);
            break;
        case DELAY_TYPE:
            if (!not_first)
                do_delay(&in_buf);
            break;
        case START_TIMER_TYPE:
            if (!not_first)
            {
                strtok ( &in_buf.start_timer.timer_description[0], "\r\n");
                if (line_cnt > 62)
                    do_page();
                printf("BEGIN: %.2s : %.80s\n", in_buf.start_timer.timer_id,
                                 in_buf.start_timer.timer_description);
                for (k= 0, cur_link = &link_det[0];
                         cur_link->link_id ;
                             cur_link++)
                    colcntres(&(cur_link->event_det));
                if (ipdrive_base.event_desc != (char *) NULL)
                    free(ipdrive_base.event_desc);
                ipdrive_base.event_desc =
                              strdup(in_buf.start_timer.timer_description);
                memset((char *) &a_rec, 0, sizeof(a_rec));
            }
            if (pr != (struct path_rec *) NULL)
            {
                if (strcmp(pr->evt, "A")
                  || strcmp(in_buf.start_timer.timer_id, pr->extra.evdef.evt))
                {
                    fprintf(stderr,
                             "Logic Error: Start timer %s does not match log\n",
                                   in_buf.start_timer.timer_id);
                    write_next(stderr, pr);
                }
                write_next(ipdanal_base.ofpe, pr);
                pr = get_next(ipdanal_base.ifpl);
            }
            break;
        case TAKE_TIME_TYPE:
        {
        char timer_id[3];

            strncpy(timer_id, in_buf.take_time.timer_id, sizeof(timer_id));
            timer_id[2] = '\0';
            if (!not_first)
            {
                in_buf.delay.fdelta = 1.0;
                do_delay(&in_buf); 
                printf("END: %.2s : %s : ", timer_id, ipdrive_base.event_desc);
                for (k= 0, cur_link = &link_det[0];
                          cur_link->link_id ;
                              cur_link++)
                {
                    printf(" %c%5.1d  %c%7.1f",
                        fld_sep,cur_link->event_det.cnt,
                        fld_sep,cur_link->event_det.tot);
                    k++;
                }
                putchar('\n');
            }
            if (pr != (struct path_rec *) NULL)
            {
                if (strcmp(timer_id, pr->evt))
                {
                    fprintf(stderr,
                             "Logic Error: End timer %s does not match log\n",
                                   timer_id);
                    write_next(stderr, pr);
                }
                if (t_rec.evt[0] == 'T')
                {
                    write_next(ipdanal_base.ofpm, &t_rec);
                    a_rec.extra.tr.pairs++;
                    a_rec.extra.tr.pack_rcvd +=
                                t_rec.extra.tr.pack_rcvd;
                    a_rec.extra.tr.pack_snt +=
                                t_rec.extra.tr.pack_snt;
                    a_rec.extra.tr.byte_rcvd +=
                                t_rec.extra.tr.byte_rcvd;
                    a_rec.extra.tr.byte_snt +=
                                t_rec.extra.tr.byte_snt;
                    t_rec.evt[0] = '\0';
                    t_rec.extra.tr.pack_rcvd = 1;  /* Bootstrap flag value */
                }
                pr->extra.tr.pairs = a_rec.extra.tr.pairs;
                pr->extra.tr.pack_rcvd = a_rec.extra.tr.pack_rcvd;
                pr->extra.tr.pack_snt = a_rec.extra.tr.pack_snt;
                pr->extra.tr.byte_rcvd = a_rec.extra.tr.byte_rcvd;
                pr->extra.tr.byte_snt = a_rec.extra.tr.byte_snt;
                write_next(ipdanal_base.ofpe, pr);
                pr = get_next(ipdanal_base.ifpl);
            }
            break;
        }
        }
    }
    if (t_rec.evt[0] == 'T')
        write_next(ipdanal_base.ofpm, &t_rec);
/*
 * Flush out the last second
 */
    in_buf.delay.fdelta = 1.0;
    do_delay(&in_buf); 
    not_first = 1;
    return pr;
}
/******************************************************************************
 * Write the packet shape summary
 */
static void output_traffic_summary(ofp)
FILE * ofp;
{
LINK * cur_link;
struct collcon * un;
int i;
int j;
#ifdef DEBUG
    fprintf(stderr,"Ready to Output Timings\n");
    fflush(stderr);
#endif
    do_page();
    printf("Packet Size Distribution Summary - Run %4.0f seconds\n", cur_time);
    printf("=========================================\n");
#ifdef DO_95
    printf("%-44.44s %5.5s %5.5s %5.5s %5.5s %5.5s %5.5s %5.5s %5.5s %5.5s \
%5.5s %5.5s %5.5s %5.5s %5.5s %5.5s\n",
           "Description",
           "Count",
           "Avge",
           "SD",
           "95%",
           "Min",
           "10%","20%","30%","40%","50%","60%","70%","80%","90%","Max");
#else
    printf("%-44.44s%c%5.5s%c%5.5s%c%5.5s%c%5.5s%c%5.5s%c%5.5s%c%5.5s\
%c%5.5s%c%5.5s%c%5.5s%c%5.5s%c%5.5s%c%5.5s%c%5.5s\n",
           "Description",fld_sep, "Count",fld_sep, "Avge",fld_sep,
           "SD",fld_sep, "Min",fld_sep, "10%",fld_sep,"20%",fld_sep,
           "30%",fld_sep,"40%",fld_sep,"50%",fld_sep,"60%",fld_sep,
           "70%",fld_sep,"80%",fld_sep,"90%",fld_sep,"Max");
#endif
    for (cur_link = &link_det[0]; cur_link->link_id; cur_link++)
    {
    double av,sd,mn,pc1,pc2,pc3,pc4,pc5,pc6,pc7,pc8,pc9,mx,c,pc95;
    double *x, *y, *sa, *sortlist;
    struct timbuc * tb;

        for (j = 0; j < 3; j++)
        {
            if (j == 0)
                un = &(cur_link->out_det);
            else
                un = &(cur_link->in_det);
            if (un->glob_cnt == 0)
                continue;
            fflush(stdout);
            if ((sortlist = (double *)
                   malloc( un->glob_cnt * sizeof(double))) == (double *) NULL)
            {
                 fprintf(stderr,"Packet size malloc() failed\n");
                 exit(1);
            }
            for (x = sortlist,
                 tb = un->first_buc;
                     tb != (struct timbuc *) NULL;
                          tb = tb->next_buc)
            {
                 if (tb->buc_cnt <= 0)
                 {
                     (void) fprintf(stderr,"Corrupt result buffer\n");
                     abort();
                 }
                 for (i = 0, y = &(tb->duration[0]); i < tb->buc_cnt; i++)
                     *x++ = *y++;
            }
            qsort(sortlist,un->glob_cnt,sizeof(double),double_comp); 
            mn = floor( 100.0 * un->glob_min+.5)/100.0;
            mx = floor( 100.0 * un->glob_max+.5)/100.0;
            av = floor( 100.0 * un->glob_tot/un->glob_cnt+.5)/100.0;
            if ( (un->glob_tot2 - un->glob_tot/un->glob_cnt*un->glob_tot) >
                   (double) 0.0)
                sd = floor( 100.0 * sqrt(un->glob_tot2 - un->glob_tot/
                                         un->glob_cnt*un->glob_tot)
                                         /un->glob_cnt+.5)/ 100.0;
            else
                sd = (double) 0.0;
            c = (double) un->glob_cnt;
            sa = sortlist + (int)floor(.1*c);
            pc1 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.2*c);
            pc2 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.3*c);
            pc3 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.4*c);
            pc4 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.5*c);
            pc5 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.6*c);
            pc6 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.7*c);
            pc7 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.8*c);
            pc8 = floor(*sa * 100.0+.5)/100.0;
            sa = sortlist + (int)floor(.9*c);
            pc9 = floor(*sa * 100.0+.5)/100.0;
#ifdef DO_95
            sa = sortlist + (int)floor(.95*c);
            pc95 = floor(*sa * 100.0+.5)/100.0;
            printf("%-3.3s:%-64.64s%c%5.1d%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f\
%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f\n",
                  (j == 0) ? "OUT" :((j == 1) ? "IN" : "ALL"),
                  cur_link->desc,fld_sep, un->glob_cnt,fld_sep,
                  av,fld_sep,sd,fld_sep,pc95,fld_sep,mn,fld_sep,pc1,fld_sep,
                  pc2,fld_sep,pc3,fld_sep,pc4,fld_sep,pc5,fld_sep,pc6,fld_sep,
                  pc7,fld_sep,pc8,fld_sep,pc9,fld_sep,mx);
#else
            printf("%-3.3s:%-64.64s%c%5.1d%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f\
%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f%c%5.2f\n",
                  (j == 0) ? "OUT" :((j == 1) ? "IN" : "ALL"),
                  cur_link->desc,fld_sep, un->glob_cnt,fld_sep,
                  av,fld_sep,sd,fld_sep,mn,fld_sep,pc1,fld_sep,
                  pc2,fld_sep,pc3,fld_sep,pc4,fld_sep,pc5,fld_sep,pc6,fld_sep,
                  pc7,fld_sep,pc8,fld_sep,pc9,fld_sep,mx);
#endif
            cur_link->desc[0] = '\0';   /* Suppress description hereafter */
            free(sortlist);
            if (j == 1)
            {
                if (cur_link->out_det.glob_cnt == 0)
                    break;
                un->glob_cnt += cur_link->out_det.glob_cnt;
                un->glob_tot += cur_link->out_det.glob_tot;
                un->glob_tot2 += cur_link->out_det.glob_tot2;
                if (un->glob_max < cur_link->out_det.glob_max)
                    un->glob_max = cur_link->out_det.glob_max;
                if (un->glob_min > cur_link->out_det.glob_min)
                    un->glob_min = cur_link->out_det.glob_max;
                for (tb = un->first_buc;
                     tb->next_buc != (struct timbuc *) NULL;
                          tb = tb->next_buc);
                tb->next_buc = cur_link->out_det.first_buc;
            }
            line_cnt++;
        }
    }
}
/*****************************************************************************
 * Process a .trf End Point record
 */
static void do_end_point(a)
union all_records * a;
{
/*
 * Add the end point to the array
 * Go and set up the end-point, depending on what it is.
 */
    if (a->end_point.iend_point_id < 0 ||
         a->end_point.iend_point_id  > MAXENDPOINTS)
                       /* Ignore if out of range */
        return;
    end_point_det[a->end_point.iend_point_id] = a->end_point;
    return;
}
/*
 * Find the link, given the from and to
 */
static LINK * link_find(from_end_point_id, to_end_point_id)
int from_end_point_id;
int to_end_point_id;
{
    LINK * cur_link;
    if (ipdrive_base.debug_level > 1)
        (void) fprintf(stderr,"link_find(%d,%d)\n",
                    from_end_point_id,to_end_point_id);
    for (cur_link = &link_det[0];
                cur_link->link_id != 0;
                     cur_link++)
        if ((ipdrive_base.verbosity && 
          ((cur_link->from_ep->iend_point_id == from_end_point_id
          && cur_link->to_ep->iend_point_id == to_end_point_id)
         || (cur_link->from_ep->iend_point_id == to_end_point_id
          && cur_link->to_ep->iend_point_id == from_end_point_id)))
        || (!ipdrive_base.verbosity && 
          ((!strcmp(cur_link->from_ep->address,
                   end_point_det[from_end_point_id].address)
          && !strcmp(cur_link->to_ep->address,
                     end_point_det[to_end_point_id].address))
          || (!strcmp(cur_link->from_ep->address,
                   end_point_det[to_end_point_id].address)
          && !strcmp(cur_link->to_ep->address,
                     end_point_det[from_end_point_id].address)))))
            break;
    return cur_link;
}
/******************************************************************************
 * Reset the counters in a collcon structure
 */
static void colcntres(tcon)
struct collcon * tcon;
{
    tcon->cnt = 0;
    tcon->tot = 0.0;
    tcon->tot2 = 0.0;
    tcon->min = 99999999;
    tcon->max  = 0.0;
    return;
}
/*
 * Add a result to a collcon-headed chain, adding
 * another result bucket if needed
 */
static void add_result(un, len)
struct collcon * un;
int len;
{
    un->cnt++;
    un->tot += len;
    un->tot2 += (len * len);
    if ( len > un->max)
        un->max = len;
    if ( len < un->min)
        un->min = len;
    un->glob_cnt++;
    un->glob_tot += len;
    un->glob_tot2 += (len * len);
    if ( len > un->glob_max)
        un->glob_max = len;
    if ( len < un->glob_min)
        un->glob_min = len;
    if (un->first_buc == (struct timbuc *) NULL ||
        un->first_buc->buc_cnt >= 32)
    {
        struct timbuc * x;
        if ((x = (struct timbuc *) malloc(sizeof(struct timbuc))) ==
           (struct timbuc *) NULL)
        {
             fprintf(stderr,"timbuc malloc() failed\n");
             exit(1);
        }
        x->next_buc = un->first_buc;
        x->buc_cnt = 0;
        un->first_buc = x;
    }
    un->first_buc->duration[un->first_buc->buc_cnt++] = (double) len;
    return;
}
/***********************************************************************
 * Process Send/Receive messages
 * The physical link overhead will be different on the different segments
 * and links of the network. We assume 14; 2 6 byte Ethernet address,
 * a 2 byte type field
 * What about a 2 byte length field and a 4 byte CRC? Many
 * Ethernet cards have a 60 character minimum packet size anyway. 
 */
#define PHYS_OVER 14
static void do_send_receive(msg)
union all_records * msg;
{
LINK * cur_link;
int head_size;
struct collcon * un, *uno;
static char x[65536];
int len;
int done;
int socket_flags = 0;

    if (ipdrive_base.debug_level > 1)
    {
        (void) fprintf(stderr,
        "Processing Send Receive Message Sequence %d\n",
                   rec_cnt);
        fflush(stderr);
    }
/*
 * See if we have already encountered this link. If we have not done
 * so, initialise it.
 */
    
    cur_link = link_find(msg->send_receive.ifrom_end_point_id,
                         msg->send_receive.ito_end_point_id);
    if (cur_link->link_id == 0)
    {
/*
 * Needs initialising
 */
        cur_link->link_id = 1;
        cur_link->from_ep = &end_point_det[
            msg->send_receive.ifrom_end_point_id];
        cur_link->to_ep = &end_point_det[
            msg->send_receive.ito_end_point_id];
       
        colcntres(&(cur_link->in_det));
        cur_link->in_det.first_buc = (struct timbuc *) NULL;
        colcntres(&(cur_link->out_det));
        cur_link->out_det.first_buc = (struct timbuc *) NULL;
        colcntres(&(cur_link->event_det));
        cur_link->event_det.first_buc = (struct timbuc *) NULL;
        if (ipdrive_base.verbosity)
            (void) sprintf(&cur_link->desc[0],"%s:(%s)%s.%s=(%s)%s.%s",
            cur_link->from_ep->protocol,
            cur_link->from_ep->con_orient,
            cur_link->from_ep->address,
            cur_link->from_ep->port_id,
            cur_link->to_ep->con_orient,
            cur_link->to_ep->address,
            cur_link->to_ep->port_id);
        else
            (void) sprintf(&cur_link->desc[0],"%s=%s",
            cur_link->from_ep->address,
            cur_link->to_ep->address);
            if (ipdrive_base.debug_level > 1)
            {
                (void) fprintf(stderr, "%s\n", &cur_link->desc[0]);
                fflush(stderr);
            }
    }
    len = msg->send_receive.imessage_len;
    head_size = sizeof(struct ip) + PHYS_OVER;
    if (!strcmp(cur_link->from_ep->protocol,"udp"))
        head_size += sizeof(struct udphdr);
    else
    if (!strcmp(cur_link->from_ep->protocol,"icmp"))
        head_size += sizeof(struct icmp);
    else
    if (!strcmp(cur_link->from_ep->protocol,"tcp"))
        head_size += sizeof(struct tcphdr);
    
    if ((ipdrive_base.verbosity && 
     (cur_link->from_ep->iend_point_id == msg->send_receive.ifrom_end_point_id))
        || (!ipdrive_base.verbosity && 
          (!strcmp(cur_link->from_ep->address,
                end_point_det[msg->send_receive.ifrom_end_point_id].address))))
        add_result( & (cur_link->out_det),len + head_size);
    else
        add_result( & (cur_link->in_det),len + head_size);
    add_result( & (cur_link->event_det),len + head_size);
    return;
}
/******************************************************************************
 * Process timer delay messages
 */
static void do_delay(a)
union all_records *a;
{
double delta;

    if (ipdrive_base.debug_level > 3)
    {
        (void) fprintf(stderr, "do_delay(%f)\n", a->delay.fdelta);
        fflush(stderr);
    }
    delta =   a->delay.fdelta;
    cur_time += delta;
/*
 * If we have passed a second, output the details for the links
 * The details always go in a single second. We assume that we will never
 * have a continuous run of messages lasting as long as a second.
 */ 
    if (cur_time - save_time >= (double) 1.0)
    {
    LINK * cur_link;
    int i,j,k;

        if (line_cnt > 62)
            do_page();
        for (k= 0, cur_link = &link_det[0]; cur_link->link_id ; cur_link++)
        {
            printf("%5.1d  %c%7.1f%c%5.1d%c %7.1f%c",
                    cur_link->out_det.cnt,fld_sep,
                    cur_link->out_det.tot,fld_sep,
                    cur_link->in_det.cnt,fld_sep,
                    cur_link->in_det.tot,fld_sep);
            colcntres(&(cur_link->out_det));
            colcntres(&(cur_link->in_det));
            k++;
        }
        line_cnt++;
        putchar((int) '\n');
        i = (int) floor(cur_time - save_time);
        for (j = 1; j < i; j++)
        {
            int l;
            if (line_cnt > 62)
                do_page();
            for (l = 0; l < k; l++)
            {
                if (fld_sep == ' ')
                    fwrite("    0       0.0     0      0.0 ",
                       sizeof(char),31,stdout);
                else
                    fwrite("    0      \t0.0    \t0     \t0.0\t",
                       sizeof(char),31,stdout);
            }
            putchar((int) '\n');
            line_cnt++;
        }
        save_time = save_time + floor(cur_time - save_time);
    }
    return;
}
/*
 * Page header
 */
static void do_page()
{
LINK * cur_link;

    if (page_no)
    {
        if (!ipdrive_base.excel_flag)
            putchar(((int) '\f'));
    }
    else
    {
        if (ipdrive_base.excel_flag)
            fld_sep = '\t';
        else
            fld_sep = ' ';
    }
    printf("\nMessage Profile (1 second intervals) File: %s Page: %d\n\n",
                fname, ++page_no);
    for (cur_link = &link_det[0]; cur_link->link_id; cur_link++)
        printf("%-30.30s%c", cur_link->desc,fld_sep);
    putchar(((int) '\n'));
    for (cur_link = &link_det[0]; cur_link->link_id; cur_link++)
         printf("Count OUT Bytes Count IN Bytes%c", fld_sep);
    putchar(((int) '\n'));
    for (cur_link = &link_det[0]; cur_link->link_id; cur_link++)
        printf("==============================%c", fld_sep);
    putchar(((int) '\n'));
    line_cnt = 5;
    return;
}

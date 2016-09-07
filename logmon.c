/*
 * logmon - Monitor the log files from a run, and send fresh contents to
 * standard out based on an external prod.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems Limited 2002, 2009";
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
struct file_con {
    char * fname;
    FILE * ifp;
    long long how_far;
    struct file_con * next_file;
};
/*
 * Allocate a file_con
 */
struct file_con * alloc_file_con(fname)
char * fname;
{
struct file_con * ret = (struct file_con *) malloc(sizeof(struct file_con));

    if (ret != NULL)
    {
        ret->fname = strdup(fname);
        ret->ifp = fopen(fname, "rb");
        ret->how_far = 0;
    }
    return ret;
}
/*
 * Construct a list of file names from a runout file, and
 * attempt to open them. If sample flag is set, only open the one file
 * from each bundle.
 */
struct file_con * process_run(pid, sample_flag)
char * pid;
int sample_flag;
{
struct file_con * anchor = NULL;
struct file_con * fcp;
int nusers;
char tran[80];
int ntrans;
char para_1[80];
int think;
char para_2[80];
int actor;
char seed[80];
FILE * fp;
char buf[2048];
int bundle;
int i;

    sprintf(buf,"runout%s",pid);
    if ((fp = fopen(buf,"rb")) == (FILE *) NULL)
    {
        fprintf(stderr,"Cannot open runout file %s\n",buf);
        return NULL;
    }
    bundle = 1;
/*
 * Skip the first three lines of the file
 */
    (void) fgets(buf,sizeof(buf),fp);
    (void) fgets(buf,sizeof(buf),fp);
    (void) fgets(buf,sizeof(buf),fp);
/*
 * Loop - pick up the details from the file
 */
    while (fgets(buf,sizeof(buf),fp) != (char *) NULL)
    {
    int nf = sscanf(buf, "%d %s %d %d %d %s %s %s",
               &nusers, tran, &ntrans, &think, &actor, seed, para_1, para_2);

        if (nf < 6)
            continue;
        if (!strcmp(tran, "end_time"))
            continue;
/*
 * If sample_flag == 0, we are going to track all the log files.
 * Otherwise, we are only going to track the first one.
 */
        if (sample_flag == 0)
        {
            for (i = 0; i < nusers; i++)
            {
                sprintf(buf, "log%.512s.%d.%d", pid, bundle, i);
                if ((fcp = alloc_file_con(buf)) != NULL)
                {
                    fcp->next_file = anchor;
                    anchor = fcp;
                }
            }
        }
        else
        {
            sprintf(buf, "log%.512s.%d.0", pid, bundle);
            if ((fcp = alloc_file_con(buf)) != NULL)
            {
                fcp->next_file = anchor;
                anchor = fcp;
            }
        }
        bundle++;
    }
    fclose(fp);
    return anchor;
}
static char * help_str = "Provide a run_id and an sample_request (Y or N) or a list of files\n";
/*
 * Routine to signal end
 */
static int finish;
static void scarper()
{
    finish = 1;
    return;
}
/*
 * Seconds since 1970 to ORACLE-like Date string
 */
static void mark_out(ofp)
FILE *ofp;
{
time_t time_stamp = time(0);
char * conv_time;
conv_time=ctime(&time_stamp);
(void) fprintf(ofp, "===> %-2.2s-%-3.3s-%-4.4s %-2.2s:%-2.2s:%-2.2s ==>\n",
               conv_time+8,
               conv_time+4,
               conv_time+20,
               conv_time+11,
               conv_time+14,
               conv_time+17);
    fflush(ofp);
return;
}
/*
 * Output everything written since last we looked
 */
static void process_file_con(fcp)
struct file_con * fcp;
{
int rdcnt;
char buf[16384];

    if (fcp->ifp == NULL)
    {
        if ((fcp->ifp = fopen(fcp->fname, "rb")) == NULL)
            return;
        if (fcp->how_far != 0) /* We have had to close this file in the past */
            fseek(fcp->ifp, fcp->how_far, 0);
    }
    while ((rdcnt = fread(buf, sizeof(char), sizeof(buf), fcp->ifp)) > 0)
        (void) fwrite(buf, sizeof(char), rdcnt, stdout);
    fcp->how_far = ftell(fcp->ifp);
    fseek(fcp->ifp, fcp->how_far, 0); /* Reset the EOF marker */
    return;
}
/***************************************************************************
 * Main Program Starts Here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
int main(argc, argv)
int argc;
char **argv;
{
char line_buf[80];
int sample_flag;
struct file_con * anchor;
struct file_con * fcp;

    if (argc < 2)
    {
        fputs(help_str, stderr);
        exit(0);
    }
    if (argc < 3 || ( *argv[2] != 'Y' && *argv[2] != 'y'))
        sample_flag = 0;
    else
        sample_flag = 1;
/*
 * If argv[1] doesn't identify a runout file, assume the arguments are
 * files to monitor. It is not an error for these to not yet exist, so
 * if the arguments are total ballocks the program will politely hang ...
 */
    if ((anchor = process_run(argv[1], sample_flag)) == NULL)
    {
        for (sample_flag = 1; sample_flag < argc; sample_flag++)
            if ((fcp = alloc_file_con(argv[sample_flag])) != NULL)
            {
                fcp->next_file = anchor;
                anchor = fcp;
            }
    }
    (void) sigset(SIGTERM, scarper);
/*
 * Now loop, as prodded, forwarding all the data that has accumulated since
 * the last prod.
 *
 * Obviously if there are multiple files:
 * -  Data needs to be written to them in atomic records.
 * -  Interleaving of their contents needs to be sensible.
 *
 * These statements should be true for PATH log files, but not much else, so
 * I would expect that if a Run ID is not provided, there would be but a single
 * file.
 */
    while (!finish)
    {
        for (fcp = anchor; fcp != NULL; fcp = fcp->next_file)
            process_file_con(fcp);
        mark_out(stdout);   /* Signals recipient we are paused */
        if (fgets(line_buf, sizeof(line_buf), stdin) == NULL)
            break;
        mark_out(stdout);   /* Signals recipient to restart */
    }
    exit(0);
}

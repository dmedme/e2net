#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
static char * help_str = "Provide an input file name, an output file name and an optional interval\
(default 30 seconds)\n";
/*
 * Routine to catch the alarm clock.
 */
static void watch_dog()
{
    return;
}
/*
 * Routine to signal end
 */
static int finish;
static void scarper()
{
    alarm(0);
    finish = 1;
    return;
}
/*
 * Seconds since 1970 to ORACLE Date string
 */
static void mark_out(ofp)
FILE *ofp;
{
time_t time_stamp = time(0);
char * conv_time;
static char time_buf[80];
conv_time=ctime(&time_stamp);
(void) fprintf(ofp, "===> %-2.2s-%-3.3s-%-4.4s %-2.2s:%-2.2s:%-2.2s ==>\n",
conv_time+8,
conv_time+4,
conv_time+20,
conv_time+11,
conv_time+14,
conv_time+17);
return;
}
int main(argc, argv)
int argc;
char **argv;
{
FILE * ifp;
FILE * ofp;
int td;
long offset;
char buf[16384];
int rdcnt;

    if (argc < 3)
    {
        fputs(help_str, stderr);
        exit(1);
    }
    if ((ifp = fopen(argv[1],"rb")) == (FILE *) NULL)
    {
        fprintf(stderr, "Cannot open %s for reading\n", argv[1]);
        fputs(help_str, stderr);
        exit(1);
    }
    if ((ofp = fopen(argv[2],"wb")) == (FILE *) NULL)
    {
        fprintf(stderr, "Cannot open %s for writing\n", argv[2]);
        fputs(help_str, stderr);
        exit(1);
    }
    if (argc == 3)
        td = 30;
    else
    if ((td = atoi(argv[3])) <= 0)
    {
        fprintf(stderr, "%s is not a valid time interval\n", argv[3]);
        fputs(help_str, stderr);
        exit(1);
    }
    (void) sigset(SIGTERM, scarper);
    fseek(ifp, 0, 2);                /* Go to the end of the file */
    while (!finish)
    {
        while ((rdcnt = fread(buf, sizeof(char), sizeof(buf), ifp)) > 0)
            (void) fwrite(buf, sizeof(char), rdcnt, ofp);
        offset = ftell(ifp);
        (void) sigset(SIGALRM,watch_dog);
        (void) alarm(td);
        mark_out(ofp);
        pause();
        fseek(ifp, offset, 0);
    }
    fclose(ifp);
    fclose(ofp);
    exit(0);
}

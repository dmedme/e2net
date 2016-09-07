/*
 * worldrun.c - Co-ordinate a distributed PATH benchmark.
 *
 * Scenario
 * ========
 * A number of users are going to start up the network benchmark kit around
 * the network. As the users start the kit, it will call home. As the calls,
 * home are received, the hosts become eligible to participate in tests.
 *
 * Processing rules are as follows.
 *
 * Initialise the control structures. 
 *
 * Kick off the minitest program on the server.
 *
 * Kick off the server end.
 *
 * Loop - await and process requests, interleaved with timouts
 *
 * There are two issues.
 * -   We need to maintain a list of available hosts
 * -   We need to control the activities of multiple hosts during a benchmark
 *
 * The basic unit of control is the runout file, which specifies
 * -   User counts
 * -   Scripts
 * -   Transaction counts
 * -   Working intensity
 * -   Actor ID
 * -   Data extraction parameters
 *
 * These are organised into a directory structure that allows for multiple
 * roles for a single collection of scripts, and assigns hosts to roles.
 *
 * A single execution engine executes a family of runout files, to give the
 * stepped test effect. Parameters are:
 * -   Root runout file name
 * -   Login stagger
 * -   Step length
 *
 * There is no provision at the moment for details of operating system monitor
 * packs, if these are relevant. These would have something monitor-y for the
 * the driver program; in this case, the runout file lines would correspond to
 * different operating system monitors.
 *
 * Script generation runs off the runout files. However, details such as the
 * generation algorithms depend on what the driver is.
 *
 * A useful feature of the original program was that the execution engines were
 * decoupled from the physical PC's by the 'office'. Thus, we did not need to
 * know in advance exactly which PC's were going to be available to us; we just
 * picked PC's that registered with us and reported themselves as being 'office
 * X'. We distributed packs with a menu of possible 'Offices'.
 *
 * This time, we are defining runs in terms of actual IP Addresses. However,
 * this program still has the job of tracking PC availability.
 *
 * The program receives instructions after it has started rather crudely,
 * through its minitest. Just 'echo ' the command string to it.
 *
 * minitest.c provides facilities for:
 * -   Synchronising clocks
 * -   Copying things about
 * -   Executing arbitrary operating system commands, with whatever privileges
 *     the triggering user possesses(!).
 * -   Carrying out stepped tests
 *
 * We need to add a facility to prematurely terminate a run.
 *
 * worldrun.c:
 * -   Maintains the list of available engines
 * -   Works off the test master file 
 *
 * worldrun.c options might control:
 * -   Generation (though this is easily done from the menu)
 * -   Distribution of test materiel
 * -   Actual tests
 * -   Triggering operating system monitors
 * -   Processes
 *
 * When a request arrives
 * - Note the IP Address and the Office name
 * When a request arrives, or a timeout occurs
 * - If the Office and IP Address have already been seen
 *   OR the Office and IP Address are new
 *   OR it has been at least 15 minutes since the last IP Address was seen for
 *   this office, and we have not yet seen 4 IP Addresses for this office
 *   - Synchronise clocks
 *   - Execute a traceroute
 *   - Trigger the test for an hour, less any unexpired run time
 *   Otherwise, if we have not yet seen 4 addresses for this office 
 *   - Add a timeout request
 * When a process exits
 * - If it is a test request, check to see if the results file exists
 * - If the results file does not exist, attempt to bring it back.
 *
     57.6.90.1  => 192.0.0.12
*/
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <unistd.h>
#include <process.h>
#include <io.h>
#else
#include <sys/wait.h>
#endif
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include "matchlib.h"
#include <errno.h>
/*****************************************************************************
 * Data structures
 */
typedef struct _office {
    char * off_name;
    int child_lim;
    int chld_cnt;
    int pc_cnt;
    long last_time;
    struct _pc * anchor;
} OFFICE;
static OFFICE test_offices[256];
typedef struct _pc {
    char * ip_address;
    int run_pid;
    struct _office * parent;
    struct _pc * next;
} PC;
#define MAXPCS 100
static PC pcs[MAXPCS];
/*
 * A Running Process
 */
typedef struct child_det   {
    int child_pid;       /* = 0 for a free slot */
    PC * own_pc;        /* msg running */
} RUN_CHILD;
/*****************************************************************************
 *  Future event management
 */
static struct go_time
{
    PC * link;
    long go_time;
} go_time[MAXPCS];
static short int head=0, tail=0, clock_running=0;
static int child_death=0;
static int our_pid;
static long alarm_save;        /* What's in the alarm clock; timer */
static void (*prev_alrm)();    /* Whatever is previously installed
                                           (either rem_time() or nothing) */

static void reset_time();      /* reset the clock system */
static void add_time();        /* manage a circular buffer of alarm clock calls */
static void rem_time();
static void alarm_preempt();   /* Put in a read timeout, in place of whatever is
                              * currently in the alarm clock
                              */
static void alarm_restore();   /* Restore the previous clock value */
static void do_things();
static void dump_children(); /* lists out the currently executing msgs     */
static void add_child();       /* administer the spawned processes */
static void rem_child();
static void die();             /* catch terminate signal */
static void scarper();         /* exit, tidying up */
static void chld_sig();        /* catch the death of a child */
static void io_sig();          /* catch a communications event */
static void seg_viol();        /* catch a segmentation violation event */
static void chld_catcher();    /* reap children */
static void minitest_spawn();  /* Start the process that services the FIFO */
static void pc_spawn();  /* Start the process that services the FIFO */
static void copy_spawn();  /* Start the process that services the FIFO */
static void server_spawn();  /* Start the process that services the FIFO */
/*********************************************************************
 * Program control structures
 */
static struct prog_glob {
    FILE * errout;
    int debug_level;
} worldrun;
/*************************************************************
 * Data to from the FIFO
 */
static int ctl_pipe[2]; /* For control commands logged by minitest */
static int fifo_pid;     /* PID of the FIFO child */
static int server_pid;   /* PID of the Server child */
static FILE * ctl_read;
static long poll_int = 10;

static RUN_CHILD child_stat[MAXPCS * 4];

static int child_cnt;
/***********************************************************************
 * Main Program Starts Here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
main(argc,argv,envp)
int argc;
char * argv[];
char * envp[];
{
/****************************************************
 *    Initialise
 */
    worldrun.errout = stderr;
    worldrun.debug_level = 4;
    child_cnt = 0;
    (void) sigset(SIGUSR1,die);       /* in order to exit */
    (void) sigset(SIGTERM,die);       /* in order to exit */
#ifdef UNIX
    (void) sigset(SIGCLD,chld_sig);
#endif
#ifdef SIGIO
    (void) sigset(SIGIO,SIG_IGN);     /* Only set for waiting on the fifo */
#endif
    (void) sigset(SIGPIPE,SIG_IGN);   /* So we don't crash out */
    (void) sigset(SIGHUP,SIG_IGN);    /* So we don't crash out */
    (void) sigset(SIGINT,SIG_IGN);    /* So we don't crash out */
    our_pid = getpid();               /* for SIGIO stuff       */
    (void) umask(0);                  /* Allow anyone to submit */
    minitest_spawn();           /* Set up child to feed the FIFO      */
    sleep(10);                  /* Wait for it to start               */
    server_spawn();             /* Kick off server end                */
    do_things();                /* process requests until nothing to do
                                 * DOES NOT RETURN
                                 */
    exit(0);
}
#ifdef SOLAR
#include <sys/stat.h>
#endif
/*
 * Exit, tidying up
 */
static void scarper()
{
    fputs("Termination Request Received; shutting down", worldrun.errout);
    if (fifo_pid)
        kill(fifo_pid,SIGTERM);    /* Get rid of the child */
    if (server_pid)
        kill(server_pid,SIGTERM);    /* Get rid of the child */
    exit(0);      /* Does not return */
}
/*****************************************************************
 * Service Shutdown Requests
 */
static void die()
{
    exit(0);                 /* No point in hanging around */
}
/*
 * Routine to kick off the child to service the world
 */
static void minitest_spawn()
{
char * home_port;

    if ((home_port = getenv("E2_HOME_PORT")) == (char *) NULL)
         home_port = "5000";
    if (pipe(ctl_pipe) == -1)
    {
        fputs("Cannot open control pipe\n", worldrun.errout);
        perror("Control pipe() Failed");
        exit(1);      /* Does not return */
    }
    if ((fifo_pid = fork()) > 0)
    {      /* PARENT success */
        if ((ctl_read = (FILE *) fdopen(ctl_pipe[0],"r")) == (FILE *) NULL)
        {
            fputs("Cannot fdopen read control pipe\n", worldrun.errout);
            scarper();      /* Does not return */
        }
        (void) setbuf(ctl_read,NULL);
        return;
    }
    else if (fifo_pid < 0)
    {      /* Parent Failed */
        fputs("Cannot fork() FIFO child\n", worldrun.errout);
        perror("Cannot fork() FIFO child\n");
        exit(1);
    }
/*
 * CHILD
 */
    close(0);
    dup2(ctl_pipe[1],1);
    dup2(1,2);
    execlp("minitest","minitest", home_port, NULL);
    fputs("Cannot execlp() minitest child\n", worldrun.errout);
    perror("Cannot execlp() minitest child\n");
    exit(1);
}
/*
 * Routine to kick off the server end
 */
static void server_spawn()
{
char * home_port;
char * home_host;
char * piid;
char * run_len;

    if ((home_host = getenv("E2_HOME_HOST")) == (char *) NULL)
         home_host = "192.168.0.5";
    if ((home_port = getenv("E2_HOME_PORT")) == (char *) NULL)
         home_port = "5000";
    if ((piid = getenv("E2_TEST_ID")) == (char *) NULL)
         piid = "ORAFIN";
    if ((run_len = getenv("E2_TEST_LEN")) == (char *) NULL)
         run_len = "86400";
    if ((server_pid = fork()) > 0)
    {      /* PARENT success */
        return;
    }
    else if (server_pid < 0)
    {      /* Parent Failed */
        fputs("Cannot fork() server child\n", worldrun.errout);
        perror("Cannot fork() server child\n");
        scarper();
    }
/*
 * CHILD
 */
    close(0);
    execlp("minitest","minitest", home_host, home_port, "SCENE", piid, run_len,
              NULL);
    fputs("Cannot execlp() server child\n", worldrun.errout);
    perror("Cannot execlp() server child\n");
    scarper();
}
/*
 * Routine to kick off the child to service a single PC
 */
static void pc_spawn(pc)
PC * pc;
{
int i;
char command_line[128];
long t;
char * home_port;
char * scen_len;
char * piid;

    if ((home_port = getenv("E2_HOME_PORT")) == (char *) NULL)
         home_port = "5000";
    if ((scen_len = getenv("E2_SCENE_LEN")) == (char *) NULL)
         scen_len = "3600";
    if ((piid = getenv("E2_TEST_ID")) == (char *) NULL)
         piid = "ORAFIN";
    sprintf(command_line,"minitest %s %s SLEW", pc->ip_address, home_port);
    fputs(command_line, worldrun.errout);
    fputc('\n',worldrun.errout);
    system(command_line);
    sprintf(command_line,"traceroute %s", pc->ip_address);
    system(command_line);
    fputs(command_line, worldrun.errout);
    fputc('\n',worldrun.errout);
    t = time(0);
    if (t - pc->parent->last_time > atoi(scen_len))
        strcpy(command_line,scen_len);
    else
        sprintf(command_line, "%u", atoi(scen_len)
                       - (t - pc->parent->last_time));
    fprintf( worldrun.errout, "Scenario will be executed on %s at %s for %s\n",
            pc->ip_address, pc->parent->off_name, command_line );
    fflush(worldrun.errout);
    pc->parent->last_time = t;
    if ((pc->run_pid = fork()) > 0)
    {      /* PARENT success */
        add_child(pc->run_pid, pc);
        return;
    }
    else if (pc->run_pid < 0)
    {      /* Parent Failed */
        fputs("Cannot fork() benchmark child\n", worldrun.errout);
        perror("Cannot fork() benchmark child\n");
        exit(1);
    }
/*
 * CHILD
 */
    close(0);
    execlp("minitest","minitest", pc->ip_address, home_port, "SCENE", piid,
            command_line, NULL);
    fputs("Cannot execlp() benchmark child\n", worldrun.errout);
    perror("Cannot execlp() benchmark child\n");
    exit(1);
}
/*
 * Routine to kick off the child to return the results from a single PC
 */
static void copy_spawn(pc)
PC * pc;
{
char command_line[128];
char * home_host;
char * home_port;

   if ((home_host = getenv("E2_HOME_HOST")) == (char *) NULL)
       home_host = "192.168.0.12";
   if ((home_port = getenv("E2_HOME_PORT")) == (char *) NULL)
       home_port = "5000";

    sprintf(command_line,"minitest %s %s COPY res%s.tar.bz2 res95.tar.bz2",
             home_host, home_port,
             pc->ip_address);
    fprintf( worldrun.errout, "minitest %s %s EXEC \"%s\"\n", pc->ip_address,
         home_port,
         command_line);
    fflush( worldrun.errout);
    if ((pc->run_pid = fork()) > 0)
    {      /* PARENT success */
        add_child(pc->run_pid, pc);
        return;
    }
    else if (pc->run_pid < 0)
    {      /* Parent Failed */
        fputs("Cannot fork() benchmark child\n", worldrun.errout);
        perror("Cannot fork() benchmark child\n");
        exit(1);
    }
/*
 * CHILD
 */
    close(0);
    execlp("minitest","minitest", pc->ip_address, home_port, "EXEC",
            command_line, NULL);
    fputs("Cannot execlp() copy child\n", worldrun.errout);
    perror("Cannot execlp() copy child\n");
    exit(1);
}
static OFFICE * off_find(office_name)
char * office_name;
{
OFFICE * x, *top;
int i;

    for (x = &test_offices[0], top = &test_offices[256];
            x < top
         && x->off_name != (char *) NULL
         && ((i = strcmp(office_name, x->off_name)) != 0); x++); 
    if (x >= top)
        return (OFFICE *) NULL;
    fprintf(worldrun.errout, "Input: %s i: %d Index: %d\n",
            office_name, i, (x - &test_offices[0]));
    if (x->off_name == (char *) NULL)
    {                                    /* New Office */
        x->off_name = strdup(office_name);
        x->child_lim = 255;
        x->chld_cnt = 0;
        x->pc_cnt = 0;
        x->last_time = 0;
        x->anchor = (PC *) NULL;
    }
    return x;
}
static PC * pc_find(ip_address )
char * ip_address;
{
PC * x;
int j;
    for (x = &pcs[0], j = 0;
            j < MAXPCS
         && x->ip_address != (char *) NULL
         && strcmp(ip_address, x->ip_address);
             j++, x++); 
    if (j >= MAXPCS)
        return (PC *) NULL;
    return x;
}
/*****************************************************************************
 * Check the FIFO for something to do, and recognise the IP address and office
 * name
 */
static void fifo_check()
{
char fifo_line[BUFSIZ];
int c;
register char * x;
int i;
long cur_time;
char ip_address[24];
char office_name[32];
OFFICE * off;
PC * pc;

    if (worldrun.debug_level > 1)
        (void) fputs("fifo_check()\n", worldrun.errout);
    for (;;)
    {
        if (fgets(fifo_line, sizeof(fifo_line) - 1, ctl_read) == (char *) NULL)
        {
            if (errno != EINTR)
            {
                fputs("Exiting\n", worldrun.errout); 
                exit(0);
            }
        }
        else
        {
            fputs(fifo_line, worldrun.errout);
            fflush(worldrun.errout);
            if ((i = sscanf(fifo_line,
              "Accept from %s succeeded ... EXEC echo e2nettst started at ",
                        ip_address)) == 1 &&
                ((x = strstr(fifo_line+58, " at ")) != (char *) NULL))
            {
                x = strtok(x + 4, "\r\n");
                strcpy(office_name, x);
                fprintf(worldrun.errout, "Seen %s - %s\n", office_name,
                           ip_address); 
                fflush(worldrun.errout);
                if ((off = off_find(office_name)) == (OFFICE *) NULL) 
                {
                    fprintf(worldrun.errout, "Failed to locate office %s\n",
                            office_name);
                    fflush(worldrun.errout);
                    continue;
                }
                if ((pc = pc_find(ip_address)) == (PC *) NULL) 
                {
                    fprintf(worldrun.errout, "Failed to locate PC %s\n",
                            ip_address);
                    fflush(worldrun.errout);
                    continue;
                }
                cur_time = time(0);
                if (pc->ip_address == (char *) NULL)
                {
                    pc->ip_address = strdup(ip_address);
                    pc->parent = off;
                    off->pc_cnt++;
                    pc->next = off->anchor;
                    off->anchor = pc; 
                }
                if (pc->run_pid == 0)
                {                     /* Nothing running at the moment */
                    if (off->chld_cnt < off->child_lim)
                    {
                        if (cur_time - pc->parent->last_time < 900)
                            add_time(pc,
                              (pc->parent->last_time + 900 - cur_time));
                        else
                            pc_spawn(pc);
                    }
                }
                else
                    pc_spawn(pc);          /* End user abort and restart */
            }
        }
        return;
    }
}
/*
 * chld_sig(); interrupt the select() or whatever.
 */
static void chld_sig()
{
    child_death++;
    return;
}
/*
 * read_timeout(); interrupt a network read that is taking too long
 */
static void read_timeout()
{
    return;
}
#ifdef UNIX
/*
 * chld_catcher(); reap children as and when
 * PYRAMID Problems:
 * - waitpid() doesn't work at all
 * - wait3() doesn't like being called when the child signal handler is
 *   installed; be sure that the signal handler has gone off before
 *   calling (and we will still disable it).
 */
static void chld_catcher(hang_state)
int hang_state;
{
    int pid;
#ifdef POSIX
    int
#else
    union wait
#endif
    pidstatus;

    if (worldrun.debug_level > 1)
        (void) fprintf(worldrun.errout,"chld_catcher(); Looking for Children....\n");
    (void) sigset(SIGCLD,SIG_DFL); /* Avoid nasties with the chld_sig/wait3()
                                       interaction */
    while ((pid=wait3(&pidstatus, hang_state, 0)) > 0)
    {
        child_death--;
        rem_child(pid,pidstatus);
    }
    child_death = 0;
    (void) sigset(SIGCLD,chld_sig); /* re-install */
    return;
}
#endif
/*
 * Function to handle requests, honouring simultaneity limits, until there
 * is absolutely nothing more to do for the moment
 */
static void do_things()
{
/*
 * Put a pointer to this struct as the last argument to select() to
 * get it to poll
 */
/*
 * Process forever (death is by signal SIGUSR1)
 */
    for (;;)
    {
/*
 * Make sure that signals will be delivered
 */
        sigrelse(SIGALRM);
        sigrelse(SIGUSR1);
#ifdef UNIX
        sigrelse(SIGCLD);
#endif
        fifo_check();
#ifdef UNIX
        if (child_death)
            chld_catcher(WNOHANG);
#endif
    }   /* Bottom of Infinite for loop */
}
/***************************************************************************
 * add a child process to the list;
 * overflow handled safely, if with degraded functionality
 */
static void add_child(pid, pc)
int pid;
PC * pc;
{
register RUN_CHILD * cur_child_ptr=child_stat, * max_child_ptr
    = &child_stat[MAXPCS *4 -1];
OFFICE * off_ptr;

    if (pc == (PC *) NULL || pc->parent == (OFFICE *) NULL)
    {
        fputs( "Logic Error: add_child() called with NULL PC or Office",
                worldrun.errout);
        return;
    }
    off_ptr = pc->parent;
    if (worldrun.debug_level > 1)
        (void) fprintf(worldrun.errout,"add_child(%d,%s) for office %s\n",
                       pid, pc->ip_address, off_ptr->off_name);
    while(cur_child_ptr < max_child_ptr)
    {
         if (cur_child_ptr->child_pid == 0)
         {
             cur_child_ptr->child_pid = pid;
             off_ptr->chld_cnt++;
             cur_child_ptr->own_pc = pc;
             child_cnt++;
             return;
         }
         cur_child_ptr++;
    }
    return;
}
static void result_check(pc)
PC * pc;
{
struct stat stat_buf;
char buf[128];

    sprintf(buf,"res%s.tar.bz2",pc->ip_address);
    if (stat(buf, &stat_buf) < 0)
        copy_spawn(pc);
    return;
}
/*
 * Remove a child process from the list; check for results; if not present,
 * attempt to copy.
 *
 * Overflow handled safely, if with degraded functionality
 */
static void rem_child(pid,pidstatus)
int pid;
#ifdef POSIX
int
#else
union wait
#endif
pidstatus;
{
PC *pc;
register RUN_CHILD * cur_child_ptr=child_stat, * max_child_ptr
    = &child_stat[MAXPCS *4 -1];

    if (worldrun.debug_level > 1)
        (void) fprintf(worldrun.errout,"rem_child() for pid %d\n", pid);
    if (pid == fifo_pid)
    {
        fputs( "FIFO handler shut down\n", worldrun.errout);
        exit(0);
    }
    else
    if (pid == server_pid)
    {
        fputs( "Benchmark handler shut down\n", worldrun.errout);
        scarper();
    }
    else
    while(cur_child_ptr < max_child_ptr)
    {
         if (cur_child_ptr->child_pid == pid)
         {
         char *x;
         char * mess;
         int y;

             if (WIFEXITED(pidstatus))
             {
                 mess = "exiting with status";
#ifdef POSIX
                 y = WEXITSTATUS(pidstatus);
#else
                 y = pidstatus.w_retcode;
#endif
             }
             else /* Terminated by signal */
             {
                 mess = "terminated by signal";
#ifdef POSIX
                 y = WTERMSIG(pidstatus);
#else
                 y = pidstatus.w_termsig;
#endif
             }
             pc = cur_child_ptr->own_pc;
             cur_child_ptr->child_pid = 0;
             cur_child_ptr->own_pc = (PC *) NULL;
             (void) fprintf(worldrun.errout,
                   "pid %d:Benchmark %s from %s finished %s %d\n",
                   pid,
                   pc->parent->off_name,
                   pc->ip_address,
                   mess, y);
             pc->run_pid = 0;
             pc->parent->chld_cnt--;
             child_cnt--;
             if (y == 0)
                 result_check(pc);
             return;
         }
         cur_child_ptr++;
    }
    return;
}
/***************************************************************************
 * Clock functions
 *
 * add_time();  add a new time for the link; start the clock if not running
 * This function moves the buffer head, but not its tail.
 *  - new_time is an absolute time in seconds since 1970.
 *  - do not add it if the link is already queued for a retry.
 */
static void add_time(link,delta)
PC * link;
int delta;
{
short int cur_ind;
long t;
struct go_time sav_time;
long new_time;

    t = time((long *) 0);
    new_time = t + delta;
    if (worldrun.debug_level > 1)
        (void) fprintf(worldrun.errout,"add_time(): PC %s %s delta %d\n",
                  (link == (PC *) NULL)? "" : link->parent->off_name,
                  (link == (PC *) NULL)? "" : link->ip_address,
                  delta);
    for (cur_ind = tail;
             cur_ind !=head && go_time[cur_ind].go_time < new_time;
                 cur_ind = (cur_ind + 1) % MAXPCS)
         if (go_time[cur_ind].link == link) return;  /* shouldn't happen */
    for (; cur_ind != head; cur_ind = (cur_ind + 1) % MAXPCS)
    {
        sav_time = go_time[cur_ind];
        go_time[cur_ind].go_time = new_time;
        go_time[cur_ind].link = link;
        new_time = sav_time.go_time;
        link = sav_time.link;
    }
    if (tail != (head + 1) % MAXPCS)
    {
        go_time[head].go_time = new_time;
        go_time[head].link = link;
        head = (head + 1) % MAXPCS;
    }
    sighold(SIGALRM);
    if (clock_running != 0)
        alarm(0);
    sigrelse(SIGALRM);
    clock_running = 0;
    rem_time();
    return;
} 
/*
 * rem_time(); tidy up the list, removing times from the tail as they
 * expire. Start the clock if there is anything in the link. Apart from
 * reset_time(), nothing else moves the tail.
 *
 * This function is NEVER called if the clock is running.
 *
 * I don't think there will be be any problems with the off_open() call messing
 * up whatever was executing when the alarm clock rang. If there are,
 * then we will make the alarm clock signal routine set a flag that
 * can be inspected by the main line code at a safe working point. This had
 * to be done for the death of child processing, and would be essential
 * if this code or any that it called attempted to access the ORACLE database.
 */
static void rem_time()
{
short int cur_ind;
int sleep_int;
long cur_time = time((long *) 0);

    if (worldrun.debug_level > 1)
        (void) fprintf(worldrun.errout,"rem_time(): Clock Running %d\n",clock_running);
    for (cur_ind = tail;
             cur_ind !=head && go_time[cur_ind].go_time <= cur_time;
                 cur_ind = (cur_ind + 1) % MAXPCS,
                 tail = cur_ind)
    {                      /* Attempt to start on the PCs indicated */
        if (go_time[cur_ind].link != (PC *) NULL)
        {
            pc_spawn(go_time[cur_ind].link);
        }
    }
    if (tail != head)
    {
        (void) sigset(SIGALRM,rem_time);
        sleep_int = go_time[tail].go_time - cur_time;
        clock_running ++;
        (void) alarm(sleep_int);
    }
    return;
} 
/*
 * Reset the time buffers
 */
static void reset_time()
{
    alarm(0);
    sigset(SIGALRM,SIG_IGN);
    tail = head;
    clock_running = 0;
    return;
}
/*
 * Routine to temporarily pre-empt the normal clock handling
 */
static void alarm_preempt()
{
    prev_alrm = sigset(SIGALRM,read_timeout);
    alarm_save = alarm(poll_int);
    return;
}
/*
 * Routine to restore it
 */
static void alarm_restore()
{
    alarm(0);
    (void) sigset(SIGALRM,prev_alrm);
    if (clock_running)
    {
        sighold(SIGALRM);
        (void) alarm(alarm_save);
    }
    return;
}
/*
 * Function to print out data about the offices
 */
static void dump_link()
{
int j;
PC * pc;

    for (j=0; test_offices[j].off_name != (char *) NULL; j++)
    {
(void) fprintf(worldrun.errout,">>>>>>>Office: %s\n",test_offices[j].off_name);
(void) fprintf(worldrun.errout,"child_lim: %d\n",test_offices[j].child_lim);
(void) fprintf(worldrun.errout,"chld_cnt: %d\n",test_offices[j].chld_cnt);
(void) fprintf(worldrun.errout,"Associated IP Addresses\n");
(void) fprintf(worldrun.errout,"=======================\n");
        for (pc = test_offices[j].anchor;
               pc != (PC *) NULL;
                    pc = pc->next)
          (void) fprintf(worldrun.errout,"%10.1ld %-16.16s\n", pc->run_pid,
                                 pc->ip_address);
        (void) fprintf(worldrun.errout,"=========================\n");
    }
    return;
}
/*
 * Function to dump running processes
 */
static void dump_children()
{
register RUN_CHILD * cur_child_ptr=child_stat, * max_child_ptr
    = &child_stat[MAXPCS *4 -1];
short int i;
    
(void) fprintf(worldrun.errout,
"Office                           IP              PID\n");
    for (i=0;cur_child_ptr < max_child_ptr;cur_child_ptr++)
    {
         if (cur_child_ptr->child_pid != 0)
         {
             i++;
            (void) fprintf(worldrun.errout,"%-33.33s %-15.15s %10.1d\n",
                   cur_child_ptr->own_pc->parent->off_name,
                   cur_child_ptr->own_pc->ip_address,
                   cur_child_ptr->child_pid);
         }
    }
    if (child_cnt != i)
         (void) fprintf(worldrun.errout,
               "Warning: Link children %d != internal count %d\n",
                  i, child_cnt);
    return;
}

/* commsprint.c
 *
 * Filter to talk to TELNET.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems Limited 1992";

#ifdef OSF
#define _SOCKADDR_LEN
#endif

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#ifdef OSF
#include <sys/ioctl.h>
#else
#include <sys/sockio.h>
#endif
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "com.h"
extern int errno;
/*
 * This is the service port listener of the Communications Server
 */

#define	BUFLEN	4096
static int debug_flag;
extern int optind ;         /* argument option index */
extern char *optarg ;       /* option argument (eg "file" in "-o file") */
extern char * comms_trace;  /* Trace File */

static void sock_prepare(sock,host,port)
struct sockaddr_in * sock;
char * host;
int port;
{
struct hostent *hp, *gethostbyname() ;
    if ((hp = gethostbyname( host))  == (struct hostent *) NULL)
    {
	perror( host) ;
	fprintf( stderr, "%s: can't find server ", host) ;
	exit(1) ;
    }
    memset((char *) sock, 0, sizeof(*sock));
    memcpy(&(sock->sin_addr),(char *) (hp->h_addr_list[0]),
             sizeof(sock->sin_addr));
    sock->sin_family = AF_INET ;
    sock->sin_port = htons((unsigned short) port);
#ifdef OSF
    sock->sin_len = (unsigned char) sizeof(*sock);
#endif
    return;
}
void propagate();
#ifdef STAND
static void usage(prog)
char * prog;
{
    fprintf( stderr, "usage: %s -d -h printer_host -p printer_port [file]\n",
               prog) ;
    exit(1) ;
}
/********************************
 * Main Program starts here
 * VVVVVVVVVVVVVVVVVVVVVVVV
 */
main( argc, argv)
int argc ;
char *argv[] ;
{
int port;
int pr_sock ;
int ac ;                    /* argument character */
int cnt ;                   /* count for buffer copying */
char *printer_name = NULL ; /* printer host, from /etc/hosts */
char buf[128];
    port = 2001;            /* A plausible default */
    while ((ac = getopt( argc, argv, "dDh:p:"))  !=  EOF)
    {
	switch (ac)
	{
	    case 'd':
	    case 'D':
		debug_flag = 1;
		break;
	    case 'h':
		printer_name = optarg ;
		break ;
	    case 'p':
		port = atoi(optarg);
		break ;
	    case '?':
	    default:
		fprintf( stderr, "%s: unknown option '%c'\n", argv[0],
                         (char) ac) ;
		usage(argv[0]) ;
		break ;
	}
    }
    if (printer_name == (char *) NULL)
        usage(argv[0]) ;
    sprintf(buf,"%s:%d",printer_name,port);

    if (optind < argc)
    {
        int f;
        (void) close(0);
	if ((f =open( argv[optind],  O_RDONLY)) < 0)
	{
	    fprintf( stderr, "%s: can't open file %s to read\n",
	        argv[0], argv[optind]) ;
	    exit(1) ;
	}
        if (f != 0)
        {
            (void) dup2(f,0);
            (void) close(f);
        }
    }
    /* read from stdin (input file) and write to the network device (printer) */
    if ((pr_sock = call_trasec(buf)) < 0)
        exit(-1);
    else
        propagate(0,pr_sock);
    exit(0) ;
}
static int exit_flag;
void sigterm()
{
    exit_flag = 1;
    return;
}
/*****************************************************************
 *   Start of Flow-control-sensitive sending code
 */
static void propagate (input_fd,output_socket_fd)
int input_fd;
int output_socket_fd;
{
    /*    Initialise -    Data Definitions */
    char transfer_buf[BUFLEN];

    int sockmask,
    readymask,
    read_count,
    icount,
    pause_flag;

    int process_fd[2],
    read_pair[2],
    write_pair[2];

    /*    Initialise the signal catcher    */

    exit_flag = 0;
    sigset(SIGTERM,sigterm);

/*****************************************************************
 *   Start of Main Loop; communicate with the distant printer.
 */
            /*    Get ready to select    */
    sockmask = (1<<input_fd) | (1<<output_socket_fd);

    read_pair[0]  = input_fd;
    write_pair[1] = input_fd;

    read_pair[1]  = output_socket_fd;
    write_pair[0] = output_socket_fd;
    pause_flag = 0;
    for(;;)
    {
        if (exit_flag)
        {
            sprintf(transfer_buf,"\n\n\n...User Terminated\f\n");
            (void) tras_write(output_socket_fd,
                       transfer_buf,strlen(transfer_buf));
            (void) close (input_fd);
            (void) close (output_socket_fd);
            return;
        }
/*
 * Note that this program:
 * - checks that there is data to read
 * - does not check that it will not be blocked on write
 */
        readymask = sockmask;
        if (select(20,&readymask,0,0,0)<1)
        {
            (void) fprintf(stderr,"Error %d select() failed\n", errno);
            exit(1);
        }
        process_fd[0] = (readymask & (1<<input_fd));
        process_fd[1] = (readymask & (1<<output_socket_fd));
        for (icount=pause_flag; icount < 2; icount++)
        {
            if (process_fd[icount])
            {
                read_count=tras_read(read_pair[icount],transfer_buf,BUFLEN);
                if (read_count < 0)
                {
                    (void) fprintf (stderr,
                      "Error %d read() error on fd %d",errno,read_pair[icount]);
                }
                else if (read_count == 0)
                {
                    goto finish;
                }
                else if (icount == 0)
                {
                    int so_far;
                    int write_count;
                    for (so_far = 0,write_count = read_count;
                            read_count > 0 && so_far < write_count;
                                so_far += read_count)
                        read_count = 
                            tras_write(write_pair[icount],transfer_buf+so_far,
                                  write_count - so_far);
                }
                else
                {
                    register char * x1, *x2;
                    register char x3;
                    if (debug_flag)
                    {
                        fwrite(transfer_buf,sizeof(char),read_count,stderr);
                        fflush(stderr);
                    }
                    for (x1 = transfer_buf,
                         x2 = x1 + read_count,
                         x3 = (char) ((pause_flag) ? 17 : 19);
                             x1 < x2;
                                 x1 ++)
                    {
                        if (*x1 == x3)
                        {
                            if (pause_flag)
                            {
                                pause_flag = 0;
                                sockmask = sockmask | (1 << input_fd);
                            }
                            else
                            {
                                pause_flag = 1;
                                sockmask = sockmask &  ~(1 << input_fd);
                            }
                        }
                        (void) fprintf(stderr,"Seen: %d\n",(int) *x1);
                    }
                }
            }
        }    /*    End of for each fd */
    }    /*    End of infinite for loop */
finish:
    (void) close (input_fd);
    (void) close (output_socket_fd);
    return;
}    /* End program */
#endif
/************************************************************************
 * Not used, but here for completeness
 *
 * Socket set up; return the file descriptor.
 */
int e2_listen(host,port)
char *host;
int port;
{
int listen_fd;
struct sockaddr_in one_sock;
/*
 *    Now create the socket to listen on
 */
    if ((listen_fd = socket(AF_INET,SOCK_STREAM,0))<0)
    { 
        perror("Communication socket create failed"); 
        (void) fprintf(stderr,
              "%s line %d: STREAM listen socket %s create failed\n",
                       __FILE__, __LINE__, host) ;
        fflush(stderr);
        return -1;
    }
/*
 * Bind its name to it
 */
    sock_prepare(&one_sock, host, port);
    if (bind(listen_fd , (struct sockaddr *) (&one_sock),
             sizeof(one_sock)))
    { 
        perror("Communication bind failed"); 
        (void) fprintf(stderr,"%s line %d: STREAM listen bind %s failed\n",
                       __FILE__, __LINE__, host) ;
        fflush(stderr);
        return -1;
    }
/*
 * Listen on it
 */
    if (listen(listen_fd , 5))
    { 
        perror("Communication listen failed"); 
        (void) fprintf(stderr,"%s line %d: STREAM listen %s failed\n",
                       __FILE__, __LINE__, host) ;
        fflush(stderr);
        return -1;
    }
    return listen_fd ;
}
/************************************************************************
 * Establish a connexion
 * - Fills in the socket stuff.
 * - Sets up a calling socket; this is validated at the other end.
 */
int e2_connect(host, port, bind_addr)
char * host;
int  port;
struct sockaddr_in * bind_addr;
{
    int e2_fd;
struct sockaddr_in other_sock;
struct linger optval;
/*
 * Ready to connect to the destination.
 */
    if ((e2_fd = socket(AF_INET,SOCK_STREAM,0))<0)
    { 
        perror("STREAM socket create failed"); 
        (void) fprintf(stderr,
           "%s line %d: STREAM connect socket %s create failed\n",
                       __FILE__, __LINE__, host) ;
        fflush(stderr);
        return -1;
    }
/*
 * Set the linger to one second, so that close will linger a while before
 * closing connection
 */
    optval.l_onoff = 2 ;
    optval.l_linger = 1 ;
    if (setsockopt(e2_fd, SOL_SOCKET, SO_LINGER, (char *) &optval,
               sizeof( optval )) < 0)
    {
        perror("Setting linger") ;
        return -1 ;
    }
/*
 * Bind its name to it
 */
    if (bind_addr != (struct sockaddr_in *) NULL &&
       bind(e2_fd , (struct sockaddr *) bind_addr, sizeof(*bind_addr)))
    { 
        perror("Communication bind failed"); 
        (void) fprintf(stderr,
           "%s line %d: STREAM connect socket bind %s failed\n",
                       __FILE__, __LINE__, host) ;
        fflush(stderr);
        return -1;
    }
    sock_prepare(&(other_sock), host, port);
    if (connect(e2_fd , (struct sockaddr *) (&other_sock),
           sizeof(other_sock)))
    {
        perror("connect() failed");
        (void) fprintf(stderr,
          "%s line %d:\n\
STREAM socket connect %s (%d.%d.%d.%d) to %d failed\n",
                __FILE__, __LINE__, host,
                (unsigned int) *((unsigned char *) &(other_sock.sin_addr)),
                (unsigned int) *(((unsigned char *) &(other_sock.sin_addr))+1),
                (unsigned int) *(((unsigned char *) &(other_sock.sin_addr))+2),
                (unsigned int) *(((unsigned char *) &(other_sock.sin_addr))+3),
                (int) other_sock.sin_port) ;
        fflush(stderr);
        return -1;
    }
    else
        return e2_fd ;
}
/************************************************************************
 * Establish a connexion as a server.
 * - Fills in the socket stuff.
 */
int e2_accept(listen_fd)
int listen_fd;
{
int e2_fd;
struct sockaddr_in other_sock;
/*
 * Accept a connection
 */
int ret_len = sizeof(other_sock);
    if ((e2_fd = accept(listen_fd , (struct sockaddr *) (&other_sock),
              &ret_len))< 0)
    {
static char * x = "Designation accept() failure\n";
        if (errno != EINTR)
        {
            perror("accept() failed");
            (void) fprintf(stderr,
               "%s line %d: STREAM socket accept from %d failed\n",
                       __FILE__, __LINE__,  listen_fd) ;
            fflush(stderr);
        }
        return -1;
    }
    return e2_fd;
}
/************************************************************************
 * TELNET Protocol Elements
 *
 * - e2tel_read()
 * - e2tel_cmd()
 * - e2tel_write()
 *
 * The status of the connexion is held in a tel_con structure, which
 * indicates the options requested and the options in effect. To the
 * calling routines, all they see is the data-stream, together with
 * an ability to interject commands (eg. interrupt). 
 *
 * The usefulness of most of these capabilities is doubtful. In particular,
 * the handling of TELNET SYNCH commands is obscure. The telnet man page
 * suggests that a TM option is returned to indicate the successful actioning
 * of the SYNCH; no mention is made of this in the RFC. The RFC hints at
 * a dual-mode in-command/in-data scan, without specifically mentioning it,
 * and also hints at multi-byte Out Of Band messages. In reality, TCP allows
 * but a single byte. This would have to be the IAC? Yet the RFC says that
 * the byte should be a DM, though it goes on to say that if the DM is not
 * found, scanning should continue until it is.
 *
 ****************************************************************************
 * Definitions for the TELNET protocol, from RFC 764.
 */
#define	IAC	255		/* Interpret as Command */
#define	DONT	254		/* You are not to use option */
#define	DO	253		/* Please, use option */
#define	WONT	252		/* I won't use option */
#define	WILL	251		/* I will use option */
#define	SB	250		/* Interpret as subnegotiation */
#define	GA	249		/* You may reverse the line */
#define	EL	248		/* Erase current line */
#define	EC	247		/* Erase current character */
#define	AYT	246		/* Are You There */
#define	AO	245		/* Abort Output--but let program finish */
#define	IP	244		/* Interrupt Process--permanently */
#define	BREAK	243		/* Break */
#define	DM	242		/* Data mark--for connect. cleaning */
#define	NOP	241		/* NOP */
#define	SE	240		/* End Sub Negotiation */
#define	EOR	239		/* End of Record (transparent mode) */
#define	SYNCH	242		/* For gaining attention etc. */
/*
 * Offsets into our TELCON array
 */
#define E2_TEL_WANTED 0
#define E2_TEL_TRIED 1
#define E2_TEL_OFFERED 2
#define E2_TEL_AGREED 3
/*
 * Subtract 240 from the byte value to give the index into
 * the following array
 */
static char *telnet_commands[] = {
	"SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
	"EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC"
};
/*
 * Well-known TELNET option codes
 */
#define	TELOPT_BINARY	0	/* 8-bit data path */
#define	TELOPT_ECHO	1	/* Echo */
#define	TELOPT_RCP	2	/* Prepare to reconnect */
#define	TELOPT_SGA	3	/* Suppress go ahead */
#define	TELOPT_NAMS	4	/* Approximate message size */
#define	TELOPT_STATUS	5	/* Give status */
#define	TELOPT_TM	6	/* Timing mark */
#define	TELOPT_RCTE	7	/* Remote controlled transmission and echo */
#define	TELOPT_NAOL 	8	/* Negotiate about output line width */
#define	TELOPT_NAOP 	9	/* Negotiate about output page size */
#define	TELOPT_NAOCRD	10	/* Negotiate about CR disposition */
#define	TELOPT_NAOHTS	11	/* Negotiate about horizontal tabstops */
#define	TELOPT_NAOHTD	12	/* Negotiate about horizontal tab disposition */
#define	TELOPT_NAOFFD	13	/* Negotiate about formfeed disposition */
#define	TELOPT_NAOVTS	14	/* Negotiate about vertical tab stops */
#define	TELOPT_NAOVTD	15	/* Negotiate about vertical tab disposition */
#define	TELOPT_NAOLFD	16	/* Negotiate about output LF disposition */
#define	TELOPT_XASCII	17	/* Extended ascic character set */
#define	TELOPT_LOGOUT	18	/* Force logout */
#define	TELOPT_BM	19	/* Byte macro */
#define	TELOPT_DET	20	/* Data Entry Terminal */
#define	TELOPT_SUPDUP	21	/* Supdup protocol */
#define	TELOPT_SUPDUPOUTPUT 22	/* Supdup output */
#define	TELOPT_SNDLOC	23	/* Send location */
#define	TELOPT_TTYPE	24	/* Terminal type */
#define	TELOPT_EOR	25	/* End of Record */
#define	TELOPT_EXOPL	255	/* Extended-options-list */
/*
 * Use the option code itself to index.
 */
char *known_telnet_options[] = {
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
	"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
	"NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
	"NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
	"DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
	"SEND LOCATION", "TERMINAL TYPE", "END OF RECORD"
};
#define KNOWN_COUNT 26
typedef struct _tel_con {
    int fd;                     /* File descriptor of socket */
    long status[4];             /* Enough bits for 32 options */
    unsigned char buf[8192];
} TELCON;
/*
 * Operations on the array of status values
 */
#define e2tel_opt_set(con,which,opt) ((con)->status[(which)] |= (1 << (opt)))
#define e2tel_opt_clr(con,which,opt) ((con)->status[(which)] &= ~(1 << (opt)))
#define e2tel_opt_tst(con,which,opt) (((con)->status[(which)]&(1<<(opt)))?1:0)
static int urg_pending;
/*************************************************************************
 * Flag the existence of the urgent pointer
 */
static int flag_urg()
{
    urg_pending = 1;
    return;
}
/************************************************************************
 * Send a telnet command
 */
static int e2tel_cmd(con, cmd, arg) 
TELCON * con;
int cmd;
int arg;
{
char buf[3];
int flags, send_len;
    switch (cmd)
    {
    case IAC:
    case GA:
    case NOP:
    case EL:
    case EC:
    case EOR:
        send_len = 2;
        break;
    case DONT:
    case WONT:
        e2tel_opt_clr(con,E2_TEL_WANTED,arg);
        e2tel_opt_set(con,E2_TEL_TRIED,arg);
        send_len = 3;
#ifdef DEBUG
if (cmd == WONT)
     fprintf(stderr,"We WONT %d\n",arg);
else
     fprintf(stderr,"We DONT Want them to %d\n",arg);
#endif
        break;
    case DO:
    case WILL:
        e2tel_opt_set(con,E2_TEL_WANTED,arg);
        e2tel_opt_set(con,E2_TEL_TRIED,arg);
        send_len = 3;
#ifdef DEBUG
if (cmd == WILL)
     fprintf(stderr,"We WILL %d\n",arg);
else
     fprintf(stderr,"We DO Want them to %d\n",arg);
#endif
        break;
    case SB:
    case SE:
        send_len = 3;
        break;
    case AYT:
    case AO:
    case IP:
    case BREAK:
    case SYNCH:
        flags = MSG_OOB;
        buf[0] = IAC;
        send_len = 2;
        if (sendto(con->fd,&buf[0],1,flags,(struct sockaddr *) NULL,0) < 1)
        {
            perror("Out of Band sendto() failed");
            return 0;
        }
        flags = 0;
        buf[0] = DM;
        if (sendto(con->fd,&buf[0],1,flags,(struct sockaddr *) NULL,0) < 1)
        {
            perror("End of Out of Band sendto() failed");
            return 0;
        }
        break;
    }
    flags = 0;
    buf[0] = IAC;
    buf[1] = cmd;
    buf[2] = arg;
    if (sendto(con->fd,&buf[0],send_len,flags,(struct sockaddr *) NULL,0) < 1)
    {
        perror("Command sendto() failed");
        return 0;
    }
#ifdef DEBUG
     fprintf(stderr,"Status: WANTED:%x TRIED:%x OFFERED:%x AGREED:%x\n",
            con->status[E2_TEL_WANTED],
            con->status[E2_TEL_TRIED],
            con->status[E2_TEL_OFFERED],
            con->status[E2_TEL_AGREED]);
#endif
    return 1;
}
/************************************************************************
 * Handle a TELNET Acknowledge (WILL, WON'T, DO, DON'T)
 */
static int e2tel_ack(con, cmd, arg) 
TELCON * con;
int cmd;
int arg;
{
int resp;
    switch(cmd)
    {
    case DO:
    case WILL:
        e2tel_opt_set(con,E2_TEL_OFFERED,arg);
        break;
    case DONT:
    case WONT:
        e2tel_opt_clr(con,E2_TEL_OFFERED,arg);
        break;
    default:         /* Invalid Option */
        (void) fprintf(stderr, "e2tel_ack() called with invalid command %d\n",
                       cmd);
        return 1;
    }
/*
 * If we have tried it, and what we want is what they offered,
 * flag it as agreed
 */
    if (e2tel_opt_tst(con,E2_TEL_TRIED,arg)
     &&  ( e2tel_opt_tst(con,E2_TEL_WANTED,arg) ==
           e2tel_opt_tst(con,E2_TEL_OFFERED,arg)))
    {
         if (e2tel_opt_tst(con,E2_TEL_OFFERED,arg))
             e2tel_opt_set(con,E2_TEL_AGREED,arg);
         else
             e2tel_opt_clr(con,E2_TEL_AGREED,arg);
    }
/*
 * Acknowledge if:
 * - We have never acknowledged it
 * - Or it has changed
 */
    if ( e2tel_opt_tst(con,E2_TEL_AGREED,arg) !=
         e2tel_opt_tst(con,E2_TEL_OFFERED,arg) ||
         !e2tel_opt_tst(con,E2_TEL_TRIED,arg))
    {
         e2tel_opt_set(con,E2_TEL_TRIED,arg);
         e2tel_cmd(con,cmd,(int) arg);
    }
    return 1;
}
/*
 * - e2tel_read()
 *
 * Attempt to read the number of bytes requested, if they are
 * available, and respond to any options or commands encountered.
 *
 * We do further reads if the count of bytes is down because of telnet
 * protocol elements.
 */
static int e2tel_read(con,buf,len)
TELCON *con;
unsigned char * buf;
int len;
{
int urg_next;
int rlen, ilen, olen, to_conv;
register unsigned char * xi, *xo, *xb;
    xi = &(con->buf[0]);     /* Holding area for data prior to protocol
                                negotiations                          */
    xb = xi;
    xo = buf;                /* Where output is being assembled */
    rlen = 0;
    ilen = (len < 8192) ? len: 8192;
    if (ilen == 0)
        ilen = 1;
    while (rlen == 0)
    {
/*
 * Return to this point if a command spans the buffer
 */
re_read:
        urg_next = 0;        /* Clear the Urgent Data Next Packet Flag */
/*
 * Read data from the link
 */
        if ((olen = read(con->fd, xi, ilen)) < 1)
        {
            if (olen < 0)
            {
                if (errno == EINTR)
                    continue;                /* Round again if signalled */
                else
                {
                    perror("e2tel_read() read()");
                    fprintf(stderr,
                           "e2tel_read() read() failed with error number: %d\n",
                            errno);
                    return olen;
                }
            }
            return rlen;                    /* Return the data returned */
        }
        if (comms_trace != (char *) NULL)
            trace_log("Pre-TELNET Read", olen, xi); 
            
/*
 * If we are hunting for the urgent marker, see if we are there
 */
        if (urg_pending)
        {
            if (ioctl(con->fd, SIOCATMARK,&urg_next) < 0)
            {
                perror("e2tel_read() SIOCATMARK ioctl() failed");
                return -1;
            }
            if (urg_next)
                urg_pending = 0;           /* Clear the hunt signal */
        }
/*
 * Search the returned data for telnet commands, and things that need stuffing.
 */ 
        for (to_conv = olen + (xi - xb); to_conv > 0; to_conv--, xb++)
        {
            switch(*xb)
            {
            case IAC:
                if (to_conv == 1)
                {            /* The buffer doesn't have the whole command */
                    xb = &(con->buf[0]);
                    *xb = IAC;
                    xi = xb + 1;
                    ilen = len - rlen + 1;
                    if (len == 0)
                          ilen++;
                    goto re_read;
                }
                else
                {
                    xb++;
                    to_conv--;
                    switch (*xb)
                    {
                    case IAC:
                        if (!urg_pending && !urg_next)
                        { /* Do not forward data if other end requested clear */
                            *xo++ = *xb;
                            rlen++;
                        }
                        break;
                    case DONT:
                    case DO:
                    case WONT:
                    case WILL:
                    case SB:
                    case SE:
                        if (to_conv == 1)
                        {          /* Get the rest of the command        */
                            xi = xb;
                            xb = &(con->buf[0]);
                            *xb = IAC;
                            *(xb + 1) = *xi;
                            xi = xb + 2;
                            ilen = len - rlen + 2;
                            goto re_read;
                        }
                        else
                        {
/*
 * Option negotiation.
 * - The response to a DO or DON'T is a WILL or WON'T.
 * - The response to a WILL or WON'T is a DO or DON'T.
 */
                            switch (*xb)
                            {
                            case DONT:
/*
 * We must always accept a disable offer
 */
                                xb++;
                                to_conv--;
                                e2tel_ack(con,WONT,*xb);
                                break;
                            case DO:
/*
 * We will own up to handling binary data. Otherwise, we reject everything.
 */
                                xb++;
                                to_conv--;
                                switch (*xb)
                                {
                                case TELOPT_BINARY:
                                case TELOPT_SGA:
                                    e2tel_ack(con,WILL,*xb);
                                    break;
                                default:
                                    e2tel_ack(con,WONT,*xb);
                                    break;
                                }
                                break;
                            case WONT:
                                xb++;
                                to_conv--;
                                e2tel_ack(con,DONT,*xb);
                                break;
                            case WILL:
                                xb++;
                                to_conv--;
                                switch (*xb)
                                {
                                case TELOPT_BINARY:
                                case TELOPT_SGA:
                                    e2tel_ack(con,DO,*xb);
                                    break;
                                default:
                                    e2tel_ack(con,DONT,*xb);
                                    break;
                                }
                                break;
                            case SB:    /* We do not recognise sub-options */
                            case SE:
                            default:
                                xb++;
                                to_conv--;
                                break;
                            }
                        }
                        break;
/*
 * Ignore all other commands altogether.
 */
                    case EL:
                    case EC:
                    case AYT:
                    case AO:
                    case IP:
                    case BREAK:
                    case EOR:
                    case GA:
                    case NOP:
                    case DM:
                    default:  /* Unrecognised Command */
                        break;
                    }
                    break;
                }
            case 13:       /* Carriage Return; special handling   */
#ifdef CR_STUFF
/*
 * The DEC 300 does not appear to stuff carriage returns as it should
 */
                if (to_conv == 1)
                {          /* Get the rest of the sequence        */
                    xb = &(con->buf[0]);
                    *xb = 13;
                    xi = xb + 1;
                    ilen = len - rlen + 1;
                    goto re_read;
                }
                else
                {
                    if (!urg_pending && !urg_next)
                    { /* Do not forward data if other end requested clear */
                         *xo++ = *xb++;
                         rlen++;
                         if (*xb != '\0')
                         {
                             *xo++ = *xb;
                             rlen++;
                         }
                    }
                    else
                        xb++;          /* Skip the two characters */
                }
                break;
#endif
            default:         /* An ordinary character             */
                if (!urg_pending && !urg_next)
                { /* Do not forward data if other end requested clear */
                    *xo++ = *xb;
                    rlen++;
                }
                break;
            }
        }
        ilen = len - rlen;
        if (ilen > 8192)
            ilen = 8192;
        xi = &(con->buf[0]);
        xb = xi;
        if (len == 0)
            break;
        else
        if (rlen == 0)
        {
            false_eof = 1;
            break;
        }
    }
    return rlen;
}
/*
 * - e2tel_write()
 */
static int e2tel_write(con,buf,len)
TELCON *con;
unsigned char * buf;
int len;
{
int i;
int wlen, ilen, olen, to_conv;
register unsigned char *xo, *xb;
/*
 * To begin with, send off the options we want
 */
    for (i = 0; i < KNOWN_COUNT; i++)
    {
         if (e2tel_opt_tst(con,E2_TEL_WANTED,i) 
          && !e2tel_opt_tst(con,E2_TEL_TRIED,i))
             e2tel_cmd(con,WILL,i);
    } 
    xo = &(con->buf[0]);     /* Holding area for data prior to protocol
                                negotiations                          */
    xb = buf;
    wlen = 0;
    ilen = (len < 4096) ? len: 4096;
    while (ilen > 0)
    {
/*
 * Search the returned data for IAC and CR, things that need stuffing.
 * In the academic instance of a send buffer > 4096, and a CR on the last
 * character, we will unnecessarily put a NULL between the CR and NL.
 * So what?
 */ 
        for (to_conv = ilen; to_conv > 0; to_conv--, xb++, wlen++)
        {
            switch(*xb)
            {
            case 13:
                 *xo++ = *xb;
                 if (to_conv < 1 || *(xb + 1) != '\n')
                 {
                     *xo++ = '\0';
                     ilen++;
                 }
                 break;
            case IAC:
                 *xo++ = *xb;
                 ilen++;
            default:
                 *xo++ = *xb;
                 break;
            }
        }
/*
 * Write data to the link
 */
        if (comms_trace != (char *) NULL)
            trace_log("Pre-TELNET Write", ilen, &(con->buf[0])); 
        if ((olen = write(con->fd, &(con->buf[0]), ilen)) < 1)
        {
            if (olen < 0)
            {
                perror("e2tel_write() write()");
                (void) fprintf(stderr,
                         "e2tel_write() write() failed with error number: %d\n",
                            errno);
                return olen;
            }
            return wlen;                    /* Return the data written */
        }
        ilen = len - wlen;
        if (ilen > 4096)
            ilen = 4096;
        xo = &(con->buf[0]);
    }
    return wlen;
}
static TELCON tras_telcon;
/**************************************************************************
 * Establish a connexion to the TRASEC. The host name and port are
 * separated by a ':'
 */
int call_trasec(where)
char *where;
{
char buf[128];
char * tname;
char *x;
char * tport;
int pr_sock ;
struct sockaddr_in dest ;
int length = sizeof(dest) ;
    strncpy(buf,where,sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    sigset(SIGIO,flag_urg);
    if ((tname = strtok(buf,":")) == (char *) NULL)
    {
        (void) fprintf(stderr,"call_trasec() strtok() for host in %s failed\n",
                where);
        return -1;
    }
    if ((tport = strtok((char *) NULL,":")) == (char *) NULL)
    {
        (void) fprintf(stderr,"call_trasec() strtok() for port in %s failed\n",
                where);
        return -1;
    }
#ifdef DEBUG
    fprintf(stderr,"Connecting to: %s : %s (%d)\n",tname,tport,atoi(tport));
#endif
/*
 * Initiate connection to the remote device (Internet port)
 */
    if ( (pr_sock = e2_connect(tname,atoi(tport),
                     (struct sockaddr_in *) NULL)) < 0)
    {
	perror("call_trasec(): Connecting socket to DEC 300") ;
	return -1 ;
    }
/*
 * Get socket name (as an additional consistency check)
 */
    if (getsockname( pr_sock, (struct sockaddr *) &dest, &length))
    {
	(void) close( pr_sock) ;
	perror("get-socket-name check") ;
	return -1 ;
    }
    memset((char *) (&tras_telcon),0,sizeof(tras_telcon));
    tras_telcon.fd = pr_sock;
/*
 * We want binary mode, with GA suppression
 */
    e2tel_opt_set(&tras_telcon, E2_TEL_WANTED, TELOPT_BINARY);
    e2tel_opt_set(&tras_telcon, E2_TEL_WANTED, TELOPT_SGA);
    e2tel_write(&tras_telcon,"",0);   /* Do the option stuff */
    for (length = 6; length; length--)
        e2tel_read(&tras_telcon,"",0); /* Do the option stuff */
    false_eof = 0;                     /* Clear the EOF flag */
    return pr_sock;
}
/**************************************************************************
 * Interface to support the TRASEC in a machine-independent way
 */
int tras_read(fd,buf,len)
int fd;
char * buf;
int len;
{
    if (fd == tras_telcon.fd)
        return e2tel_read((&tras_telcon),buf,len);
    else
        return read(fd,buf,len);
}
int tras_write(fd,buf,len)
int fd;
char * buf;
int len;
{
    if (fd == tras_telcon.fd)
        return e2tel_write((&tras_telcon),buf,len);
    else
        return write(fd,buf,len);
}
int tras_flush(fd)
int fd;
{
    if (fd == tras_telcon.fd)
        return e2tel_cmd((&tras_telcon),SYNCH,0);
    else
        return 0;
}

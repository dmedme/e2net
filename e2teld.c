/*
 * Copyright (c) E2 System 1985
 */
static char * sccs_id="Copyright E2 Systems Limited 1985, 1992, 1999\n\
@(#) $Name$ $Id$\n";
#ifdef LCC
#include <winsock2.h>
#include <intrinsics.h>
#else
#ifdef VCC2003
#include <winsock2.h>
#define sleep _sleep
int errno;
#else
#include <winsock.h>
#define SD_RECEIVE 0
#define	SD_SEND 1
#define SD_BOTH 2
#endif
#endif
#include <windows.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#ifndef O_NOINHERIT
#define O_NOINHERIT 0x80
#endif
#ifndef P_DETACH
#define P_DETACH 4
#endif
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define COMMAND_PROCESSOR "C:\\WINNT\\SYSTEM32\\CMD.EXE"

#define BUFLEN      2048
static void e2spawn();
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
    int false_eof;              /* Flag needed for option processing */
    long status[4];             /* Enough bits for 32 options */
    unsigned char buf[8192];
} TELCON;
struct sock_file_pair {
    int sock_fd;
    int file_fd;
};
struct sock_file_telnet_pair {
    int sock_fd;
    int file_fd;
    TELCON telcon;
};
/*
 * Operations on the array of status values
 */
#define e2tel_opt_set(con,which,opt) ((con)->status[(which)] |= (1 << (opt)))
#define e2tel_opt_clr(con,which,opt) ((con)->status[(which)] &= ~(1 << (opt)))
#define e2tel_opt_tst(con,which,opt) (((con)->status[(which)]&(1<<(opt)))?1:0)
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
/*
 * Read data from the link
 */
        if ((olen = recvfrom(con->fd, xi, ilen,0,0,0)) < 1)
        {
            if (olen < 0)
            {
                if (errno == EINTR)
                    continue;                /* Round again if signalled */
                else
                {
                    perror("e2tel_read() recvfrom()");
                    fprintf(stderr,
                     "e2tel_read() recvfrom() failed with error number: %d\n",
                            errno);
                    return olen;
                }
            }
            return rlen;                    /* Return the data returned */
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
                        /* Do not forward data if other end requested clear */
                        *xo++ = *xb;
                        rlen++;
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
                    /* Do not forward data if other end requested clear */
                    *xo++ = *xb++;
                    rlen++;
                    if (*xb != '\0')
                    {
                        *xo++ = *xb;
                        rlen++;
                    }
                }
                break;
#endif
            default:         /* An ordinary character             */
                /* Do not forward data if other end requested clear */
                *xo++ = *xb;
                rlen++;
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
            con->false_eof = 1;
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
        if ((olen = sendto(con->fd, &(con->buf[0]), ilen,0,0,0)) < 1)
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

static void sigterm()
{
    puts("User Terminated");
    WSACleanup();
    exit(0);
}
/******************************************************************************
 * VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
 * Entry point - Main Program Start Here
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nCmdShow)
{
char * fifo_args[30];                           /* Dummy arguments to process */
short int i;
/*
 * Process the arguments in the string that has been read
 */
    if ((fifo_args[0]=strtok(lpCmdLine,"  \n"))==NULL)
         return 0;
/*
 * Generate an argument vector
 */
    for (i=1;
             i < 29 && (fifo_args[i]=strtok(NULL," \n")) != (char *) NULL;
                 i++);
    fifo_args[i] = (char *) NULL; 
    return main(i,fifo_args);
}
void do_command(accept_socket_fd)
int accept_socket_fd;
{
char *x;
char buf[128];
#ifdef DEBUG
char logfile[40];
FILE * logfp;

    sprintf(logfile,"log_acc%d", accept_socket_fd);
    logfp = fopen(logfile, "wb");
    fputs("Processing a command\n", logfp);
    fflush(logfp);
#else
#define logfp stderr
#endif
/*
 * Have to hook up a pipe, and spawn
 */
    if ((x = getenv("COMSPEC")) == (char *) NULL)
        x = COMMAND_PROCESSOR;
    e2spawn(accept_socket_fd, NULL, x
#ifdef DEBUG
                 , logfp
#endif
                 );
    closesocket(accept_socket_fd);
#ifdef DEBUG
    fclose(logfp);
#endif
    return;
}    /* end of spawned command processing  */
/*
 * Socket to File progression. These routines kill off the sockets always,
 * but not the files (which might be shared with other threads).
 */
void  sock_file_telnet_forward(sfp)
struct sock_file_telnet_pair * sfp;
{
unsigned char transfer_buf[BUFLEN];
int read_count;
    for (;;)
    {
        if ((read_count=e2tel_read(&(sfp->telcon), transfer_buf,BUFLEN)) <= 0)
            break;
        if (write(sfp->file_fd, transfer_buf,read_count) != read_count)
            break;
    }
    shutdown(sfp->sock_fd, SD_BOTH);
    closesocket(sfp->sock_fd);
    close(sfp->file_fd);
    free((char *) sfp);
    return;
}
void file_sock_forward(sfp)
struct sock_file_pair * sfp;
{
unsigned char transfer_buf[BUFLEN];
int read_count;
    for (;;)
    {
        if ((read_count=read(sfp->file_fd, transfer_buf,BUFLEN)) <= 0)
            break;
        if (sendto(sfp->sock_fd, transfer_buf,read_count, 0,0,0)
                    != read_count)
            break;
    }
    shutdown(sfp->sock_fd, SD_BOTH);
    closesocket(sfp->sock_fd);
    close(sfp->file_fd);
    free((char *) sfp);
    return;
}
/*
 * Function to fire off a child process connected by pipes to a socket
 */
static void e2spawn(accept_socket_fd, prog_name, command_line
#ifdef DEBUG
, logfp
#endif
)
int accept_socket_fd;
char * prog_name;
char * command_line;
#ifdef DEBUG
FILE *logfp;
#endif
{
int hthread;
HANDLE hthread1;
struct sock_file_telnet_pair * sock_to_file;
struct sock_file_pair * file_to_sock;
int pwrite[2];
int pread[2];
int h0;
int h1;
int h2;
STARTUPINFO si;
PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = NULL;
    si.dwX = 0;
    si.dwY = 0;
    si.dwXSize = 0;
    si.dwYSize= 0;
    si.dwXCountChars = 0;
    si.dwYCountChars= 0;
    si.dwFillAttribute= 0;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.wShowWindow = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;
/*
 * Duplicate the standard file handles
 */
    fprintf(logfp,"Executing command %s\n", command_line);
    fflush(logfp);
/*
 * Create the read pipe
 */
    if (_pipe(&pread[0],4096,O_BINARY|O_NOINHERIT))
    {
        fprintf(logfp,"pipe(pread...) failed error:%d\n", errno);
        return;
    }
#ifdef DEBUG
    else
        fprintf(logfp,"pipe(pread...) gives files:(%d,%d)\n", pread[0],
                   pread[1]);
#endif
    if (_pipe(&pwrite[0],4096,O_BINARY|O_NOINHERIT))
    {
        fprintf(logfp,"pipe(pwrite...) failed error:%d\n", errno);
        return;
    }
#ifdef DEBUG
    else
        fprintf(logfp,"pipe(pwrite...) gives files:(%d,%d)\n", pwrite[0],
                   pwrite[1]);
#endif
/*
 * Set up the pipe handles for inheritance
 */
    if ((h0 = _dup(pread[0])) < 0)
    {
        fprintf(logfp,"dup2(pread[0],0) failed error:%d\n", errno);
        return;
    }
    close(pread[0]);
    if ((h1 = _dup(pwrite[1])) < 0)
    {
        fprintf(logfp,"dup2(pwrite[1],1) failed error:%d\n", errno);
        return;
    }
    if (( h2 = _dup(pwrite[1])) < 0)
    {
        fprintf(logfp,"dup2(pwrite[1],2) failed error:%d\n", errno);
        return;
    }
    close(pwrite[1]);
/*
 * Set up the socket/pipe forwarding
 */
    sock_to_file = (struct sock_file_telnet_pair *)
                        malloc(sizeof(struct sock_file_telnet_pair));
    
    memset((char *) sock_to_file, 0, sizeof(struct sock_file_telnet_pair));
    file_to_sock = (struct sock_file_pair *)
                        malloc(sizeof(struct sock_file_pair));
    sock_to_file->file_fd = pread[1];
    file_to_sock->file_fd = pwrite[0];
    file_to_sock->sock_fd = accept_socket_fd;
    sock_to_file->sock_fd = accept_socket_fd;
    sock_to_file->telcon.fd = accept_socket_fd;
    e2tel_opt_set(&(sock_to_file->telcon), E2_TEL_WANTED, TELOPT_BINARY);
    e2tel_opt_set(&(sock_to_file->telcon), E2_TEL_WANTED, TELOPT_SGA);
    e2tel_write(&(sock_to_file->telcon),"",0);   /* Do the option stuff */
    for (hthread = 6; hthread; hthread--)
        e2tel_read(&(sock_to_file->telcon),"",0); /* Do the option stuff */
    sock_to_file->telcon.false_eof = 0;           /* Clear the EOF flag */
/*
 * Restore the normal handles
 */
    si.hStdInput = (HANDLE) _get_osfhandle(h0);
    si.hStdOutput = (HANDLE) _get_osfhandle(h1);
    si.hStdError = (HANDLE) _get_osfhandle(h2);

    if (!CreateProcess(prog_name, command_line, NULL, NULL, TRUE,
                  0, NULL, NULL, &si, &pi))
        fprintf(logfp,"Create process failed error %d\n",errno);
#ifdef DEBUG
    else
        fputs("Create process succeeded\n", logfp);
#endif
    fflush(logfp);
    close(h0);
    close(h1);
    close(h2);
    hthread1 = CreateThread(NULL, 0,
                       (LPTHREAD_START_ROUTINE) sock_file_telnet_forward,
                       (LPVOID) sock_to_file, 0, &hthread);
    file_sock_forward(file_to_sock);
    closesocket(accept_socket_fd);
    close(pread[1]);
    close(pwrite[0]);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hthread1);
    CloseHandle((HANDLE) hthread);
    return;
}
/*****************************************************************
 *   Start of Main Program
 */
int main (argc,argv)
int argc;
char* argv[];
{
struct sockaddr_in listen_sock, calling_sock;
int accept_socket_fd, listen_socket_fd;
/*
 * Initialise - use input parameters to set up listen port or
 * address of port to connect to
 */
long int child_pid;
int socket_flags=0;
int calladdrlength=sizeof(listen_sock);
#ifdef DEBUG
char logfile[40];
FILE * logfp;
#else
#define logfp stderr
#endif
/*
 * Construct the Socket Addresses
 */
WORD wVersionRequested;
WSADATA wsaData;
wVersionRequested = 0x0101;
    child_pid = getpid();
#ifdef DEBUG
    sprintf(logfile,"log%d", child_pid);
    logfp = fopen(logfile,"wb");
    fprintf(logfp, "argc: %d argv[0]: %s\n", argc, argv[0]);
    fflush(logfp);
#endif
    if (argc < 2)
        exit(1);
    if ( WSAStartup( wVersionRequested, &wsaData ))
    {
        fprintf(logfp, "WSAStartup error: %d", errno);
        exit(1);
    }
/*
 * The socket to listen on
 */
    memset((char *) &listen_sock, 0, sizeof(listen_sock));
    listen_sock.sin_family = AF_INET;
    listen_sock.sin_port   = htons((short) atoi(argv[1]));
    listen_sock.sin_addr.s_addr = (INADDR_ANY);
/*
 * Initialise the signal catcher
 */
    signal(SIGINT, sigterm);
/*
 * Now create the socket to listen on
 */
    if ((listen_socket_fd=socket(AF_INET,SOCK_STREAM,6))<0)
    { 
        printf("Listen create failed"); 
        fprintf(logfp, "socket() error: %d", errno); 
        exit(1);
    }
/*
 * Bind its name to it
 */
    if (bind(listen_socket_fd,
                 (struct sockaddr *) &listen_sock,sizeof(listen_sock)))
    { 
        fprintf(logfp, "bind() error: %d", errno); 
        printf("Listen bind failed"); 
        exit(1);
    }
/*
 * Declare it ready to accept calls
 */
    if (listen(listen_socket_fd,5))
    {
        printf("listen failed");
        fprintf(logfp, "  error: %d", errno); 
        exit(1);
    }
#ifdef DEBUG
    fputs("Listen succeeded\n", logfp);
#endif
/*****************************************************************
 *   Start of Main Loop; wait for connexions and trace them, until
 *   terminate signal arrives; when a connexion arrives, spawn a handler.
 */
    for (;;)
    {
/*
 * Wait for calls
 */
     HANDLE ht;

        if ((accept_socket_fd = accept(listen_socket_fd,
                    (struct sockaddr *) &calling_sock, &calladdrlength)) < 0)
        {
            fprintf(logfp, "Accept failed error: %d", errno);
            if (errno == EINTR)
                continue;
            exit(1);
        }
        fprintf(logfp, "Accept from %s succeeded\n",
                     inet_ntoa(calling_sock.sin_addr));
        ht = CreateThread(NULL, 0,
                       (LPTHREAD_START_ROUTINE) do_command,
                       (LPVOID) accept_socket_fd,
                      0, &child_pid);
        CloseHandle((HANDLE) child_pid);
        CloseHandle(ht);
#ifdef DEBUG
        fflush(logfp);
#endif
    }    /*    End of infinite for */
}    /* End of Main */

/*
 * Copyright (c) E2 System 1985
 */
#ifdef UNIX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>
#define closesocket close
#ifndef SD_RECEIVE
#define SD_RECEIVE 0
#endif
#ifndef SD_SEND
#define	SD_SEND 1
#endif
#ifndef SD_BOTH
#define SD_BOTH 2
#endif
#else
#define __USE_W32_SOCKETS
#include <winsock2.h>
#include <windows.h>
#ifdef LCC
#include <intrinsics.h>
#else
#include <winsock.h>
#define SD_RECEIVE 0
#define	SD_SEND 1
#define SD_BOTH 2
#endif
#include <process.h>
#include <io.h>
#include <fcntl.h>
#ifndef O_NOINHERIT
#define O_NOINHERIT 0x80
#endif
#endif
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef UNIX
#define SLEEP_FACTOR 1000
#else
#ifndef O_BINARY
#define O_BINARY 0
#endif
#define SLEEP_FACTOR 1
#define GetLastError() (errno)
#endif

#define LISTEN_SERV argv[1]
#define CALL_HOST   argv[2]
#define CALL_PORT   argv[3]
#define BUFLEN      1400
#define FIRST_PRIV  803
#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 8
#endif
int errno;
static void do_scen();
static void e2spawn();
#ifdef MINGW32
static SOCKET __stdcall socket(int af, int stype, int prot)
{

    return WSASocket(af, stype, prot, 0, 0, 0);
}
#endif

static void sigterm()
{
    puts("User Terminated");
#ifndef UNIX
    WSACleanup();
#endif
    exit(0);
}
#ifdef UNIX
static void sigchild()
{
int pid;
#ifdef POSIX
int
#else
union wait
#endif
    wait_status;

    (void) sigset(SIGCLD,SIG_DFL); /* Avoid nasties with the chld_sig/wait3()
                                       interaction */
    while ((pid=wait3(&wait_status, WNOHANG, 0)) > 0);
    (void) sigset(SIGCLD,sigchild); /* re-install */
    return;
}
#else
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
struct relay_parms {
    int accept_socket_fd;
    char * call_host;
    unsigned short call_port;
};
struct sock_pair {
    int sock_in_fd;
    int sock_out_fd;
    int gone_flag;
    struct sock_pair * other;
};
/*
 * Socket to File progression.
 */
void  sock_forward(sfp)
struct sock_pair * sfp;
{
unsigned char transfer_buf[BUFLEN];
int read_count;

    for (;;)
    {
        if ((read_count=recvfrom(sfp->sock_in_fd, transfer_buf,BUFLEN,
                                            0,0,0)) <= 0)
        {
            if (read_count = GetLastError())
                fprintf(stderr,"recvfrom() failed error %d\n", read_count);
            break;
        }
        if (sendto(sfp->sock_out_fd, transfer_buf,read_count,0,0,0)
                        != read_count)
        {
            fprintf(stderr,"sendto() failed error %d\n", GetLastError());
            break;
        }
        if (sfp->other->gone_flag)
            break;
    }
    shutdown(sfp->sock_in_fd, SD_RECEIVE);
    shutdown(sfp->sock_out_fd, SD_SEND);
    sfp->gone_flag = 1;
    return;
}
#endif
static void do_forward(accept_socket_fd, call_host, call_port)
int accept_socket_fd;
char * call_host;
unsigned short call_port;
{
#ifdef UNIX
/*
 * Initialise - use input parameters to set up port to connect to
 */
struct hostent *connect_host,
    *gethostbyname();
long int in_addr;
struct protoent *tcp_prot,
    *getprotobyname();
fd_set sockmask,
    readymask,
    dummy;
int read_count,
    icount;
int process_fd[2],
    read_pair[2],
    write_pair[2];
int calladdrlength=sizeof(listen_sock);
char transfer_buf[BUFLEN];

/*
 * Get ready to select
 */

    if ((output_socket_fd = connect_relay(call_host, call_port)) == -1)
    {
        fprintf(stderr, "Output connect() failed error %d\n", errno);
        return;
    }
/*
 * Get ready to select
 */
    FD_ZERO(&dummy);
    FD_ZERO(&sockmask);
    FD_ZERO(&readymask);

    FD_SET(in_fd, &sockmask);
    FD_SET(output_socket_fd, &sockmask);

    read_pair[0]  = in_fd;
    write_pair[1] = in_fd;

    read_pair[1]  = output_socket_fd;
    write_pair[0] = output_socket_fd;

    for(;;)
    {
/*
 * Note that this program:
 * - checks that there is data to read
 * - does not check that it will not be blocked on write
 */
        readymask = sockmask;
        if (select(20,&readymask,&dummy,&dummy,0)<1)
        {
            perror("select()");
            fprintf(stderr,"PID %d Error %d Select failed",
                        getpid(),errno);
            exit(1);
        }
        process_fd[0] = FD_ISSET(in_fd, &readymask);
        process_fd[1] = FD_ISSET(output_socket_fd, &readymask);
        for (icount=0; icount < 2; icount++)
        {
            if (process_fd[icount])
            {
                read_count=read(read_pair[icount],transfer_buf,
                     sizeof(transfer_buf));
                if (read_count <= 0)
                {
                    close (in_fd);
                    close (output_socket_fd);
                    exit(0);
                }
                else
                    write(write_pair[icount],transfer_buf,read_count);
            }
        }
    }
#else
HANDLE hthread;
int threadid;
int output_socket_fd;
struct sock_pair * acc_to_call;
struct sock_pair * call_to_acc;

    fprintf(stderr,"Forwarding %d to %s:%u\n", accept_socket_fd,
         call_host, ntohs(call_port));
    fflush(stderr);
/*
 * Create the output socket
 */
    if ((output_socket_fd = connect_relay(call_host, call_port)) < 0)
    {
        fprintf(stderr,"Failed to connect error: %d\n", GetLastError());
        return;
    }
/*
 * Set up the socket forwarding
 */
    acc_to_call = (struct sock_pair *)
                        malloc(sizeof(struct sock_pair));
    
    memset((char *) acc_to_call, 0, sizeof(struct sock_pair));
    call_to_acc = (struct sock_pair *)
                        malloc(sizeof(struct sock_pair));
    memset((char *) call_to_acc, 0, sizeof(struct sock_pair));
    acc_to_call->sock_out_fd = output_socket_fd;
    call_to_acc->sock_in_fd = output_socket_fd;
    call_to_acc->sock_out_fd = accept_socket_fd;
    acc_to_call->sock_in_fd = accept_socket_fd;
    call_to_acc->other = acc_to_call;
    acc_to_call->other = call_to_acc;
    hthread = CreateThread(NULL, 0,
                      (LPTHREAD_START_ROUTINE) sock_forward,
                      (LPVOID) acc_to_call,
                      0, &threadid);
    sock_forward(call_to_acc);
    closesocket(accept_socket_fd);
    closesocket(output_socket_fd);
    free(call_to_acc);
    free(acc_to_call);
    WaitForSingleObject(hthread,INFINITE);
    CloseHandle(hthread);
    CloseHandle((HANDLE) threadid);
#endif
    fputs("Session closed\n", stderr);
    return;
}
/*
 * Function to fire off a child thread
 */
#ifndef UNIX
static void nt_forward(relay_parms)
struct relay_parms * relay_parms;
{
    do_forward(relay_parms->accept_socket_fd, 
                relay_parms->call_host, relay_parms->call_port);
    return;
}
#endif
/*************************************************************************
 * Establish a connection to a relay host/port
 */
int connect_relay(call_host, call_port)
char * call_host;
unsigned short int call_port;
{
char *x;
struct sockaddr_in connect_sock;
int on=1;
struct linger optval;
int output_socket_fd;
long num_host;
struct hostent num_ent;
long * phost; 
/*
 * Initialise - use input parameters to set up call to news server
 */
struct hostent *connect_host;
int    read_count, socket_flags=0, icount;
int calladdrlength=sizeof(connect_sock);
struct sock_pair * acc_to_call, * call_to_acc;
unsigned char transfer_buf[BUFLEN];
/*
 * Construct the Socket Address to connect to
 */
    memset((char *) &connect_sock, 0, sizeof(connect_sock));
/*
 * Because NT4 gethostbyname is so useless
 */
    if ((num_host = inet_addr(call_host)) != -1)
    {
        memcpy(&connect_sock.sin_addr,&num_host, sizeof(num_host)); 
        num_ent.h_addrtype = AF_INET;
        num_ent.h_addr_list = &phost;
        num_ent.h_addr = (char *) &num_host;
        num_ent.h_length = sizeof(num_host);
        connect_host = &num_ent;
    }
    else
    if ((connect_host=gethostbyname(call_host)) != (struct hostent *) NULL)
        memcpy(&connect_sock.sin_addr,connect_host->h_addr, 
                     connect_host->h_length);
    else
    {
        fprintf(stderr,"host %s not found\n",call_host);
        return (-1);
    }
    connect_sock.sin_family = connect_host->h_addrtype;
    connect_sock.sin_port   =  call_port; /* Already put in network order */
/*
 * Now create the socket to output on
 */
    if ((output_socket_fd = socket(AF_INET,SOCK_STREAM,6)) < 0)
    {
        perror("socket() failed");
        return -1;
    }
/*
 * Set the linger to ten seconds, so that close will linger a while before
 * closing connection
 */
    optval.l_onoff = 1;
    optval.l_linger = 10*SLEEP_FACTOR;  /* Factor should not be needed */
    if (setsockopt(output_socket_fd, SOL_SOCKET,
                  SO_LINGER, (char *) &optval, sizeof( optval )) < 0)
    {
        perror("setsockopt() failed");
        return -1;
    }
/*
 * Connect with the destination
 */
    if (connect(output_socket_fd,
                    (struct sockaddr *) &connect_sock,sizeof(connect_sock)))
    { 
        perror("connect() failed");
        return -1;
    }
#ifdef DEBUG
    else
        fputs("Connect succeeded\n", stderr);
#endif
    setsockopt(output_socket_fd, IPPROTO_TCP, TCP_KEEPALIVE, &on,
                        sizeof(on));
    return output_socket_fd;
}
/*****************************************************************
 *   Start of Main Program
 */
int main (argc,argv)
int argc;
char* argv[];
{
int on=1;
struct sockaddr_in listen_sock, calling_sock;
int listen_socket_fd;
int accept_socket_fd;
#ifndef UNIX
    struct relay_parms rp;
    HANDLE hthread;
#endif
/*
 * Initialise - use input parameters to set up listen port or
 * address of port to connect to
 */
long int child_pid;
struct hostent *connect_host;
int    read_count, socket_flags=0, icount;
int calladdrlength=sizeof(listen_sock);
struct sock_pair * acc_to_call, * call_to_acc;
unsigned char transfer_buf[BUFLEN];
char *x;
unsigned short call_port;
/*
 * Construct the Socket Addresses
 */
#ifndef UNIX
WORD wVersionRequested;
WSADATA wsaData;
wVersionRequested = 0x0202;
#endif
    child_pid = getpid();
#ifdef DEBUG
    sprintf(logfile,"log%d", child_pid);
    stderr = fopen(logfile,"wb");
    fprintf(stderr, "argc: %d argv[0]: %s\n", argc, argv[0]);
    fflush(stderr);
#endif
#ifndef UNIX
    if ( WSAStartup( wVersionRequested, &wsaData ))
    {
        fprintf(stderr, "WSAStartup error: %d %d", errno, WSAGetLastError());
        exit(1);
    }
#endif
    if (argc < 4)
    {
        fputs("Give a listen socket, a call host and a call socket\n",stderr);
        exit(0);
    }
/*
 * The socket to listen on
 */
    memset((char *) &listen_sock, 0, sizeof(listen_sock));
    listen_sock.sin_family = AF_INET;
    listen_sock.sin_port   = htons((short) atoi(LISTEN_SERV));
    listen_sock.sin_addr.s_addr = (INADDR_ANY);
    call_port   = htons((short) atoi(CALL_PORT));
#ifndef UNIX
    rp.call_host = CALL_HOST;
    rp.call_port = call_port;
#endif

/*
 * Initialise the signal catcher
 */
#ifdef UNIX
    signal(SIGCHLD,sigchild);
    signal(SIGTERM, sigterm);
#endif
    signal(SIGINT, sigterm);
/*
 * Now create the socket to listen on
 */
    if ((listen_socket_fd=socket(AF_INET,SOCK_STREAM,6))<0)
    { 
        fprintf(stderr, "socket() error: %d\n", GetLastError()); 
        fputs("Listen create failed\n", stderr); 
#ifndef UNIX
        WSACleanup();
#endif
        exit(1);
    }
#ifndef SO_REUSEADDR
#define SO_REUSEADDR 2
#endif
    if ((setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, &on,
                        sizeof(on))) < 0)
        fprintf(stderr, "Failed to enable socket address re-use error: %d\n",
                GetLastError());
/*
 * Bind its name to it
 */
    if (bind(listen_socket_fd,
                 (struct sockaddr *) &listen_sock,sizeof(listen_sock)))
    { 
        fprintf(stderr, "bind() error: %d\n", GetLastError()); 
        fputs("Listen bind() failed\n", stderr); 
#ifndef UNIX
        WSACleanup();
#endif
        exit(1);
    }
/*
 * Declare it ready to accept calls
 */
    if (listen(listen_socket_fd,5))
    {
        fprintf(stderr, "  error: %d\n", GetLastError()); 
#ifndef UNIX
        fputs("listen failed\n", stderr);
        WSACleanup();
#endif
        exit(1);
    }
#ifdef DEBUG
    fputs("Listen succeeded\n", stderr);
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
        if ((accept_socket_fd = accept(listen_socket_fd,
                    (struct sockaddr *) &calling_sock, &calladdrlength)) < 0)
        {
            fprintf(stderr, "Accept failed error: %d", GetLastError());
            continue;
        }
        fprintf(stderr, "Accept from %s succeeded ... ",
                         inet_ntoa(calling_sock.sin_addr));
        setsockopt(accept_socket_fd, IPPROTO_TCP, TCP_KEEPALIVE, &on,
                    sizeof(on));
#ifdef UNIX
        if ((child_pid=fork())==0)
        {
            do_forward(accept_socket_fd, CALL_HOST, call_port);
            exit(0);
        }
        close(accept_socket_fd);
#else
        rp.accept_socket_fd = accept_socket_fd;
        hthread = CreateThread(NULL, 0,
                      (LPTHREAD_START_ROUTINE) nt_forward, (LPVOID) &rp,
                      0, &child_pid);
        CloseHandle((HANDLE) child_pid);
        CloseHandle(hthread);
#endif
#ifdef DEBUG
        fflush(stderr);
#endif
    }    /*    End of infinite for */
}    /* End of Main */

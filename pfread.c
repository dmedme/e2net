#include <sys/types.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <net/pfilt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct bpf_hdr {
	struct timeval	bh_tstamp;	/* time stamp */
	u_int		bh_caplen;	/* length of captured portion */
	u_int		bh_datalen;	/* original length of packet */
};
static struct timeval tv;
static struct timezone tz;
catch_int()
{
   gettimeofday(&tv,&tz);
   fprintf(stderr,"End: %d.%06d\n", tv.tv_sec, tv.tv_usec);
   exit(0);
}
main ()
{
int fd;
int i;
int n;
struct bpf_hdr bh;
int backlog=5000;
short int bits;
unsigned char buf[1048576];
struct enstamp snoop;
#ifdef TTY
int ttyfd = open("/dev/tty",O_RDWR);
#endif
    bits = ENTSTAMP | ENPROMISC | ENBATCH | ENCOPYALL;
    signal(SIGINT,catch_int);
    signal(SIGHUP,catch_int);
    signal(SIGQUIT,catch_int);
    signal(SIGTERM,catch_int);
#ifdef TTY
    if (ttyfd > 0)
    write(ttyfd,"Press any key when you are ready to start, INTR to stop\n",56);
    read(0, &buf[0], 1);
#endif
    gettimeofday(&tv,&tz);
    fprintf(stderr,"Begin: %d.%06d\n", tv.tv_sec, tv.tv_usec);
    if ((fd = pfopen("pf0",O_RDONLY)) < 0)
    {
        perror("open() failed\n");
        exit(1);
    }
    if (ioctl(fd,EIOCMBIS,&bits) < 0)
    {
        perror("ioctl(EIOCMBIS) failed\n");
        exit(1);
    }
    if (ioctl(fd,EIOCSETW,&backlog) < 0)
    {
        perror("ioctl(EIOCSETW) failed\n");
        exit(1);
    }
    fputs("pfread                 \n", stdout);
    for(;;)
    {
        if ((n = read(fd,buf,sizeof(buf))) <= 0)   
        {
            perror("read() failed\n");
            exit(1);
        }
        else
        {
/*            n = ENALIGN(n);
            fprintf(stderr,"read: %d\n",n); */
            memcpy((char *) &snoop,buf,sizeof(snoop));
            bh.bh_tstamp = snoop.ens_tstamp;
            bh.bh_datalen = snoop.ens_count;
            bh.bh_caplen = snoop.ens_count;
            n = ENALIGN(bh.bh_caplen);
            fwrite((char*) &bh, 1, sizeof(bh), stdout);
            fwrite(buf +20,sizeof(char),bh.bh_caplen,stdout);
#ifdef DEBUG
            (void) fprintf(stderr,
              "Packet Filter Header Details are:\n\
            snoop.ens_stamplen: %d\n\
            snoop.ens_flags: %d\n\
            snoop.ens_count: %d\n\
            snoop.ens_dropped: %d\n\
            snoop.ens_ifoverflows: %d\n\
            snoop.ens_tstamp.tv_sec: %d\n\
            snoop.ens_tstamp.tv_usec: %d\n",
            snoop.ens_stamplen,
            snoop.ens_flags,
            snoop.ens_count,
            snoop.ens_dropped,
            snoop.ens_ifoverflows,
            snoop.ens_tstamp.tv_sec,
            snoop.ens_tstamp.tv_usec);
#endif
        }
    }
    close(fd);
    exit(0);
}

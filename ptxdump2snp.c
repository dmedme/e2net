/*
 * ptxdump2snp.c - Convert the output from PTX tcpdump into a file
 * that can be handled by E2's snoop-based utilities
 *
 * Set up as a filter, so can take output straight from PTX tcpdump.
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct snoop_header {
    long len;
    long saved_len;
    long unknown[2];
    long secs_since_1970;
    long musecs;
};
/*
 * Only works with a valid time hh:mm:ss.ss
 */
static void do_timestamp(b, secs,musecs)
char * b;
long * secs;
long * musecs;
{
     *secs = ((*b) - 48) * 10 *3600 +
             (*(b + 1) - 48) * 3600 +
             (*(b + 3) - 48) * 10 * 60 +
             (*(b + 4) - 48) * 60 +
             (*(b + 6) - 48) * 10 +
             (*(b + 7) - 48);
    *musecs = (*(b + 9) - 48) * 100000 + (*(b + 10) - 48 ) * 10000;
    return;
}
/*
 * Bring in h pair of hexadecimal bytes, and output a binary byte.
 */
static void hex2byte(out, in)
char * out;
char * in;
{
/*
 * Build up half-byte at a time, subtracting 48 initially, and subtracting
 * another 7 (to get the range from A-F) if > (char) 9;
 */
    register char tmp;
    tmp = *in - (char) 48;
    if (tmp > (char) 9)
       tmp -= (char) 7; 
    if (tmp > (char) 15)
       tmp -= (char) 32;    /* Handle lower case */
    *out = (unsigned char) (((int ) tmp) << 4);
    in++;
    tmp = *in - (char) 48;
    if (tmp > (char) 9)
       tmp -= (char) 7; 
    if (tmp > (char) 15)
       tmp -= (char) 32;    /* Handle lower case */
    *out |= tmp;
    return;
}
static void snoop_write(s,m)
struct snoop_header * s;
char * m;
{
static struct	ether_header {
	unsigned char ether_dhost[6];
	unsigned char ether_shost[6];
	unsigned short	ether_type;
} e;
int j = s->len + sizeof(struct ether_header);
    e.ether_type=htons(0x800);
    s->len = htonl(j);
    s->saved_len = s->len;
    s->secs_since_1970 = htonl((s->secs_since_1970));
    s->musecs = htonl((s->musecs));
    fwrite((char *) s,sizeof(char),
          sizeof(struct snoop_header),stdout);   /* The snoop header */
    fwrite((char *) &e,sizeof(char),
          sizeof(struct ether_header),stdout);   /* The ether header */
    fwrite(m,sizeof(char), j - sizeof(e),stdout);       /* The packet */
    if ((j = (j % 4)))
        fwrite(m,sizeof(char), 4 - j, stdout);   /* The alignment stuff */
    return;
}
main()
{
time_t base_time;
char buf[132];
char mess[4096];
char * in_ptr;
char * top_ptr;
char* mess_ptr;
struct snoop_header snoop;
    memset((char *) (&snoop), 0,sizeof(snoop));
    base_time = (time(0)/86400)*86400;
    fwrite(buf,sizeof(char),16,stdout);   /* The snoop file header */
    while(fgets(buf,sizeof(buf) - 1, stdin) != (char *) NULL)
    {
        switch (buf[0])
        {
        case ' ':
            for (in_ptr = &buf[3],
                 top_ptr = in_ptr + strlen(in_ptr) - 1,
                 top_ptr = (top_ptr < (in_ptr + 48))?top_ptr: (in_ptr + 48);
                     in_ptr < top_ptr && *in_ptr != ' ';
                         in_ptr += 3, mess_ptr++, snoop.len++)
                 hex2byte(mess_ptr,in_ptr);
            break;
        default:
/*
 * Start of new message
 */
            if (snoop.len)
                snoop_write(&snoop, &mess[0]);
            do_timestamp(&buf[0],&(snoop.secs_since_1970),&(snoop.musecs));
            snoop.secs_since_1970 += base_time;
            snoop.len = 0;
            mess_ptr = &mess[0];
            break;
        }
    }
    if (snoop.len)
        snoop_write(&snoop, &mess[0]);
    exit(0);
}

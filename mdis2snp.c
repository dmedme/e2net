/*
 * mdis2snp.c - Convert the output from MDIS's network traces
 * so that they can be handled by E2's snoop-based utilities
 *
 * Takes two arguments:
 * - the file with the packet timestamps
 * - the file with the message dumps
 *
 * Sample input.
 * =============
 * Timings:
 * - Packet Number
 * - From Ethernet
 * - To Ethernet
 * - Ethernet Type
 * - Frame length
 * - Flags of some kind?
 * - Time difference since previous packet
 * - ms (constant)
     1 0090271885F5 HP611912     IP           198         1.......    0.000 ms
 *
 * Packet decode:
Frame: Number: 22          Length:   239 bytes
       Errors: None                                  
       Receive Channels: tonytest
ether: ออออออออออออออออออออออ Ethernet Datalink Layer ออออออออออออออออออออออ
       Station: 00-90-27-18-85-F5 ----> HP611912                            
       Type: 0x0800 (IP)                                                    
   ip: อออออออออออออออออออออออออ Internet Protocol อออออออออออออออออออออออออ
       Station: 172.16.1.222    ----> 172.16.1.3         Protocol: TCP      
       Version: 4                     Header Length (32 bit words): 5       
       Precedence: Routine                                                  
       Low Delay, Normal Throughput,  Normal Reliability                    
       Total length: 221 bytes                                              
       Fragmentation not allowed, Last fragment                             
       Identification: 19544          Fragment Offset: 0                    
       Time to Live: 128 seconds      Checksum: 0x52B1 (valid)              
  tcp: อออออออออออออออออออ Transmission Control Protocol อออออออออออออออออออ
       Source Port: 1056                 Destination Port:  1521            
       Sequence Number: 794376           Acknowledgement Number: 624918977  
       Data Offset (32-bit words): 5     Window: 7622                       
       Control bits: Push Function Requested (PSH)                          
                     Acknowledgement Field is Valid (ACK)                   
       Urgent Pointer: 0                 Checksum: 0xC6A9 (valid)           
Data:                                                       ASCII display   
0000  00 B5 00 00 06 00 00 00  00 00 03 47 C3 02 80 71    ณ...........G...qณ
0010  01 02 12 7E D5 03 01 6C  00 00 00 00 00 B8 DB C2    ณ...~...l........ณ
0020  02 01 07 CC 2D CC 00 01  02 00 00 00 00 EC D9 CB    ณ....-...........ณ
0030  00 01 01 00 00 00 00 00  53 45 4C 45 43 54 20 4E    ณ........SELECT Nณ
0040  56 4C 28 4B 57 5F 54 45  58 54 2C 27 63 66 61 63    ณVL(KW_TEXT,'cfacณ
0050  73 27 29 20 20 20 46 52  4F 4D 20 43 46 41 43 53    ณs')   FROM CFACSณ
0060  5F 4B 45 59 57 4F 52 44  53 20 20 57 48 45 52 45    ณ_KEYWORDS  WHEREณ
0070  20 4B 57 5F 4C 41 4E 47  55 41 47 45 20 3D 20 27    ณ KW_LANGUAGE = 'ณ
0080  45 4E 47 4C 49 53 48 27  20 20 41 4E 44 20 4B 57    ณENGLISH'  AND KWณ
0090  5F 4B 45 59 57 4F 52 44  20 3D 20 27 43 46 41 43    ณ_KEYWORD = 'CFACณ
00A0  53 27 20 20 01 01 01 01  00 00 00 00 00 01 03 00    ณS'  ............ณ
00B0  00 01 1E 00 00                                      ณ.....           ณ
 *
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "e2net.h"
double floor();

static FILE * ifp1, *ifp2, *ofp;
struct snoop_header {
    long len;
    long saved_len;
    long unknown[2];
    long secs_since_1970;
    long musecs;
};
static struct ether_header e;
/*
 * Works with a time HHh:mm:ss.ss
 */
static void do_timestamp(b, secs,musecs)
char * b;
long * secs;
long * musecs;
{
int h;
int m;
int s;
int mil;
int i;
    if ((i = sscanf(b,"%dh:%dm %d.%d\n", &h, &m, &s, &mil)) != 4)
    {
        fprintf(stderr, "Failed to match time in %s\n", b);
        return;
    }
    *secs = 3600 * h + 60 * m + s;
    *musecs = 1000 * mil;
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
int j = s->len;
    s->len = htonl(j);
    s->saved_len = s->len;
    s->secs_since_1970 = htonl((s->secs_since_1970));
    s->musecs = htonl((s->musecs));
    fwrite((char *) s,sizeof(char),
          sizeof(struct snoop_header),ofp);   /* The snoop header */
    fwrite(m,sizeof(char), j, ofp);       /* The packet */
    if ((j = (j % 4)))
        fwrite(m,sizeof(char), 4 - j, ofp);   /* The alignment stuff */
    return;
}
main(argc, argv)
int argc;
char ** argv;
{
time_t base_time;
char buf[132];
char mess[4096];
char * in_ptr;
char * top_ptr;
char* mess_ptr;
char *x;
int i, j;
struct snoop_header snoop;
struct ip ip;
struct tcphdr tcp;
char eth1[30];
char eth2[30];
struct in_addr ina;
float tgap;
    e.ether_type=htons(0x800);
    memset((char *) (&snoop), 0,sizeof(snoop));
    if (argc < 4)
    {
        fputs(
"Provide an input timing file, and input trace file and an output file\n",
              stderr);
        exit(0);
    }
    ofp = fopen(argv[3], "wb");
    ifp1 = fopen(argv[1], "rb");
    ifp2 = fopen(argv[2], "rb");
    fwrite(buf,sizeof(char),16,ofp);   /* The snoop file header */
    while(fgets(buf,sizeof(buf) - 1, ifp1) != (char *) NULL)
    {
        sscanf(buf, "%i %s %s %*s %i %*s %f",
               &i, &eth1[0], &eth2[0], &snoop.len, &tgap);
        while((x = fgets(buf,sizeof(buf) - 1, ifp2)) != (char *) NULL
            &&  buf[0] != 'F');
        if (x == (char *) NULL)
        {
            fputs("Premature End of File on Trace Input\n", stderr);
            exit(1);
        }
        sscanf(buf, "%*s %*s %i  %*s %i ", &j,  &snoop.saved_len);
        if (i != j || snoop.len != snoop.saved_len)
        {
            fprintf(stderr,
       "Trace Mismatch. Timing Frame %d Length %d; Trace Frame %d Length %d\n",
              i, snoop.len, j, snoop.saved_len);
            exit(1);
        }
        for(i = 0; i < 7; i++)
           (void) fgets(buf,sizeof(buf) - 1, ifp2);
        if (strncmp(&buf[0], "       Station: ", 16))
        {
            fputs("Did not see the Stations\n", stderr);
            exit(1);
        }
/*
 * Construct the Ethernet Header
 */
        memset((char *) &(e.ether_dhost), 0, 6);
        memset((char *) &(e.ether_shost), 0, 6);
        if (eth1[0] == 'H')
        {
            i = 3;
            x = &eth1[2];
        }
        else
        {
            i = 0;
            x = &eth1[0];
        }
        for (; i < 6 && ((*x >= '0' && *x <= '9') || (*x >= 'A' && *x <= 'F'));
                      i++)
        {
            hex2byte(((char *)&(e.ether_shost[i])),x);
            x += 2;
        }
        if (eth2[0] == 'H')
        {
            i = 3;
            x = &eth2[2];
        }
        else
        {
            i = 0;
            x = &eth2[0];
        }
        for (; i < 6 && ((*x >= '0' && *x <= '9') || (*x >= 'A' && *x <= 'F'));
                      i++)
        {
            hex2byte(((char *)&(e.ether_dhost[i])),x);
            x += 2;
        }
/*
 * Packet timestamp
 */
        snoop.secs_since_1970 = htonl((snoop.secs_since_1970));
        snoop.musecs = htonl((snoop.musecs));
        printf("%f\n", (double) tgap);
/*
 * None of the timings is over a second
 */
        snoop.musecs += (long) floor(((double) tgap) * 1000.0);
        if (snoop.musecs > 999999)
        {
            snoop.secs_since_1970 += 1;
            snoop.musecs -= 1000000;
        }
/*
 * Construct the IP header
 */
        sscanf(buf, " %*s %s %*s %s", &eth1[0], &eth2[0]);
        i = inet_addr(&(eth1[0]));
        memcpy((char *) &(ip.ip_src), &i, sizeof(long));
        i = inet_addr(&(eth2[0]));
        memcpy((char *) &(ip.ip_dst), &i, sizeof(long));
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %i %*s %*s %*s %*s %*s %i", &(i),
                      &(j));
        ip.ip_v = i;
        ip.ip_hl = j;
        ip.ip_tos = 0;
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %*s %i", &i);
        ip.ip_len = htons(i);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %i %*s %*s %i", &i, &j);
        ip.ip_id = htons(i);
        ip.ip_off = htons(j);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %*s %*s %i %*s %i", &i, &j);
        ip.ip_ttl = i;
        ip.ip_sum = htons(j);
 	ip.ip_p = IPPROTO_TCP;			/* protocol  */
/*
 * TCP Header
 */
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %*s %i %*s %*s %i", &i, &j);
        tcp.th_sport = htons(i);
        tcp.th_dport = htons(j);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %*s %i %*s %*s %i", &(tcp.th_seq),
                                                &(tcp.th_ack));
        tcp.th_seq = htonl(tcp.th_seq);
        tcp.th_ack = htonl(tcp.th_ack);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        sscanf(buf, " %*s %*s %*s %*s %i %*s %i", &i, &j);
        tcp.th_off = i;
        tcp.th_win = htons(j);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        tcp.th_flags = 0;
        while (strstr(buf, "Checksum") == (char *) NULL)
        {
             if (strstr(buf, "PSH") != (char *) NULL)
                tcp.th_flags |= TH_PUSH;
             if (strstr(buf, "ACK") != (char *) NULL)
                tcp.th_flags |= TH_ACK;
             if (strstr(buf, "FIN") != (char *) NULL)
                tcp.th_flags |= TH_FIN;
             if (strstr(buf, "URG") != (char *) NULL)
                tcp.th_flags |= TH_URG;
             if (strstr(buf, "SYN") != (char *) NULL)
                tcp.th_flags |= TH_SYN;
             if (strstr(buf, "RST") != (char *) NULL)
                tcp.th_flags |= TH_RST;
             (void) fgets(buf,sizeof(buf) - 1, ifp2);
        }
        sscanf(buf, " %*s %*s %i %*s %i", &i, &j);
        tcp.th_urp = htons(i);
        tcp.th_sum = htons(j);
        (void) fgets(buf,sizeof(buf) - 1, ifp2);
        memcpy(&mess[0], (char *) &e, sizeof(e));
        memcpy(&mess[sizeof(e)], (char *) &ip, sizeof(ip));
        memcpy(&mess[sizeof(e) + sizeof(ip)], (char *) &tcp, sizeof(tcp));
        mess_ptr = &mess[sizeof(e) + sizeof(ip) + sizeof(tcp)];
        if (!strncmp(&buf[0], "Data:", 5))
        {
            for (;;)
            {
                (void) fgets(buf,sizeof(buf) - 1, ifp2);
                switch (buf[0])
                {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    for (in_ptr = &buf[6], i = 8,
                         top_ptr = in_ptr + strlen(in_ptr) - 1,
                         top_ptr = (top_ptr < (in_ptr + 48))?top_ptr:
                                 (in_ptr + 48);
                             i > 0 && in_ptr < top_ptr && *in_ptr != ' ';
                                 in_ptr += 3, mess_ptr++,  i--)
                         hex2byte(mess_ptr,in_ptr);
                    in_ptr++;
                    for (i = 8;
                             i > 0 && in_ptr < top_ptr && *in_ptr != ' ';
                                 in_ptr += 3, mess_ptr++,  i--)
                         hex2byte(mess_ptr,in_ptr);
                    break;
                default:
                    goto nxt;
                }
            }
        }
nxt:
        *mess_ptr++ = '\0';
        *mess_ptr++ = '\0';
        *mess_ptr++ = '\0';
        *mess_ptr++ = '\0';
        if (snoop.len)
            snoop_write(&snoop, &mess[0]);
    }
    exit(0);
}

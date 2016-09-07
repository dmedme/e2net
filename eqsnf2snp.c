/*
 * eqsnf2snp.c - Convert the output from Equant's General Sniffer logs
 * so that they can be handled by E2's snoop-based utilities
 *
 * Set up as a filter.
 *
 * Sample input:

Packet 5:  00:E0:1E:D1:96:DD -> HP [7B:DA:F5]
    Network:  Ethernet
    Frame type:  Ethernet II,  Frame size:  587
    Frame protocol:  [0800] IP     
    Time:  11h:24m 01.970sec,  Diff. time: 41041.573
                    RAW PACKET LISTING:
0000  08 00 09 7B DA F5 00 E0  1E D1 96 DD 08 00 45 00    ...{⁄ı.‡.—ñ›..E.
0010  02 3D 12 24 40 00 1E 06  29 27 0A 56 01 23 0A AF    .=.$@...)'.V.#.Ø
0020  09 49 04 5C 05 F5 02 4C  7B 84 46 76 4D B1 50 18    .I.\.ı.L{ÑFvM±P.
0030  21 60 63 BC 00 00 02 15  00 00 06 00 00 00 00 00    !`cº............
0040  03 47 98 02 80 09 01 01  E8 1B E0 00 02 01 CC 00    .Gò.Ä...Ë.‡...Ã.
0050  00 00 00 00 F0 1F 64 00  01 07 44 B0 64 00 01 02    .....d...D∞d...
0060  00 00 00 00 00 00 00 00  00 90 25 65 00 01 01 20    .........ê%e... 
0070  20 53 45 4C 45 43 54 20  20 22 49 4E 5F 50 41 52     SELECT  "IN_PAR
0080  54 5F 4D 41 53 54 45 52  22 2E 22 50 41 52 54 5F    T_MASTER"."PART_
0090  49 44 22 20 2C 20 20 20  20 20 20 20 20 20 20 20    ID" ,           
00A0  22 49 4E 5F 50 41 52 54  5F 4D 41 53 54 45 52 22    "IN_PART_MASTER"
00B0  2E 22 50 41 52 54 5F 44  45 53 43 22 20 2C 20 20    ."PART_DESC" ,  
00C0  20 20 20 20 20 20 20 20  20 22 49 4E 5F 50 52 4F             "IN_PRO
00D0  44 55 43 54 5F 50 52 4F  43 45 53 53 49 4E 47 5F    DUCT_PROCESSING_
00E0  46 4C 41 47 53 22 2E 22  44 50 54 5F 52 45 51 22    FLAGS"."DPT_REQ"
00F0  20 2C 20 20 20 20 20 20  20 20 20 20 20 22 49 4E     ,           "IN
0100  5F 50 52 4F 44 55 43 54  5F 50 52 4F 43 45 53 53    _PRODUCT_PROCESS
0110  49 4E 47 5F 46 4C 41 47  53 22 2E 22 53 45 52 49    ING_FLAGS"."SERI
0120  41 4C 49 5A 45 44 22 20  2C 20 20 20 20 20 20 20    ALIZED" ,       
0130  20 20 20 20 22 49 4E 5F  50 41 52 54 5F 4D 41 53        "IN_PART_MAS
0140  54 45 52 22 2E 22 50 52  4F 44 55 43 54 5F 54 59    TER"."PRODUCT_TY
0150  50 45 22 20 20 20 20 20  46 52 4F 4D 20 22 49 4E    PE"     FROM "IN
0160  5F 50 41 52 54 5F 4D 41  53 54 45 52 22 20 2C 20    _PART_MASTER" , 
0170  20 20 20 20 20 20 20 20  20 20 22 49 4E 5F 50 52              "IN_PR
0180  4F 44 55 43 54 5F 50 52  4F 43 45 53 53 49 4E 47    ODUCT_PROCESSING
0190  5F 46 4C 41 47 53 22 20  20 20 20 20 57 48 45 52    _FLAGS"     WHER
01A0  45 20 28 20 22 49 4E 5F  50 41 52 54 5F 4D 41 53    E ( "IN_PART_MAS
01B0  54 45 52 22 2E 22 50 52  4F 44 5F 50 52 4F 43 5F    TER"."PROD_PROC_
01C0  43 4F 44 45 22 20 3D 20  22 49 4E 5F 50 52 4F 44    CODE" = "IN_PROD
01D0  55 43 54 5F 50 52 4F 43  45 53 53 49 4E 47 5F 46    UCT_PROCESSING_F
01E0  4C 41 47 53 22 2E 22 50  52 4F 44 5F 50 52 4F 43    LAGS"."PROD_PROC
01F0  5F 43 4F 44 45 22 20 28  2B 29 29 20 61 6E 64 20    _CODE" (+)) and 
0200  20 20 20 20 20 20 20 20  20 28 20 28 20 22 49 4E             ( ( "IN
0210  5F 50 41 52 54 5F 4D 41  53 54 45 52 22 2E 22 50    _PART_MASTER"."P
0220  41 52 54 5F 49 44 22 20  3D 20 3A 61 73 5F 70 61    ART_ID" = :as_pa
0230  72 74 5F 69 64 20 29 20  29 20 20 01 01 00 00 00    rt_id ) )  .....
0240  00 00 00 60 01 00 00 01  08 00 00                   ...`....... ....
   ---------------------------------------------------------------    
 */
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VCC2003
#include <winsock2.h>
#endif
#ifdef NT4
#include <windows.h>
#ifdef LCC
#include <winsock2.h>
#else
#ifndef VCC2003
#include <winsock.h>
#endif
#endif
struct ether_header {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    unsigned short ether_type;
};
#else
#include "e2net.h"
#endif
static FILE * ifp, *ofp;
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
int i;
struct snoop_header snoop;
    e.ether_type=htons(0x800);
    memset((char *) (&snoop), 0,sizeof(snoop));
    if (argc < 3)
        ofp = stdout;
    else
        ofp = fopen(argv[2], "wb");
    if (argc < 2)
        ifp = stdin;
    else
        ifp = fopen(argv[1], "rb");
    fwrite(buf,sizeof(char),16,ofp);   /* The snoop file header */
    while(fgets(buf,sizeof(buf) - 1, ifp) != (char *) NULL)
    {
        switch (buf[0])
        {
        case 'P':
            if (!strncmp(buf, "Packet ",7))
            {
                memset((char *) &(e.ether_dhost), 0, 6);
                memset((char *) &(e.ether_shost), 0, 6);
                if ((x = strchr(buf, ':')) != (char *) NULL
                 && (x = strchr(x + 1, ':')) != (char *) NULL)
                {
                    for (i = 0, x = x - 2;
                            i < 6 && ((*x >= '0' && *x <= '9') ||
                                  (*x >= 'A' && *x <= 'F'));
                              i++)
                    {
                        hex2byte(((char *)&(e.ether_dhost))[i],x);
                        x += 3;
                    }
                }
                if ((x = strchr(x, ':')) != (char *) NULL)
                {
                    for (i = 0, x = x - 2;
                            i < 6 && ((*x >= '0' && *x <= '9') ||
                                  (*x >= 'A' && *x <= 'F'));
                              i++)
                    {
                        hex2byte(((char *) &(e.ether_shost))[i],x);
                        x += 3;
                    }
                }
            }
        case ' ':
            if (!strncmp(buf, "    Time:",9))
            {
                mess_ptr = &mess[0];
                do_timestamp(&buf[10], &(snoop.secs_since_1970),
                    &(snoop.musecs));
            }
            else
            if (!strncmp(buf, "   ---------------------------------------------------------------",66))
            { 
                if (snoop.len)
                    snoop_write(&snoop, &mess[0]);
                snoop.len = 0;
                mess_ptr = &mess[0];
            }
            break;
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
                 top_ptr = (top_ptr < (in_ptr + 48))?top_ptr: (in_ptr + 48);
                     i > 0 && in_ptr < top_ptr && *in_ptr != ' ';
                         in_ptr += 3, mess_ptr++, snoop.len++, i--)
                 hex2byte(mess_ptr,in_ptr);
            in_ptr++;
            for (i = 8;
                     i > 0 && in_ptr < top_ptr && *in_ptr != ' ';
                         in_ptr += 3, mess_ptr++, snoop.len++, i--)
                 hex2byte(mess_ptr,in_ptr);
            break;
        default:
            break;
        }
    }
    if (snoop.len)
        snoop_write(&snoop, &mess[0]);
    exit(0);
}

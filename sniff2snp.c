/************************************************************************
 * Convert files captured by the Infinistream capture utilities to files
 * E2 snoop-oriented facilities can handle.
 *
 * Snoop  File Format (from RFC 1761)
 * ==================================

   The snoop packet capture file is an array of octets structured as
   follows:

        +------------------------+
        |                        |
        |      File Header       |
        |                        |
        +------------------------+
        |                        |
        |     Packet Record      |
        ~        Number 1        ~
        |                        |
        +------------------------+
        .                        .
        .                        .
        .                        .
        +------------------------+
        |                        |
        |     Packet Record      |
        ~        Number N        ~
        |                        |
        +------------------------+

   The File Header is a fixed-length field containing general
   information about the packet file and the format of the packet
   records it contains.  One or more variable-length Packet Record
   fields follow the File Header field.  Each Packet Record field holds
   the data of one captured packet.

3. File Header

   The structure of the File Header is as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                     Identification Pattern                    +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Version Number = 2                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Datalink Type                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Identification Pattern:

                A 64-bit (8 octet) pattern used to identify the file as
                a snoop packet capture file.  The Identification Pattern
                consists of the 8 hexadecimal octets:

                        73 6E 6F 6F 70 00 00 00

                This is the ASCII string "snoop" followed by three null
                octets.

        Version Number:

                A 32-bit (4 octet) unsigned integer value representing
                the version of the packet capture file being used.  This
                document describes version number 2.  (Version number 1
                was used in early implementations and is now obsolete.)

        Datalink Type:

                A 32-bit (4 octet) field identifying the type of
                datalink header used in the packet records that follow.
                The datalink type codes are listed in the table below:

                Datalink Type           Code
                -------------           ----
                IEEE 802.3              0
                IEEE 802.4 Token Bus    1
                IEEE 802.5 Token Ring   2
                IEEE 802.6 Metro Net    3
                Ethernet                4
                HDLC                    5
                Character Synchronous   6
                IBM Channel-to-Channel  7
                FDDI                    8
                Other                   9
                Unassigned              10 - 4294967295

4. Packet Record Format

   Each packet record holds a partial or complete copy of one packet as
   well as some descriptive information about that packet.  The packet
   may be truncated in order to limit the amount of data to be stored in
   the packet file.  In addition, the packet record may be padded in
   order for it to align on a convenient machine-dependent boundary.
   Each packet record holds 24 octets of descriptive information about
   the packet, followed by the packet data, which is variable-length,
   and an optional pad field.  The descriptive information is structured

   as six 32-bit (4-octet) integer values.

   The structure of the packet record is as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Original Length                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Included Length                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Packet Record Length                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Cumulative Drops                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Timestamp Seconds                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Timestamp Microseconds                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                          Packet Data                          .
    .                                                               .
    +                                               +- - - - - - - -+
    |                                               |     Pad       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Original Length

                32-bit unsigned integer representing the length in
                octets of the captured packet as received via a network.

        Included Length

                32-bit unsigned integer representing the length of the
                Packet Data field.  This is the number of octets of the
                captured packet that are included in this packet record.
                If the received packet was truncated, the Included
                Length field will be less than the Original Length
                field.

        Packet Record Length

                32-bit unsigned integer representing the total length of
                this packet record in octets.  This includes the 24
                octets of descriptive information, the length of the
                Packet Data field, and the length of the Pad field.

        Cumulative Drops

                32-bit unsigned integer representing the number of
                packets that were lost by the system that created the
                packet file between the first packet record in the
                file and this one.  Packets may be lost because of
                insufficient resources in the capturing system, or for
                other reasons.  Note: some implementations lack the
                ability to count dropped packets.  Those
                implementations may set the cumulative drops value to
                zero.

        Timestamp Seconds

                32-bit unsigned integer representing the time, in
                seconds since January 1, 1970, when the packet arrived.

        Timestamp Microseconds

                32-bit unsigned integer representing microsecond
                resolution of packet arrival time.

        Packet Data

                Variable-length field holding the packet that was
                captured, beginning with its datalink header.  The
                Datalink Type field of the file header can be used to
                determine how to decode the datalink header.  The length
                of the Packet Data field is given in the Included Length
                field.

        Pad

                Variable-length field holding zero or more octets that
                pads the packet record out to a convenient boundary.

5.  Data Format

   All integer values are stored in "big-endian" order, with the high-
   order bits first.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
/***********************************************************************
 * Getopt support
 */
extern int optind;           /* Current Argument counter.      */
extern char *optarg;         /* Current Argument pointer.      */
extern int opterr;           /* getopt() err print flag.       */
extern int errno;
static char magic[] = {
    'X', 'C', 'P', '\0'
};

struct file_hdr {
    char magic[4];
    char file_version[8];
    unsigned int secs_since_1970;
    unsigned int packet_cnt;
    unsigned int filler_off20;
    unsigned int start_data;
    unsigned int end_data;
    unsigned char filler_off32[20];
    unsigned long long base_time;
    unsigned char rest_off60[68];
};
static char buf[65536];
struct packet_hdr {
    unsigned long long delta_time;
    unsigned short int pack_len;
    unsigned short int cap_len;
    unsigned char rest_off12[28];
};
struct snoop_header {
    unsigned int len;
    unsigned int saved_len;
    unsigned int record_len;
    unsigned int cumulative_drops;
    unsigned int secs_since_1970;
    unsigned int musecs;
};

static int file_proc(ifp, ofp, fname)
FILE * ifp;
FILE * ofp;
char * fname;
{
int ret;
struct file_hdr fhdr;
struct packet_hdr phdr;
struct snoop_header shdr;

    (void) fread((char *) &fhdr, sizeof(struct file_hdr), sizeof(char), ifp);
    if (strcmp(fhdr.magic, magic))
    {
        fprintf(stderr, "Error: %s is not an XCP file\n", fname);
        return 0;
    }
    fseek(ifp, fhdr.start_data, 0); 
    while((ret = fread((char *) &phdr,sizeof(unsigned char),sizeof(phdr),ifp)) > 0 
      && ftell(ifp) <= fhdr.end_data)
    {
#ifdef DEBUG
        fprintf(stderr,"%lx:%x:%x\n",
            phdr.delta_time,
            phdr.cap_len,
            phdr.pack_len);
#endif
        shdr.record_len = htonl(phdr.cap_len + sizeof(shdr));
        shdr.saved_len = htonl(phdr.cap_len);
        shdr.len = htonl(phdr.pack_len);
        shdr.cumulative_drops = 0;
        shdr.secs_since_1970 = htonl((long) (fhdr.secs_since_1970 +
              phdr.delta_time/1000000000));
        shdr.musecs = htonl((long) (( (phdr.delta_time 
           - (phdr.delta_time/1000000000)*1000000000)/1000)));
        fwrite((char*) &shdr, sizeof(shdr),sizeof(char), ofp);
        if ((ret = fread(&buf[0],sizeof(unsigned char), phdr.cap_len, ifp)) < 1)
        {
            perror("fread() failed");
            (void) fprintf(stderr,
    "Read of %s : %d bytes failed with UNIX errno %d\n",fname, 
                    phdr.cap_len, errno);
            exit(1);
        }
        fwrite(&buf[0], sizeof(char), phdr.cap_len, ofp);
    }
    return 1;
}
/**************************************************************************
 * Main Program
 * VVVVVVVVVVVV
 */
int main(argc,argv)
int argc;
char ** argv;
{
int  ch;
int i;
FILE *f;
FILE *of;
struct file_hdr h;

    of = stdout;
    while ( ( ch = getopt ( argc, argv, "ho:" ) ) != EOF )
    {
        switch ( ch )
        {
        case 'o' :
            of = fopen(optarg, "wb");
            break;
        case 'h' :
            (void) puts("sniff2snp: E2 Systems Sniffer Windows Sniffer File to Snoop Conversion Utility\n\
  You can specify:\n\
  -o to select a named output file (default stdout)\n\
Then list the files to process. The output is emitted to the output file\n");
            exit(0);
        default:
        case '?' : /* Default - invalid opt.*/
               (void) fprintf(stderr,"Invalid argument; try -h\n");
               exit(1);
            break;
        }
    }
    memset(buf,0,16);
    strcpy(&buf[0], "snoop");
    buf[11] = 2;
    (void) fwrite(&buf[0],sizeof(char),16,of);
    if (optind == argc)
        file_proc(stdin, of, "(stdin)");
    else
    for (i = optind; i < argc; i++)
    {

        if ((f = fopen(argv[i],"rb")) == (FILE *)NULL)
        {
            perror("fopen() failed");
            (void) fprintf(stderr,
                  "Open of %s failed with UNIX errno %d\n", argv[i], errno);
            continue;
        }
        if (!file_proc(f, of, argv[i]))
            (void) fprintf(stderr, "Issue with %s\n", argv[i]);
        fclose(f);
    }
    fclose(of);
    exit(0);
}


#include <stdio.h>
#include <fcntl.h>
/**************************************************************************
 * Render hexdecimal characters as a binary stream.
 */
char * hexout(out, in, len)
char * out;
char *in;
int len;
{
char * top = out + len;
/*
 * Build up half-byte at a time, subtracting 48 initially, and subtracting
 * another 7 (to get the range from A-F) if > (char) 9;
 */
register char * x = out,  * x1 = in;

    while (x < top)
    {
        register char x2;
        x2 = *x1 - (char) 48;
        if (x2 > (char) 48)
           x2 -= (char) 32;    /* Handle lower case */
        if (x2 > (char) 9)
           x2 -= (char) 7; 
        *x = (unsigned char) (((int ) x2) << 4);
        x1++;
        if (*x1 == '\0')
            break;
        x2 = *x1++ - (char) 48;
        if (x2 > (char) 48)
           x2 -= (char) 32;    /* Handle lower case */
        if (x2 > (char) 9)
           x2 -= (char) 7; 
        *x++ |= x2;
    }
    return x;
}
int main(argc,argv)
int argc;
char ** argv;
{
int fd, loc, rlen;
char buf[8192];

    if (argc < 4)
    {
        fputs("Provide a filename, a location, and a hexadecimal patch value\n",
              stderr);
        exit(0);
    }
    if ((fd = open(argv[1],O_RDWR)) < 0)
    {
        perror("open() failed");
        exit(1);
    }
    if ((loc = atoi(argv[2])) < 0)
    {
        fputs("Patch location must not be negative\n", stderr);
        exit(1);
    }
    rlen = strlen(argv[3]);
    if (rlen > 2*sizeof(buf))
        rlen = 2*sizeof(buf);
    (void) hexout(buf,argv[3],rlen);
    lseek(fd,loc,0);
    write(fd,buf, rlen/2);
    close(fd);
    exit(0);
}

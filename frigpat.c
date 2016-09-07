#include <stdio.h>
#include <fcntl.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif
int main(argc,argv)
int argc;
char ** argv;
{
int fd, loc, len;

    if (argc < 4)
    {
        fputs(
"Provide a filename, a location,  a patch string and an optional NUL flag\n",
              stderr);
        exit(0);
    }
    if ((fd = open(argv[1],O_RDWR|O_BINARY)) < 0)
    {
        perror("open() failed");
        exit(1);
    }
    if ((loc = atoi(argv[2])) < 0)
    {
        fputs("Patch location must not be negative\n", stderr);
        exit(1);
    }
    if ((len = strlen(argv[3])) < 1)
    {
        fputs("Cannot apply zero-length patch\n", stderr);
        exit(1);
    }
    lseek(fd,loc,0);
    write(fd,argv[3], len);
    if (argc > 4)
        write(fd,"",1);
    close(fd);
    exit(0);
}

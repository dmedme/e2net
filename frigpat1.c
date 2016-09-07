#include <stdio.h>
#include <fcntl.h>
int main(argc,argv)
int argc;
char ** argv;
{
int fd, fd1, loc, rlen;
char buf[8192];

    if (argc < 4)
    {
        fputs("Provide a filename, a location, and a patch file\n",
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
    if ((fd1 = open(argv[3],O_RDONLY)) < 0)
    {
        perror("open() failed");
        exit(1);
    }
    lseek(fd,loc,0);
    while ((rlen = read(fd1, buf, sizeof(buf))) > 0)
        write(fd,buf, rlen);
    close(fd);
    close(fd1);
    exit(0);
}

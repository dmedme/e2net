#include <stdio.h>
main()
{
int x;

    while((x = getchar()) != EOF)
    {
        putchar((x & 0x7f));
    }
    exit(0);
}

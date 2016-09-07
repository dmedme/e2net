#include <stdio.h>
main()
{
int c;
int last_c = -1; 
int pos = 0;

    while((c = fgetc(stdin)) >= 0)
    {
        pos++;
        switch (c)
        {
        case 0:
            last_c = 0;
            break; 
        case 0x10:
            if (last_c == 0)
                last_c = 0x10;
            else
                last_c = -1;
            break; 
        case 0xed:
            if (last_c == 0x10)
                last_c = 0xed;
            else
                last_c = -1;
            break; 
        case 0xb0:
            if (last_c == 0xed)
/*
        case 'N':
            last_c = 'N';
            break; 
        case 'L':
            if (last_c == 'N')
                last_c = 'L';
            else
                last_c = -1;
            break; 
        case 'S':
            if (last_c == 'L')
                last_c = 'S';
            else
                last_c = -1;
            break; 
        case 'R':
            if (last_c == 'S')
*/
               printf("Seen at pos: %d\n", (pos - 4));
        default:
            last_c = -1;
            break;
        }
/*        printf("c: %c last_c: %d pos: %d\n", c, last_c, pos); */
    }
    exit(0);
}

#include <stdio.h>
#include <string.h>
/*
 * Support for an implemention of a Boyes-Moore scan of buffer data
 */
struct bm_table {
    int match_len;
    unsigned char * match_word;
    int forw[256];
};
/*
 * Structure for supporting multiple concurrent buffered use of the Boyes-Moore
 * Scan
 */
struct bm_frag {
    struct bm_table *bp;
    int tail_len;
    unsigned char * tail;
};
/*
 * Functions in e2net.c
 */
struct bm_table * bm_compile();
struct bm_table * bm_compile_bin();
unsigned char * bm_match();
struct bm_table * bm_casecompile();
struct bm_table * bm_casecompile_bin();
unsigned char * bm_casematch();
/******************************************************************************
 * Routine to support scan where scan pattern can span multiple buffers.
 */
unsigned char * bm_match_frag(bfp, base, bound, bm_routine)
struct bm_frag * bfp;
unsigned char * base;
unsigned char * bound;
unsigned char * (*bm_routine)();
{
unsigned char * ret;

    if (bfp->tail_len > 0)
    {
/*
 * If there is a tail input, we need to see if there is a match starting within
 * it.
 */
        bfp->tail = (unsigned char *) realloc(bfp->tail,
                                       bfp->tail_len + bfp->bp->match_len - 1);
        if ((bound - base) < bfp->bp->match_len)
        {
            memcpy(bfp->tail + bfp->tail_len, base, (bound -base));
            bfp->tail_len += (bound - base);
        } 
        else
        {
            memcpy(bfp->tail + bfp->tail_len, base, bfp->bp->match_len - 1);
            bfp->tail_len += (bfp->bp->match_len - 1);
        } 
/*
 * If we have a match in the overlap region, return it.
 * Note that the calling routine's life becomes difficult if it next wants to
 * jump to an offset.
 * -    If the offset is negative, we may well be stuffed; the data likely is
 *      lost.
 * -    If the offset is positive, it may need to be passed over to the main
 *      buffer, so the caller needs to know how much the tail has grown. Which
 *      requires intimate knowledge of the logic here.
 * -    Or, it may jump to a point we haven't seen yet.
 * It is certainly easier to accumulate the whole thing first ...
 */
        if ((ret = bm_routine(bfp->bp, bfp->tail, bfp->tail + bfp->tail_len)) <=
             bfp->tail + bfp->tail_len - bfp->bp->match_len)
            return ret;
/*
 * If the new base has not got beyond the tail, then shrink the
 * the tail. This can't happen unless there isn't enough in the main buffer for
 * a full match.
 */
        if ((bound - base) < bfp->bp->match_len)
        {
            if (((bfp->tail + bfp->tail_len) - ret) >(bound - base))
            {
                memmove(bfp->tail, ret, (((bfp->tail + bfp->tail_len) - ret)));
                bfp->tail_len = (((bfp->tail + bfp->tail_len) - ret));
                return bfp->tail;
            }
/*
 * Otherwise, we must be in the new bit. Discard the tail and adjust the base.
 */
            else
                base += ((bound - base) - ((bfp->tail + bfp->tail_len) - ret));
        }
        else
            base += (bfp->bp->match_len - 1
                      -(((bfp->tail + bfp->tail_len) - ret)));
        free(bfp->tail);
        bfp->tail = (unsigned char *) NULL;
        bfp->tail_len = 0;
    }
    if (bfp->tail != NULL || bfp->tail_len != 0)
        fprintf(stderr, "Logic Error: the tail(%d) at (%x) should have gone by now\n", bfp->tail_len, (unsigned int) bfp->tail);
/*
 * If we have found it, return it
 */
    if ((ret = bm_routine(bfp->bp, base, bound)) <=(bound - bfp->bp->match_len))
        return ret;
/*
 * If we have not found it, save the tail and return the tail
 */
    bfp->tail_len = (bound - ret);
    if (bfp->tail_len > 0)
    {
        bfp->tail = (unsigned char *) malloc(bfp->tail_len);
        memcpy( bfp->tail, ret, bfp->tail_len);
    }
    return bfp->tail;
}
/******************************************************************************
 * Routines to implement a Boyes-Moore scan of buffer data
 *
 * Create a Boyes-Moore control table
 */
struct bm_table * bm_compile_bin(wrd, len)
unsigned char * wrd;
int len;
{
struct bm_table * bp;
unsigned char * x;
int i;

    if ((bp = (struct bm_table *) malloc(sizeof(struct bm_table)))
                == (struct bm_table *) NULL)
        return (struct bm_table *) NULL;
/*
 * By default, skip forwards the length - 1
 */
    bp->match_len = len;
    bp->match_word = (unsigned char *) malloc(len);
    memcpy(bp->match_word, wrd, len);
    for (i = 0; i < 256; i++)
        bp->forw[i] = len;
/*
 * Adjust the skip length for the characters that are present. The skip length
 * takes you to the last character of the word if it is all there.
 */
    for (x = wrd, i = len; i > 0; x++, i--)
        bp->forw[*x] = len - ( x - wrd ) - 1;
    return bp;
}
/******************************************************************************
 * Routines to implement a Boyes-Moore scan of buffer data
 *
 * Create a case-insensitive Boyes-Moore control table
 */
struct bm_table * bm_casecompile_bin(wrd, len)
unsigned char * wrd;
int len;
{
struct bm_table * bp;
unsigned char * x;
int i;

    if ((bp = (struct bm_table *) malloc(sizeof(struct bm_table)))
                == (struct bm_table *) NULL)
        return (struct bm_table *) NULL;
/*
 * By default, skip forwards the length - 1
 */
    bp->match_len = len;
    bp->match_word = (unsigned char *) malloc(len);
    memcpy(bp->match_word, wrd, len);
    for (i = 0; i < 256; i++)
        bp->forw[i] = len;
/*
 * Adjust the skip length for the characters that are present. The skip length
 * takes you to the last character of the word if it is all there.
 */
    for (x = wrd, i = len; i > 0; x++, i--)
    {
        bp->forw[*x] = len - ( x - wrd ) - 1;
        if (islower(*x))
            bp->forw[toupper(*x)] = len - ( x - wrd ) - 1;
        else
        if (isupper(*x))
            bp->forw[tolower(*x)] = len - ( x - wrd ) - 1;
    }
    return bp;
}
struct bm_table * bm_compile(wrd)
unsigned char * wrd;
{
    return bm_compile_bin(wrd, strlen(wrd));
}
struct bm_table * bm_casecompile(wrd)
unsigned char * wrd;
{
    return bm_casecompile_bin(wrd, strlen(wrd));
}
/*
 * For characters that are present;
 * - When first seen, skip back and start matching from the beginning
 * - When seen out of place in the match, skip ahead again
 */ 
unsigned char * bm_match(bp, base, bound)
struct bm_table * bp;
unsigned char * base;
unsigned char * bound;
{
int i = bp->match_len - 1;
unsigned char * x = base + i;
unsigned char * x1;

    while (x < bound)
    {
        i = bp->forw[*x];
        if (i != 0)
            x += i;   /* Anywhere but a last character match */
        else
        {
            x -= (bp->match_len - 1);
            if ( x < base )
                x += bp->match_len;
            else
            {
                for (x1 = bp->match_word, i = bp->match_len;
                        i > 0 && *x1 == *x; x1++, x++, i--);
                if (i == 0)
                    return (x - bp->match_len);
                x += i;
            }
        }
    }
#ifdef NEW_BM_SEMANTICS
    x -= ( bp->match_len - 1);
    if (x < base)
        x = base;
    return x;
#else
    return (unsigned char *) NULL;
#endif
}
/*
 * For characters that are present;
 * - When first seen, skip back and start matching from the beginning
 * - When seen out of place in the match, skip ahead again
 */ 
unsigned char * bm_casematch(bp, base, bound)
struct bm_table * bp;
unsigned char * base;
unsigned char * bound;
{
unsigned char * x = base + bp->match_len - 1;
unsigned char * x1;
int i;

    while (x < bound)
    {
        i = bp->forw[*x];
        if (i != 0)
            x += i;   /* Anywhere but a last character match */
        else
        {
            x -= (bp->match_len - 1);
            if ( x < base )
                x += bp->match_len;
            else
            {
                for (x1 = bp->match_word, i = bp->match_len;
                        i > 0
                     && (*x1 == *x
                      || (isupper(*x1) && tolower(*x1) == *x)
                      || (islower(*x1) && toupper(*x1) == *x));
                          x1++, x++, i--);
                if (i == 0)
                    return (x - bp->match_len);
                x += i;
            }
        }
    }
#ifdef NEW_BM_SEMANTICS
    x -= ( bp->match_len - 1);
    if (x < base)
        x = base;
    return x;
#else
    return (unsigned char *) NULL;
#endif
}
#ifdef DEBUG_STAND
unsigned char * test_str[] = {
"ATSAAA4TA44TATSAMS   4NATATATAT",
"AMS   4NAT SAMS",
"AMS   4NAT SAMS   SAMS   4NAT",
"AMS   4NATATATS   SAMS   4NATSAMS   4NAT",
"AMS4N 4NATATATAT SAMS   4NATSAMS   4NAT",
"AMS   4NATATATATA SAMS   4NASAMS    4NAT",
"SAMS   4NAT",
"SAMS   4NAT SAMS",
NULL };
#define BITE 33
main()
{
struct bm_table * bp;
struct bm_frag * bfp;
unsigned char ** x;
unsigned char * y;
unsigned char * base;
unsigned char * bound;

/*    bp = bm_compile("SAMS   4NAT"); */
    bp = bm_compile("ATATAT");
    bfp = (struct bm_frag *) malloc(sizeof(struct bm_frag));
    bfp->bp = bp;
    bfp->tail = NULL;
    bfp->tail_len = 0;
    for (x = test_str; *x != (unsigned char *) NULL; x++)
    {
        puts(*x);
        y = bm_match(bp, *x, *x + strlen(*x));
        while (y <= (*x + strlen(*x) - bp->match_len))
        {
            printf("Match:%.*s\n", bp->match_len, y);
            y += bp->match_len;
        }
        if (y < *x + strlen(*x))
            puts("No Match");
    }
    for (base = test_str[0], bound = test_str[7] + strlen(test_str[7]);
            base < bound;
                base += BITE)
    {
    int xlen = bfp->tail_len;

        printf("Piece|%.*s|%.*s\n", bfp->tail_len, bfp->tail, BITE, base);
        y = bm_match_frag(bfp, base, base + BITE, bm_match);
        if (y == bfp->tail && bfp->tail_len < bp->match_len)
            printf("No Match, now:%.*s\n", bfp->tail_len, bfp->tail);
        else
        {
            printf("Match:%.*s\n", bp->match_len, y);
            y += bp->match_len;
            if (bfp->tail_len > 0)
            {
/*
 * xlen is the amount of transfer. There may also be an amount of unscanned
 * buffer.
 */
                xlen = bfp->tail_len - xlen;
                bfp->tail_len = (bfp->tail + bfp->tail_len) - y;
                if (bfp->tail_len == 0 && xlen == 0)
                {
                    free(bfp->tail);
                    bfp->tail = NULL;
                }
                else
                {
                    if (bfp->tail_len > 0)
                        memmove(bfp->tail, y, bfp->tail_len);
                    if (BITE - xlen > 0)
                    {
                        bfp->tail = realloc(bfp->tail, bfp->tail_len +
                                           (BITE - xlen));
                        memcpy(bfp->tail + bfp->tail_len, base + xlen,
                                         (BITE - xlen));
                    }
                    bfp->tail_len += (BITE - xlen);
                }
                
            }
            else
            if (y < base + BITE)
            {
                bfp->tail_len = (base + BITE - y);
                bfp->tail = (unsigned char *) malloc( bfp->tail_len );
                memcpy(bfp->tail, y,  bfp->tail_len );
            }
        }
    }
    exit(0);
}
#endif

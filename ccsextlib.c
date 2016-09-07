/*
 * Scan a snoop file and pull out the ORACLE CCS ODBC elements.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "tabdiff.h"
#include "e2conv.h"
#include "e2net.h"
static struct frame_con * cur_frame;
static void do_ccsodbc();
static void ccsodbc_handle();
/*
 * Structure allocated when a session is started that holds per-cursor
 * statistics plus session state.
 *
 * This code handles multiple parallel sessions.
 */
struct ccs_sess {
    int out_curs;     /* We assume that there is only one outstanding at once */
    int out_len;      /* How big it is to be                                  */
    char * long_bind;
};
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
int i;
register struct ccs_sess * rop = (struct ccs_sess *) frp->app_ptr;
    if (rop != (struct ccs_sess *) NULL)
    {
        if (rop->long_bind != (char *) NULL)
            free(rop->long_bind);
        free((char *) rop);
    }
    if (frp->ofp != (FILE *) NULL && frp->ofp != stdout)
    {
        fclose(frp->ofp);
        frp->ofp = (FILE *) NULL;
    }
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int ccs_app_recognise(frp)
struct frame_con *frp;
{
static int sess_cnt = 0;
char fname[32];
    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is the listener (6968)
 */
    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if (from == 6968 || to == 6968)
        {
            sprintf(fname,"sql_%d.sql", sess_cnt++);
            frp->ofp = fopen(fname, "wb");
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;        /* Out of file descriptors      */
            if (from == 6968)
                frp->reverse_sense = 1;   /* Flag which end is the client */
            frp->off_flag = 0;
            frp->len_len = 2;
            frp->big_little = 0;
            frp->fix_size = 2;
            frp->fix_mult = 1;
            if (from == 6968)
                frp->reverse_sense = 1;
            frp->do_mess = do_ccsodbc;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) calloc(sizeof(struct ccs_sess),1);
            return 1;
        }
    }
    return 0;
}
/*
 * Function that is called to process whole application messages accumulated
 * by tcp_frame_accum()
 */
static void do_ccsodbc(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
    cur_frame = frp;
    (void) ccsodbc_handle(frp->ofp,
               frp->hold_buf[dir_flag], frp->top[dir_flag],
                (!dir_flag) ^ frp->reverse_sense);
    return;
}
static void ccsodbc_handle(fp, x,top,out)
FILE *fp;
unsigned char * x;
unsigned char * top;
int out;
{
int curs;
int op_code;
int i, j;
unsigned char * x1;
#ifdef DEBUG
        (void) gen_handle(fp, x,top,1);
        fputs("==========\n", fp);
#endif
    if (out)
    {
/*
 * Recognise the first field (in the cases we are interested in, it is the
 * cursor number)
 */
        if (((struct ccs_sess *) (cur_frame->app_ptr))->out_len)
        {
/*
 * We pick up the long binary data from the start of the record.
 *
 * Note the memory leak, since long_bind is not freed when the session
 * ends.
 */
            if (((struct ccs_sess *) (cur_frame->app_ptr))->long_bind 
                 != (char *) NULL)
                free(((struct ccs_sess *) (cur_frame->app_ptr))->long_bind);
            ((struct ccs_sess *) (cur_frame->app_ptr))->long_bind = (char *)
                    malloc(2*
                       ((struct ccs_sess *) (cur_frame->app_ptr))->out_len +
                       4 *(((struct ccs_sess *) (cur_frame->app_ptr))->out_len/
                             40 + 1) + 2 + 2 + 2 + 8);
            x = ((struct ccs_sess *) (cur_frame->app_ptr))->long_bind;
            strcpy( x, "[HEXTORAW('");
            for (x = x + 11,
                 x1 = cur_frame->hold_buf[0],
                 top = x1 + ((struct ccs_sess *) (cur_frame->app_ptr))->out_len;
                       x1 < top;
                            x1 += 40)
            {
                i = ((top - x1) < 40)? (top - x1) : 40;
                memcpy(x, hexin(x1,  i), 2*i);
                x += 2*i;
                if (top > x1 + 60)
                {
                    strcpy(x, "'+\n'");
                    x += 4;
                }
            }
            strcpy(x, "')]");
            ((struct ccs_sess *) (cur_frame->app_ptr))->out_len = 0;
        }
        else
        {
            x += 2;
            for (x1 = x; x1 < top && *x1 != 0xff; x1++);
            if (x1 >= top)
                return;
            *x1 = '\0';
            curs = atoi(x);
            x = x1 + 1;
/*
 * Recognise the second field (in the cases we are interested in, it is an
 * op code of some kind).
 */
            for (x1 = x; x1 < top && *x1 != 0xff; x1++);
            if (x1 >= top)
                return;
            *x1 = '\0';
            op_code = atoi(x);
            x = x1 + 1;
            switch(op_code)
            {
            case 6:
                fprintf(fp, "\\RELEASE:%d\\\n", curs);
                break;
            case 8:
/*
 * Skip to the start of the SQL text
 */
                for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                if (x1 >= top)
                    return;
                fprintf(fp, "\\PARSE:%d\\\n", curs); 
                x = x1 + 1;
/*
 * Replace the ? place holders with numbered bind variables
 */
                i = 1;
                for (j = 0, x1 = x; x1 < top && *x1 != 0xff; x1++)
                {
                    if (*x1 == '?')
                    {
                        fprintf(fp, ":b%d", i);
                        i++;
                        j += 2;
                    }
                    else
                    if (*x1 == ' ' && j > 70)
                    {
                        fputc('\n', fp);
                        j = 0;
                    }
                    else
                    {
                        fputc(*x1, fp);
                        j++;
                    }
                }
                fputs("\n/\n", fp); 
                break;
            case 10:
                fprintf(fp, "\\EXEC:%d\\\n", curs); 
/*
 * Now scan for bind variables
 */
                for (i = 0; i < 4; i++)
                {
                    for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                    if (x1 >= top)
                    {
                        fprintf(fp, "\\FETCH:%d\\\n", curs); 
                        return;
                    }
                    x = x1 + 1;
                }
                while (x < top)
                {
                    for (x1 = x; x1 < top && *x1 != 0xfe; x1++);
                    if (*x == 0x01)
                    {
                        x++;
                        fputc('\'', fp);
                        fwrite(x, (x1 - x), sizeof(char), fp);
                        fputc('\'', fp);
                    }
                    else
                    if (*x == 0x02)
                    {
                        fputs("''", fp);
                    }
                    else
                    if (*x == 0x09)
                    {
                        if ((((struct ccs_sess *)
                                (cur_frame->app_ptr))->long_bind
                                          == (char *) NULL)
                         || (((struct ccs_sess *)
                                (cur_frame->app_ptr))->out_curs != curs))
                            fputs("\n\\C:WARNING - Missing Bind Variable\\\n",
                                  fp);
                        else
                            fputs(((struct ccs_sess *)
                                     (cur_frame->app_ptr))->long_bind, fp);
                    }
                    else
                    {
                        fprintf(fp,
                       "\n\\C:WARNING - Unknown Bind Code: %x Value:%*.*s\\\n",
                            (unsigned int) *x, (x1 - x - 1), (x1 - x - 1),
                                x + 1); 
                    }
                    x = x1 + 1;
                    if (x < top)
                        fputc(',', fp);
                    else
                        fputc('\n', fp);
                }
            case 12:
                fprintf(fp, "\\FETCH:%d\\\n", curs); 
                break;
            case 14:
                fprintf(fp,
                 "\\PARSE:%d\\\nSELECT owner, table_name, table_type,''\n\
 from all_catalog where owner != 'SYS' and owner != 'SYSTEM'\n\
 and upper(table_name) like upper('",
                         curs);
                for (i = 0; i < 3; i++)
                {
                    for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                    if (x1 >= top)
                        return;
                    x = x1 + 1;
                }
                for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                if (x1 >= top)
                    return;
                fwrite(x, (x1 - x), sizeof(char), fp);
                fputs("') escape '\\' and (table_type = '",fp);
                for (x = x1 + 1, x1 = x; x1 < top && *x1 != 0xff; x1++);
                fwrite(x, (x1 - x), sizeof(char), fp);
                fprintf(fp, "')\norder by table_type, owner, table_name\n\
/\n\\EXEC:%d\\\n\\FETCH:%d\\\n",
                        curs, curs);
                break;
            case 18:
                fprintf(fp,
                 "\\PARSE:%d\\\nselect * from all_tab_columns where owner='",
                         curs);
                for (i = 0; i < 2; i++)
                {
                    for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                    if (x1 >= top)
                        return;
                    x = x1 + 1;
                }
                for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                if (x1 >= top)
                    return;
                fwrite(x, (x1 - x), sizeof(char), fp);
                fputs("' and table_name like upper('", fp);
                for (x = x1 + 1, x1 = x; x1 < top && *x1 != 0xff; x1++);
                fwrite(x, (x1 - x), sizeof(char), fp);
                fprintf(fp, "') escape '\\'\n/\n\\EXEC:%d\\\n\\FETCH:%d\\\n",
                        curs, curs);
                break;
            case 28:
/*
 * This appears to be a message with a length in it; the length of a binary
 * bind variable. Bind variables are marked with a ?. The next message has the
 * binary block of this length as its first element.
 */
                for (i = 0; i < 4; i++)
                {
                    for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                    if (x1 >= top)
                        return;
                    x = x1 + 1;
                }
                ((struct ccs_sess *) (cur_frame->app_ptr))->out_curs = curs;
                for (i = 0; x < top; x++)
                {
                   i = i*10;
                   i += (*x - 48);
                }
                ((struct ccs_sess *) (cur_frame->app_ptr))->out_len = i;
                if (cur_frame->left[0] != 0)
                    abort();      /* See if we need to deal with this */
                cur_frame->left[0] = 
                    ((struct ccs_sess *) (cur_frame->app_ptr))->out_len;
                free(cur_frame->hold_buf[0]);
                cur_frame->hold_buf[0] = (char *) malloc(cur_frame->left[0]);
                cur_frame->top[0] = cur_frame->hold_buf[0];
                break;
            case 32:
                fprintf(fp,
                 "\\PARSE:%d\\\nselect * from ", curs);
                for (i = 0; i < 2; i++)
                {
                    for (x1 = x; x1 < top && *x1 != 0xff; x1++);
                    if (x1 >= top)
                        return;
                    x = x1 + 1;
                }
                for ( x1 = x; x1 < top && *x1 != 0xff; x1++);
                if (x1 >= top)
                    return;
                fwrite(x, (x1 - x), sizeof(char), fp);
                fputc('.', fp);
                for (x = x1 + 1, x1 = x; x1 < top && *x1 != 0xff; x1++);
                fwrite(x, (x1 - x), sizeof(char), fp);
                fprintf(fp, "\n/\n\\EXEC:%d\\\n\\FETCH:%d\\\n",
                        curs, curs);
                break;
            default:
                fprintf(fp,
                       "\\C:CRSR:%d:OP:%d\\\n",
                            curs, op_code);
                break;
            }
        }
    }
    return;
}

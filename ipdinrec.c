/*
 * ipdinrec.c
 * - Routines that read or write one of the valid record types
 *   off a FILE.
 *
 * ipdinrec()
 *   - Sets up the record in a buffer that is passed to it
 *   - Strips trailing spaces
 *   - Returns the record type found
 *
 * ipdoutrec()
 *   - Fills a static buffer with the data that is passed to it
 *   - Strips trailing spaces
 *   - Returns 1 if successful, 0 if not.
 *
 ****************************************************************************/
static char * sccs_id ="@(#) $Name$ $Id$\nCopyright (c) E2 Systems 1995\n";
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef LCC
#ifndef VCC2003
#include <sys/file.h>
#endif
#endif
#ifdef V32
#include <time.h>
#else
#ifndef LCC
#ifndef VCC2003
#include <sys/time.h>
#endif
#endif
#endif
/*
 * The following are just to keep ipdrive.h happy
 */
#include "ansi.h"
#include "e2conv.h"
#include "e2net.h"
#include "hashlib.h"
#include "ipdrive.h"
/*
 * ipdrive message Control
 */
struct ipd_rec ipd_mess[] = {
{ END_POINT_TYPE,END_POINT_NAME, "1S3 1I4 1I4 1I4 1S33 1S11 1S2 1S11" },
{ SEND_RECEIVE_TYPE,SEND_RECEIVE_NAME, "1S3 1I4 1I4 1I4" },
{ SOCK_CLOSE_TYPE,SOCK_CLOSE_NAME, "1S3 1I4 1I4" },
{ SEND_FILE_TYPE,SEND_FILE_NAME, "1S3 1I4 1S33 1S107 1S15 1S10"},
{ DELAY_TYPE,DELAY_NAME, "1S3 1I4 1D8"},
{ THINK_TYPE,THINK_NAME, "1S3 1I4"},
{ START_TIMER_TYPE,START_TIMER_NAME, "1S3 1I4 1S3 1S81"},
{ TAKE_TIME_TYPE,TAKE_TIME_NAME, "1S3 1I4 1S3"},
{ E2EOF }};
/*
 * Initialise the control structures for the message recognition
 */
void ipd_init()
{
struct ipd_rec *dmp;
    ipdrive_base.nmt = hash(256, string_hh, strcmp);
    for (dmp = &ipd_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(ipdrive_base.nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    return;
}
/*********************************************************************
 * ipdinrec - read a record off the input stream
 * - read the record type
 * - return (char *) NULL if can't get the full thing
 * - strip any trailing space
 * - find out which record it is
 * - switch on the record type
 * - copy the record type
 * - read each field in turn into the buffer, null terminate it
 * - any error, return (char *) NULL
 * - if ultimately successful,
 * - return the record type originally read
 */

struct ipd_rec * ipdinrec(fp, b)
FILE * fp;
union all_records * b;
{
static char buf1[sizeof(union all_records) + 32];
static char buf2[sizeof(union all_records) + 1];
struct ipd_rec * dmp;
HIPT *h;
char * x;
int mess_len;

    if (fp == (FILE *) NULL || b == (union all_records *) NULL)
    {
        (void) fprintf(stderr,
               "Logic Error: ipdinrec() called with NULL parameter(s)\n");
        return (struct ipd_rec *) NULL;
    }
    do
    {
        if (fgets(buf1, sizeof(buf1), fp) == (char *) NULL)
            return (struct ipd_rec *) NULL;
    }
    while (buf1[0] == '#' || buf1[0] == '\n' || buf1[0] == '\r');
    buf2[0] = buf1[0];
    buf2[1] = buf1[1];
    buf2[2] = '\0';
    if ((h = lookup(ipdrive_base.nmt, &buf2[0])) == (HIPT *) NULL)
    {
        (void) fputs( "Format failure: invalid message\n",stderr);
        (void) fputs(&buf1[0], stderr);
        return (struct ipd_rec *) NULL;
    }
    dmp = ((struct ipd_rec *) (h->body));
    if (dmp->mess_io == (struct iocon *) NULL)
        return dmp;
    if (ipdrive_base.debug_level > 2)
        fputs(&buf1[0], stderr);
    mess_len = e2rec_conv(1, &buf1[0], &buf2[0], dmp->mess_io, '|');
    if (ipdrive_base.debug_level > 2 && mess_len != dmp->mess_len)
            fprintf(stderr, "Expected: %d Actual: %d\n",
                 dmp->mess_len, mess_len);
/*********************************************************************
 * Record Definitions
 */
    strcpy(b->end_point.record_type,&buf2[0]);
    x = &buf2[3];
    
    if (dmp->mess_id == END_POINT_TYPE)
    {
        (void) memcpy(&b->end_point.iactor_id,x,
                     sizeof(b->end_point.iactor_id));
        x += sizeof(b->end_point.iactor_id);
        (void) memcpy(&b->end_point.iend_point_id,x,
                     sizeof(b->end_point.iend_point_id));
        x += sizeof(b->end_point.iend_point_id);
        (void) memcpy(&b->end_point.iaddress_family,x,
                     sizeof(b->end_point.iaddress_family));
        x += sizeof(b->end_point.iaddress_family);
        (void) memcpy( b->end_point.address,x,
                     sizeof(b->end_point.address));
        x += sizeof(b->end_point.address);
        (void) memcpy( b->end_point.protocol,x,
                     sizeof(b->end_point.protocol));
        x += sizeof(b->end_point.protocol);
        (void) memcpy( b->end_point.con_orient,x,
                     sizeof(b->end_point.con_orient));
        x += sizeof(b->end_point.con_orient);
        (void) memcpy( b->end_point.port_id,x,
                     sizeof(b->end_point.port_id));
    }
    else
    if (dmp->mess_id == SEND_RECEIVE_TYPE)
    {
        (void) memcpy(&b->send_receive.ifrom_end_point_id,x,
                     sizeof(b->send_receive.ifrom_end_point_id));
        x += sizeof(b->send_receive.ifrom_end_point_id);
        (void) memcpy(&b->send_receive.ito_end_point_id,x,
                     sizeof(b->send_receive.ito_end_point_id));
        x += sizeof(b->send_receive.ito_end_point_id);
        (void) memcpy(&b->send_receive.imessage_len,x,
                     sizeof(b->send_receive.imessage_len));
    }
    else
    if (dmp->mess_id == SOCK_CLOSE_TYPE)
    {
        (void) memcpy(&b->sock_close.ifrom_end_point_id,x,
                     sizeof(b->sock_close.ifrom_end_point_id));
        x += sizeof(b->sock_close.ifrom_end_point_id);
        (void) memcpy(&b->sock_close.ito_end_point_id,x,
                     sizeof(b->sock_close.ito_end_point_id));
    }
    else
    if (dmp->mess_id == SEND_FILE_TYPE)
    {
        (void) memcpy(&b->send_file.iactor_id,x,
                     sizeof(b->send_file.iactor_id));
        x += sizeof(b->send_file.iactor_id);
        (void) memcpy( b->send_file.host_name,x,
                     sizeof(b->send_file.host_name));
        x += sizeof(b->send_file.host_name);
        (void) memcpy( b->send_file.send_file_name,x,
                     sizeof(b->send_file.send_file_name));
        x += sizeof(b->send_file.send_file_name);
        (void) memcpy( b->send_file.dest_ftp_user_id,x,
                     sizeof(b->send_file.dest_ftp_user_id));
        x += sizeof(b->send_file.dest_ftp_user_id);
        (void) memcpy( b->send_file.dest_ftp_pass,x,
                     sizeof(b->send_file.dest_ftp_pass));
    }
    else
    if (dmp->mess_id == DELAY_TYPE)
    {
        (void) memcpy(&b->delay.iactor_id,x,
                     sizeof(b->delay.iactor_id));
        x += sizeof(b->delay.iactor_id);
        (void) memcpy(&b->delay.fdelta,x,
                     sizeof(b->delay.fdelta));
    }
    else
    if (dmp->mess_id == THINK_TYPE)
    {
        (void) memcpy(&b->think.ithink,x,
                     sizeof(b->delay.fdelta));
    }
    else
    if (dmp->mess_id == START_TIMER_TYPE)
    {
        (void) memcpy(&b->start_timer.iactor_id,x,
                     sizeof(b->start_timer.iactor_id));
       x += sizeof(b->start_timer.iactor_id);
        (void) memcpy( b->start_timer.timer_id,x,
                     sizeof(b->start_timer.timer_id));
       x += sizeof(b->start_timer.timer_id);
        (void) memcpy( b->start_timer.timer_description,x,
                     sizeof(b->start_timer.timer_description));
    }
    else
    if (dmp->mess_id == TAKE_TIME_TYPE)
    {
        (void) memcpy(&b->take_time.iactor_id,x,
                     sizeof(b->take_time.iactor_id));
       x += sizeof(b->take_time.iactor_id);
        (void) memcpy( b->take_time.timer_id,x,
                     sizeof(b->take_time.timer_id));
    }
    else
    {
        (void) fprintf(stderr, "Format failure: Unrecognised record type\n");
        (void) fprintf(stderr, "(%d),(%d),(%d)\n", (int) buf2[0],
                                                   (int) buf2[1],
                                                   (int) buf2[2]);
        return (struct ipd_rec *) NULL;
    }
    return dmp;
}
/***************************************************************
 * ipdoutrec() - write out a record
 */
int ipdoutrec(fp, b)
FILE * fp;
union all_records * b;
{
int buf_len;
    if (fp == (FILE *) NULL || b == (union all_records *) NULL)
    {
         (void) fprintf(stderr,
               "Logic Error: ipdoutrec() called with NULL parameter(s)\n");
         return 0;
    }
    buf_len = 0;
    if (ipdrive_base.debug_level > 2)
        (void) fprintf(stderr,"ipdoutrec() File Descriptor: %d\n",fileno(fp));

/*********************************************************************
 * Communication Record Definitions
 */
if (!strcmp(b->end_point.record_type,END_POINT_NAME))
{
    (void) fprintf(fp,"%s|%u|%u|%u|%s|%s|%s|%s\n",
        END_POINT_NAME,
        b->end_point.iactor_id,
        b->end_point.iend_point_id,
        b->end_point.iaddress_family,
        b->end_point.address,
        b->end_point.protocol,
        b->end_point.con_orient,
        b->end_point.port_id);
}
else
if (!strcmp(b->send_receive.record_type,SEND_RECEIVE_NAME))
{
    (void) fprintf(fp,"%s|%u|%u|%u|%u\n",
                       SEND_RECEIVE_NAME,
        b->send_receive.ifrom_end_point_id,
        b->send_receive.ito_end_point_id,
        b->send_receive.imessage_len);
}
else
if (!strcmp(b->send_file.record_type,SEND_FILE_NAME))
{
    (void) fprintf(fp, "%s|%u|%s|%s|%s|%s\n",
                       SEND_FILE_NAME,
        b->send_file.iactor_id,
        b->send_file.host_name,
        b->send_file.send_file_name,
        b->send_file.dest_ftp_user_id,
        b->send_file.dest_ftp_pass);
}
else
if (!strcmp(b->delay.record_type,DELAY_NAME))
{
    (void) fprintf(fp, "%s|%u|%16.6f\n",
                       DELAY_NAME,
        b->delay.iactor_id,
        b->delay.fdelta);
}
else
if (!strcmp(b->start_timer.record_type,START_TIMER_NAME))
{
    (void) fprintf(fp, "%s|%u|%s|%s\n",
                       START_TIMER_NAME,
        b->start_timer.iactor_id,
        b->start_timer.timer_id,
        b->start_timer.timer_description);
}
else
if (!strcmp(b->take_time.record_type,TAKE_TIME_NAME))
{
    (void) fprintf(fp, "%s|%u|%s\n",
                       TAKE_TIME_NAME,
        b->take_time.iactor_id,
        b->take_time.timer_id);
}
else /* An unknown Message Type !? */
{
    (void) fprintf(stderr,"Garbage in the record buffer?\n");
    return 0;
}
    return 1;
}

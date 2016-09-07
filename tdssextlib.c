/*
 * Scan a snoop file and create a generic PATH script.
 *
 * This file represents a new approach. Instead of outputting the script as
 * we go, we accumulate the whole thing, and then write everything out at the
 * end. The intention is to avoid difficulties with responses happening in
 * parallel, messages being broken into multiple packets, etc. etc..
 *
 * We use this file in order to:
 * -   Leave genconv.c and e2net.c alone.
 * -   Make use of the fact that genconv.c has dealt with retransmissions and
 *     packet drops for us.
 *
 * We maintain a tree representing the order in which we want to output things.
 *
 * At the moment we assume that the traffic is simply request/response pairs.
 * We don't cater for one way or unsolicited messages.
 *
 * We output the whole thing at the end.
 *
 * SQLServer 2005 and later are layered on SuperSocketLib. So the usual 8 byte
 * header TDS packets are transported in packets with a 16 byte header packet.
 * Thus, we have to deal with an extra layer. 
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "matchlib.h"
#include "e2conv.h"
#include "e2net.h"
#include "scripttree.h"
static struct frame_con * cur_frame;
static void do_mess();
static FILE * ofp;
static int both_ways;
static int verbose;
static struct script_control script_control;
/*
 * TDS message Control
 */
static char * sts_desc[] = {
 "F_ENDOFMESSAGE", /* 0x1 */
 "F_ATTENTIONACK", /* 0x2 */
 "F_IGNOREEVENT", /* 0x2 */
 "F_PARTOFBATCH" /* 0x4 */
};
static char * mdata_flags[] = {
/* 0x1 */ "D_NULLABLE_BIT",
/* 0x2 */ "D_CASESENSITIVE_BIT",
/* 0xc */ "D_UPDATABLE_BITS",
/* 0x10 */ "D_IDENTITY_BIT",
/* 0x20 */ "D_COMPUTED_BIT",
/* 0xc0 */ "D_RESERVED_ODBC_BITS"
};
static char * ac_flags[] = {
/* 0x0 */ "A_READONLY",
/* 0x4 */ "A_READWRITE",
/* 0x8 */ "A_READWRITEUNKNOWN"
};
struct tds_mess {
    int mess_id;
    char *mess_name;
    char *mess_form;
    struct iocon * mess_io;
    int mess_len;
};
static char * parm_flags[] = {
/* 0x1 */ "P_PARAM_IS_FOR_OUTPUT",
/* 0x2 */ "P_USE_DEFAULT_PARAM_VALUE"
};
static char * done_flags[] =  {
/* 0x1 */ "F_DONE_MORE",
/* 0x2 */ "F_DONE_ERROR",
/* 0x4 */ "F_DONE_INXACT",
/* 0x8 */ "F_DONE_PROC",
/* 0x10 */ "F_DONE_COUNT",
/* 0x20 */ "F_DONE_ATTN",
/* 0x40 */ "F_DONE_INPROC",
/* 0x80 */ "F_DONE_RPCINBATCH" 
};
static struct tds_mess pack_mess[] = {
/*
 * Variable details. The data type (actually I4) is followed by ... what (I4)
 * and then a set of read/write flags, finishing with the field length.
 */
{0x1, "M_TDS_SQLBATCH", "2I1 1I2 4I1 4I4 1I2 1I4"},
{0x2, "M_TDS_PRETDS7LOGIN", "2I1 1I2 4I1"},
{0x3, "M_TDS_RPC", "2I1 1I2 4I1 4I4 1I2 1I4 1U-2"},
{0x4, "M_TDS_TABLERESPONSE", "2I1 1I2 4I1"},
{0x6, "M_TDS_ATTENTION", "2I1 1I2 4I1"},
{0x7, "M_TDS_BULKLOADDATA", "2I1 1I2 4I1"},
{0xa, "M_TDS_PROTOCOLERROR", "2I1 1I2 4I1"},
{0xd, "M_TDS_LOGOUT", "2I1 1I2 4I1"},
{0xe, "M_TDS_DTCREQUEST", "2I1 1I2 4I1"},
{0x10, "M_TDS_TDS7LOGIN", "2I1 1I2 4I1"},
{0x11, "M_TDS_SSPIMESSAGE", "2I1 1I2 4I1"},
{0x12, "M_TDS_SUBSESSION", "2I1 1I2 4I1" },
{0x53, "M_TDS_SUPER_SOCK", "4I1 3I4" }, /* Actually carries the others */
{ 0 }};
/* SSL Header; 5 bytes common to all types. */
static struct tds_mess ssl_pack_mess[] = {
{0x14, "SSL3_RT_CHANGE_CIPHER_SPEC", "3I1 1H-3" }, /* Beware; big-endian */
{0x15, "SSL3_RT_ALERT", "3I1 1H-3" },
{0x16, "SSL3_RT_HANDSHAKE", "3I1 1H-3" },
{0x17, "SSL3_RT_APPLICATION_DATA", "3I1 1H-3" }, /* 1H-3 sidesteps SSL decoding */
{0}};
static struct tds_mess ssl_comp_mess[] = {
{0x0, "SSL3_MT_HELLO_REQUEST", "2I1 1I2"},
{0x1, "SSL3_MT_CLIENT_HELLO", "2I1 1I2 2I1 1H32 1H-1 1H-3 1H-3"},
{0x2, "SSL3_MT_SERVER_HELLO", "2I1 1I2 1H32 1H-1 1I2 1I1"},
{0xb, "SSL3_MT_CERTIFICATE", "2I1 1H-32"},
{0xc, "SSL3_MT_SERVER_KEY_EXCHANGE", "2I1 1I2"},
{0xd, "SSL3_MT_CERTIFICATE_REQUEST", "2I1 1I2"},
{0xe, "SSL3_MT_SERVER_DONE", "2I1 1I2"},
{0xf, "SSL3_MT_CERTIFICATE_VERIFY", "2I1 1I2"},
{0x10, "SSL3_MT_CLIENT_KEY_EXCHANGE", "2I1 1I2 1H-3"},
{0x14, "SSL3_MT_FINISHED", "2I1 1I2"},
{0}};

static struct tds_mess tds_mess[] = {
{0x0, "T_NOTOKEN", "1I1"},
{0x1, "T_ENVCHANGE_DATABASE", "1I1 2U-1"},
{0x2, "T_ENVCHANGE_LANG", "1I1 2U-1"},
{0x3, "T_ENVCHANGE_CHARSET", "1I1 2U-1"},
{0x4, "T_ENVCHANGE_PACKETSIZE", "1I1 2U-1"},
{0x5, "T_ENVCHANGE_UNICODELCID", "1I1 2U-1"},
{0x6, "T_ENVCHANGE_UNICODECOMP", "1I1 2U-1"},
{0x7, "T_ENVCHANGE_SQLCOLLATION", "1I1 2H-1"},
{0x9, "T_AOPCNTB", "2I1 1I4"},
{0x1a, "T_TDS_PRELOGIN", "28I1 5S0" },
{0x1f, "T_TDS_VOID", "2I1 1H-1"},
{0x22, "T_TDS_IMAGE", "2I1 1H-1"},
{0x23, "T_TDS_TEXT", "2I1 1U-1"},
{0x24, "T_TDS_UNIQUEID", "2I1 1H8"},
{0x25, "T_TDS_VARBINARY", "2I1 1H-1"},
{0x26, "T_TDS_INTN", "2I1 1I-1"},
{0x27, "T_TDS_VARCHAR", "2I1 1S-1"},
{0x2d, "T_TDS_BINARY", "2I1 1H-1"},
{0x2f, "T_TDS_CHAR", "2I1 1S-1"},
/* {0x30, "T_AOPSTDEV", "2I1"}, */
{0x30, "T_TDS_INT1", "2I1"},
{0x31, "T_AOPSTDEVP", "2I1"},
/* {0x32, "T_AOPVAR", "2I1"} */
{0x32, "T_TDS_BIT", "2I1"},
{0x33, "T_AOPVARP", "2I1"},
{0x34, "T_TDS_INT2", "2I1"},
{0x37, "T_TDS_DECIMAL", "2I1"},
{0x38, "T_TDS_INT4", "2I1"},
{0x3a, "T_TDS_SMALLDATETIME", "2I1 1H4"},
{0x3b, "T_TDS_SMALLFLOAT", "2I1 1H4"},
{0x3c, "T_TDS_MONEY", "2I1 1H8"},
{0x3d, "T_TDS_DATETIME", "2I1 1H8"},
{0x3e, "T_TDS_FLT8", "2I1 1D8"},
{0x3f, "T_TDS_NUMERIC", "2I1 1H8"},
{0x4b, "T_AOPCNT", "2I1"},
{0x4d, "T_AOPSUM", "2I1"},
{0x4f, "T_AOPAVG", "2I1"},
{0x50, "T_UDT_TIMESTAMP", "2I1 1H8"},
{0x51, "T_AOPMIN", "2I1"},
{0x52, "T_AOPMAX", "2I1"},
{0x53, "T_AOPANY", "2I1"},
{0x62, "T_TDS_SQLVARIANT", "2I1 1H-1"},
{0x63, "T_TDS_NTEXT", "2I1 1U-2"},
{0x68, "T_TDS_BITN", "2I1 1I-1"},
{0x6a, "T_TDS_DECIMALN", "2I1 1H-1"},
{0x6c, "T_TDS_NUMERICN", "2I1 1H-1"},
{0x6d, "T_TDS_FLTN", "2I1 1D-1"},
{0x6e, "T_TDS_MONEYN", "2I1 1H-1"},
{0x6f, "T_TDS_DATETIMEN", "2I1 1H-1"},
{0x78, "T_OFFSET", "2I1"},
{0x79, "T_RETURNSTATUS", "1I1 1I4"},
{0x7a, "T_TDS_SMALLMONEY", "2I1 1H4"},
{0x7f, "T_TDS_INT8", "2I1 1H8"},
/* {0x7f, "T_TDS_BIGINT", "2I1"}, duplicate! */
{0x81, "T_COLMETADATA", "7I1"},
{0x88, "T_ALTMETADATA", "2I1"},
{0xa4, "T_TABNAME", "4I1 1S-2"},
{0xa5, "T_COLINFO", "15I1"},
{0xa5, "T_TDS_BIGVARBINARY", "2I1 1H-2"},
{0xa7, "T_TDS_BIGVARCHAR", "8I1 1S-2"},
{0xa9, "T_ORDER", "5I1"},
{0xaa, "T_ERROR", "2I1"},
{0xab, "T_INFO", "1I1 1I2 6I1 1U-2 1U-1 5I1"},
{0xac, "T_RETURNVALUE", "1I1 1I2"},
{0xad, "T_LOGINACK", "1I1 1I2 5I1 1U-1 4I1"},
/* {0xad, "T_TDS_BIGBINARY", "2I1"}, */
{0xaf, "T_TDS_BIGCHAR", "8I1 1S-2"},
{0xc1, "T_SQLSELECT", "6I1"},
{0xc6, "T_SQLCREATETABLE", "2I1"},
{0xc7, "T_SQLDROPTABLE", "2I1"},
{0xd0, "T_WHAT", "3I1 U-1"},
{0xd1, "T_ROW", "1I1"},
{0xd2, "T_ROW2", "1I1"},
{0xd3, "T_ALTROW", "2I1"},
{0xd8, "T_SQLALTERTABLE", "2I1"},
{0xde, "T_SQLCREATEPROCEDURE", "2I1"},
{0xdf, "T_SQLDROPPROCEDURE", "2I1"},
{0xe3, "T_ENVCHANGE", "1I1 1I2"},
{0xe7, "T_TDS_NVARCHAR", "3I1 1H5 1U-1"},
{0xed, "T_SSPI", "2I1"},
{0xef, "T_TDS_NCHAR", "2I1 1U-1"},
{0xfd, "T_DONE", "4I1"},
{0xfe, "T_DONEPROC", "9I1"},
{0xff, "T_DONEINPROC", "3I1"},
{ 0 }};

static char * curs_type_flags[] = {
/* 0x1 */ "CT_CURS_KEYSET_DRIVEN",
/* 0x2 */ "CT_CURS_DYNAMIC",
/* 0x4 */ "CT_CURS_FORWARD_ONLY",
/* 0x8 */ "CT_CURS_INSENSITIVE",
/* 0x10 */ "CT_CURS_FAST_FORWARD_ONLY",
/* 0x1000 */ "CT_CURS_PARAMETERIZED_SQL",
/* 0x2000 */ "CT_CURS_AUTO_FETCH",
/* 0x4000 */ "CT_CURS_AUTO_CLOSE",
/* 0x8000 */ "CT_CURS_CHECK_ACCEPTED_TYPES",
/* 0x10000 */ "CT_CURS_KEYSET_ACCEPTABLE",
/* 0x20000 */ "CT_CURS_DYNAMIC_ACCEPTABLE",
/* 0x40000 */ "CT_CURS_FORWARD_ONLY_ACCEPTABLE",
/* 0x80000 */ "CT_CURS_STATIC_ACCEPTABLE",
/* 0x100000 */ "CT_CURS_FAST_FORWARD_ACCEPTABLE"
};

static char * curs_prop_flags[] = {
/* 0x1 */ "CP_CURS_READONLY",
/* 0x2 */ "CP_CURS_LOCKCC",
/* 0x4 */ "CP_CURS_OPTCC",
/* 0x8 */ "CP_CURS_OPTCCVAL",
/* 0x2000 */ "CP_CURS_OPEN_ON_ANY_SQL",
/* 0x4000 */ "CP_CURS_UPDATE_KEYSET_INPLACE",
/* 0x10000 */ "CP_CURS_READ_ONLY_ACCEPTABLE",
/* 0x20000 */ "CP_CURS_LOCKS_ACCEPTABLE",
/* 0x40000 */ "CP_CURS_OPTIMISTIC_ACCEPTABLE"
};
static char * curs_struct[] = {
/* 0x1 */ "CS_CURS_TEXTPTR_ONLY",
/* 0x2 */ "CS_CURS_CURSOR_NAME",
/* 0x3 */ "CS_CURS_TEXTDATA"
};
static char * curs_ops[] = {
/* 0x1 */ "CO_CURS_UPDATE",
/* 0x2 */ "CO_CURS_DELETE",
/* 0x4 */ "CO_CURS_INSERT",
/* 0x8 */ "CO_CURS_REFRESHPOS",
/* 0x10 */ "CO_CURS_LOCK",
/* 0x20 */ "CO_CURS_SETPOSITION",
/* 0x40 */ "CO_CURS_SETABSOLUTE",
};
static char * curs_state[] = {
/* 0x1 */ "CS_CURS_FIRST",
/* 0x2 */ "CS_CURS_NEXT",
/* 0x4 */ "CS_CURS_PREV",
/* 0x8 */ "CS_CURS_LAST",
/* 0x10 */ "CS_CURS_ABSOLUTE",
/* 0x20 */ "CS_CURS_RELATIVE",
/* 0x40 */ "CS_CURS_BY_VALUE",
/* 0x80 */ "CS_CURS_REFRESH",
/* 0x100 */ "CS_CURS_INFO",
/* 0x200 */ "CS_CURS_PREV_NOADJUST",
/* 0x400 */ "CS_CURS_SKIP_UPDT_CNCY"
};

static char * col_info[] = {
/* 0x4 */ "CI_EXPRESSION",
/* 0x8 */ "CI_KEY",
/* 0x10 */ "CI_HIDDEN",
/* 0x20 */ "CI_DIFFERENT_NAME"
};

static char * rpc_option_flags[] = {
/* 0x0 */ "RPCO_NONE",
/* 0x1 */ "RPCO_SENT_WITH_RECOMPILE",
/* 0x2 */ "RPCO_NO_METADATA_RETURNED"
};

static char * curs_op_rslts[] = {
/* 0x1 */ "CR_FETCH_SUCCEEDED",
/* 0x2 */ "CR_FETCH_MISSING",
/* 0x4 */ "CR_FETCH_ENDOFKEYSET",
/* 0xc */ "CR_FETCH_ENDOFRESULTS",
/* 0x10 */ "CR_FETCH_ADDED",
/* 0x20 */ "CR_FETCH_UPDATED"
};
static char * stray_errors[] = {
/* 0x423a */ "SE_INFO_EXECUTING_SQL_DIRECTLY_NO_CURSOR",
/* 0x420d */ "SE_ERROR_INVALID_CURSOR"
};

static char * ext_procs[] = {
/* 0x1 */ "X_SP_CURSOR",
/* 0x2 */ "X_SP_CURSOR_OPEN",
/* 0x3 */ "X_SP_CURSOR_PREPARE",
/* 0x4 */ "X_SP_CURSOR_EXECUTE",
/* 0x5 */ "X_SP_CURSOR_PREP_EXEC",
/* 0x6 */ "X_SP_CURSOR_UNPREPARE",
/* 0x7 */ "X_SP_CURSOR_FETCH",
/* 0x8 */ "X_SP_CURSOR_OPTION",
/* 0x9 */ "X_SP_CURSOR_CLOSE",
/* 0xa */ "X_SP_EXECUTE_SQL",
/* 0xb */ "X_SP_PREPARE",
/* 0xc */ "X_SP_EXECUTE",
/* 0xd */ "X_SP_PREP_EXEC",
/* 0xe */ "X_SP_PREP_EXEC_RPC",
/* 0xf */ "X_SP_UNPREPARE"
};
/*
 * Hash function for MS SQL Server message IDs
 */
unsigned mess_hh(w,modulo)
char * w;
int modulo;
{
long l = (long) w;
long maj = (l & 0xff00) >> 3;
    return(((int) ((l & 0xff) | maj)) & (modulo-1));
}
static HASH_CON * idt;
static HASH_CON * nmt;
static HASH_CON * idp;
static HASH_CON * idsslp;
static HASH_CON * idsslt;
/***********************************************************************
 * The following logic allows us to feed in the interesting ports.
 */
static int extend_listen_flag; /* Feed in extra listener ports            */ 
static int match_port[100];    /* List of ports to match against          */
static int match_cnt;            /* Number of ports in the list    */
static void tdss_match_add(arr, cnt, port)
int * arr;
int * cnt;
int port;
{
    if (*cnt < 100)
    {
       arr[*cnt] = port;
       (*cnt)++;
    }
    return;
}
static int tdss_match_true(arr, cnt, from, to)
int *arr;
int cnt;
int from;
int to;
{
int i;
#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif

    for (i = 0; i < cnt; i++)
    {
       if (arr[i] == from || arr[i] == to)
       {
           if (arr[i] == to)
               return  1;         /* Flag which end is the client */
           else
               return -1;
       }
    }
    return 0;
}
/*
 * Discard dynamically allocated session structures. Empty for now. But stops
 * the script file being closed on session close.
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
char buf[80];
/*
 * Allocate a message close
 */
    buf[0] = '\\';
    buf[1] = 'X';
    buf[2] = ':';
    ip_dir_copy(&buf[3], frp, 0);
    strcat(&buf[23], "\\\n"); /* Cannot be less than 20 long */
    (void) new_script_element(&script_control, buf, NULL);
    if (frp->app_ptr != (char *) NULL)
        free(frp->app_ptr);
    return;
}
/*
 * Allow listener ports to be specified in the environment
 */
static void extend_listen_list()
{
char * x;
int i;

    extend_listen_flag = 1;
    if ((x = getenv("E2_TDS_PORTS")) != (char *) NULL)
    {
        for (x = strtok(x," "); x != (char *) NULL; x = strtok(NULL, " "))
        {
            if ((i = atoi(x)) > 0 && i < 65536)   
                tdss_match_add(match_port, &match_cnt, i);
        }
    }
    if ((x = getenv("E2_BOTH")) != (char *) NULL)
        both_ways = 1;
    if ((x = getenv("E2_VERBOSE")) != (char *) NULL)
        verbose = 1;
    return;
}
/*
 * Initialise the control structures for the message recognition
 */
void tds_init()
{
struct tds_mess *dmp;

    nmt = hash(1024, string_hh, strcmp);
    idt = hash(512, mess_hh, icomp);
    idp = hash(32, long_hh, icomp);
    idsslp = hash(8, mess_hh, icomp);
    idsslt = hash(32, mess_hh, icomp);
    for (dmp = &tds_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(idt, (char *) dmp->mess_id, (char *) dmp);
        insert(nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    for (dmp = &pack_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(idp, (char *) dmp->mess_id, (char *) dmp);
        insert(nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    for (dmp = &ssl_comp_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(idsslt, (char *) dmp->mess_id, (char *) dmp);
        insert(nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    for (dmp = &ssl_pack_mess[0]; dmp->mess_name != (char *) NULL; dmp++)
    {
        insert(idsslp, (char *) dmp->mess_id, (char *) dmp);
        insert(nmt, dmp->mess_name, (char *) dmp);
        if (dmp->mess_form != (char *) NULL)
            dmp->mess_len = e2rec_comp(&(dmp->mess_io), dmp->mess_form);
        else
            dmp->mess_len = 0;
    }
    extend_listen_list();
    return;
}
/*
 * Function that decides which sessions are of interest, and sets up the
 * relevant areas of the frame control structure. We are aiming to get
 * genconv.c e2net.* etc. into a state where new applications can be added
 * with no changes to the framework.
 */
int tdss_app_recognise(frp)
struct frame_con *frp;
{
int i;
unsigned short int from, to;
char buf[80];

    cur_frame = frp;
/*
 * Decide if we want this session.
 * We want it if:
 * -  The protocol is TCP
 * -  The port is identified in the list of interesting ports, managed
 *    with tdss_match_add() and tdss_match_true()
 */
    if (idt == NULL)
        tds_init();
    if (frp->prot == E2_TCP)
    {
/*
 *      if (!(frp->tcp_flags & TH_SYN))
 *          return 0;
 */
        memcpy((char *) &to, &(frp->port_to[1]), 2);
        memcpy((char *) &from, &(frp->port_from[1]), 2);
        if (from == 1433)
            i = -1;
        else
        if (to == 1433)
            i = 1;
        else
            i = tdss_match_true(match_port, match_cnt, from, to);
        if (i)
        {
        struct script_element * x;

            if (ofp == (FILE *) NULL)
                ofp = fopen("notes.txt", "wb");
            frp->ofp = ofp;
            if (frp->ofp == (FILE *) NULL)
            {
                perror("tdss_script.sql fopen() failed");
                frp->ofp = stdout;   /* Out of file descriptors */
            }
            frp->off_flag = 2;
            frp->len_len = 2;
            frp->big_little = 0;   /* A big-endian length */
            frp->fix_size = 8;
/*
 * This does not seem to apply now
 *
            frp->off_flag = 4;
            frp->len_len = 4;
            frp->big_little = 1;   /o A little-endian length o/
            frp->fix_size = 16;
 */
            frp->fix_mult = 0;
/*
 * Allocate a message open
 */
            strcpy(buf,"\\LOGIN:");
            ip_dir_copy(&buf[7], frp, 0);
            strcat(&buf[27], "\\\n");     /* Cannot be less than 20 long */
            (void) new_script_element(&script_control, buf, NULL);
/*
 * Now set up the request/response tracking 
 */
            if (i == -1)
                frp->reverse_sense = 1;
            frp->do_mess = do_mess;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (unsigned char *) malloc(sizeof(struct script_sess));
            ((struct script_sess *)(frp->app_ptr))->send_tracker = NULL;
            ((struct script_sess *)(frp->app_ptr))->recv_tracker = NULL;
            return 1;
        }
    }
    else
    if (frp->prot == E2_UDP )
    {
        memcpy((char *) &to, &(frp->port_to[1]), 2);
        memcpy((char *) &from, &(frp->port_from[1]), 2);
        if (from == 7 || to == 7)
        {
            if (ofp == (FILE *) NULL)
                ofp = fopen("tdss_script.sql", "wb");
            frp->ofp = ofp;
            if (frp->ofp == (FILE *) NULL)
                frp->ofp = stdout;   /* Out of file descriptors */
            if (from == 7)
                frp->reverse_sense = 1;
            frp->do_mess = do_e2sync;
            frp->cleanup = do_cleanup;
            frp->app_ptr = (char *) &script_control;
            return 1;
        }
    }
    return 0;
}
void init_send_recv(ap, frp, dir_flag)
struct script_sess * ap;
struct frame_con * frp;
int dir_flag;
{
char head_buf[80];

    head_buf[0] = '\\';
    head_buf[1] = 'S';
    head_buf[2] = 'Q';
    head_buf[3] = 'L';
    head_buf[4] = ':';
    ip_dir_copy(&head_buf[5], frp, dir_flag);
    strcat(&head_buf[25],"\\\n");
    ap->send_tracker = new_script_element(&script_control, head_buf, "\n/\n");
    head_buf[1] = 'R';
    head_buf[2] = 'E';
    head_buf[3] = 'S';
    ap->recv_tracker = new_script_element(&script_control,
                                    (both_ways)?head_buf: NULL, "\\END\\\n");
    return;
}
/*
 * Function that is called to process messages
 */
static void do_mess(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct script_sess * ap = (struct sess *) (frp->app_ptr);
int sav_len;

    if (frp->top[dir_flag] == frp->hold_buf[dir_flag])
        return;           /* Ignore it if there is no data */
    cur_frame = frp;
    if ((!dir_flag) ^ frp->reverse_sense)
    {
/*
 * A send
 */
        if (ap->send_tracker == NULL            /* First time */
         || (ap->recv_tracker != NULL           /* New message */
           &&  ap->recv_tracker->body != NULL))
            init_send_recv(ap, frp, dir_flag);
        sav_len = ap->send_tracker->body_len;
        ap->send_tracker->body_len += (frp->top[dir_flag] -
                                      frp->hold_buf[dir_flag]);
        if (ap->send_tracker->body == NULL)
            ap->send_tracker->body = (unsigned char *) malloc(
                 ap->send_tracker->body_len);
        else
            ap->send_tracker->body = (unsigned char *) realloc(
                 ap->send_tracker->body, ap->send_tracker->body_len);
        memcpy(ap->send_tracker->body + sav_len, frp->hold_buf[dir_flag],
                 ap->send_tracker->body_len - sav_len);
    }
    else
    if (ap->recv_tracker != NULL)
    {
/*
 * A receive that we want
 */
        sav_len = ap->recv_tracker->body_len;
        ap->recv_tracker->body_len += (frp->top[dir_flag] -
                                      frp->hold_buf[dir_flag]);
        if (ap->recv_tracker->body == NULL)
        {
            ap->recv_tracker->body = (unsigned char *) malloc(
                 ap->recv_tracker->body_len);
        }
        else
            ap->recv_tracker->body = (unsigned char *) realloc(
                 ap->recv_tracker->body, ap->recv_tracker->body_len);
        memcpy(ap->recv_tracker->body + sav_len, frp->hold_buf[dir_flag],
                 ap->recv_tracker->body_len - sav_len);
    }
    return;
}
/*
 * Save just the final element of the message. Why???
 */
static void decode_last(tp, fdp, op, top)
struct tds_mess * tp;
struct fld_descrip * fdp;
unsigned char *op;
unsigned char *top;
{
struct iocon * iop = tp->mess_io;

    if (iop != (struct iocon *) NULL)
    {
        while (iop->next_iocon != (struct iocon *) NULL)
            iop = iop->next_iocon;
        (void) (*(iop->getfun))(fdp->fld,iop->alen, op, top);
    }   
    return;
}
/*
 * Handle tabular data. Column descriptors sometimes precede the values they
 * define, and sometimes they are collected in groups, and define decoders
 * for the records that follow. 
 */
static unsigned char * tdsrow_handle(fp, col_cnt, x, top, out)
FILE *fp;
int col_cnt;
unsigned char * x;
unsigned char * top;
int out;
{
int i;
/*
 * Construct the decoder
 */
    for (i = 0; i < col_cnt; i++)
    {
    }
/*
 * Apply the decoder to the records
 */

    return top;
}
/*
 * To Do:
 * -  Separate routines to decode the main message types:
 *    -  RPC
 *    -  Table Response
 *    -  DTC stuff
 * -  Decode incoming by creating a Message Format for the row from the
 *    column info
 * -  Try to make sense of the two 4 byte 'counters' on the end of the
 *    'SuperSocket' header.
 * -  Provide an easier interface to the decoder stuff, essentially modelled
 *    on an array sub-script, rather than poking around in the descriptors
 *    in the calling routine.
 */
static void tdsapi_handle(fp, x,top,out)
FILE *fp;
unsigned char * x;
unsigned char * top;
int out;
{
int i, j;
unsigned char * x1;
int mess_id;
int mess_len;
HIPT * h;
struct fld_descrip * desc_arr;
struct tds_mess * dmp;
char buf[8192];
int len;
unsigned short int from;
unsigned char * bound;

    if (verbose)
    {
        if (out)
            fputs(">->->->->>\n", fp);
        else
        if (both_ways)
            fputs("<-<-<-<-<<\n", fp);
        if (out | both_ways)
            (void) gen_handle(fp, x,top,1);
        if (out)
            fputs(">=>=>=>=>>\n", fp);
        else
        if (both_ways)
            fputs("<=<=<=<=<<\n", fp);
    }
    if (!out && !verbose)
    {
        fputc('\n', fp);
        return;
    }
/*
 * Outer loop - TDS packets
 */
    while (x < top)
    {
        mess_id = x[0];
        mess_len = x[2]*256 + x[3];
        bound = x + mess_len;
        if ((h = lookup(idp, (char *) mess_id)) == (HIPT *) NULL
         && (h = lookup(idsslp, (char *) mess_id)) == (HIPT *) NULL)
        {
             (void) fprintf(fp,
                "Format failure: unknown message ID:%d length:%d\n", 
                            mess_id, mess_len);
        }
        else
        {
            dmp = ((struct tds_mess *) (h->body));
            fputs(dmp->mess_name, fp);
            fputc('|', fp);
            if (verbose)
                i = e2rec_map_bin(&desc_arr, x, &buf[0], dmp->mess_io, '|', '\\');
            else
                i = e2rec_map_bin(&desc_arr, x, NULL, dmp->mess_io, '|', '\\');
            if (i)
            {
                x1 = desc_arr[i-1].fld +  desc_arr[i-1].len;
                if (!verbose)
                {
                    buf[0] = '\0';
                    decode_last(dmp, &desc_arr[i-1],&buf[0],&buf[65535]);
                }
                fputs(&buf[0], fp);
                fputc('\n', fp);
            }
            else
            {
                fputs("Logic Error: couldn't parse packet header\n", fp);
                x1 = x +8;
            }
            fflush(fp);
            if (mess_id == 1 /* M_TDS_SQLBATCH */)
            {
                unin_r(x1, (bound - x1), &buf[0], &buf[65536]);
                fputs(buf, fp);
                fputc('\n', fp);
                return;
            }
            else
            {
                while (x1 < top && x1 < bound)
                {
                    mess_id = x1[0];
                    if ((h = lookup(idt, (char *) mess_id)) == (HIPT *) NULL
                     && (h = lookup(idp, (char *) mess_id)) == (HIPT *) NULL
                     && (h = lookup(idsslp, (char *) mess_id)) == (HIPT *) NULL)
                    {
                        (void) fprintf(fp, "Format failure: unknown token ID:%d\n", 
                                    mess_id);
                        gen_handle(fp, x1, (bound < top)?bound: top, 1);
                        break;
                    }
                    dmp = ((struct tds_mess *) (h->body));
/*
 * Convert the record
 */
/*            if (mess_id >7) */
                    {
                        fputs(dmp->mess_name, fp);
                        fputc('|', fp);
                    }
                    if (verbose)
                    {
                        i = e2rec_map_bin(&desc_arr, x1, &buf[0],
                                  dmp->mess_io, '|', '\\');
                        if (i)
                        {
                            fputs(&buf[0], fp);
                            x1 = desc_arr[i-1].fld +  desc_arr[i-1].len;
                        }
                    }
                    else
                    {
/*
 * Summary only if not verbose?
 */
                        i = e2rec_map_bin(&desc_arr, x1,
                                       NULL, dmp->mess_io, '|', '\\');
                        if (i)
                        {
                            x1 = desc_arr[i-1].fld +  desc_arr[i-1].len;
/*                            if (mess_id > 7) */
                            {
                                buf[0] = '\0';
                                decode_last(dmp, &desc_arr[i-1],&buf[0],&buf[65535]);
                                fputs(&buf[0], fp);
                                fputc('\n', fp);
                            }
                        }
                    }
                    if (!i)
                    {
                        fputs("Logic Error: couldn't parse token\n", fp);
                        x1++;
                    }
                }
            }
        }
        x = bound;
    }
    return;
}
/*
 * Produce the generic script.
 */
void output_script()
{
struct script_element * tp;

    if (ofp != NULL)
        fclose(ofp);
    if ((ofp = fopen("tdss_script.sql", "wb")) == NULL)
        return;
    for (tp = script_control.anchor; tp != NULL; tp = tp->next_track)
    {
        if (tp->head != NULL && (tp->foot == NULL || tp->body != NULL))
        {
            fputs(tp->head, ofp);
            if (tp->body != NULL)
            {
                tdsapi_handle(ofp, tp->body,tp->body + tp->body_len,1);
            }
            if (tp->foot != NULL)
                fputs(tp->foot, ofp);
        }
    }
    fclose(ofp);
    ofp = NULL;
    return;
}

/************************************************************************
 * opldrive.h - Header for opldrive and related programs.
 *
 *
@(#) $Name$ $Id$
*/
#ifndef OPLDRIVE_H
#define OPLDRIVE_H

#include <sys/param.h>
#include <stdio.h>
#include <ctype.h>
/*****************************************************************
 * The data for processing the statement files
 */
#ifndef PATHSIZE
#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif
#define PATHSIZE MAXPATHLEN
#endif
#define WORKSPACE 32768
#define MAX_SCRAM 32

enum look_status {CLEAR, PRESENT};

enum tok_id {SQL, FIELD, EOR, PEOF};

/*
 * Control structure for dynamic statements
 */
struct dyn_con {
    HENV henv;
    HDBC hdbc;
    HSTMT hstmt;
    char * statement;         /* Text of SQL Statement               */
    char     *bdp;           /* -> Descriptor used for BIND vars    */
    char     *sdp;           /* -> Descriptor used for SELECT vars  */
    short     *sdt;           /* -> arr of original DESCRIBE'd types */
    char      *scram_flags;   /* -> arr of scramble flags            */
    short int *sv_widths;     /* Widths */
    short int *sv_types;      /* Types */
    short int *sv_precs;      /* Precisions */
    short int *sv_nulls;      /* Nulls */
    short int *sb_map;        /* Counted lists of the number of
                                 references in the bind descriptor
                                 list to columns in the select
                                 descriptor list                     */
    int       sdtl;           /* no of entries in sdt[] and
                                            scram_flags              */
    int       bd_size;        /* Size of Bind variable descriptor    */
    int       bv_size;        /* Max no of chars in Bind Var name    */
    int       sd_size;        /* Size of Select list descriptor      */
    int       sv_size;        /* Max no chars in Select List colnames*/
    int       ind_size;       /* Max no chars in indicator names     */
    int       ret_status;     /* Returned status                     */
    int       to_do;          /* Number remaining for processing     */
    int       so_far;         /* Number retrieved so far             */
    int       cur_ind;        /* The current array position          */
    int       fld_ind;        /* The current field position          */
    short int *cur_map;       /* The current field position in the
                                 select/bind map                     */
    int       chars_read;     /* Count of characters read by selects */
    int       chars_sent;     /* Length of SQL Statements            */
    int       rows_read;      /* Count of rows processed             */
    int       rows_sent;      /* Count of rows processed             */
    int       fields_read;    /* Count of fields read                */
    int       fields_sent;    /* Count of fields sent                */
};
struct dyn_con * dyn;
/*****************************************************************************
 * Macros for manipulating ORACLE VARCHARs etc.
 */
#define NULLTERM(x) (x).arr[(x).len]='\0'
#ifdef AIX_X
#define STRTOVAR(x,y) {(void) strcpy((char *) &(x).arr[0],(char *)(y));\
(x).len=strlen((char *)(y));}
#else
#define STRTOVAR(x,y) {(void) strcpy((char *) &(x).arr[0],(((y) == (char *) 0)?"":(char *)(y)));\
(x).len=strlen(((char *)(y) == (char *) 0)?"":(char *)(y));}
#endif
#define VARTOVAR(x,y) {(void) memcpy((void *) &(x).arr[0],(void *) &(y).arr[0],\
(y).len);(x).len=(y).len;(x).arr[(x).len]='\0';}
/*
 * The following macro assumes sufficient memory has been allocated.
 * Do not use it with NULL pointers.
 */
#define VARTOSTR(x,y) {(void) memcpy((void *)(x),(void *)&(y).arr[0],(y).len);\
*(((char *)(x))+(y).len)='\0';}
#define TRAIL_SPACE_STRIP(x,y)\
{ char *_y; for (_y=(x)+(y)-1;\
 (y)>0 &&(*_y=='\0'||*_y==' '||*_y=='\t');*_y-- ='\0',(y)--);}
#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

/*************************************************************************
 * Functions defined in opldrive.c
 */
void exec_sel();
void get_cols();
void prep_dml();
void exec_dml();
void or_connect();
void ini_sel_vars();
void ini_bind_vars();
void def_bind_vars();
void free_vars();
struct dyn_con * dyn_init();
enum tok_id get_tok();
void form_print();
void col_dump();
void col_disc();
void dyn_fetch();
void dyn_kill();
void con_insert();
void con_delete();
void desc_bind();
short int quote_stuff();
short int out_field();
void desc_sel();
void add_field();
enum tok_id prem_eof();
void sort_out();
/******************************************************************
 * Parser data
 */
char * tbuf;
char * tlook;
enum tok_id look_tok;
enum look_status look_status;
/*
 * Functions that must be defined by a user of pathslib.pc
 */
char * scramble();
void scarper();

extern int char_long;
extern int scram_cnt;       /* Count of to-be-scrambled strings */
extern char * scram_cand[]; /* Candidate scramble patterns */
#endif

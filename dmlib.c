/******************************************************************************
 * dmlib.c - Scanner for the ISA Dialog Manager protocol, as used by the
 * MANCOS Maginus package.
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
#include "hashlib.h"
#include "e2conv.h"
#include "e2net.h"
static struct frame_con * cur_frame;
/******************************************************************************
 * Dialog Manager Specifics
 */
enum prod_response {NEUTRAL, PROD, RESPONSE};
#define UNKNOWN "Unknown token"
#define INCORRECT "Erroneus value"
/*
 * Thing returned by lexical analysis routines
 */
struct lex_tok {
    struct lex_tok * prev_tok;
    unsigned char token;             /* The token represented */
    unsigned short int vlen;         /* The value length      */
    union {
        unsigned char v[sizeof(char *)];
                                     /* The value (extra space as necessary) */
        long n;                      /* Numeric value                        */
        char * lp;                   /* Pointer to something or other        */
    } value;
};
/*
 * Function to process rexec() messages
 */
static void do_rexec_track();
/*
 * Lexical functions
 */
static struct lex_tok * dm_resynch(); /* Function to handle unexpected tokens */
static struct lex_tok * dm_flag();    /* Function to handle flag bytes        */
static struct lex_tok * dm_1byte();   /* Function to handle one byte fields   */
static struct lex_tok * dm_2bytes();  /* Function to handle two byte fields   */
static struct lex_tok * dm_3bytes();  /* Function to handle three byte fields */
static struct lex_tok * dm_4bytes();  /* Function to handle four byte fields  */
static struct lex_tok * dm_string();  /* Function to handle string fields     */
static struct lex_tok * dm_block();   /* Function to handle wide fields       */
/*
 * Record parsing functions
 */
static struct lex_tok * dm_x84_some_via_h_clear();
static struct lex_tok * dm_x85_arr_set_h();
static struct lex_tok * dm_x86_set_v();
static struct lex_tok * dm_x87_req_v();
static struct lex_tok * dm_x89_req_h();
static struct lex_tok * dm_x8e_arr_set_v();
static struct lex_tok * dm_x8f_arr_get_v();
static struct lex_tok * dm_x91_call_fun();
static struct lex_tok * dm_x96_tran_h();
static struct lex_tok * dm_x98_some_via_app_h();
static struct lex_tok * dm_x9a_some_via_h_sc();
static struct lex_tok * dm_xa0_arr_set_r();
static struct lex_tok * dm_xa3_arr_call_fun();
static struct lex_tok * dm_xa5_arr_get_set_v();
static struct lex_tok * dm_xa8_set_dia_h();
static struct lex_tok * dm_xbc_close();
static struct lex_tok * dm_xbd_beg_dia();
static struct lex_tok * dm_xbf_beg_func();
static struct lex_tok * dm_xc4_ack_some_via_h_clear();
static struct lex_tok * dm_xc5_ack_arr_set_h();
static struct lex_tok * dm_xc6_ack_v_set();
static struct lex_tok * dm_xc7_sup_v();
static struct lex_tok * dm_xc9_sup_h();
static struct lex_tok * dm_xce_ack_arr_set_v();
static struct lex_tok * dm_xcf_ack_arr_get_v();
static struct lex_tok * dm_xd1_ack_call_fun();
static struct lex_tok * dm_xd6_sup_tran_h();
static struct lex_tok * dm_xd8_ack_some_via_app_h();
static struct lex_tok * dm_xda_ack_some_via_h_sc();
static struct lex_tok * dm_xe0_ack_arr_set_r();
static struct lex_tok * dm_xe3_ack_arr_call_fun();
static struct lex_tok * dm_xe5_arr_v_resp();
static struct lex_tok * dm_xe8_ack_dia_h_set();
static struct lex_tok * dm_xfd_fin_beg();
static struct lex_tok * dm_xff_fin_func();
/*
 * Function to recognise tokens and discard them
 */
static struct lex_tok * dm_discard();
/*
 * The token table
 */
static struct lex_table {
    unsigned char token;
    char * description;
    struct lex_tok * (*parse_func)();
    enum prod_response prod_response;
    int dir_flag;
    unsigned char pair;
} lex_table[] = {{0x0,"Filler?",dm_flag, NEUTRAL},
{0x1,"End",dm_flag, NEUTRAL},
{0x2,UNKNOWN,dm_resynch, NEUTRAL},
{0x3,UNKNOWN,dm_resynch, NEUTRAL},
{0x4,UNKNOWN,dm_resynch, NEUTRAL},
{0x5,UNKNOWN,dm_resynch, NEUTRAL},
{0x6,UNKNOWN,dm_resynch, NEUTRAL},
{0x7,UNKNOWN,dm_resynch, NEUTRAL},
{0x8,UNKNOWN,dm_resynch, NEUTRAL},
{0x9,UNKNOWN,dm_resynch, NEUTRAL},
{0xa,UNKNOWN,dm_resynch, NEUTRAL},
{0xb,UNKNOWN,dm_resynch, NEUTRAL},
{0xc,UNKNOWN,dm_resynch, NEUTRAL},
{0xd,UNKNOWN,dm_resynch, NEUTRAL},
{0xe,UNKNOWN,dm_resynch, NEUTRAL},
{0xf,UNKNOWN,dm_resynch, NEUTRAL},
{0x10,UNKNOWN,dm_resynch, NEUTRAL},
{0x11,UNKNOWN,dm_resynch, NEUTRAL},
{0x12,UNKNOWN,dm_resynch, NEUTRAL},
{0x13,UNKNOWN,dm_resynch, NEUTRAL},
{0x14,UNKNOWN,dm_resynch, NEUTRAL},
{0x15,UNKNOWN,dm_resynch, NEUTRAL},
{0x16,UNKNOWN,dm_resynch, NEUTRAL},
{0x17,UNKNOWN,dm_resynch, NEUTRAL},
{0x18,UNKNOWN,dm_resynch, NEUTRAL},
{0x19,UNKNOWN,dm_resynch, NEUTRAL},
{0x1a,UNKNOWN,dm_resynch, NEUTRAL},
{0x1b,UNKNOWN,dm_resynch, NEUTRAL},
{0x1c,UNKNOWN,dm_resynch, NEUTRAL},
{0x1d,UNKNOWN,dm_resynch, NEUTRAL},
{0x1e,UNKNOWN,dm_resynch, NEUTRAL},
{0x1f,UNKNOWN,dm_resynch, NEUTRAL},
{' ',UNKNOWN, dm_resynch, NEUTRAL},
{'!',UNKNOWN, dm_resynch, NEUTRAL},
{'"',UNKNOWN, dm_resynch, NEUTRAL},
{'#',UNKNOWN, dm_resynch, NEUTRAL},
{'$',UNKNOWN, dm_resynch, NEUTRAL},
{'%',UNKNOWN, dm_resynch, NEUTRAL},
{'&',UNKNOWN, dm_resynch, NEUTRAL},
{'\'',UNKNOWN, dm_resynch, NEUTRAL},
{'(',UNKNOWN, dm_resynch, NEUTRAL},
{')',UNKNOWN, dm_resynch, NEUTRAL},
{'*',UNKNOWN, dm_resynch, NEUTRAL},
{'+',UNKNOWN, dm_resynch, NEUTRAL},
{',',UNKNOWN, dm_resynch, NEUTRAL},
{'-',UNKNOWN, dm_resynch, NEUTRAL},
{'.',UNKNOWN, dm_resynch, NEUTRAL},
{'/',UNKNOWN, dm_resynch, NEUTRAL},
{'0',UNKNOWN, dm_resynch, NEUTRAL},
{'1',UNKNOWN, dm_resynch, NEUTRAL},
{'2',UNKNOWN, dm_resynch, NEUTRAL},
{'3',UNKNOWN, dm_resynch, NEUTRAL},
{'4',UNKNOWN, dm_resynch, NEUTRAL},
{'5',UNKNOWN, dm_resynch, NEUTRAL},
{'6',UNKNOWN, dm_resynch, NEUTRAL},
{'7',UNKNOWN, dm_resynch, NEUTRAL},
{'8',UNKNOWN, dm_resynch, NEUTRAL},
{'9',UNKNOWN, dm_resynch, NEUTRAL},
{':',UNKNOWN, dm_resynch, NEUTRAL},
{';',UNKNOWN, dm_resynch, NEUTRAL},
{'<',UNKNOWN, dm_resynch, NEUTRAL},
{'=',UNKNOWN, dm_resynch, NEUTRAL},
{'>',UNKNOWN, dm_resynch, NEUTRAL},
{'?',UNKNOWN, dm_resynch, NEUTRAL},
{'@',UNKNOWN, dm_resynch, NEUTRAL},
{'A',UNKNOWN, dm_resynch, NEUTRAL},
{'B',UNKNOWN, dm_resynch, NEUTRAL},
{'C',UNKNOWN, dm_resynch, NEUTRAL},
{'D',"Indicator", dm_flag, NEUTRAL},
{'E',"Indicator", dm_flag, NEUTRAL},
{'F',UNKNOWN, dm_resynch, NEUTRAL},
{'G',"Indicator", dm_flag, NEUTRAL},
{'H',UNKNOWN, dm_resynch, NEUTRAL},
{'I',"Function", dm_4bytes, NEUTRAL},
{'J',UNKNOWN, dm_resynch, NEUTRAL},
{'K',UNKNOWN, dm_resynch, NEUTRAL},
{'L',UNKNOWN, dm_resynch, NEUTRAL},
{'M',"Indicator", dm_flag, NEUTRAL},
{'N',UNKNOWN, dm_resynch, NEUTRAL},
{'O',UNKNOWN, dm_resynch, NEUTRAL},
{'P',UNKNOWN, dm_resynch, NEUTRAL},
{'Q',"Count", dm_1byte, NEUTRAL},
{'R',"Repeat", dm_2bytes, NEUTRAL},
{'S',UNKNOWN, dm_resynch, NEUTRAL},
{'T',"Indicator", dm_flag, NEUTRAL},
{'U',"Indicator", dm_flag, NEUTRAL},
{'V',"String", dm_string, NEUTRAL},
{'W',"Block", dm_block, NEUTRAL},
{'X',"Indicator", dm_flag, NEUTRAL},
{'Y',"Flag", dm_1byte, NEUTRAL},
{'Z',"Indicator", dm_flag, NEUTRAL},
{'[',UNKNOWN, dm_resynch, NEUTRAL},
{'\\',UNKNOWN, dm_resynch, NEUTRAL},
{']',UNKNOWN, dm_resynch, NEUTRAL},
{'^',UNKNOWN, dm_resynch, NEUTRAL},
{'_',UNKNOWN, dm_resynch, NEUTRAL},
{'`',"Indicator", dm_flag, NEUTRAL},
{'a',"Char", dm_1byte, NEUTRAL},
{'b',"Short int", dm_2bytes, NEUTRAL},
{'c',"Long int", dm_4bytes, NEUTRAL},
{'d',"Field", dm_flag, NEUTRAL},
{'e',"Record", dm_1byte, NEUTRAL},
{'f',"Indicator", dm_flag, NEUTRAL},
{'g',"Handle", dm_4bytes, NEUTRAL},
{'h',"Marker", dm_flag, NEUTRAL},
{'i',"Count", dm_1byte, NEUTRAL},
{'j',"Bits?", dm_2bytes, NEUTRAL},
{'k',UNKNOWN, dm_resynch, NEUTRAL},
{'l',UNKNOWN, dm_resynch, NEUTRAL},
{'m',UNKNOWN, dm_resynch, NEUTRAL},
{'n',UNKNOWN, dm_resynch, NEUTRAL},
{'o',UNKNOWN, dm_resynch, NEUTRAL},
{'p',UNKNOWN, dm_resynch, NEUTRAL},
{'q',UNKNOWN, dm_resynch, NEUTRAL},
{'r',UNKNOWN, dm_resynch, NEUTRAL},
{'s',UNKNOWN, dm_resynch, NEUTRAL},
{'t',UNKNOWN, dm_resynch, NEUTRAL},
{'u',UNKNOWN, dm_resynch, NEUTRAL},
{'v',UNKNOWN, dm_resynch, NEUTRAL},
{'w',UNKNOWN, dm_resynch, NEUTRAL},
{'x',UNKNOWN, dm_resynch, NEUTRAL},
{'y',UNKNOWN, dm_resynch, NEUTRAL},
{'z',UNKNOWN, dm_resynch, NEUTRAL},
{'{',UNKNOWN, dm_resynch, NEUTRAL},
{'|',UNKNOWN, dm_resynch, NEUTRAL},
{'}',UNKNOWN, dm_resynch, NEUTRAL},
{'~',UNKNOWN, dm_resynch, NEUTRAL},
{0x7f,UNKNOWN, dm_resynch, NEUTRAL},
{0x80,UNKNOWN,dm_resynch, NEUTRAL},
{0x81,UNKNOWN,dm_resynch, NEUTRAL},
{0x82,UNKNOWN,dm_resynch, NEUTRAL},
{0x83,UNKNOWN,dm_resynch, NEUTRAL},
{0x84,"SomethingViaHandle - Clear?",dm_x84_some_via_h_clear,PROD,0,0xc4},
{0x85,"ArraySetHandle",dm_x85_arr_set_h,PROD,0,0xc5},
{0x86,"SetVariable",dm_x86_set_v,PROD,0,0xc6},
{0x87,"RequestValue",dm_x87_req_v,PROD,0,0xc7},
{0x88,UNKNOWN,dm_resynch, NEUTRAL},
{0x89,"RequestHandle",dm_x89_req_h,PROD,0,0xc9},
{0x8a,UNKNOWN,dm_resynch, NEUTRAL},
{0x8b,UNKNOWN,dm_resynch, NEUTRAL},
{0x8c,UNKNOWN,dm_resynch, NEUTRAL},
{0x8d,UNKNOWN,dm_resynch, NEUTRAL},
{0x8e,"ArraySetVariable",dm_x8e_arr_set_v,PROD,0,0xce},
{0x8f,"ArrayGetVariable",dm_x8f_arr_get_v,PROD,0,0xcf},
{0x90,UNKNOWN,dm_resynch, NEUTRAL},
{0x91,"CallFunction",dm_x91_call_fun,PROD,0,0xd1},
{0x92,UNKNOWN,dm_resynch, NEUTRAL},
{0x93,UNKNOWN,dm_resynch, NEUTRAL},
{0x94,UNKNOWN,dm_resynch, NEUTRAL},
{0x95,UNKNOWN,dm_resynch, NEUTRAL},
{0x96,"TranslateHandle",dm_x96_tran_h,PROD,0,0xd6},
{0x97,UNKNOWN,dm_resynch, NEUTRAL},
{0x98,"SomethingViaApplicationHandle",dm_x98_some_via_app_h,PROD,0,0xd8},
{0x99,UNKNOWN,dm_resynch, NEUTRAL},
{0x9a,"SomethingViaHandle - SetCaret?",dm_x9a_some_via_h_sc,PROD,0,0xda},
{0x9b,UNKNOWN,dm_resynch, NEUTRAL},
{0x9c,UNKNOWN,dm_resynch, NEUTRAL},
{0x9d,UNKNOWN,dm_resynch, NEUTRAL},
{0x9e,UNKNOWN,dm_resynch, NEUTRAL},
{0x9f,UNKNOWN,dm_resynch, NEUTRAL},
{0xa0,"ArraySetRecord",dm_xa0_arr_set_r,PROD,0,0xe0},
{0xa1,UNKNOWN,dm_resynch, NEUTRAL},
{0xa2,UNKNOWN,dm_resynch, NEUTRAL},
{0xa3,"ArrayCallFunctions",dm_xa3_arr_call_fun,PROD,0,0xe3},
{0xa4,UNKNOWN,dm_resynch, NEUTRAL},
{0xa5,"ArrayGetSetValues",dm_xa5_arr_get_set_v,PROD,0,0xe5},
{0xa6,UNKNOWN,dm_resynch, NEUTRAL},
{0xa7,UNKNOWN,dm_resynch, NEUTRAL},
{0xa8,"SetDialogHandle",dm_xa8_set_dia_h,PROD,0,0xe8},
{0xa9,UNKNOWN,dm_resynch, NEUTRAL},
{0xaa,UNKNOWN,dm_resynch, NEUTRAL},
{0xab,UNKNOWN,dm_resynch, NEUTRAL},
{0xac,UNKNOWN,dm_resynch, NEUTRAL},
{0xad,UNKNOWN,dm_resynch, NEUTRAL},
{0xae,UNKNOWN,dm_resynch, NEUTRAL},
{0xaf,UNKNOWN,dm_resynch, NEUTRAL},
{0xb0,UNKNOWN,dm_resynch, NEUTRAL},
{0xb1,UNKNOWN,dm_resynch, NEUTRAL},
{0xb2,UNKNOWN,dm_resynch, NEUTRAL},
{0xb3,UNKNOWN,dm_resynch, NEUTRAL},
{0xb4,UNKNOWN,dm_resynch, NEUTRAL},
{0xb5,UNKNOWN,dm_resynch, NEUTRAL},
{0xb6,UNKNOWN,dm_resynch, NEUTRAL},
{0xb7,UNKNOWN,dm_resynch, NEUTRAL},
{0xb8,UNKNOWN,dm_resynch, NEUTRAL},
{0xb9,UNKNOWN,dm_resynch, NEUTRAL},
{0xba,UNKNOWN,dm_resynch, NEUTRAL},
{0xbb,UNKNOWN,dm_resynch, NEUTRAL},
{0xbc,"BeginClose",dm_xbc_close,PROD,1},
{0xbd,"BeginDialog",dm_xbd_beg_dia,PROD,1,0xfd},
{0xbe,UNKNOWN,dm_resynch, NEUTRAL},
{0xbf,"BeginFunction",dm_xbf_beg_func,PROD,1,0xff},
{0xc0,UNKNOWN,dm_resynch, NEUTRAL},
{0xc1,UNKNOWN,dm_resynch, NEUTRAL},
{0xc2,UNKNOWN,dm_resynch, NEUTRAL},
{0xc3,UNKNOWN,dm_resynch, NEUTRAL},
{0xc4,"AckSomethingViaHandle - Clear?",dm_xc4_ack_some_via_h_clear,
           RESPONSE,1, 0x84},
{0xc5,"AckArraySetHandle",dm_xc5_ack_arr_set_h,RESPONSE,1,0x85},
{0xc6,"AckSetVariable",dm_xc6_ack_v_set,RESPONSE,1,0x86},
{0xc7,"SupplyValue",dm_xc7_sup_v,RESPONSE,1,0x87},
{0xc8,UNKNOWN,dm_resynch, NEUTRAL},
{0xc9,"SupplyHandle",dm_xc9_sup_h,RESPONSE,1,0x89},
{0xca,UNKNOWN,dm_resynch, NEUTRAL},
{0xcb,UNKNOWN,dm_resynch, NEUTRAL},
{0xcc,UNKNOWN,dm_resynch, NEUTRAL},
{0xcd,UNKNOWN,dm_resynch, NEUTRAL},
{0xce,"AckArraySetVariable",dm_xce_ack_arr_set_v,RESPONSE,1,0x8e},
{0xcf,"ArraySupplyVariable",dm_xcf_ack_arr_get_v,RESPONSE,1,0x8f},
{0xd0,UNKNOWN,dm_resynch, NEUTRAL},
{0xd1,"AckCallFunction",dm_xd1_ack_call_fun,RESPONSE,1,0x91},
{0xd2,UNKNOWN,dm_resynch, NEUTRAL},
{0xd3,UNKNOWN,dm_resynch, NEUTRAL},
{0xd4,UNKNOWN,dm_resynch, NEUTRAL},
{0xd5,UNKNOWN,dm_resynch, NEUTRAL},
{0xd6,"SupplyTranslatedHandle",dm_xd6_sup_tran_h,RESPONSE,1,0x96},
{0xd7,UNKNOWN,dm_resynch, NEUTRAL},
{0xd8,"AckSomethingViaApplicationHandle",dm_xd8_ack_some_via_app_h,RESPONSE,
            1,0x98},
{0xd9,UNKNOWN,dm_resynch, NEUTRAL},
{0xda,"AckSomethingViaHandle - SetCaret?",dm_xda_ack_some_via_h_sc,
       RESPONSE,1,0x9a},
{0xdb,UNKNOWN,dm_resynch, NEUTRAL},
{0xdc,UNKNOWN,dm_resynch, NEUTRAL},
{0xdd,UNKNOWN,dm_resynch, NEUTRAL},
{0xde,UNKNOWN,dm_resynch, NEUTRAL},
{0xdf,UNKNOWN,dm_resynch, NEUTRAL},
{0xe0,"AckArrSetRecord",dm_xe0_ack_arr_set_r,RESPONSE,1,0xa0},
{0xe1,UNKNOWN,dm_resynch, NEUTRAL},
{0xe2,UNKNOWN,dm_resynch, NEUTRAL},
{0xe3,"AckArrayCallFunctions",dm_xe3_ack_arr_call_fun,RESPONSE,1,0xa3},
{0xe4,UNKNOWN,dm_resynch, NEUTRAL},
{0xe5,"ArrayVariableResponse",dm_xe5_arr_v_resp,RESPONSE,1,0xa5},
{0xe6,UNKNOWN,dm_resynch, NEUTRAL},
{0xe7,UNKNOWN,dm_resynch, NEUTRAL},
{0xe8,"AckDialogHandleSet",dm_xe8_ack_dia_h_set,RESPONSE,1,0xa8},
{0xe9,UNKNOWN,dm_resynch, NEUTRAL},
{0xea,UNKNOWN,dm_resynch, NEUTRAL},
{0xeb,UNKNOWN,dm_resynch, NEUTRAL},
{0xec,UNKNOWN,dm_resynch, NEUTRAL},
{0xed,UNKNOWN,dm_resynch, NEUTRAL},
{0xee,UNKNOWN,dm_resynch, NEUTRAL},
{0xef,UNKNOWN,dm_resynch, NEUTRAL},
{0xf0,UNKNOWN,dm_resynch, NEUTRAL},
{0xf1,UNKNOWN,dm_resynch, NEUTRAL},
{0xf2,UNKNOWN,dm_resynch, NEUTRAL},
{0xf3,UNKNOWN,dm_resynch, NEUTRAL},
{0xf4,UNKNOWN,dm_resynch, NEUTRAL},
{0xf5,UNKNOWN,dm_resynch, NEUTRAL},
{0xf6,UNKNOWN,dm_resynch, NEUTRAL},
{0xf7,UNKNOWN,dm_resynch, NEUTRAL},
{0xf8,UNKNOWN,dm_resynch, NEUTRAL},
{0xf9,UNKNOWN,dm_resynch, NEUTRAL},
{0xfa,UNKNOWN,dm_resynch, NEUTRAL},
{0xfb,UNKNOWN,dm_resynch, NEUTRAL},
{0xfc,UNKNOWN,dm_resynch, NEUTRAL},
{0xfd,"FinishBegin",dm_xfd_fin_beg,RESPONSE,0,0xbd},
{0xfe,UNKNOWN,dm_resynch, NEUTRAL},
{0xff,"FinishFunction",dm_xff_fin_func, RESPONSE, 0, 0xbf}};
/*
 * Structure allocated when a session is started that holds Dialog Manager-
 * specific session state. We need to have a stack of unacknowledged calls,
 * and memory for the elements that are going to go into the RESPONSE records,
 * eg. User Name, Password (just in case it turns out to be useful later),
 * Program, Program Description, Start Time, Function.
 */
struct dm_context {
   char user_name[32];
   char password[32];
   char program_name[32];
   char program_description[80];
   char function_name[64];
   struct call_stack {
      struct lex_tok * top;
      int stack_depth;
   } call_stack[2];
   HASH_CON * handle_name;           /* Handle/Name translation table */
};
/*
 * Lexical scanner
 */
struct lex_tok * dm_get_tok(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_table * lp;
FILE * ofp;

    ofp = frp->ofp;
    if (ofp == (FILE *) NULL)
        ofp = stderr;
/*
 * Check that we have not run out of buffer
 */
    if (*ucpp >= frp->top[dir_flag])
        return (struct lex_tok *) NULL;
    lp = &lex_table[**ucpp];
    if (lp->token != **ucpp)
    {
        fprintf(frp->ofp,
              "Lexical table corrupt; token %u does not match character %u\n",
                     lp->token, **ucpp);
        return (struct lex_tok *) NULL;
    }
    if (lp->prod_response == NEUTRAL)
        return (lp->parse_func)(frp, dir_flag, ucpp);
    else
    if (dir_flag != lp->dir_flag)
    {
        fprintf(frp->ofp,
              "Function %u seen in wrong direction %u\n", lp->token, dir_flag);
        return dm_resynch(frp, dir_flag, ucpp);
    }
/*
 *  A record type. The function in the table is a pattern parser rather than
 *  a lexical analysis routine.
 */
    return dm_flag(frp, dir_flag, ucpp);
}
/*
 * Push a token onto the stack
 */
static void dm_push(csp, tp)
struct call_stack * csp;
struct lex_tok * tp;
{
    fprintf(cur_frame->ofp,"Pushing %x\n",tp->token);
    fflush(cur_frame->ofp);
    tp->prev_tok = csp->top;
    csp->top = tp;
    csp->stack_depth++;
    return;
}
/*
 * Pop a token from the stack
 */
static struct lex_tok * dm_pop(csp)
struct call_stack * csp;
{
struct lex_tok * tp = csp->top;

    if (tp == (struct lex_tok *) NULL || csp->stack_depth <= 0)
    {
        fprintf(cur_frame->ofp,
     "%s:%d Logic Error: Popping non-existent stack element\n",
                   __FILE__, __LINE__);
        fflush(cur_frame->ofp);
    }
    else
    {
        csp->top = tp->prev_tok;
        csp->stack_depth--;
    }
    fprintf(cur_frame->ofp,"Popping %x\n",tp->token);
    fflush(cur_frame->ofp);
    return tp;
}
/*
 * Deal with a flag byte, or a record type byte
 */
struct lex_tok * dm_flag(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;

    if ((kp = (struct lex_tok *) malloc(sizeof(struct lex_tok))) ==
          (struct lex_tok *) NULL)
        return kp;
    kp->token = **ucpp;
    kp->vlen = 0;
    kp->value.n = 0;
    kp->prev_tok = (struct lex_tok *) NULL;
    (*ucpp)++;
    return kp;
}
/*
 * Deal with one byte of data. If we run out, it will be returned short, and
 * the rest will have to be picked up later.
 */
struct lex_tok * dm_1byte(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;

    if ((kp = dm_flag(frp, dir_flag, ucpp)) == (struct lex_tok *) NULL)
        return kp;
    if (*ucpp < frp->top[dir_flag])
    {
        kp->vlen = 1;
        kp->value.v[0] = **ucpp;
        (*ucpp)++;
    }
    else
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
    return kp;
}
/*
 * Deal with two bytes of data. If we run out, it will be returned short, and
 * the rest will have to be picked up later.
 */
struct lex_tok * dm_2bytes(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;

    if ((kp = dm_flag(frp, dir_flag, ucpp)) == (struct lex_tok *) NULL)
        return kp;
    if (*ucpp < frp->top[dir_flag] - 1)
    {
        kp->vlen = 2;
        kp->value.n = (**ucpp) << 8;
        (*ucpp)++;
        kp->value.n += (**ucpp);
        (*ucpp)++;
    }
    else
    {
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
        if (*ucpp < frp->top[dir_flag])
        {
            kp->vlen = 1;
            kp->value.v[0] = **ucpp;
            (*ucpp)++;
        }
    }
    return kp;
}
/*
 * Deal with four bytes of data. If we run out, it will be returned short, and
 * the rest will have to be picked up later.
 */
struct lex_tok * dm_4bytes(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;
int i;

    if ((kp = dm_flag(frp, dir_flag, ucpp)) == (struct lex_tok *) NULL)
        return kp;
    for (i = (frp->top[dir_flag] - *ucpp),
         i = (i > 4) ? 4: i,
         kp->value.n = 0;
             i > 0;
                 i--)
    {
        kp->vlen++;
        kp->value.n <<= 8;
        kp->value.n += (**ucpp);
        (*ucpp)++;
    }
    if (kp->vlen != 4)
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
    return kp;
}
/*
 * Deal with three bytes of data. If we run out, it will be returned short, and
 * the rest will have to be picked up later.
 */
struct lex_tok * dm_3bytes(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;
int i;

    if ((kp = dm_flag(frp, dir_flag, ucpp)) == (struct lex_tok *) NULL)
        return kp;
    for (i = (frp->top[dir_flag] - *ucpp),
         i = (i > 3) ? 3: i,
         kp->value.n = 0;
             i > 0;
                 i--)
    {
        kp->vlen++;
        kp->value.n <<= 8;
        kp->value.n += (**ucpp);
        (*ucpp)++;
    }
    if (kp->vlen != 3)
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
    return kp;
}
/*
 * Deal with string data. If we run out, it will be returned short, and
 * the rest will have to be picked up later. As an optimisation, we tack the
 * data onto the lex_tok structure unless the V marker is the last character
 * of the message. In this case, we will have to re-allocate it when we know how
 * big it needs to be.
 */
struct lex_tok * dm_string(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;
int i;
unsigned char * p;
  

    if (*ucpp == (frp->top[dir_flag] - 1))    /* The string length is UNKNOWN */
    {
        kp = dm_flag(frp, dir_flag, ucpp);
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
        return kp;
    }
    if ((kp = (struct lex_tok *) malloc(sizeof(struct lex_tok) +
              *(*ucpp + 1) + 2 - sizeof(char *))) == (struct lex_tok *) NULL)
        return kp;
    kp->token = **ucpp;
    kp->prev_tok = (struct lex_tok *) NULL;
    (*ucpp)++;
    for (i = (frp->top[dir_flag] - *ucpp),
         i = (i > (**ucpp + 1)) ? (**ucpp + 1): i,
         kp->vlen = 1,
         p = &(kp->value.v[0]);
             i > 0;
                 (kp->vlen)++, i--, p++, (*ucpp)++)
         *p = **ucpp;
    if (kp->vlen != (2 + kp->value.v[0]))
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
    else
        *p = '\0';
    return kp;
}
/*
 * Deal with wide string data. If we run out, it will be returned short, and
 * the rest will have to be picked up later. As an optimisation, we tack the
 * data onto the lex_tok structure unless we have not got the full length. In
 * this case, we will have to re-allocate it when we know how big it needs to
 * be.
 */
struct lex_tok * dm_block(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct lex_tok * kp;
int i;
unsigned char * p;
  

    if (*ucpp >= (frp->top[dir_flag] - 2))    /* The string length is UNKNOWN */
    {
        kp = dm_flag(frp, dir_flag, ucpp);
        if (*ucpp == (frp->top[dir_flag] - 1))
        {
            kp->value.v[0] = 1;
            kp->value.v[1] = *(*ucpp + 1);
        }
        else
            kp->value.v[0] = 0;
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
        return kp;
    }
    if ((kp = (struct lex_tok *) malloc(sizeof(struct lex_tok) +
              (*(*ucpp + 1))*256 + *(*ucpp + 2) + 3 - sizeof(char *)))
                       == (struct lex_tok *) NULL)
        return kp;
    kp->token = **ucpp;
    kp->prev_tok = (struct lex_tok *) NULL;
    (*ucpp)++;
    for (i = (frp->top[dir_flag] - *ucpp),
         i = (i > (**ucpp*256 + *(*ucpp + 1) + 2))
           ? (**ucpp *256 + *(*ucpp + 1)+ 2)
           : i,
         kp->vlen = 1,
         p = &(kp->value.v[0]);
             i > 0;
                 (kp->vlen)++, i--, p++, (*ucpp)++)
         *p = **ucpp;
    if (kp->vlen != (3 + kp->value.v[0] *256 + kp->value.v[1]))
        dm_push(&(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]),
                  kp);
    else
        *p = '\0';
    return kp;
}
/**********************************************************************
 * Search for a string representation of a handle
 */
static char * name_find(dp,n)
struct dm_context * dp;
unsigned int n;
{
HIPT * h;
#ifdef DEBUG
    fprintf(stderr, "name_find(%lx,%u)\n", (unsigned long int) dp, n);
    fflush(stderr);
#endif
    if ((h = lookup(dp->handle_name, (char *) n)) != (HIPT *) NULL)
        return h->body;
    else
        return (char *) NULL;
}
/*
 * Add a name/handle translation to the table
 */
static void name_add(dp, bname, h)
struct dm_context * dp;
char * bname;
unsigned long int h;
{
char * sname = strdup(bname);
#ifdef DEBUG
    fprintf(stderr, "name_add(%lx,%s,%u)\n", (unsigned long int) dp, bname, h);
    fflush(stderr);
#endif
    insert(dp->handle_name, (char *) h, sname);
    return;
}
/*
 * Default action; print an error message, and advance one character
 */
static struct lex_tok * dm_resynch(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
FILE * ofp;

    ofp = frp->ofp;
    if (ofp == (FILE *) NULL)
        ofp = stderr;
    if (ofp != (FILE *) NULL)
        fprintf(ofp,"%x %s at offset %d\n", (unsigned) **ucpp,
                 lex_table[**ucpp].description,
                       (*ucpp - frp->hold_buf[dir_flag])); 
    (*ucpp)++;
    return NULL;
}
/*
 * Deal with left over data; complete (if possible) a token that spans multiple
 * TCP message elements.
 */
struct lex_tok * dm_rest(frp, dir_flag, ucpp)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
{
struct call_stack * csp =
              &(((struct dm_context *)(frp->app_ptr))->call_stack[dir_flag]);
struct lex_tok * kp = csp->top;
struct lex_tok * xp;
int i;
unsigned char * p;
/*
 * If the thing is a string, and we did not know the length, get the length,
 * and allocate a new structure with space for the length, and for the value.
 */
    if (lex_table[kp->token].parse_func == dm_string)
    {
        if (kp->vlen == 0)
        {
    
            if ((xp = (struct lex_tok *) malloc(sizeof(struct lex_tok) +
                  **ucpp + 2 - sizeof(char *))) == (struct lex_tok *) NULL)
                return xp;
            xp->token = kp->token;
            xp->prev_tok = kp->prev_tok;
            free(kp);
            csp->top = xp;
            kp = xp;
            kp->vlen = 2;
            kp->value.v[0] = **ucpp;
            (*ucpp)++;
        }
/*
 * Work out how much more data is needed, and attempt to read it.
 */
        i = kp->value.v[0] + 2 - kp->vlen;
        for (p = &(kp->value.v[kp->vlen - 1]);
                 *ucpp < frp->top[dir_flag] && i > 0;
                     (kp->vlen)++, i--, p++, (*ucpp)++)
             *p = **ucpp;
        if (!i)
            *p = '\0';
    }
    else
    if (lex_table[kp->token].parse_func == dm_block)
    {
        if (kp->vlen < 2)
        {
            if (kp->value.v[0] == '\0')
            {
                if ((xp = (struct lex_tok *) malloc(sizeof(struct lex_tok) +
                  **ucpp * 256 +
                  *(*ucpp + 1) + 3 - sizeof(char *)))
                                                    == (struct lex_tok *) NULL)
                    return xp;
                xp->value.v[0] = **ucpp;
                (*ucpp)++;
            }
            else
            {
                if ((xp = (struct lex_tok *) malloc(sizeof(struct lex_tok) +
                  kp->value.v[1]* 256 +
                  **ucpp + 3 - sizeof(char *))) == (struct lex_tok *) NULL)
                    return xp;
                xp->value.v[0] = kp->value.v[1];
            }
            xp->value.v[1] = **ucpp;
            (*ucpp)++;
            xp->vlen = 3;
            xp->token = kp->token;
            xp->prev_tok = kp->prev_tok;
            free(kp);
            csp->top = xp;
            kp = xp;
        }
/*
 * Work out how much more data is needed, and attempt to read it.
 */
        i = kp->value.v[0]*256 + kp->value.v[1] + 3 - kp->vlen;
        for (p = &(kp->value.v[kp->vlen - 1]);
                 *ucpp < frp->top[dir_flag] && i > 0;
                     (kp->vlen)++, i--, p++, (*ucpp)++)
             *p = **ucpp;
        if (!i)
            *p = '\0';
    }
    else
    {
/*
 * Work out how much more data is needed, and attempt to read it.
 */
        if (lex_table[kp->token].parse_func == dm_1byte)
            i = 1;
        else
        if (lex_table[kp->token].parse_func == dm_2bytes)
            i = 2 - kp->vlen;
        else
        if (lex_table[kp->token].parse_func == dm_3bytes)
            i = 3 - kp->vlen;
        else
        if (lex_table[kp->token].parse_func == dm_4bytes)
            i = 4 - kp->vlen;
        else
        {
            fprintf(frp->ofp,
                "Logic Error: dm_rest() called with unexpected token %x:%s\n",
                     kp->token, lex_table[kp->token].description);
            i = 0;
        }
        while ( *ucpp < frp->top[dir_flag] && i > 0)
        {
            kp->vlen++;
            kp->value.n <<= 8;
            kp->value.n += (**ucpp);
            (*ucpp)++;
            i--;
        }
    }
/*
 * If we have got it all, pop it off the stack
 */
    if (!i)
        (void) dm_pop(csp);
    return kp;
}
/*
 * Record parsing routines
 *
 * These routines may all be called multiple times for the same record, if
 * the records span TCP messages, so the record type switch logic must only
 * be called the once.
 */
static struct lex_tok * dm_x84_some_via_h_clear(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x85_arr_set_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));
struct lex_tok * pair_tok;

    while (this_tok != (struct lex_tok *) NULL
        && this_tok->token != 1
        && this_tok != dp->call_stack[dir_flag].top)
    {
        fputs(lex_table[this_tok->token].description, frp->ofp);
        if (lex_table[this_tok->token].parse_func == dm_resynch)
            fprintf(frp->ofp, " %x\n", this_tok->token);
        else
        if (this_tok->vlen > 0)
        {
            if (lex_table[this_tok->token].parse_func == dm_string)
            {
/*
 * In a hurry - does not cater for the string and its handle being in
 * different TCP messages
 */
                fprintf(frp->ofp, " %s\n", &(this_tok->value.v[1]));
                pair_tok = this_tok;
                this_tok = dm_get_tok(frp, dir_flag, ucpp);
                if (this_tok != (struct lex_tok *) NULL
                  && this_tok != dp->call_stack[dir_flag].top)
                    name_add(dp,  &(pair_tok->value.v[1]), this_tok->value.n);
                free(pair_tok);
            }
            else
                fprintf(frp->ofp, " %u\n", this_tok->value.n);
        }
        if (dp->call_stack[dir_flag].top != this_tok)
            free((char *) this_tok); 
        else
            break;
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
    }
    return this_tok;
}
static struct lex_tok * dm_x86_set_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x87_req_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x89_req_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));

    while (this_tok != (struct lex_tok *) NULL
        && this_tok->token != 1
        && this_tok != dp->call_stack[dir_flag].top)
    {
        fputs(lex_table[this_tok->token].description, frp->ofp);
        if (lex_table[this_tok->token].parse_func == dm_resynch)
            fprintf(frp->ofp, " %x\n", this_tok->token);
        else
        if (this_tok->vlen > 0)
        {
            if (lex_table[this_tok->token].parse_func == dm_string)
            {
                fprintf(frp->ofp, " %s\n", &(this_tok->value.v[1]));
                dp->call_stack[dir_flag].top->value.lp =
                        strdup(&(this_tok->value.v[1]));
            }
            else
                fprintf(frp->ofp, " %u\n", this_tok->value.n);
        }
        free((char *) this_tok); 
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
    }
    return this_tok;
}
static struct lex_tok * dm_x8e_arr_set_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x8f_arr_get_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x91_call_fun(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));
char *x;
/*
 * Read the handle
 */
    if (dp->call_stack[dir_flag].top->vlen == 0)
    {
        dp->call_stack[dir_flag].top->vlen = 1;
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
        if (this_tok == dp->call_stack[dir_flag].top)
            return this_tok;                            /* Not all there */
    }
    else
    if (dp->call_stack[dir_flag].top->vlen == 1)
    {
        dp->call_stack[dir_flag].top->vlen = 2;
        x = name_find(dp, this_tok->value.n);
        if (x == (char *) NULL)
            x = UNKNOWN;
        fputs(lex_table[0xbf].description, frp->ofp);
        fprintf(frp->ofp, " %s\n", x);
    }
/*
 * Deal with the rest
 */
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x96_tran_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x98_some_via_app_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_x9a_some_via_h_sc(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xa0_arr_set_r(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xa3_arr_call_fun(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));
char *x;

    while (this_tok != (struct lex_tok *) NULL
        && this_tok->token != 1
        && this_tok != dp->call_stack[dir_flag].top)
    {
        fputs(lex_table[this_tok->token].description, frp->ofp);
        if (lex_table[this_tok->token].parse_func == dm_resynch)
            fprintf(frp->ofp, " %x\n", this_tok->token);
        else
        if (this_tok->vlen > 0)
        {
            if (lex_table[this_tok->token].parse_func == dm_string)
            {
                fprintf(frp->ofp, " %s\n", &(this_tok->value.v[1]));
                dp->call_stack[dir_flag].top->value.lp =
                        strdup(&(this_tok->value.v[1]));
            }
            else
            {
                if ((this_tok->token == 'g')
                  && ((x = name_find(dp,this_tok->value.n)) != (char *) NULL))
                {
                    fputc(' ', frp->ofp);
                    fputs(x, frp->ofp);
                }
                fprintf(frp->ofp, " %u\n", this_tok->value.n);
            }
        }
        free((char *) this_tok); 
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
    }
    return this_tok;
}
static struct lex_tok * dm_xa5_arr_get_set_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xa8_set_dia_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_x85_arr_set_h(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xbc_close(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xbd_beg_dia(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xbf_beg_func(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));
char *x;
int i;
/*
 * Read the handle
 */
    if (dp->call_stack[dir_flag].top->vlen == 0)
    {
        dp->call_stack[dir_flag].top->vlen = 1;
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
        if (this_tok == dp->call_stack[dir_flag].top)
            return this_tok;                            /* Not all there */
    }
    if (dp->call_stack[dir_flag].top->vlen == 1)
    {
        dp->call_stack[dir_flag].top->vlen = 2;
        x = name_find(dp, this_tok->value.n);
        if (x == (char *) NULL)
            x = UNKNOWN;
        fputs(lex_table[0xbf].description, frp->ofp);
        fprintf(frp->ofp, " %s\n", x);
        if (dp->call_stack[dir_flag].stack_depth == 1)
        {
            strncpy(dp->function_name, x, sizeof(dp->function_name));
            frp->tran_start = frp->last_t[dir_flag];
            for (i = 0; i < 2; i++)
            {
                frp->tran_cnt[i] = frp->cnt[i];
                frp->tran_len[i] = frp->len[i];
                frp->tran_cs_tim[i] = frp->cs_tim[i];
                frp->tran_nt_tim[i] = frp->nt_tim[i];
            }
        }
    }
/*
 * Deal with the rest
 */
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xc4_ack_some_via_h_clear(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xc5_ack_arr_set_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xc6_ack_v_set(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xc7_sup_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
/*
 * Supply a handle in response to a request
 */
static struct lex_tok * dm_xc9_sup_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));

    while (this_tok != (struct lex_tok *) NULL
       &&  this_tok->token != 1
       &&  dp->call_stack[dir_flag].top != this_tok)
    {
        fputs(lex_table[this_tok->token].description, frp->ofp);
        if (lex_table[this_tok->token].parse_func == dm_resynch)
            fprintf(frp->ofp, " %x\n", this_tok->token);
        else
        if (this_tok->vlen > 0)
        {
            if (lex_table[this_tok->token].parse_func == dm_4bytes)
            {
                fprintf(frp->ofp, " %u\n", this_tok->value.n);
                if (dp->call_stack[!dir_flag].top->token == 
                                            lex_table[this_tok->token].pair
                  && dp->call_stack[!dir_flag].top->value.lp != (char *) NULL)
                {
                    name_add(dp, dp->call_stack[!dir_flag].top->value.lp,
                                 this_tok->value.n);
                    free(dp->call_stack[!dir_flag].top->value.lp);
                    dp->call_stack[!dir_flag].top->value.lp = (char *) NULL;
                }
            }
            else
            if (lex_table[this_tok->token].parse_func == dm_string)
            {
                fprintf(frp->ofp, " %s\n", &(this_tok->value.v[1]));
                dp->call_stack[dir_flag].top->value.lp =
                        strdup(&(this_tok->value.v[1]));
            }
            else
                fprintf(frp->ofp, " %u\n", this_tok->value.n);
        }
        free((char *) this_tok); 
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
    }
    return this_tok;
}
static struct lex_tok * dm_xce_ack_arr_set_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xcf_ack_arr_get_v(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xd1_ack_call_fun(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xd6_sup_tran_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xd8_ack_some_via_app_h(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xda_ack_some_via_h_sc(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xe0_ack_arr_set_r(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xe3_ack_arr_call_fun(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xe5_arr_v_resp(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xe8_ack_dia_h_set(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xfd_fin_beg(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
static struct lex_tok * dm_xff_fin_func(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
    return dm_discard(frp, dir_flag, ucpp, this_tok);
}
/*
 * Generic record recognition routine
 */
static struct lex_tok * dm_discard(frp, dir_flag, ucpp, this_tok)
struct frame_con * frp;
int dir_flag;
unsigned char ** ucpp;
struct lex_tok * this_tok;
{
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));

    while (this_tok != (struct lex_tok *) NULL
        && this_tok->token != 1
        && dp->call_stack[dir_flag].top != this_tok)
    {
        fputs(lex_table[this_tok->token].description, frp->ofp);
        if (lex_table[this_tok->token].parse_func == dm_resynch
          || this_tok->vlen == 0)
            fprintf(frp->ofp, " %x\n", this_tok->token);
        else
        {
            if (lex_table[this_tok->token].parse_func == dm_string)
                    fprintf(frp->ofp, " %.*s\n", this_tok->vlen -2,
                                    &(this_tok->value.v[1]));
            else
            if (lex_table[this_tok->token].parse_func == dm_block)
                    fprintf(frp->ofp, " %.*s\n", this_tok->vlen -3,
                                    &(this_tok->value.v[2]));
            else
                fprintf(frp->ofp, " %u\n", this_tok->value.n);
        }
        free((char *) this_tok); 
        this_tok = dm_get_tok(frp, dir_flag, ucpp);
    }
    return this_tok;
}
/******************************************************************************
 * Output the response for a Dialog Manager transaction element. There is no
 * messing about with gaps here. The response is built up from knowledge of
 * the protocol.
 */
static void dm_output_response (f,dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval resp_time;
struct dm_context * dp;
int i;
/*
 * When the message is going from the client to the server
 * work out the response time so far (ie. last server response - initial
 * client response), and the time from this packet to the tran_start
 * packet, and the time from this packet to the last server packet.
 *
 * If the response time is positive we need to output a response record:
 * - Record Type
 * - Label
 * - Time Start
 * - Response
 * - Packets Out
 * - Packets In
 * - Bytes Out
 * - Bytes In
 * - Dialog Manager-specific stuff
 */
    if (f->corrupt_flag)
        f->corrupt_flag = 0;
    else
    {
/*
 * Work out the overall response time
 */
        tvdiff(&(f->last_t[dir_flag].tv_sec),
                                          /* The time when this message began */
           &(f->last_t[dir_flag].tv_usec),
           &(f->tran_start.tv_sec),       /* The time when the previous       */
           &(f->tran_start.tv_usec),      /* transaction began                */
           &(resp_time.tv_sec),        /* The difference                   */
           &(resp_time.tv_usec));
/*
 * Work out the time apportionment
 */
        for (i = 0; i < 2; i++)
        {
            tvdiff(&(f->cs_tim[i].tv_sec),
               &(f->cs_tim[i].tv_usec),
               &(f->tran_cs_tim[i].tv_sec),
               &(f->tran_cs_tim[i].tv_usec),
               &(f->tran_cs_tim[i].tv_sec),
               &(f->tran_cs_tim[i].tv_usec));
            tvdiff(&(f->nt_tim[i].tv_sec),
               &(f->nt_tim[i].tv_usec),
               &(f->tran_nt_tim[i].tv_sec),
               &(f->tran_nt_tim[i].tv_usec),
               &(f->tran_nt_tim[i].tv_sec),
               &(f->tran_nt_tim[i].tv_usec));
        }
        head_print(f->ofp, f);
        fprintf(f->ofp, "RESPONSE|%s|%d.%06d|%d.%06d|%d|%d|%d|%d|%d.%06d|%d.%06d|%d.%06d|%d.%06d|",
                    "DM", f->tran_start.tv_sec, f->tran_start.tv_usec,
                    resp_time.tv_sec, resp_time.tv_usec,
                    f->cnt[!dir_flag] - f->tran_cnt[!dir_flag],
                    f->cnt[dir_flag] - f->tran_cnt[dir_flag],
                    f->len[!dir_flag] - f->tran_len[!dir_flag],
                    f->len[dir_flag] - f->tran_len[dir_flag],
                    f->tran_cs_tim[!dir_flag].tv_sec,
                    f->tran_cs_tim[!dir_flag].tv_usec,
                    f->tran_nt_tim[!dir_flag].tv_sec,
                    f->tran_nt_tim[!dir_flag].tv_usec,
                    f->tran_nt_tim[dir_flag].tv_sec,
                    f->tran_nt_tim[dir_flag].tv_usec,
                    f->tran_cs_tim[dir_flag].tv_sec,
                    f->tran_cs_tim[dir_flag].tv_usec);
        date_out(f->ofp, f->tran_start.tv_sec, f->tran_start.tv_usec);
/*
 * Now the Dialog Manager-specific elements
 */
        dp = ((struct dm_context *) (f->app_ptr));
        fprintf(f->ofp, "%s|%s|%s\n",
             dp->user_name,
             dp->program_name,
             dp->function_name);
#ifdef DEBUG
        fprintf(f->ofp, "RUNNING|%d.%06d|%d.%06d|%d.%06d|%d.%06d\n",
                    f->cs_tim[0].tv_sec,
                    f->cs_tim[0].tv_usec,
                    f->nt_tim[0].tv_sec,
                    f->nt_tim[0].tv_usec,
                    f->nt_tim[1].tv_sec,
                    f->nt_tim[1].tv_usec,
                    f->cs_tim[1].tv_sec,
                    f->cs_tim[1].tv_usec);
#endif
    }
    return;
}
/******************************************************************************
 * Process Dialog Manager messages
 * - If there is an incomplete lexical element at the top of the relevant stack,
 *   attempt to complete its read; if the read is still not complete, return
 * - Otherwise, get the first token
 * - Now process messages until the End of Message marker is seen, or we run
 *   out of message.
 * - If we are in an incomplete message, resume its processing.
 * - Otherwise, the processing is based on the token just read.
 */
static void do_dm(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct lex_tok * this_tok;
struct dm_context * dp;
unsigned char * ucp;
FILE * ofp;
int i;

    cur_frame = frp;
    ofp = frp->ofp;
    if (ofp == (FILE *) NULL)
        ofp = stderr;
/*
 * Dump out the input message
 */
    (void) gen_handle(ofp,frp->hold_buf[dir_flag],frp->top[dir_flag], 1);
    dp = ((struct dm_context *) (frp->app_ptr));
    ucp = frp->hold_buf[dir_flag];
/*
 * If we are starting from scratch, read the first token (that should be a
 * record type)
 */
    if ((this_tok = dp->call_stack[dir_flag].top) == (struct lex_tok *) NULL)
        this_tok = dm_get_tok(frp,dir_flag,&ucp);
/*
 * If we have an incomplete token on the top of the stack, read the rest of it.
 */
    else
    if (lex_table[this_tok->token].prod_response == NEUTRAL
     && lex_table[this_tok->token].parse_func != dm_resynch)
        this_tok = dm_rest(frp, dir_flag, &ucp);
    if (this_tok == (struct lex_tok *) NULL)
    {
        fputs("Failed to allocate token at all\n", ofp);
        return;
    }
/*
/*
 * Sanity check our input
 */
    if (dp->call_stack[dir_flag].top == (struct lex_tok *) NULL
     && lex_table[this_tok->token].prod_response == NEUTRAL)
    {
        fprintf(ofp,"Stray token or unknown record type %x %s direction %d\n",
                     this_tok->token,
             lex_table[this_tok->token].description, dir_flag); 
        return;
    }
/*
 * Loop - Process lexical tokens until the input is exhausted.
 */
    while (this_tok != (struct lex_tok *) NULL)
    {
/*
 * If we still have an incomplete token on the top of the stack, return
 */
        if (this_tok == dp->call_stack[dir_flag].top
         && lex_table[this_tok->token].prod_response == NEUTRAL)
        {
            if (ucp < frp->top[dir_flag])
            {
                fprintf(ofp,
     "%s:%d Logic Error: Incomplete token %x but have only read to %x not %x\n",
                   __FILE__, __LINE__,
                   this_tok->token, (long) ucp, (long) frp->top[dir_flag]);
            }
            return;
        }
/*
 * At this point, we have read a complete token. Now we must pick the
 * appropriate routine to call.
 *
 * Whilst our token is a record type, we push our token onto the stack, and read
 * another token.
 */
        while (this_tok != (struct lex_tok *) NULL
            && lex_table[this_tok->token].prod_response != NEUTRAL)
        {
            if (this_tok != dp->call_stack[dir_flag].top)
                dm_push(&(dp->call_stack[dir_flag]), this_tok);
            this_tok = dm_get_tok(frp, dir_flag, &ucp);
        }
/*
 * The top of the stack is now a record-type routine, and our token is an atomic
 * token; we call the record type associated with the top of the stack.
 */
       if (this_tok != (struct lex_tok *) NULL
         && lex_table[this_tok->token].prod_response == NEUTRAL
         && this_tok != dp->call_stack[dir_flag].top)
           this_tok =
                 (lex_table[dp->call_stack[dir_flag].top->token].parse_func)(
                                         frp, dir_flag, &ucp, this_tok);
/*
 * If the parse has completed with an End Of Record marker, look to match
 * the record with its mate, and pop both stacks. If we are at the top level,
 * then we output a response record.
 */
        if (this_tok != (struct lex_tok *) NULL && this_tok->token == 1)
        {
            free((char *) this_tok); 
            if (lex_table[dp->call_stack[dir_flag].top->token].prod_response
                            == RESPONSE)
            {
                if (dp->call_stack[!dir_flag].top == (struct lex_tok *) NULL)
                {
                    fprintf(ofp,
     "%s:%d Logic Error: RESPONSE %x:%s in direction %d but no PROD on stack\n",
                        __FILE__, __LINE__,
                          dp->call_stack[dir_flag].top->token,
                lex_table[dp->call_stack[dir_flag].top->token].description,
                        dir_flag); 
                    this_tok = dm_pop(&(dp->call_stack[dir_flag]));
                    free((char *) this_tok); 
                }
                else
                if ( lex_table[dp->call_stack[dir_flag].top->token].pair ==
                             dp->call_stack[!dir_flag].top->token)
                {
                    if (dp->call_stack[dir_flag].stack_depth == 1)
                        dm_output_response(frp, dir_flag);
                    for (i = 0; i < 2; i++)
                    {
                        this_tok = dm_pop(&(dp->call_stack[i]));
                        free((char *) this_tok); 
                    }
                }
            }
            this_tok = dm_get_tok(frp,dir_flag,&ucp);
        }
    }
    return;
}
/*
 * Discard dynamically allocated Dialog Manager session context
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
struct dm_context * rop = (struct dm_context *) frp->app_ptr;
struct lex_tok * lp, *lp1;
int i;

    if (rop != (struct dm_context *) NULL)
    {
        if (rop->handle_name != (HASH_CON *) NULL)
        {
            iterate(rop->handle_name,NULL,free);
            cleanup(rop->handle_name);
        }
        for (i = 0; i < 2; i++)
        {
            for (lp = rop->call_stack[i].top;
                     lp != (struct lex_tok *) NULL;
                          lp = lp1)
            {
                lp1 = lp->prev_tok;
                free((char *) lp);
            }
        }
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
 * Keep track of Dialog Manager sessions that are in the process of being
 * set up
 */
static int match_port[512];    /* List of ports to match against          */
static struct frame_con * prv_frame[100];
                             /* Corresponding frame control structures */

static int match_cnt;              /* Number of ports in the list    */
static void dm_match_add(frp, port)
struct frame_con *frp;
int port;
{
    if (match_cnt < sizeof(match_port)/sizeof(int))
    {
       match_port[match_cnt] = port;
       if (( prv_frame[match_cnt] = (struct frame_con *)
                               malloc(sizeof(struct frame_con))) !=
                               (struct frame_con *) NULL)
       {
           *(prv_frame[match_cnt]) = *frp;
           frp->ofp = stdout;              /* Stop the file being closed */
           frp->app_ptr = (char *) NULL;   /* Inhibit cleanup            */
           match_cnt++;
       }
    }
    return;
}
/*
 * Check whether the session matches an expected Dialog Manager session
 */
static struct frame_con * dm_match_true(from,to)
int from;
int to;
{
int i;
struct frame_con * ret_ptr;
#ifdef DEBUG
    printf("From port:%d To Port:%d\n",from,to);
#endif
    for (i = 0; i < match_cnt; i++)
    {
       if (match_port[i] == from || match_port[i] == to)
       {
           ret_ptr = prv_frame[i];
           match_port[i] = 0;          /* Mark the entry as free. There is no */
                                       /* such thing as a zero port number.   */
           if (i == (match_cnt - 1))
           {
/*
 * Reclaim the list entries if possible.
 */
               do
               {
                   match_cnt--;
                   i--;
               }
               while (i > -1 && match_port[i] == 0);
           }
           return ret_ptr;
       }
    }
    return (struct frame_con *) NULL;
}
/*
 * Decide whether or not we want this session
 */
int dm_app_recognise(frp)
struct frame_con * frp;
{
static int sess_seq;
char fname[28];
struct frame_con * prv_ptr;
int i;

    if (frp->prot == E2_TCP)
    {
    unsigned short int from, to;

        memcpy(&to, &(frp->port_to[1]), 2);
        memcpy(&from, &(frp->port_from[1]), 2);
        if (from == 512 || to == 512)
        {
            frp->do_mess = do_rexec_track;
            frp->cleanup = do_cleanup;
            if (from == 512)
                frp->reverse_sense = 1;
            frp->gap = 0;
            frp->tran_start = frp->this_time;
            sprintf(fname,"dm_%d",sess_seq++);
            if ((frp->ofp = fopen(fname,"wb")) == (FILE *) NULL)
                 frp->ofp = stdout;
            frp->app_ptr = (char *) calloc(sizeof(struct dm_context),1);
            return 1;
        }
        else
        if ((prv_ptr = dm_match_true(from, to)) != (struct frame_con *) NULL
#ifdef CONSISTENT
          && (( !hcntstrcmp(prv_ptr->net_from,frp->net_from)
              && !hcntstrcmp(prv_ptr->net_to,frp->net_to))
          || ( !hcntstrcmp(prv_ptr->net_from,frp->net_to)
              && !hcntstrcmp(prv_ptr->net_to,frp->net_from)))
#endif
           )
        {
            frp->app_ptr = prv_ptr->app_ptr;
            frp->ofp = prv_ptr->ofp;
            frp->tran_start = prv_ptr->tran_start;
            for (i = 0; i < 2; i++)
            {
                frp->tran_cnt[i] = 0;
                frp->tran_len[i] = 0;
                frp->tran_cs_tim[i].tv_sec = 0;
                frp->tran_nt_tim[i].tv_sec = 0;
                frp->tran_cs_tim[i].tv_usec = 0;
                frp->tran_nt_tim[i].tv_usec = 0;
                frp->len[i] += prv_ptr->len[!i];
                frp->cnt[i] += prv_ptr->cnt[!i];
                tvadd(&(frp->cs_tim[i].tv_sec),
                    &(frp->cs_tim[i].tv_usec),
                    &(prv_ptr->cs_tim[!i].tv_sec),
                    &(prv_ptr->cs_tim[!i].tv_usec),
                    &(frp->cs_tim[i].tv_sec),
                    &(frp->cs_tim[i].tv_usec));
                tvadd(&(frp->nt_tim[i].tv_sec),
                    &(frp->nt_tim[i].tv_usec),
                    &(prv_ptr->nt_tim[!i].tv_sec),
                    &(prv_ptr->nt_tim[!i].tv_usec),
                    &(frp->nt_tim[i].tv_sec),
                    &(frp->nt_tim[i].tv_usec));
            }
            ((struct dm_context *) (frp->app_ptr))->handle_name =
                        hash(256, long_hh, icomp);
            frp->do_mess = do_dm;
            frp->cleanup = do_cleanup;
            free((char *) prv_ptr);
            return 1;
        }
    }
    return 0;
}
/*****************************************************************************
 * Process a Dialog Manager session startup remote execution.
 */
static void do_rexec_track(frp, dir_flag)
struct frame_con * frp;
int dir_flag;
{
struct timeval el_diff;
unsigned char *p, *p1;
unsigned short int to;
struct dm_context * dp = ((struct dm_context *) (frp->app_ptr));
static struct bm_table * bp;
FILE * ofp;

    cur_frame = frp;
    ofp = frp->ofp;
    if (ofp == (FILE *) NULL)
        ofp = stderr;
/*
 * Dump out the input message
 */
    (void) gen_handle(ofp,frp->hold_buf[dir_flag],frp->top[dir_flag], 1);

    if (bp == (struct bm_table *) NULL)
        bp = bm_compile("-IDMconnect ");

    if (((!dir_flag) ^ frp->reverse_sense) /* User Input */
      && dp != (struct dm_context *) NULL
      && dp->user_name[0] == '\0')
    {
/*
 * Use the string match to signal that the input line is valid
 */
        if ((p1 = bm_match(bp,frp->hold_buf[dir_flag] + 11, frp->top[dir_flag]))
              != (unsigned char *) NULL)
        {
            p = frp->hold_buf[dir_flag];
            if (*p == '\0')
                p++;
            strcpy(dp->user_name, p);  /* UNIX User     */
            p += strlen(p) + 1;
            strcpy(dp->password, p);                         /* UNIX Password */
/*
 * We need to pass the program name from the calling session if there is one
 * We are not bothering with the database at the moment, but we easily could.
 */
            strcpy(dp->function_name, "Launch");             /* Description   */
            for (p = frp->top[dir_flag]  - 3; *p != ' '; p--);
            memcpy(dp->program_name,p + 1, (frp->top[dir_flag] - p));
            dp->program_name[(frp->top[dir_flag] - p)] = '\0'; /* Program name*/
            if ((p = strchr(p1 + 15, ':')) != (unsigned char *) NULL)
                dm_match_add(frp, atoi(p+1));                /* PC DM Port    */
        }
    }
    return;
}

/*
 * Scan captured network packets and generate an input file for the E2 Systems
 * packet driver.
 */
static char * sccs_id="@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems 1996";

#include <sys/types.h>
#ifndef VCC2003
#include <sys/time.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "e2conv.h"
#include "e2net.h"
#include "hashlib.h"
static void do_traf();
#ifdef SOLAR
#define E2INET_NEED
#endif
#ifdef LINUX
#define E2INET_NEED
#endif
#ifdef E2INET_NEED
char * e2inet_ntoa(l)
long l;
{
union {
unsigned long l;
struct in_addr i;
} test;

    test.l = l;
    return inet_ntoa(test.i);
}
#else
#ifndef inet_ntoa
#define e2inet_ntoa inet_ntoa
#endif
#endif
static void do_assimilate();
extern HASH_CON * get_open_sess();
/*
 * This code handles multiple parallel sessions.
 *
 * Each new session, we need to allocate new End Points for each end, if
 * they do not exist.
 *
 * We also need to allocate actors.
 *
 * For connection and peers, we might only need one actor per participating
 * host. What we should do depends in detail on the degree of asynchronicity
 * in each host. The maximum asynchronicity comes about if we allocate one
 * actor per end point; we must manually adjust this in the light of what
 * we know about the application.
 *
 * We need one actor per host/listen session. This will give us a problem when
 * a single transaction involves multiple connexions to the same listen socket,
 * because the listener will not be able to tell which actor it is. Therefore,
 * we allocate fresh socket numbers for each. By outputting duplicate EP
 * records, we do not lose the original meaning.
 *
 * Actors need to have a last time stamp associated with them. We output a
 * delay if the time since the last receive, plus accumulated small gaps,
 * exceeds one second. We need to think carefully about this when we come
 * to reduce the numbers of actors, for example with a three tier
 * architecture.
 *
 * The standard routine for putting timing events in session files will not
 * work, for three reasons.
 * - We are using a different format for the time stamps
 * - We only have a single output file
 * - Do we want to compare the timings from the points of view of different
 *   actors?
 *
 * Sample output.
 *
DT|0|.5
EP|0|0|2|localhost|tcp|C|10000
EP|0|1|2|localhost|udp|P|10001
EP|1|2|2|localhost|tcp|L|10002
EP|1|3|2|localhost|tcp|C|10003
EP|2|4|2|localhost|tcp|L|10004
EP|3|5|2|localhost|udp|P|10005
ST|0|A1|First Test Time
SR|0|2|64
DT|1|5.5
SR|3|4|64
DT|3|6.5
SR|4|3|64
SR|2|0|64
SR|1|5|64
SR|5|1|64
TT|0|A1
 *
 * Structure allocated when a session is started, that holds session state.
 */
static struct trafext_base {
    int next_act_end;            /* Allocation of end points and actors    */
    int next_port_id;            /* Allocation of port ID's                */
    struct timeval base_time;    /* Used to help co-ordinate sessions      */
    long user_host;              /* Host that the real user is using       */
    long app_server;             /* Middle tier host                       */
    long last_host;              /* Host that could kick off a new session */
    long sync_host;              /* Host that could kick off a new session */
    HASH_CON * port_xlat;        /* Mapping for listen ports               */
    int provisional_flag;        /* Provisionally captured details exist   */
    struct tf_con * tf_anchor;   /* Closed provisional files               */ 
    unsigned short listener_port;/* To help track elusive ORACLE sessions  */
    unsigned short forms_port;
    unsigned int forms_list_flag;
    unsigned int server_heuristics;
    struct timeval last_user_time;
    int user_seen;
} trafext_base;
/*
 * Linked list of files that need to be deleted
 */
struct tf_con {
    struct tf_con * next;
    char nm[1];
};
void tf_note(n)
char *n;
{
int l;
struct tf_con * tp;

    if (n != (char *) NULL)
    {
        l = strlen(n);
        if ((tp = (struct tf_con *) malloc(sizeof(struct tf_con) + l))
            != (struct tf_con *) NULL)
        {
            tp->next = trafext_base.tf_anchor;
            strcpy(&(tp->nm[0]), n);
            trafext_base.tf_anchor = tp;
        }
    }
    return;
}
void tf_zap()
{
struct tf_con * tp;

    while (trafext_base.tf_anchor != (struct tf_con *) NULL)
    {
        tp = trafext_base.tf_anchor;
        trafext_base.tf_anchor = tp->next;
        unlink(tp->nm);
        free((char *) tp);
    }
    return;
}
void tf_clone()
{
FILE *fp;
struct tf_con * tp;
char buf[256];

    for (tp = trafext_base.tf_anchor;
             tp != (struct tf_con *) NULL;
                 tp = tp->next)
    {
        trafext_base.tf_anchor = tp->next;
        if ((fp = fopen(tp->nm, "rb")) != (FILE *) NULL)
        {
            while(fgets(buf, sizeof(buf), fp) != (char *) NULL)
                 fputs(buf, stdout);
            fclose(fp);
        }
    }
    return;
}
/*****************************************************************************
 * Handling of multiple listen port connections
 */
struct list_map {
    unsigned int real_host;
    unsigned int real_port;
    unsigned int mapped_port; 
    unsigned int mapped_end_id; 
    int mapped_act_id;
};
/*
 * Listen port hash function
 */
static unsigned hash_func(x, modulo)
unsigned char * x;
int modulo;
{
    return ((unsigned long int) ((((struct list_map *) x)->real_host) ^
            (((struct list_map *) x)->real_port)) & (modulo-1));
}
/*
 * Listen port hash comparison function
 */
static int comp_func(x1, x2)
unsigned char * x1;
unsigned char * x2;
{
    if ( (((struct list_map *) x1)->real_port
           == ((struct list_map *) x2)->real_port)
      && (((struct list_map *) x1)->real_host
           == ((struct list_map *) x2)->real_host))
        return 0;
    else
    if (((struct list_map *) x1)->real_host
                 < ((struct list_map *) x2)->real_host)
        return -1;
    else
    if (((struct list_map *) x1)->real_host
                 > ((struct list_map *) x2)->real_host)
        return 1;
    else
    if (((struct list_map *) x1)->real_port
                 < ((struct list_map *) x2)->real_port)
        return -1;
    else
        return 1;
}
/*
 * Initialise a listen map structure
 */
static struct list_map * new_list_map(real_host, real_port, mapped_port,
                                      mapped_act_id, mapped_end_id)
unsigned long real_host;
unsigned int real_port;
unsigned int mapped_port;
unsigned int mapped_act_id;
unsigned int mapped_end_id;
{
struct list_map * x;

    if ((x = (struct list_map *) malloc( sizeof(struct list_map)))
          == (struct list_map *) NULL)
        return x;
    x->real_host = real_host;
    x->real_port = real_port;
    x->mapped_port = mapped_port;
    x->mapped_act_id = mapped_act_id;
    x->mapped_end_id = mapped_end_id;
    insert(trafext_base.port_xlat, (char *) x, (char *) x);
    return x;
} 
/*
 * Find a list map structure, if possible
 */
static struct list_map * find_list_map(real_host, real_port)
unsigned long real_host;
unsigned int real_port;
{
struct list_map x;
HIPT *h;

    x.real_host = real_host;
    x.real_port = real_port;
    if ((h = lookup(trafext_base.port_xlat, (char *) &x)) != (HIPT *) NULL)
        return (struct list_map *) (h->body);
    else
        return (struct list_map *) NULL;
} 
/******************************************************************************
 * Per-session data
 */
struct traf_sess {
int act_id_from;
int act_id_to;
int end_id_from;
int end_id_to;
unsigned short int from_port;
int as_of_right;
int provisional;
int activated;
int found_cnt;
struct timeval last_recv;         /* Last receive                             */
struct timeval delay;             /* Unallocated delay                        */
};
/*
 * Discard dynamically allocated session structures
 */
static void do_cleanup(frp)
struct frame_con *frp;
{
int i;
register struct traf_sess * rop = (struct traf_sess *) frp->app_ptr;
/*
 * Write out a session close record.
 */
    fprintf(frp->ofp, "SC|%u|%u\n",
            ((struct traf_sess *) frp->app_ptr)->end_id_from,
            ((struct traf_sess *) frp->app_ptr)->end_id_to);
    if (!memcmp((char  *) &(trafext_base.user_host), &(frp->net_from[1]),
           sizeof(struct in_addr))
     || !memcmp((char  *) &(trafext_base.user_host), &(frp->net_to[1]),
           sizeof(struct in_addr)))
    {
        trafext_base.last_host = 0;
        trafext_base.sync_host = 0;
    }
/*
 * We will take this; it is fully enclosed in one of our band requests
 */
    if (frp->ofp != stdout && frp->ofp != stderr)
    {
        do_assimilate(frp);
        frp->ofp = (FILE *) NULL;
    }
    if (rop != (struct traf_sess *) NULL)
    {
        free((char *) rop);
        frp->app_ptr = NULL;
    }
    return;
}
/*
 * Discard speculatively collected session details
 */
static void do_discard(frp)
struct frame_con *frp;
{
struct traf_sess * rop = (struct traf_sess *) frp->app_ptr;
char fname[20];

    if (frp->ofp != stdout
      && frp->ofp != stderr
      && rop != (struct traf_sess *) NULL)
    {
        fclose(frp->ofp);
        sprintf(fname,"tmp%u", rop->end_id_from);
        unlink(fname);
    }
    if (rop != (struct traf_sess *) NULL)
        free((char *) rop);
    frp->do_mess = NULL;
    frp->app_ptr = NULL;
    frp->cleanup = NULL;
    frp->ofp = stderr;
    return;
}
/*
 * Collect speculatively collected session details
 */
static void do_assimilate(frp)
struct frame_con *frp;
{
struct traf_sess * rop = (struct traf_sess *) frp->app_ptr;
char buf[256];

    if (frp->ofp != stdout
      && frp->ofp != stderr
      && rop != (struct traf_sess *) NULL)
    {
        fseek(frp->ofp, 0, 0);
        while(fgets(buf, sizeof(buf), frp->ofp) != (char *) NULL)
            fputs(buf, stdout);
        sprintf(buf,"tmp%u", rop->end_id_from);
        fclose(frp->ofp);
        unlink(buf);
        frp->ofp = stdout;
        rop->as_of_right = 1;
        rop->provisional = 0;
    }
    return;
}
/*
 * Doubt speculatively collected session details. Save the session details,
 * but not the data.
 */
static void do_doubt(frp)
struct frame_con *frp;
{
struct traf_sess * rop = (struct traf_sess *) frp->app_ptr;
char buf[256];
int i;

    if (frp->ofp != stdout
      && frp->ofp != stderr
      && rop != (struct traf_sess *) NULL)
    {
        fseek(frp->ofp, 0, 0);
        for (i = 4;
                 i && fgets(buf, sizeof(buf), frp->ofp) != (char *) NULL;
                     i--)
            fputs(buf, stdout);
        fclose(frp->ofp);
        sprintf(buf,"tmp%u", rop->end_id_from);
        unlink(buf);
        frp->ofp = stdout;
    }
    if ( rop != (struct traf_sess *) NULL && rop->provisional)
    {
        rop->as_of_right = 0;
        rop->provisional = 0;
    }
    return;
}
/*
 * Mark pooled connections as active.
 */
static void do_activate(frp)
struct frame_con *frp;
{
struct traf_sess * rop = (struct traf_sess *) frp->app_ptr;
char fname[20];

    if (frp->do_mess == do_traf
     && rop != (struct traf_sess *) NULL
     && !rop->as_of_right)
        rop->activated = 1;
    return;
}
/*
 * Mark pooled connections as in-active.
 */
static void do_deactivate(frp)
struct frame_con *frp;
{
struct traf_sess * rop = (struct traf_sess *) frp->app_ptr;
char fname[20];

    if (frp->do_mess == do_traf
     && rop != (struct traf_sess *) NULL
     && !rop->as_of_right)
        rop->activated = 0;
    return;
}
/*****************************************************************************
 * Generate Traffic Output.
 *
 * We have to generate:
 * - A delay if one is applicable
 * - A send/receive message
 */
static void do_traf(f, dir_flag)
struct frame_con * f;
int dir_flag;
{
struct timeval el_diff;
int i;
unsigned char * p1;
int app_dir;
unsigned short int from, to;
struct traf_sess * rop = (struct traf_sess *) f->app_ptr;
/*
 * Provisional items exist that must be dealt with
 * If the message is going to our user host, we want them.
 */
    if ( !memcmp((char  *) &(trafext_base.user_host),
            (dir_flag)?&(f->net_to[1]):&(f->net_from[1]),
            sizeof(struct in_addr)))
        trafext_base.last_user_time = f->this_time;
    if (trafext_base.provisional_flag == 1
      && (!memcmp((char  *) &(trafext_base.user_host),
            &(f->net_from[1]), sizeof(struct in_addr))
      || !memcmp((char  *) &(trafext_base.user_host),
            &(f->net_to[1]), sizeof(struct in_addr))))
    {
        trafext_base.provisional_flag = 0;
        if (!memcmp((char  *) &(trafext_base.user_host),
            (dir_flag)?&(f->net_from[1]):&(f->net_to[1]),
                          sizeof(struct in_addr))
            || trafext_base.forms_list_flag)
        {
            iterate(get_open_sess(), NULL, do_assimilate);
            trafext_base.forms_list_flag = 0;
        }
        else
            iterate(get_open_sess(), NULL, do_doubt);
    }
    else
    if (!rop->as_of_right)
    {
        tvdiff(&(f->this_time.tv_sec),
           &(f->this_time.tv_usec),
           &(trafext_base.last_user_time.tv_sec),
           &(trafext_base.last_user_time.tv_usec),
           &(el_diff.tv_sec),
           &(el_diff.tv_usec));
        if (el_diff.tv_sec > 0)
        {
            do_discard(f);
            return;
        }
        else
        if (!rop->activated && !rop->provisional)
            return;
    }
    tvdiff(&(f->this_time.tv_sec),
           &(f->this_time.tv_usec),
           &(rop->last_recv.tv_sec),
           &(rop->last_recv.tv_usec),
           &(el_diff.tv_sec),
           &(el_diff.tv_usec));
    tvadd( &(rop->delay.tv_sec),
           &(rop->delay.tv_usec),
           &(el_diff.tv_sec),
           &(el_diff.tv_usec),
           &(rop->delay.tv_sec),
           &(rop->delay.tv_usec));
    if ( (rop->delay.tv_sec) > 1)
    {
        fprintf(f->ofp, "DT|%d|%u.%06u\n",
            ((dir_flag)?(rop->act_id_to):
            (rop->act_id_from)),
            (rop->delay.tv_sec),
            (rop->delay.tv_usec));
        if ((rop->delay.tv_usec < 0)
         || (rop->delay.tv_usec) >= 1000000)
        {
            fprintf(f->ofp,
    "Logic Error: this_time %d %d last_recv %d %d el_diff %d %d delay %d %d\n",
                     f->this_time.tv_sec,
                     f->this_time.tv_usec,
                    rop->last_recv.tv_sec,
                    rop->last_recv.tv_usec,
                    el_diff.tv_sec,
                    el_diff.tv_usec,
                    rop->delay.tv_sec,
                    rop->delay.tv_usec);
        }
        rop->delay.tv_sec = 0;
        rop->delay.tv_usec = 0;
    }
    rop->last_recv = f->this_time;
/*
 * Now output the actual message command itself
 */
    fprintf(f->ofp, "SR|%u|%u|%u\n",
            (dir_flag)?(rop->end_id_to) :(rop->end_id_from),
            (dir_flag)?(rop->end_id_from) :(rop->end_id_to),
            f->pack_len - sizeof(struct ether_header) - sizeof(struct ip) -
             ((f->prot == E2_TCP) ?
                   sizeof(struct tcphdr) :
                   sizeof(struct udphdr)));
/*
 * Update the saved host details
 */
    if (!memcmp((char  *) &(trafext_base.user_host), 
            (dir_flag)?&(f->net_to[1]):&(f->net_from[1]),
                   sizeof(struct in_addr)))
    {
         memcpy((char  *) &(trafext_base.sync_host),
            (dir_flag)?&(f->net_from[1]):&(f->net_to[1]),
           sizeof(struct in_addr));
         memcpy((char  *) &(trafext_base.last_host),
            (dir_flag)?&(f->net_from[1]):&(f->net_to[1]),
           sizeof(struct in_addr));
         iterate(get_open_sess(), NULL, do_activate);
    }
    else
    if (!memcmp((char  *) &(trafext_base.user_host),
            (dir_flag)?&(f->net_from[1]):&(f->net_to[1]),
           sizeof(struct in_addr)))
    {
         trafext_base.sync_host = 0;
         trafext_base.last_host = 0;
    }
    else
    {
         memcpy((char  *) &(trafext_base.last_host), &(f->net_to[1]),
           sizeof(struct in_addr));
    }
    return;
}
/*
 * Set up to generate the actor script elements for this session
 */
int traf_app_recognise(frp)
struct frame_con * frp;
{
struct timeval el_diff;
struct list_map * lmp;
unsigned long to_host;
unsigned long to_port;
struct traf_sess * rop;
int as_of_right;

    if ( trafext_base.next_port_id == 0)
    {
    char *x;

        trafext_base.port_xlat = hash(2048, hash_func, comp_func);
        if ((x = getenv("E2_BASE_PORT")) != (char *) NULL)
        {
            trafext_base.next_port_id = atoi(x);
            if (trafext_base.next_port_id < 1
             || trafext_base.next_port_id > 65535)
            trafext_base.next_port_id = 10000;
        }
        else
            trafext_base.next_port_id = 10000;
        trafext_base.next_act_end = 1;
        trafext_base.base_time = frp->this_time;
        if ((x = getenv("E2_USER_HOST")) != (char *) NULL)
            trafext_base.user_host = inet_addr(x);
        if ((x = getenv("E2_APP_SERVER")) != (char *) NULL)
            trafext_base.app_server = inet_addr(x);
        if (getenv("E2_HEURISTICS") != (char *) NULL)
            trafext_base.server_heuristics = 1;
        else
            trafext_base.server_heuristics = 0;
        if ((x = getenv("E2_TNS_PORTS")) != (char *) NULL)
            trafext_base.listener_port = atoi(x);
        else
            trafext_base.listener_port = 1521;
        if ((x = getenv("E2_FORMS_PORT")) != (char *) NULL)
            trafext_base.forms_port = atoi(x);
        else
            trafext_base.forms_port = 80;
    }
/*
 * If this packet goes to or from the user host, or it originates on the last
 * host to receive a packet, or it originates on the last host that received
 * a packet from the user host, or it is database traffic, we are
 * (potentially) interested.
 */
#ifdef CONSERVATIVE
    if ((frp->prot == E2_TCP || frp->prot == E2_UDP)
      && (!trafext_base.server_heuristics
      || (!memcmp((char  *) &(trafext_base.user_host), &(frp->net_from[1]),
           sizeof(struct in_addr))
      || !memcmp((char  *) &(trafext_base.user_host), &(frp->net_to[1]),
           sizeof(struct in_addr))
      || !memcmp((char  *) &(trafext_base.sync_host), &(frp->net_from[1]),
           sizeof(struct in_addr))
      || (!memcmp((char  *) &(trafext_base.last_host), &(frp->net_from[1]),
           sizeof(struct in_addr)) && trafext_base.sync_host != 0)
      || (trafext_base.sync_host == 0 && trafext_base.last_host == 0
        && trafext_base.user_seen
       && !memcmp((char  *) &(trafext_base.listener_port),
                    &(frp->port_to[1]), 2)
         && (trafext_base.app_server == 0
          || !memcmp((char  *) &(trafext_base.app_server), &(frp->net_from[1]),
                    sizeof(struct in_addr)))))))
#endif
        as_of_right = 1;                /* Pretty definitely one of ours */
#ifdef CONSERVATIVE
    else
    if ( trafext_base.user_seen 
      && !memcmp((char  *) &(trafext_base.listener_port),
            &(frp->port_to[1]), 2))
        as_of_right = -1;               /* Perhaps it is pooled          */
    else
        as_of_right = 0;                /* Not interesting               */
#endif
    if (as_of_right)
    {
    struct in_addr x;
    unsigned short int port;
/*
 * Set the user seen flag if appropriate
 */
        if (!trafext_base.user_seen
          && (!memcmp((char  *) &(trafext_base.user_host), &(frp->net_from[1]),
                 sizeof(struct in_addr))
          || !memcmp((char  *) &(trafext_base.user_host), &(frp->net_to[1]),
           sizeof(struct in_addr))))
            trafext_base.user_seen = 1;
/*
 * Indicate the functions to be used
 */
        frp->do_mess = do_traf;
        frp->cleanup = do_cleanup;
        frp->gap = 0;
/*
 * Allocate the traffic-generator-specific data
 */
        frp->app_ptr = (char *) calloc(sizeof(struct traf_sess),1);
        rop = (struct traf_sess *) (frp->app_ptr);
/*
 * Assign actor/end point ID's for each end. The rules are:
 * -  If the originator is the user host, it is given actor_id 0.
 * -  The originator is always given a new port id
 * -  If we haven't seen the listen port before, create a new listen port
 *    entry. Otherwise, take the details from the existing one.
 */
        if (!memcmp((char  *) &(trafext_base.user_host), &(frp->net_from[1]),
            sizeof(struct in_addr)))
        {
            if (!memcmp((char  *) &(trafext_base.forms_port),
                         &(frp->port_to[1]), 2))
                trafext_base.forms_list_flag = 1;
            else
                trafext_base.forms_list_flag = 0;
            rop->act_id_from = 0;
        }
        else
        {
            rop->act_id_from = trafext_base.next_act_end;
            trafext_base.forms_list_flag = 0;
        }
        rop->end_id_from = trafext_base.next_act_end;
        trafext_base.next_act_end++;
        rop->from_port = trafext_base.next_port_id;
        trafext_base.next_port_id++;
/*
 * Now deal with the To elements
 */
        memcpy((char *) &port, &(frp->port_to[1]), 2);
        memcpy((char *) &to_host,  &(frp->net_to[1]), sizeof(struct in_addr));
        to_port = (unsigned long) port;
        memcpy(&port, &(frp->port_from[1]), 2);
/*
 * Is this is a new listen port?
 */
        if ((lmp = find_list_map(to_host, to_port)) == (struct list_map *) NULL)
        {
            lmp = new_list_map(to_host, to_port,
                  trafext_base.next_port_id,
                  trafext_base.next_act_end,
                  trafext_base.next_act_end);
            rop->act_id_to = trafext_base.next_act_end;
            rop->end_id_to = trafext_base.next_act_end;
            trafext_base.next_port_id++;
            trafext_base.next_act_end++;
        }
        else
        {
            rop->act_id_to = lmp->mapped_act_id;
            rop->end_id_to = lmp->mapped_end_id;
        }
        if (!memcmp((char  *) &(trafext_base.listener_port),
            &(frp->port_to[1]), 2))
        {
        unsigned short known_check;

            memcpy((char  *) &(known_check), &(frp->port_from[1]), 2);
            if (known_check == 63585
             || known_check == 63981
             || known_check == 64812
             || known_check == 34536)
            {
                frp->ofp = stdout;
                rop->as_of_right = 1;
                rop->activated = 1;
                goto bot;
            }
        }
#ifdef CONSERVATIVE
        if ((trafext_base.sync_host == 0
         && trafext_base.last_host == 0
         && !memcmp((char  *) &(trafext_base.listener_port),
                    &(frp->port_to[1]), 2)
         && (trafext_base.app_server == 0
          || !memcmp((char  *) &(trafext_base.app_server), &(frp->net_from[1]),
                    sizeof(struct in_addr)))
         && memcmp((char  *) &(trafext_base.user_host), &(frp->net_from[1]),
                    sizeof(struct in_addr))
         && memcmp((char  *) &(trafext_base.user_host), &(frp->net_to[1]),
                    sizeof(struct in_addr)))
          || ((as_of_right == -1) && !trafext_base.forms_list_flag))
        {
/*
 * We do not know yet whether or not this session is required. We have to
 * wait and see.
 */
         char fname[20];

            sprintf(fname, "tmp%u", rop->end_id_from);
            frp->ofp = fopen(fname, "wb+");
            trafext_base.provisional_flag = 1;
            rop->provisional = 1;
            rop->as_of_right = 0;
            rop->activated = 0;
        }
        else
#endif
        {
            frp->ofp = stdout;
            rop->as_of_right = 1;
            rop->activated = 1;
        }
bot:
/*
 * Output the From End point details; twice, once with the original details,
 * the second time with our new allocated details
 */
        memcpy((char  *) &x, &(frp->net_from[1]), sizeof(struct in_addr));
        fprintf(frp->ofp, "#EP|%d|%d|2|%s|%s|%c|%u\n",
            rop->act_id_from,
            rop->end_id_from,
               inet_ntoa(x),
             (frp->prot == E2_TCP) ? "tcp" : "udp",
             (frp->prot == E2_TCP) ? 'C' : 'P',
             port);
        fprintf(frp->ofp, "EP|%d|%d|2|%s|%s|%c|%u\n",
            rop->act_id_from,
            rop->end_id_from,
               inet_ntoa(x),
             (frp->prot == E2_TCP) ? "tcp" : "udp",
             (frp->prot == E2_TCP) ? 'C' : 'P',
             rop->from_port);
/*
 * Likewise the To End Point details.
 */
        fprintf(frp->ofp, "#EP|%d|%d|2|%s|%s|%c|%u\n",
            rop->act_id_to,
            rop->end_id_to,
               e2inet_ntoa(to_host),
             (frp->prot == E2_TCP) ? "tcp" : "udp",
             (frp->prot == E2_TCP) ? 'L' : 'P',
             to_port);
        fprintf(frp->ofp, "EP|%d|%d|2|%s|%s|%c|%u\n",
            rop->act_id_to,
            rop->end_id_to,
               e2inet_ntoa(to_host),
             (frp->prot == E2_TCP) ? "tcp" : "udp",
             (frp->prot == E2_TCP) ? 'L' : 'P', lmp->mapped_port);
#ifdef TRACK_START_TIMES
/*
 * Log how long it is since the beginning of the capture, if it is more than
 * one second. Otherwise, remember it.
 */
        tvdiff(&(frp->this_time.tv_sec),  /* The time when this message began */
               &(frp->this_time.tv_usec),
               &(trafext_base.base_time.tv_sec),
               &(trafext_base.base_time.tv_usec),
               &(el_diff.tv_sec),
               &(el_diff.tv_usec));
        if (el_diff.tv_sec > 1)
            fprintf(frp->ofp, "DT|%d|%u.%06u\n",
                rop->act_id_from,
               (el_diff.tv_sec),
               (el_diff.tv_usec));
        else
            rop->delay = el_diff;
#else
        rop->delay.tv_sec = 0;
        rop->delay.tv_usec = 0;
#endif
        rop->last_recv = frp->this_time;
        return 1;
    }
    else
        frp->ofp = stderr;
    return 0;
}

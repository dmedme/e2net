/*
 * trafanal.c - Glaxo MDIS Traffic simulations.
 *
 * Inputs:
 * 1.  'Network Impulses'. A timed event (eg. login) which is
 *     characterised by:
 *     -  A number of communication links involved.
 *     -  For each link
 *        -  The number of bytes (which consume bandwidth)
 *        -  The number of packets (which 'consume' 'latency')
 * 2.  Scripts; sequences of operations that are carried out in order,
 *     and which constitute the actions performed by a single user
 *     to achieve some end. A list of Network Impulses and Think Times.
 * 3.  Scenarios; numbers of users of each script. The users are spread
 *     evenly along the script (ie. Stagger = (sum of Think times)/Users),
 *     but in a Monte Carlo Simulation we might use rand48() or similar
 *     to get value from extending a run.
 * 4.  Links, characterised by:
 *     -  The bandwidth; the rate at which packets are delivered
 *     -  The latency; time spent by a packet in the link.
 *
 * We have for the scripts files derived by ipdanal.c which indicate:
 *     -  Second by second, the number of packets in that second 
 *     -  Timing Points; places where the response to be calculated
 *        is bracketed.
 *
 * The files we have do not have the correct descriptions, although
 * these can be added fairly easily.
 *
 * We want to derive from it a sum for each bracket. Make this a new
 * option of ipdanal. 
 *
 * For the scenarios, we have runout files.
 *
 * We have not defined a file with the link profile information.
 *
 * Outputs:
 * 1.  A second by second indication of the amount of bandwidth
 *     being consumed.
 * 2.  A series of 'Transaction Times'. If they were in the normal event
 *     format, we could use fdreport to process the results.
 *
 * Algorithm Features Needed:
 * This looks like a case for C++, because we want things like the Impulses
 * to write out their response times independently of the way that the
 * Network Links report their utilisation. This will not be anything like
 * as efficient as array manipulations, but it is much more flexible and
 * extensible.  
 * 1.  The arrow of time, goes on second by second.
 * 2.  Each Link invites each of the Bundles to 'Submit Bids'.
 * 3.  Each Bundle asks each of its Users to Submit a Bid.
 * 4.  The User down-dates its Think Time. If this goes to zero, and there
 *     is no Current Impulse, the Next Impulse becomes Current Impulse.
 *     This step is circular.
 * 5.  If the User has a Current Impulse, the Impulse is invited to Submit
 *     a Bid for each Link. For this simulation, we insist that the Bid
 *     cannot exceed the Link Capacity. In fact, it cannot exceed the capacity
 *     of the narrowest Link that the Impulse encompasses.
 * 6.  Each Link sums its Bids, and works out a Ration. This Ration is then
 *     given to the Bidders.
 * 7.  It is possible that a Ration will cause a Bidder to have to reduce
 *     its Bid for another Link. If we had a scenario where 1 hop traffic
 *     and multi-hop traffic shared the same Link, more might be available
 *     for other Users. Might there be difficulty is ensuring convergence,
 *     if those putting back may be the beneficiaries of others' gifts?
 * 8.  When a ration allows a Bid to be fully satisfied, and the Impulse
 *     is exhausted, the Impulse time is logged, and the Bid and Impulse
 *     are removed. The User's Next Impulse must advance.
 * 9.  Each Link logs the traffic it has carried that second.
 *
 * We appear to have the following objects.
 * -  Links
 * -  Bundles
 * -  Users
 * -  Scripts
 * -  Impulses
 * -  Bids
 */
#include <stdio.h>
#include <stdlib.h>

static double app[300], oapp[300], db[300], odb[300];
/*
 * This function reads a file derived from the output from ipdanal.c,
 * which itself processes message by message script files in order
 * to break them up into characters per second per link.
 * It initialises the data structures used to work out conversation
 * duration.
 */
int gettraf(fname,outarr1, outarr2, users,curuser,dbuser,
            curleft,dbleft,lastz,orig, stagger, cur_stagger)
char * fname;
double * outarr1;
double * outarr2;
int users;
double ** curuser;
double ** dbuser;
double * curleft;
double * dbleft;
int *lastz;
int *orig;
int stagger;
int cur_stagger;
{
    FILE * f;
    int i;
    int lcnt = 0;
    char buf[132];
    double rd[8];
    double *savoutarr1 = outarr1;
    double *savoutarr2 = outarr2;
    if ((f = fopen(fname,"r")) != (FILE *) NULL)
    {
        while(fgets(buf,sizeof(buf),f) > (char *) NULL)
       {
           int nf = sscanf(buf,"%lf %lf %lf %lf %lf %lf %lf %lf",
               &rd[0], &rd[1], &rd[2], &rd[3], &rd[4], &rd[5], &rd[6], &rd[7]);
           if (nf < 4)
           {
               fprintf(stderr,"Failed to scan %s:\n%sSaw %d fields\n",
                       fname,buf,nf);
               continue;
           }
#ifdef DEBUG
           else
           {
               fprintf(stderr,
            "Scanned %s:\n%sSaw %d fields\n%f %f %f %f %f %f %f %f",
                       fname,buf,nf,
               rd[0], rd[1], rd[2], rd[3], rd[4], rd[5], rd[6], rd[7]);
           }
#endif
           *outarr1++ = (rd[1] + rd[3]);
           if (nf > 4)
               *outarr2++ = (rd[5] + rd[7]);
           else
               *outarr2++ = (double) 0.0;
           lcnt++;
       }
       fclose(f);
    }
    else
    {
        perror("fopen() failed");
        fprintf(stderr,"...Filename %s\n",fname);
    }
    outarr1 = savoutarr1 + cur_stagger;
    outarr2 = savoutarr2 + cur_stagger;
    for (i = 0; i < users; i++)
    {
         *curuser++ = outarr1;
         *dbuser++ = outarr2;
         *curleft++ = *outarr1;
         *dbleft++ = *outarr2;
         *lastz++ = -1;
         *orig++ = 0;
         outarr1 -= stagger;
         outarr2 -= stagger;
         if (outarr1 < savoutarr1)
         {
             outarr1 += lcnt;
             outarr2 += lcnt;
         }
     }
    return lcnt;
}
/*
 * This function examines the state of each users conversation after the
 * bandwidth has been apportioned to the sessions. It looks for
 * conversations that have just started, and conversations that have
 * just completed; the latter it logs.
 */   
void adjust_secs(users, curuser, dbuser, curleft, dbleft, lastz, wall, orig,
abase,atop,dbase,dtop,    timf)
int users;
double ** curuser;
double ** dbuser;
double   *curleft;
double  *dbleft;
int *lastz;
int wall;
int *orig;
double *abase;
double *atop;
double *dbase;
double *dtop;
FILE * timf;
{
int j;
    for (j = 0;
             j < users;
                 j++,curleft++,dbleft++,lastz++,wall++,orig++,
                 curuser++,dbuser++)
    {
/* - Now pass through again processing the zeroes. Advance the pointers,
 *   adjusting for wrap. If the pointer now points at zero, if lastz is not
 *   -1, write out a response record, with original and actual, and reset
 *   last z,
 */
        if (*(curleft) == 0.0 && *(dbleft) == 0.0)
        {          /* This element needs to be advanced */
            if (**curuser == 0.0 && **dbuser == 0.0)
            {   /* This element is zero */
                if ( *lastz != -1)
                {      /* Last was not zero */
                   fprintf(timf,"%d\t%d\n",(*orig - *lastz),(wall - *lastz));
                   *lastz = -1;
                }
            }
            else
            if (*lastz == -1)
            {      /* last element was zero; this element is not */
                *lastz = wall;
                *orig = wall;
            }
            (*curuser)++;
            if (*curuser >= atop)
                *curuser = abase;
            (*dbuser)++;
            if (*dbuser >= dtop)
                *dbuser = dbase;
            *curleft = **curuser;
            *dbleft = **dbuser;
            (*orig)++;            
        }
        else
        if (*lastz == -1)
        {
            *lastz = wall;
            *orig = wall;
        }
    }
    return;
}
/*
 * Share out the bandwidth amongst the conversations
 */
int adjust_users(users, curleft, dbleft,ca,cd, capp, cdb, oapp, odb)
int users;
double   *curleft;
double  *dbleft;
double ca;
double cd;
double *capp;
double *cdb;
double *oapp;
double *odb;
{
int j;
int nzcnt = 0;
    for (j = 0; j < users; j++, curleft++, dbleft++)
    {
        if (*(curleft) != 0.0)
        {
            if (*curleft > ca)
            {
                *curleft -= ca;
                *oapp += ca;
            }
            else
            {
                *oapp += *curleft;
                *capp += (ca - *curleft);
                *curleft = 0.0;
            }
        }
        if (*(dbleft) != 0.0)
        {
            if (*dbleft > cd)
            {
                *dbleft -= cd;
                *odb += cd;
            }
            else
            {
                *odb += *dbleft;
                *cdb += (cd - *dbleft);
                *dbleft = 0.0;
            }
        }
        if (*(curleft) != 0.0 || *(dbleft) != 0.0)
            nzcnt++;
    }
    return nzcnt;
}
/*
 * Process a scenario, producing:
 * -  A file listing the traffic on each link.
 * -  A file of conversation durations.
 */
void do_scen(period,stagger,oname,lusers,rusers,pusers,ausers,
    aband, dband, tname)
int period;
int  stagger;
char * oname;
int lusers;
int rusers;
int pusers;
int ausers;
double aband;
double dband;
char * tname;
{
int i;
int  cur_stagger = 0;
FILE * f, *timf;
int lcnt;
static double lapp[60];
static double ldb[60];
static double * lcuruser[100];
static double * ldbuser[100];
static double  lcurleft[100];
static double  ldbleft[100];
static int llastz[100];
static int lorig[100];
int rcnt;
static double rapp[200];
static double rdb[200];
static double *rcuruser[100];
static double *rdbuser[100];
static double  rcurleft[100];
static double  rdbleft[100];
static int rlastz[100];
static int rorig[100];
int pcnt;
static double papp[200];
static double pdb[200];
static double *pcuruser[100];
static double *pdbuser[100];
static double  pcurleft[100];
static double  pdbleft[100];
static int plastz[100];
static int porig[100];
int acnt;
static double aapp[200];
static double adb[200];
static double *acuruser[100];
static double *adbuser[100];
static double  acurleft[100];
static double  adbleft[100];
static int alastz[100];
static int aorig[100];
double ca, cd;
double capp = 0.0, cdb = 0.0;

    lcnt =  gettraf("LOGIN.TXT",lapp,ldb,lusers,lcuruser,ldbuser,
            lcurleft,ldbleft,llastz,lorig,stagger,cur_stagger);
    cur_stagger = ((cur_stagger + stagger * lusers) % lcnt);
    rcnt =  gettraf("REMIND.TXT",rapp,rdb,rusers,rcuruser,rdbuser,
            rcurleft,rdbleft,rlastz,rorig,stagger,cur_stagger);
    cur_stagger = (( cur_stagger + stagger * rusers) % rcnt);
    pcnt =  gettraf("PROJREG.TXT",papp,pdb,pusers,pcuruser,pdbuser,
            pcurleft,pdbleft,plastz,porig,stagger,cur_stagger);
    cur_stagger = (( cur_stagger + stagger * pusers) % pcnt);
    acnt =  gettraf("ADHOC.TXT",aapp,adb,ausers,acuruser,adbuser,
            acurleft,adbleft,alastz,aorig,stagger,cur_stagger);
    if ((f = fopen(oname,"w")) != (FILE *) NULL &&
         (timf = fopen(tname,"w")) != (FILE *) NULL)
    {
        for (i = 0; i < period; i++)
        {
            int nzcnt = 0;
            oapp[i] = 0.0;
            odb[i] = 0.0;
            ca = aband/((double) (lusers + rusers + pusers + ausers));
            cd = dband/((double) (lusers + rusers + pusers + ausers));
/*
 * Processing:
 * - First pass;go through all the users for all scripts, and get their
 *   demands for the current second. Count the non-zero items.
 * - Work out the proportion of the total that can be satisfied.
 * - Now share this out amongst the non-zero users.
 * - If they are less, count the surplus, reduce the non-zero count.
 * - Otherwise, decrement.
 * - Repeat until there is no more to share.
 */
            do
            {
                nzcnt = 0;
                capp = 0.0;
                cdb = 0.0;
                nzcnt += adjust_users(lusers, lcurleft,
                         ldbleft,ca,cd, &capp, &cdb, &oapp[i], &odb[i]);
                nzcnt += adjust_users(rusers, rcurleft,
                         rdbleft,ca,cd, &capp, &cdb, &oapp[i], &odb[i]);
                nzcnt += adjust_users(pusers, pcurleft,
                         pdbleft,ca,cd, &capp, &cdb, &oapp[i], &odb[i]);
                nzcnt += adjust_users(ausers, acurleft,
                         adbleft,ca,cd, &capp, &cdb, &oapp[i], &odb[i]);
                if (nzcnt)
                {
                    ca = capp/((double) nzcnt);
                    cd = cdb/((double) nzcnt);
                }
            }
            while (nzcnt != 0 && ( capp != 0.0 || cdb != 0.0)); 
            fprintf(f,"%10.0f\t%10.0f\n", oapp[i], odb[i]);
/*
 * Now pass through again processing the zeroes. Advance the pointers,
 * adjusting for wrap. If the pointer now points at zero, if lastz is not
 * -1, write out a response record, with original and actual, and reset
 * last z, wall etc.
 */
            adjust_secs(lusers, lcuruser, ldbuser, lcurleft, ldbleft,
                   llastz, i, lorig,&lapp[0],&lapp[lcnt],
                   &ldb[0],&ldb[lcnt],timf);
            adjust_secs(rusers, rcuruser, rdbuser, rcurleft, rdbleft,
                   rlastz, i, rorig,&rapp[0],&rapp[rcnt],
                   &rdb[0],&rdb[rcnt],timf);
            adjust_secs(pusers, pcuruser, pdbuser, pcurleft, pdbleft,
                   plastz, i, porig,&papp[0],&papp[pcnt],
                   &pdb[0],&pdb[pcnt],timf);
            adjust_secs(rusers, rcuruser, rdbuser, rcurleft, rdbleft,
                   rlastz, i, rorig,&rapp[0],&rapp[rcnt],
                   &rdb[0],&rdb[rcnt],timf);
        }
        fclose(f);
        fclose(timf);
    }
    else
    {
        perror("output fopen() failed");
        fprintf(stderr,"File Names:%s, %s\n",oname,tname);
    }
    return;
}
main()
{
    do_scen(300,3,"all300.txt",30,100,90,80,3000000.0/8.0,
                     3000000.0/8.0,"all300.tim");
    do_scen(300,3,"c64k10.txt",1,3,3,3,
            65536.0/8.0,3000000.0/8.0,"c64k10.tim");
    do_scen(300,3,"s64k10.txt",1,3,3,3,
            65536.0/8.0,3000000.0/8.0,"s64k10.tim");
    do_scen(300,3,"c128k10.txt",2,7,6,5,
            65536.0/8.0,3000000.0/8.0,"c128k10.tim");
    do_scen(300,3,"s128k10.txt",2,7,6,5,
            65536.0/8.0,3000000.0/8.0,"s128k10.tim");
    do_scen(300,3,"cs2m150.txt",15,50,45,40,"cs2m150.tim");
    exit(0);
}

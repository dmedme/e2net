#!/bin/bash
# mulhisps.sh
#
# This creates a series of files of data extracted from the system process
# accounting records, one for each day.
#
OS=NT4
export OS
if [ "$OS" = AIX ]
then
    INST_AWK=awk
    INST_ACCT_BIN=sbin
    INST_ACCT_LOC=usr
elif [ "$OS" = NT4 ]
then
    INST_AWK=gawk
    INST_ACCT_BIN=sbin
    INST_ACCT_LOC=var
elif [ "$OS" = OSF ]
then
    INST_AWK=nawk
    INST_ACCT_BIN=sbin
    INST_ACCT_LOC=var
else
    INST_AWK=nawk
    INST_ACCT_BIN=lib
    INST_ACCT_LOC=var
fi
# ***********************************************************************
# single_day - produce a summary of the day's process accounting
# ***********************************************************************
# hisps outputs a faithful rendition of the process acconting record.
# It is preferred over acctcom because:
# - it is much more efficient (because it does not translate user numbers
#   to names, etc.). acctcom takes over an hour to process the day's data
#   on OSF
# - it emits all the process accounting fields
# The output is:
# - Command
# - User time
# - System time
# - Elapsed time
# - Start time
# - UID
# - GID
# - Memory
# - IO
# - Major, Minor
# - Accounting Flags
#
single_day () {
fname=$1
echo All Commands
echo ============
sort $fname | $INST_AWK -F\| 'BEGIN {
    printf "%-8.8s %4.4s %8.8s %8.8s %8.8s %8.8s %8.8s %8.8s\n",\
    "Command","Cnt","User","Sys","Elapsed","A.User","A.Sys","A.Elap"
    printf "%-8.8s %4.4s %8.8s %8.8s %8.8s %8.8s %8.8s %8.8s\n",\
    "=======","===","====","===","=======","======","=====","======"
comm = ""
cs = 0
 to_cnt = 0
 tot_us =0
 tot_sy = 0
tot_el = 0
}
{
if ( $1 != comm)
{
   if (comm != "")
   {
    printf "%-8.8s %4d %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f\n",\
   comm, cnt, us, sy, el,  us/cnt, sy/cnt, el/cnt 
   tot_cnt += cnt
  tot_us +=  us
  tot_el +=  el
   tot_sy += sy
   }
   cs++
   comm = $1
   cnt = 1
   us  = $2
   sy = $3
   el = $4
}
else
{
   cnt++
   us  += $2
   sy += $3
   el += $4
}
}
END {
    if (cnt > 0)
    printf "%-8.8s %4d %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f\n",\
   comm, cnt, us, sy, el,  us/cnt, sy/cnt, el/cnt 
   tot_cnt += cnt
  tot_us +=  us
  tot_el +=  el
   tot_sy += sy
print "commands seen : " cs
    printf "%-8.8s %4.4s %8.8s %8.8s %8.8s %8.8s %8.8s %8.8s\n",\
    "=======","===","====","===","=======","======","=====","======"
    if (tot_cnt)
    printf "%-8.8s %4d %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f\n",\
   "Total", tot_cnt, tot_us, tot_sy, tot_el,  tot_us/tot_cnt, tot_sy/tot_cnt, tot_el/tot_cnt 
}'
echo ORACLE Commands
echo ===============
 $INST_AWK -F"|" 'BEGIN {
seen_users = 0
OFMT="%.13g"
while((getline<"possorph.dat") > 0)
    possorph[$1] = 1
}
#
# Prepare the user-specific stack of oracle processes.
function ini_user(user) {
    if (seen_user[user] == 0)
    {
        seen_user[user] = 1
        user_list[seen_users] = user
        seen_users++
        prev_el[user]=0
        pre[user]=""
        other_usr[user] = 0
        other_sys[user] = 0
    }
    batstack[user]=0
    return
}
#
# Output a line re-formatted and combined with ORACLE sub-processes
#
# - Correction made for BST on loading
# - Flag indicates whether should remove the initial CPU total.
# - This is correct for a non-batch process if the instrumentation is
#   running, since the instrumentation has already captured it.
#
function output_line(line,flag) {
nf = split(line,arr,"|")
ora_usr = 0
ora_sys = 0
#print "Output " nf " " line
user = arr[6]
line_cnt = batstack[user]
for (i = 0; i < line_cnt; i++) 
{
    j = split(stack_line[user,i],arr1,"|")
# User Time
    ora_usr = ora_usr + arr1[2]
# System Time
    ora_sys = ora_sys + arr1[3]
}
start_secs = arr[5]
end_secs = start_secs + arr[4]
# ****************************************************************************
# Output Format
# - UID
# - Command
# - Start time
# - End time
# - Elapsed time
# - User time
# - System time
# - ORACLE User time
# - ORACLE System time
# - Flag (0 = Finished normally, 1 = Out of Order)
    print user "|" arr[1] "|" start_secs "|" end_secs "|" arr[4] "|" arr[2] "|" arr[3] "|" ora_usr "|" ora_sys "|" flag
# ****************************************************************************
    ini_user(user)
return
}
#
# Ferret away an ORACLE process accounting line
#
function push_oracle(line) {
    nx = batstack[user]
    if (nx)
    {
        split(stack_line[user,0],arr1,"|")
        sqlnet = "oracle  |0|0|" arr1[4] "|" arr1[5] "|" user
        output_line(sqlnet,1)
        nx = 0
    }
    stack_line[user,nx] = line
    batstack[user] = nx + 1
    return
}
#
# Process a line
# The logic is
# -  collect the ORACLE stuff.
# -  for anything else of interest:
#    -  hang on to it if we have no ORACLE stuff, and we need to output it
#    -  output it if we have ORACLE stuff
{
    if ($1 == "orapop  ")
        next
    last_time = $5
    user = $6
    if (seen_user[user] == 0)
        ini_user(user)
    if ($1 == "oracle  " || $1 == "orapop  ")
    {
        if (prev_el[user] != 0)
        {
            if (batstack[user] != 0)
            {
                output_line(pre[user],1)
                push_oracle($0)
            }
            else
            {
                push_oracle($0)
                output_line(pre[user],1)
            }
            prev_el[user] = 0
        }
        else
            push_oracle($0)
        next
    }
    x = substr($1,1,3)
    poss_flag = 0
    if ($1 == "exp     " || $1 == "imp     " )
        poss_flag = 1;
#
# This command is not intrinsically of interest.
#
    if (possorph[x] == 0 && poss_flag == 0)
    {
        other_usr[user] = other_usr[user] + $2
        other_sys[user] = other_sys[user] + $3
        next
    }
    else
    {
#        print "non-oracle " $0
#
# Is this a case where the application finished early?
#
       if (prev_el[user] != 0)
       {
           output_line(pre[user],1)
           prev_el[user] = 0
       }
       if (batstack[user] == 0)
       {
#
# If the elapsed time is zero, add to the other category
#
           if ($4 > 0 )
           {
               pre[user] = $0
               prev_el[user] = $4 
           }
           else
           {
               other_usr[user] +=  $2
               other_sys[user] +=  $3
           }
       }
       else
#
# Application Finished OK, we already have the ORACLE figure.
#
           output_line($0,0)
    }
}
#
# Print out what we have left, as a single record for each user
#
END {
    start_secs = int(last_time/86400) * 86400
    end_secs = start_secs + 86399
    for (i0 = 0; i0 < seen_users; i0++)
    {
        user = user_list[i0]
        if (prev_el[user] != 0)
            output_line(pre[user],1)
        cleanup = " other|" other_usr[user] "|" other_sys[user] "|86399|" start_secs "|" user
        output_line(cleanup,1)
    }
}' $fname |
sed 's/[ 	][ 	]*//g' | tee oracomms.lis | sort -t\| +1 | $INST_AWK -F\| 'BEGIN {
    printf "%-8.8s %4.4s %8.8s %8.8s %8.8s %8.8s %8.8s\n",\
    "Command","Cnt","User","Sys","Elapsed","Ora.User","Ora.Sys"
    printf "%-8.8s %4.4s %8.8s %8.8s %8.8s %8.8s %8.8s\n",\
    "=======","===","====","===","=======","======","====="
comm = ""
cs = 0
 tot_cnt = 0
 tot_us =0
 tot_sy = 0
 tot_ora_us =0
 tot_ora_sy = 0
tot_el = 0
}
{
if ( $2 != comm)
{
   if (comm != "")
   {
    printf "%-8.8s %4d %8.2f %8.2f %8.2f %8.2f %8.2f\n",\
   comm, cnt, us, sy, el,  ora_us, ora_sy
   tot_cnt += cnt
  tot_us +=  us
  tot_el +=  el
   tot_sy += sy
   tot_ora_sy += ora_sy
   tot_ora_us += ora_us
   }
   cs++
   comm = $2
   cnt = 1
   us  = $6
   sy = $7
   ora_us  = $8
   ora_sy = $9
   el = $5
}
else
{
   cnt += 1
   us  += $6
   sy += $7
   el += $5
   ora_us  += $8
   ora_sy += $9
}
}
END {
    if (cnt > 0)
    printf "%-8.8s %4d %8.2f %8.2f %8.2f %8.2f %8.2f\n",\
   comm, cnt, us, sy, el,  ora_us,ora_sy
   tot_cnt += cnt
  tot_us +=  us
  tot_ora_us +=  ora_us
  tot_el +=  el
   tot_sy += sy
   tot_ora_sy += ora_sy
print "commands seen : " cs
    printf "%-8.8s %4.4s %8.8s %8.8s %8.8s %8.8s %8.8s\n",\
    "=======","===","====","===","=======","======","====="
    if (tot_cnt)
    printf "%-8.8s %4d %8.2f %8.2f %8.2f %8.2f %8.2f\n",\
   "Total", tot_cnt, tot_us, tot_sy, tot_el,  tot_ora_us, tot_ora_sy
}'
return
}
# **********************************************************************
# Main process - Split the input stream up a day at a time 
#
for i in pacct
do
$INST_AWK -F "|" 'BEGIN {
    if ((getline)< 0)
        exit
#
# 907113600 = 30 September 1998
#
    split($5,arr1," ")
    split(arr1[3],arr,":")
    dow = (arr1[2] + 3) % 7 
    start_time = (arr1[2]*86400 + arr[1]*3600 + arr[2]*60 + arr[3]) 
    ld=int((start_time + $4)/86400)
    fname="pacct." ld
    print $0 >fname
}
{
    split($5,arr1," ")
    split(arr1[3],arr,":")
    dow = (arr1[2] + 3) % 7 
    start_time = (arr1[2]*86400 + arr[1]*3600 + arr[2]*60 + arr[3]) 
    if ( ld < int((start_time + $4)/86400))
    {
        close(fname)
        print fname
        ld=int((start_time + $4)/86400)
        fname="pacct." ld
    }
    print $0 >fname
}
END {
    close(fname)
    print fname
}' pacct 
done | while read ln
do
single_day $ln > $ln.sum
rm $ln
done
for i in *.sum
do
echo $i | sed 's/[^.]*\.\([^.]*\)\.sum/\1 Oct 1998/'
gawk '/^ORACLE/ { flag = 1
next
}
flag == 1 { print }' $i
done > daybyday.txt
echo ======================= >> daybyday.txt
echo Overall Summary >> daybyday.txt
echo ======================= >> daybyday.txt
single_day pacct >> daybyday.txt
exit

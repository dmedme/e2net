#!/bin/sh
# Create some scripts to be getting on with
# Parameters
# 1 - Name of seed script
# 2 - The PID
# 3 - The bundle
# 4 - Number of users
# 5 - Number of transactions each will do
# 6 - Dummy
# 7 - Event Wait Time
# 8 - The substitution place-holders
# set -x
PATH_HOME=${PATH_HOME:-..}
PATH_AWK=${PATH_AWK:-nawk}
export PATH_HOME PATH_AWK
# ***********************************************************************
# Function   : discard_used
# Parameters :
# 1 - input file
discard_used() {
for fname in $*
do
#
# Do nothing if there is nothing to do
#
    if [ ! -f  "$fname" -o ! -f "$fname".used ]
    then
        continue
    fi
    sort -n $fname.used > $fname.tmp
    $PATH_AWK 'function next_skip() { if ((getline<tmp) <  1)
         n = 99999999
    else
         n = $0 + 2
    return n
    }
    BEGIN {
tmp="'$fname'.tmp"
spent="'$fname'.spent"
nxr = next_skip()}
    NR < nxr { print }
    NR == nxr { print>>spent
         nxr = next_skip() }
    NR > nxr {print "Logic Error: NR:" NR " nxr: " nxr >>spent
system("cp " tmp " " tmp ".sav")
print
while(nxr <= NR)
nxr = next_skip()}' $fname > $fname.new
#
# Shrink the master file and keep the full list
#
    mv $fname.new $fname
    rm $fname.used $fname.tmp
    done
    return
}
# ***********************************************************************
# Function   : create_edits
# Parameters :
# 1 - input file
# 2 - g
# 3 - seq
#
create_edits () {
$PATH_AWK  '
# ***********************************************************************
# Functions to give values from a list
#
# Return the null string if not found, otherwise a valid value
#
function tabopen(table_name, start_point) {
    if (nofile[table_name] == 1)
        return
    rname= path_home "/data/" table_name ".db"
    fname[table_name]=rname
    rec = 0
    if ((getline<rname) < 1)
    {
         nofile[table_name] = 1
         return
    }
    tabcols[table_name] = $0
    getline<rname
    for (icnt = 0; icnt < start_point; icnt++)
        if ((getline<rname) < 1)
        {
            close(rname)
            getline<rname
            getline<rname
            start_point = (start_point % rec)
            icnt = 0
            rec = 0
        }
        else
            rec++
    rec_no[table_name] = rec
    tabnext(table_name)
#    print "# tabopen(" table_name "," start_point ") tabline: " tabline[table_name]
#    print "# tabcols: " tabcols[table_name]
    return
}
function tabnext(table_name) {
    if (nofile[table_name] == 1)
        return
    if ((getline<fname[table_name]) < 1)
    {
        close(fname[table_name])
        getline<fname[table_name]
        getline<fname[table_name]
        rec_no[table_name] = 0
    }
    else
        rec_no[table_name]++
#
# Make it possible to ensure that values are only used once
#
    usedf=fname[table_name] ".used"
    print rec_no[table_name]>>usedf
    tabline[table_name] = $0
#    print "# tabnext(" table_name ") tabline: " tabline[table_name]
    return
}
#
# If it is not known, provide
# a number if the field is like REFNO, a date if a date,
# otherwise a 4 character string 
#
function unknown_val(column_name) {
    if (index(column_name,"REFNO") > 0)
        return -next_number++
    else
    if (index(column_name,"DATE") > 0|| index(column_name,"DTTM") > 0)
        return ndate(0)
    else
        return substr(nstring(),1,4)
}
function colpick(table_name,column_name,fetch_flag) {
#
# First, find which column it is.
#
    if (tabcols[table_name] == "")
        tabopen(table_name, next_number % 33337)
    if (tabcols[table_name] == "")
    {
        tabcols[table_name] = column_name
        tabline[table_name] = unknown_val(column_name)
        return tabline[table_name]
    }
    nf = split(tabcols[table_name],arr, data_sep)
    for (i1cnt = 0; i1cnt <= nf && arr[i1cnt] != column_name; i1cnt++);
    if (i1cnt > nf)
    {
        tabcols[table_name] = tabcols[table_name]  data_sep column_name
        arr[i1cnt] = unknown_val(column_name)
        tabline[table_name] = tabline[table_name]  data_sep arr[i1cnt]
        return arr[i1cnt]
    }
    if (fetch_flag == "F")
        tabnext(table_name)
    split(tabline[table_name],arr, data_sep)
#
# If a new value, or no values, invent some, and stuff them in the current
# record.
#
    if (fetch_flag == "C")
    {
        arr[i1cnt] = unknown_val(column_name)
        tabline[table_name] = arr[1]
        for (i = 2; i <= nf; i++)
             tabline[table_name] = tabline[table_name]  data_sep arr[i]
    }
    return arr[i1cnt] 
}
function nstring() {
    sav_str =  substr(next_str,next_off,next_len)
    next_str = substr(next_str,1,next_off - 1) substr(src_str,src_off,next_len) substr(next_str, next_off + next_len, 35 - next_off)
    src_str = substr(src_str,1,src_off - 1) sav_str substr(src_str, src_off + next_len, 33 - src_off)
    next_len = next_len + 1
    if (next_len > 10)
       next_len -= 10
    next_off += 3
    if ( next_off  > 23 )
        next_off -= 23
    src_off += 4
    if ( src_off  > 29 )
        src_off -= 29
    return next_str
}
function inidate(which,lim) {
maxcount[which] = lim
counter[which] = 1
next_day[which]=1
next_month[which]="JAN"
next_year[which]=2000
return
}
function ndate (which) {
if (counter[which] == 0 || counter[which] == maxcount[which])
    inidate(which,maxcount[which])
counter[which]++
next_day[which]++
if ( next_day[which] >= 28 )
{
    if ( next_month[which] == "JAN" && next_day[which] == 32 )
         {next_month[which] = "FEB";next_day[which] = 1}
    else
    if ( next_month[which] == "FEB" && next_day[which] == 29 )
         {next_month[which] = "MAR";next_day[which] = 1}
    else
    if ( next_month[which] == "MAR" && next_day[which] == 32 )
         {next_month[which] = "APR";next_day[which] = 1}
    else
    if ( next_month[which] == "APR" && next_day[which] == 31 )
         {next_month[which] = "MAY";next_day[which] = 1}
    else
    if ( next_month[which] == "MAY" && next_day[which] == 32 )
         {next_month[which] = "JUN";next_day[which] = 1}
    else
    if ( next_month[which] == "JUN" && next_day[which] == 31 )
         {next_month[which] = "JUL";next_day[which] = 1}
    else
    if ( next_month[which] == "JUL" && next_day[which] == 32 )
         {next_month[which] = "AUG";next_day[which] = 1}
    else
    if ( next_month[which] == "AUG" && next_day[which] == 32 )
         {next_month[which] = "SEP";next_day[which] = 1}
    else
    if ( next_month[which] == "SEP" && next_day[which] == 31 )
         {next_month[which] = "OCT";next_day[which] = 1}
    else
    if ( next_month[which] == "OCT" && next_day[which] == 32 )
         {next_month[which] = "NOV";next_day[which] = 1}
    else
    if ( next_month[which] == "NOV" && next_day[which] == 31 )
         {next_month[which] = "DEC";next_day[which] = 1}
    else
    if ( next_month[which] == "DEC" && next_day[which] == 32 )
    {
         next_day[which] = 1;
         next_month[which] = "JAN"
         next_year[which] ++
         if (next_year[which] == 2002)
             next_year[which] = 2000
    }
}
    return next_day[which] "-" next_month[which] "-" next_year[which]
}
BEGIN {
# Problems with Dynix nawk not accepting -v.....
seed="'$seed'"
bundle='$bundle'
ntrans='$ntrans'
nusers='$nusers'
g='$2'
seq='$3'
pid="'$pid'"
path_home="'$PATH_HOME'"
data_sep = "|"
# Date allocation
#
next_day[0]=1
next_month[0]="JAN"
next_year[0]=2001
counter[0]=9999999999
#
# Number allocation
#
next_number= 10000000 + (ntrans * bundle * nusers *seq + g * 997 + seq ) * 997+ seed
#
# String allocation
#
next_str="ABC DEF GHI JKL MNO PQR STU VWX YZ"
next_len=1
next_off=1
src_str="ZYX WVU TSRQ PONM LKJI HGFE DCBA"
src_off=1
FS =  data_sep
fil_cnt = 0
comm_cnt = 0
outf="sed" pid "." bundle "." g "." seq "." fil_cnt
}
!/^#/ {
    ln = $1
    targ = $2
#    print "# colpick(" $3 "," $4 "," $5 ")"
    if (NF > 5)
    {
        adj_len = $6 * (length(colpick($3, $4, "N")) - $5)
        if (NF > 6)
            adj_len = adj_len + $10 * (length(colpick($7, $8, "N")) - $9)
        if (NF > 10)
            adj_len = adj_len + $14 * (length(colpick($11, $12, "N")) - $13)
        if (adj_len == 0)
            next
        else
            subst = $2 + adj_len
    }
    else
    subst = colpick($3,$4,$5)
#    print "# returns: " subst
    print ln " s" data_sep targ data_sep subst data_sep >outf
    comm_cnt++
    if (comm_cnt >=90)
    {
        close(outf)
        fil_cnt++
        outf="sed" pid "." bundle "." g "." seq "." fil_cnt
        comm_cnt = 0
    }
}
END {
    if (comm_cnt == 0)
        fil_cnt--
    for (i = 0; i < fil_cnt; i++)
        print "sed -f sed" pid "." bundle "." g "." seq "." i "|"
    print "sed -f sed" pid "." bundle "." g "." seq "." fil_cnt
} ' $1.def
#
# Discard used data values - we don't in this case.
#
    return
}
clone_script () {
i=0
seed_script=$1
pid=$2
bundle=$3
nusers=$4
ntrans=$5
think=$6
seed=$7
sed_script=$pid.sedlis
while [ $i -lt $nusers ]
do
    j=1
#
# If a def file exists, use it, otherwise just copy
#
    cat /dev/null > echo$pid.$bundle.$i
    {
#
# Start with the login element
#
    if [ -f $PATH_PREAMBLE.def -a -f $PATH_PREAMBLE.$PATH_EXT ]
    then
        create_edits $PATH_PREAMBLE $i $j > $sed_script 
sed -e "s/\\\\W[1-9][0-9]*\\\\/\\\\W$think\\\\/" $PATH_PREAMBLE.$PATH_EXT |
        eval `cat $sed_script` | sed '
s/\([ 0123][0-9][ -][JFMASONDjfmasond][AEPUCOaepuco][NBRYLGPTVCnbrylgptvc][ -]\)[12][90]\([0-9][0-9]\) [ 012][0-9]:[ 0-5][0-9]:[0-5][0-9]/\1\2/g'
        rm -f sed$pid.$bundle.$i.*
        discard_used `$PATH_AWK -F\| 'NF == 5 { print "'$PATH_HOME'/data/" $3 ".db" }' $PATH_PREAMBLE.def | sort | uniq`
    elif [ -f $PATH_PREAMBLE.$PATH_EXT ]
    then
        sed -e "s/\\\\W[1-9][0-9]*\\\\/\\\\W$think\\\\/
s/\\([ 0123][0-9][ -][JFMASONDjfmasond][AEPUCOaepuco][NBRYLGPTVCnbrylgptvc][ -]\\)[12][90]\\([0-9][0-9]\\) [ 012][0-9]:[ 0-5][0-9]:[0-5][0-9]/\\1\\2/g" $PATH_PREAMBLE.$PATH_EXT
    fi
    while [ $j -le $ntrans ]
    do
#
# Start with a per-loop element
#
    if [ -f ../csscripts/singref.def -a -f ../csscripts/singref.$PATH_EXT ]
    then
        create_edits ../csscripts/singref $i $j > $sed_script 
sed -e "s/\\\\W[1-9][0-9]*\\\\/\\\\W$think\\\\/" ../csscripts/singref.$PATH_EXT |
        eval `cat $sed_script` | sed '
s/\([ 0123][0-9][ -][JFMASONDjfmasond][AEPUCOaepuco][NBRYLGPTVCnbrylgptvc][ -]\)[12][90]\([0-9][0-9]\) [ 012][0-9]:[ 0-5][0-9]:[0-5][0-9]/\1\2/g'
        rm -f sed$pid.$bundle.$i.*
    elif [ -f ../csscripts/singref.$PATH_EXT ]
    then
        sed -e "s/\\\\W[1-9][0-9]*\\\\/\\\\W$think\\\\/
s/\\([ 0123][0-9][ -][JFMASONDjfmasond][AEPUCOaepuco][NBRYLGPTVCnbrylgptvc][ -]\\)[12][90]\\([0-9][0-9]\\) [ 012][0-9]:[ 0-5][0-9]:[0-5][0-9]/\\1\\2/g"  ../csscripts/singref.$PATH_EXT
    fi
    if [ -f $seed_script.def ]
    then
        create_edits $seed_script $i $j > $sed_script 
sed -e "s/\\\\W[1-9][0-9]*\\\\/\\\\W$think\\\\/" $seed_script.$PATH_EXT |
        eval `cat $sed_script` | sed '
s/\([ 0123][0-9][ -][JFMASONDjfmasond][AEPUCOaepuco][NBRYLGPTVCnbrylgptvc][ -]\)[12][90]\([0-9][0-9]\) [ 012][0-9]:[ 0-5][0-9]:[0-5][0-9]/\1\2/g'
        rm -f sed$pid.$bundle.$i.*
    else
        sed -e "s/\\\\W[1-9][0-9]*\\\\/\\\\W$think\\\\/
s/\\([ 0123][0-9][ -][JFMASONDjfmasond][AEPUCOaepuco][NBRYLGPTVCnbrylgptvc][ -]\\)[12][90]\\([0-9][0-9]\\) [ 012][0-9]:[ 0-5][0-9]:[0-5][0-9]/\\1\\2/g" $seed_script.$PATH_EXT
    fi
        j=`expr $j + 1`
    done
    }>> echo$pid.$bundle.$i
    think=`expr $think + 1`
    if [ $think -gt 60 ]
    then
        think=30
    fi
    if [ -f $seed_script.def ]
    then
        discard_used `$PATH_AWK -F\| 'NF == 5 { print "'$PATH_HOME'/data/" $3 ".db" }' $seed_script.def | sort | uniq`
    fi
    i=`expr $i + 1`
done
return
}

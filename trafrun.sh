:
#!/bin/sh
# trafrun.sh - run a Traffic Benchmark
# Copyright (c) E2 Systems 1995
# @(#) $Name$ $Id$
# *************************************************************************
# Remote services are provided by E2's minitest, which provides remote copy
# clock adjust and execution services in a machine-independent way.
#
# gzip is used for transmission compression purposes, and needs to be
# available on all participating machines. 
TRAF_OS=${TRAF_OS:-NT4}
export TRAF_OS
case "$TRAF_OS" in
NT4)
    TRAF_AWK=gawk
    ;;
AIX|HPUX)
    TRAF_AWK=awk
    ;;
*)
    TRAF_AWK=nawk
    ;;
esac
export TRAF_AWK
# *****************************************************************************
# This script defines the layout of the files used to control Traffic benchmarks
#
# Certain elements are constrained by the need to use fdreport.
#
# For an individual host, we must have a runout file and echo files. In the
# runout file, the number of users, the script name and the number of
# transaction loops are in the same places. We also use a think time in the
# usual way, so that also goes in the same place. We do not have a typing speed.
# We need an actor id. So that goes in the typing speed place.
#
# A single transaction script will have a number of actors and IP addresses in
# it. Only one copy is needed to control any number of incarnations. However:
# - The IP Addresses for Peer End Points need to be correct.
# - The IP Addresses for Listen End Points need to be correct for actors that
#   connect to them.
# - If an actor listens, only one incarnation can be started.
# - If an actor does not listen, we need one program started for each user.
#
# We need to define a higher level thing, which lists all the hosts,
# all the scripts, and the relationship between them. This would be even more
# useful if we could globally map IP addresses, but it is more flexible if we do
# not do this.
#
# A server may have to talk to any number of different hosts simultaneously.
#
# We need to make sure that each script is supported by actors on all
# the necessary hosts.
#
# This argues for having a master file, ordered by script, with the script
# name and a list of all the actors and hosts that apply to it.
#
# Script by script, we allocate numbers of users, and allocate them to hosts.
# The allocation is many to many scripts to hosts; complex.
#
# On the master machine, we generate the runout files and the translated seeds.
#
# These are packaged up for distribution.
#
# A relational database would make a lot of sense here, since we have scripts,
# hosts, and relationships between them. However, we will use flat files.
#
# They are unpacked, and the echo files generated, remotely.
#
# ***************************************************************************
# Function to generate the echo files on a particular host
trafscale() {
if [ $# -lt 1 ]
then
    echo trafscale requires a runout file ID
    return
fi
pid=$1
if [ ! -f runout$pid ] 
then
    echo trafscale: runout file runout$pid does not exist
    return
fi
j=1
echo Please wait
i=""
while :
do
    if [ ! -f runout$pid$i ]
    then
        break
    fi
(
# Runout file layout
# 3 junk lines
# Lines consisting of space separated:
#    nusers tran ntrans think actor {4 further parameters. fdreport needs them}
#
# Skip the first three lines
#
read l
read l
read l
bundle=1
while :
do
    read nusers tran ntrans think actor runtype para_1 para_2 para_3 || break
    if [ "$ntrans" = "start_time" -o "$ntrans" = "" ]
    then
        break
    fi
# Notify user and wait for acknowledgement
    echo "TH|$think" > echo$pid$i.$bundle.0
    cat $tran  >>echo$pid$i.$bundle.0
    g=0
    while [ "$g" -lt "$ntrans" ]
    do 
        grep -v '^EP' $tran >>echo$pid$i.$bundle.0
        g=`expr $g + 1`
    done
    bundle=`expr $bundle + 1`
done
) < runout$pid$i
    i=_$j
    j=`expr $j + 1`
done
#
echo Echo regeneration complete for $pid
return
}
# ************************************************************************
# Function to execute scenario components at a particular host
#
execute_scenario() {
    this_pid=$1
#
# Process the runout file
#
(
read i
read i
read i
bundle=1
while :
do
    read nusers tran ntrans think actor runtype para_1 para_2 para_3
    if [ "$ntrans" = "start_time" -o "$ntrans" = "" ]
    then
        break
    fi
    if [ "$actor" = 0 ]
    then
        i=0
        while [ $i -lt $nusers ]
        do
            outfile=log$this_pid.$bundle.$i
            infile=echo$this_pid.$bundle.0
            dumpfile=dump$this_pid.$bundle.$i
#
# Start the local driver
#
            ipdrive $othargs $outfile $this_pid $bundle $i $infile 0 >$dumpfile 2>&1 & 
# stagger the start up
            sleep 1
            i=`expr $i + 1`
        done
    else
        outfile=log$this_pid.$bundle.$i.$actor
        infile=echo$this_pid.$bundle.0
        dumpfile=dump$this_pid.$bundle.$i.$actor
        ipdrive $othargs $outfile $this_pid $bundle $i $infile $actor >$dumpfile 2>&1 & 
    fi
done
) < runout$pid
    return
}
# *************************************************************************
# Function to kick off the remote components of a traffic run
#
# It assumes the hosts are provided in the order that they will have actors
# assigned.
trafremstart() {
hosts_done=""
while [ $# != 0 ]
do
#
# Copy over the traffic files
#
    actor=$1
    shift
    f=$1
    shift
    case $hosts_done in
    *${f}*)
        ;;
    *)
       gzip < echo$pid.$bundle.0 | minitest $f 5000 "gzip -d >echo$pid.$bundle.0"
        ;;
    esac
    s=0
    hosts_done=$hosts_done/$f
    minitest </dev/null $f 5000 "ipdrive $othargs log$pid.$bundle.$s.$actor $pid $bundle $s echo$pid.$bundle.$s $actor >dump$pid.$bundle.$s 2>&1 &"
done
return
}
#
# Start netstat on each remote machine.
#
trafremnet() {
for f in $*
do
minitest </dev/null $f 5000 "netstat -i 20 > netout$pid 2>&1 &"
done
return
}
#
# Now shut them down. This will only need to be called once for each host, rather than once
# for each bundle
#
trafremkill() {
for f in $*
do
    minitest </dev/null $f 5000 "ps -e | $TRAF_AWK '/ipdrive/ || /netstat/ {print \$1}' | xargs kill -INT "
done
return
}
conduct_test() {
# **************************************************************************
# Main process starts here
#
trap '' 1
if [ $# -lt 1 ]
then
    echo Provide a runout file id
    exit 1
fi
pid=$1
if [ ! -f runout$pid ]
then
    echo Provide a valid runout file id
    exit 1
fi
if [ $# -lt 2 ]
then
    seconds=600 
else
    seconds=$2
fi
if [ $# -gt 2 ]
then
    shift
    shift
    othargs=$*
else
    othargs=""
fi
set -x
# ********************************************************************
# Identify the list of required hosts
#
trflist=`$TRAF_AWK '!/end_time/ { if(NR>3) print $2}' runout$pid `
allhosts=`for i in $trflist
do
    $TRAF_AWK -F"|" '/^EP/ {
        if ($2 != 0)
            print $2 "|" $5
    }' $i | sort | uniq | sed 's/.*|//
s/  *//g'
done | sort | uniq`
# ********************************************************************
# Start the remote actors
#
bundle=1
for i in `$TRAF_AWK '!/end_time/ { if(NR>3) print $2}' runout$pid `
do
    trafremstart ` $TRAF_AWK -F"|" '/^EP/ {
        if ($2 != 0)
            print $2 "|" $5
    }' $i | sort | uniq | sed 's/  *//g
s/|/ /'`
    bundle=`expr $bundle + 1`
done
# ********************************************************************
# Start any remote netstat processes. This would only be useful for UNIX
#
trafremnet $allhosts
# ********************************************************************
# Start the local processes
#
# Input code to initiate performance monitors here !!!!!
#
# Run Phased Trials, to ramp up the users
#
cat /dev/null >elapsed$pid
loop=0
phase=
while [ -f runout$pid$phase ]
do
    tosecs >>elapsed$pid
    execute_scenario $pid$phase
    sleep $seconds
    tosecs >>elapsed$pid
    loop=`expr $loop + 1`
    phase=_$loop
done
ps -e | $TRAF_AWK '/ipdrive/ { print  $1 }' | xargs kill -INT
wait
# *******************************************************************
# merge the output files, bringing over the others from the other hosts
#
cat log${pid}* > mer$pid
rm -f log${pid}*
trafremkill $allhosts
for f in $allhosts
do
    minitest </dev/null $f 5000 "cat log${pid}* | gzip" | gzip -d >> mer$pid
done 
sort -n -t: mer$pid > comout$pid
#
# Produce the report pack
#
loop=0
phase=
while [ -f runout$pid$phase ]
do
    read start_time || break
    read end_time || break
    fdreport.sh $pid $start_time $end_time $phase
    loop=`expr $loop + 1`
    phase=_$loop
done <elapsed$piid
return
}

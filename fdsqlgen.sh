#!/bin/sh
# fdsqlgen; Generate scripts for use during a Client-Server Benchmark
# @(#) $Name$ $Id$
# Copyright (c) 1993 E2 Systems
#
. fdsqlclone.sh
if [ $# -lt 1 ]
then
    echo Enter runout file ID
    exit 1
fi
pid=$1
if [ ! -f runout$pid ] 
then
echo "Create a runout file as does not exist; defaults are in square brackets thus[10]"
echo
echo "There must be three junk lines before the transactions" > runout$pid
echo "Run Parameters" >> runout$pid
echo "==============" >> runout$pid
    bundle=1
         echo "Accepting Details for Bundle Number " $bundle
         while :
         do
         echo "Enter the transaction for this bundle; return to quit the loop."
         echo "Scripts available in directory:"
echo --------------------------------------------------------------------
         ls -C *.seed
    read tran
    if [ -z "$tran" ]
    then
        break 
    fi
    echo "Enter the number of simulated users [10]:\c"
    read nusers
    if [ -z "$nusers" ]
    then
        nusers=10
 #TAILOR change default
    fi
    echo "Enter the number of transactions each will do [100]:\c"
    read ntrans
    if [ -z "$ntrans" ]
    then
        ntrans=100
 #TAILOR change default
    fi
    echo "Enter the think time between events [100]:\c"
    read think
    if [ -z "$think" ]
    then
        ntrans=10
 #TAILOR change default
    fi
    echo "Enter the data file  [junk]:\c"
    read dfile
    if [ -z "$dfile" ]
    then
        dfile=junk
 #TAILOR change default
    fi
    echo "Enter the substitution targets [junk]:\c"
    read subst
    if [ -z "$subst" ]
    then
        subst=junk
 #TAILOR change default
    fi
    echo "If happy with above press return, if not type n and return \c"
    read resp
    if [ -z "$resp" ]
    then
     echo $nusers $tran $ntrans $think 1 $dfile $subst >> runout$pid
     bundle=`expr $bundle + 1`
     fi
   done
fi
echo Please wait for all the setups to finish. It will bleep at you.
(
#
# Skip the first three lines
#
read i
read i
read i
bundle=1
while :
do
    read nusers tran ntrans think cps seed subst
    if [ "$ntrans" = "start_time" -o "$ntrans" = "" ]
    then
        break
    fi
# 1 - Name of seed script
# 2 - The PID
# 3 - The bundle
# 4 - Number of users
# 5 - Number of transactions each will do
# 6 - Think Time
# 7 - The substitution place-holders
    clone_script $tran $pid $bundle $nusers $ntrans $think $seed "$subst"
     bundle=`expr $bundle + 1`
done
) < runout$pid
#
# Notify user and wait for acknowledgement
wait
echo Echo regeneration complete for $pid

#!/bin/sh
# trafscale.sh; Create a control file for the traffic generator
# @(#) $Name$ $Id$
# Copyright (c) 1993 E2 Systems
#
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
echo "Three junk lines needed" > runout$pid
echo "Run Parameters" >> runout$pid
echo "==============" >> runout$pid
    bundle=1
         echo "Accepting Details for Bundle Number " $bundle
         while :
         do
         echo "Enter the transaction for this bundle; return to quit the loop."
         echo "Traffic specs available in directory:"
echo --------------------------------------------------------------------
         ls -C *trf
    read tran
    if [ -z "$tran" ]
    then
        break 
    fi
    if [ -z "$cps" ]
    then
        cps=10
    fi
    if [ -z "$think" ]
    then
        think=10
 #TAILOR change default
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
    if [ -z "$runtype" ]
    then
        runtype="m"
 #TAILOR change default
    fi
    echo "If happy with above press return, if not type n and return \c"
    read resp
    if [ -z "$resp" ]
    then
     echo $nusers $tran $ntrans $think $cps $runtype 1 2 3 >> runout$pid
     bundle=`expr $bundle + 1`
     fi
   done
fi
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
    read nusers tran ntrans think cps runtype para_1 para_2 para_3
    if [ "$ntrans" = "start_time" -o "$ntrans" = "" ]
    then
        break
    fi
# Notify user and wait for acknowledgement
echo Please wait
    cp $tran echo$pid.$bundle.0
    g=0
    while [ "$g" -lt "$ntrans" ]
    do 
        grep -v '^EP' $tran >>echo$pid.$bundle.0
        g=`expr $g + 1`
    done
    bundle=`expr $bundle + 1`
done
) < runout$pid
#
echo Echo regeneration complete for $pid
exit

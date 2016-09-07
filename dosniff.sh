#!/bin/bash
# dosniff.sh - Process all the sniffer traces
#
set -x
for i in *.txt *.TXT
do
    j=`echo $i | sed 's/\..*//'`
    /e2soft/e2net/eqsnf2snp $i fred.snp
    if /e2soft/e2net/sqlmul fred.snp
    then
        :
    else
        echo Failed on $i
    fi
    if grep -l ':SLOW:' sql_*.sql
    then
    x=`grep -l ':SLOW:' sql_*.sql`
    for k in $x
    do
        mv $k ${j}_$k
    done
    fi
    rm -f sql_*.sql
done

#!/bin/sh
# respproc.sh - Process the results of scanning the network traces
#
E2_SYB_PORTS=5000
export E2_SYB_PORTS
c:/e2soft/sybperf/badsort_e2stdio -- lock.snp >fred.log 2>&1
mkdir sessions duff
mv syb_*.sql smb_*.txt sessions
#
# Look for duff sessions, and put them on one side
#
mv `for i in sessions/syb_*.sql
do
gawk 'BEGIN { n = 0 }
/Corruption/ { n = 0
next
}
/\|RESPONSE\|/ { if (n > 9)
    print FILENAME
    exit
}
/^\\C:/ { n++ }' $i
done` duff
#
# Deal with the responses
#
grep '|RESPONSE|' sessions/syb_*.sql sessions/smb_* | tee allresp.txt | c:/e2soft/perfdb/sarprep -u
gawk -F\| 'BEGIN { n = 0 } {n += $11} $11 > 5 { print $0} END {if (NR) print n/NR}' allresp.txt > longresp.txt
#
# Deal with the sessions
#
grep '|Session ' sessions/syb_*.sql sessions/smb_* > allsess.txt
c:/e2soft/e2net/allresp.sh allsess.txt 23 /dev/null 150.135.104.58  > sesstmp.txt
sed '/^sessions/ s/.*\\C://' sesstmp.txt | c:/e2soft/perfdb/sarprep -c
#
# Deal with the SQL
#
c:/hlthchk/pirate/final/norm.sh badsort.exp

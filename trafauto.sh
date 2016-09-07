#!/bin/sh
# trafauto.sh - Insert timing events at sensible points.
#
for i in $*
do
   nawk -F\| 'BEGIN {
last_r = 0
event_id = 161
del = 0
stform = "ST|0|%2.2X|Event %2.2X\n"
ttform = "TT|0|%2.2X\n"
printf stform, event_id, event_id
}
/^DT/ { if ($3 > 5)
    {
        printf ttform, event_id
        event_id++
        print $0
        printf stform, event_id, event_id
        next
    }
}
{ print}
END {
    printf ttform, event_id
}' $i > $i.tmp
   mv $i.tmp $i
done
exit

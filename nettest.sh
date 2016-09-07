#!/bin/sh
# Sample network response times
for i in `cat samhosts`
do
ping -s $i 64 10
done | nawk '/^72 bytes.*\(/ { print $5 $7; next }
/^72 bytes/ { print $4 $6}' | sed 's/(144.124.//
s/\.[^)]*):time=/ /
s/144.124.//
s/\.[^=]*=/ /g
s/\./ /g' | sort -n |
nawk 'BEGIN {
nm[1] = "Aberdeen"
nm[2] = "Barlinnie"
nm[3] = "Castle Huntly"
nm[4] = "Cornton Vale"
nm[5] = "Dumfries"
nm[6] = "Dungavel"
nm[7] = "Edinburgh"
nm[8] = "Friarton"
nm[9] = "Glenochil"
nm[10] = "Greenock"
nm[11] = "Inverness"
nm[12] = "Longriggend"
nm[13] = "Low Moss"
nm[14] = "Noranside"
nm[15] = "Penninghame"
nm[16] = "Perth"
nm[17] = "Peterhead"
nm[18] = "Polmont"
nm[19] = "Shotts"
nm[20] = "Calton House"
nm[21] = "College"
nm[22] = "Central Stores"
nm[23] = "HM Inspecorate"
nm[24] = "Stats Unit"
}
{if (last != $1)
{ if (last != "")
{ print last " " cnt " " tot/cnt " " nm[last] }
tot = 0
cnt = 0
last = $1 }
cnt++
tot += $2 } END { print last " " cnt " " tot/cnt " " nm[last] }' > sitetimes$$.lis

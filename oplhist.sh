#!/bin/sh
# Convert pacct.txt into a number of users histogram
gawk -F\| 'BEGIN {
dy[0] = "Sun"
dy[1] = "Mon"
dy[2] = "Tue"
dy[3] = "Wed"
dy[4] = "Thu"
dy[5] = "Fri"
dy[6] = "Sat"
}
/^ora7_sv/ {
split($5,arr1," ")
split(arr1[3],arr,":")
dow = (arr1[2] + 3) % 7 
print "user" NR " " int($4) " " (907113600 + arr1[2]*86400 + arr[1]*3600 + arr[2]*60 + arr[3])  dy[dow] " " $5 " BST 1998"
}' pacct | sort -n +2 |   /e2soft/perfdb/usehist 1200 | tee junk.log | gawk '/Oct/ {
if (NF == 6)
{
   if ($2 > dy)
       dy=$2
}
else
if ($6 > dy)
    dy = $6
lt=0
}
 NF == 5 {
if ($1 ~ "=")
    next
split($1,arr,":")
if (arr[1] < lt)
    dy++
lt = arr[1]
if ($3 > 0)
print dy " Oct 1998 " $1 "\t" $2 "\t" $3 "\t" int($2/1200)+1 }'

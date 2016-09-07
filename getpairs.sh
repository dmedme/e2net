#!/bin/sh
# Look up challenge pairs
#
strings loops*.snp | nawk '/_W[0-9][0-9]*;[0-9]/ {
split($0, arr, ";")
fn = arr[2]
getline
if ($0 ~ "SBGUI")
print fn " " $NF
}' |  sort | uniq | nawk 'BEGIN {n = 0}
{while(n < $1)
{
    print "-1,"
    n++
}
n++
print $2 ","
}
END {
while(n < 100)
{
    print "-1,"
    n++
}
}'

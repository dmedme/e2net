#!/e2/bin/bash
# Get rid of spurious 'M' commands following 'X' commands
# and construct End Point records.
#
for i in $*
do
gawk -F ":" 'BEGIN {
ep_cnt = 0
}
/^\\X:/ { print
    a = $2
    b = $3 
    getline
    if ($1 == "\\M" && ((a == $2 && b == $3) || (a == $3 && b == $2)))
        next
}
/^\\M:/ {
    a = $2
    b = substr($3,1,length($3) - 1)
    if (ep[a] == "")
    {
        split(a, arr, ";")
        print "\\E:" arr[1] ":" arr[2] ":" arr[1] ":" arr[2] ":C\\"
        ep[a] = "Y"
    }
    if (ep[b] == "")
    {
        split(b, arr, ";")
        print "\\E:" arr[1] ":" arr[2] ":" arr[1] ":" arr[2] ":L\\"
        ep[b] = "Y"
    }
  
}
{ print }' $i > junk.log
if [ -s junk.log ]
then
grep '^\\E:' junk.log >$i
grep -v '^\\E:' junk.log >>$i
fi
done

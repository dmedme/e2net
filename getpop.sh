#!/bin/sh
gawk -F"|" '{ print $5 "|" ($10 + $11) "|" ($12 + $13)}' alltraf.txt |
sort | gawk -F "|" 'BEGIN {lp = ""
print "Protocol|Packets|Bytes"}
{
    if (lp != $1)
    {
        if (lp != "")
           print lp "|" p "|" b
        lp = $1
        p = $2
        b = $3
    }
    else
    {
        p += $2
        b += $3
    }
}
END {
        if (lp != "")
           print lp "|" p "|" b
}' > protsum.lis
    

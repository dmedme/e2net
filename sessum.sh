#!/bin/sh
# sessum.sh - Summarise the packet traffic details in various ways.
# Available input files.
# - sess.lis is a list of all the packets.
# - sessum.lis has the traffic summarised by directional end point pairs.
# - sessor.lis has the out and returned traffic grouped together.
# *********************************************************************
# snoopfix is a snoop-file reader that doesn't core dump on large files.
#
# It extracts a minimum of data from the snoop trace.
#
# Parameters:
# - Input file (from snoop)
# - Output file (sorted by session end points).
#   - From and to Ethernet addresses
#   - From and to IP addresses
#   - Ethernet Frame Size
#   - Timestamp
#
do_snoop_fix()  {
snoopfix -n $1 | sed '/^$/ d' | sort -t\| +1 -3 +5 > $2
   return
}
# *********************************************************************
# Summarise traffic.
# Parameters:
# - Input file (from do_snoop_fix)
# - Output file.
#   - First ethernet interface
#   - Second ethernet interface
#   - First IP Address
#   - Second IP Address
#   - IP Traffic Packets Out
#   - IP Traffic Bytes Out
#   - IP Traffic Packets Return
#   - IP Traffic Bytes Return
#   - Non-IP Traffic Packets Out
#   - Non-IP Traffic Bytes Out
#   - Non-IP Traffic Packets Return
#   - Non-IP Traffic Bytes Return
# 
do_traff_sum() {
ifname=$1
ofname=$2
nawk -F\| 'function clrvar() {
    eth_to = ""
    eth_from = ""
    ip_to = ""
    ip_from = ""
    len = 0
    cnt = 0
    return
}
BEGIN { clrvar() }
{
    if (eth_from != $2 || eth_to != $3 || ip_from != $6 || ip_to != $7)
    {
        if (eth_to != "")
        {
             print eth_from "|" eth_to "|" cnt "|" len "|" ip_from "|" ip_to
        }
        eth_from = $2
        eth_to = $3
        ip_to = ""
        ip_from = ""
        if ($3 == "ff:ff:ff:ff:ff:ff")
            ip_to = "BROADCAST"
        else
        if ($3 == "1:20:8a:0:0:0" || $3 == "3:0:0:0:0:1")
            ip_to = "MULTICAST"
        if ( $6 != "ARP" && $6 != "REVARP" && $6 != "NCP" && $6 != "IPX0" && $6 != "IPX4"  && $6 != "RIP" && $6 != "LLC"   && $6 != "PUP" && $6 != "UNKNOWN" )
        {
            ip_from = $6
            if (ip_to != "BROADCAST" && ip_to != "MULTICAST")
            {
               if ($7 ~ "224.0.0.")
                   ip_to = "MULTICAST"
               else
               if ($7 ~ "255")
                   ip_to = "BROADCAST"
               else
                   ip_to = $7
            }
        }
        len = $4
        cnt = 1
    }
    else
    {
        len += $4
        cnt++
    }
}
END {
    print eth_from "|" eth_to "|" cnt "|" len "|" ip_from "|" ip_to
}' $ifname | nawk -F\| '{
#
# Summarise traffic by session, getting the addresses the same way round:
# - From and to Ethernet addresses
# - From and to IP addresses
# - Ethernet Frame Size
# - Timestamp
    key= $2 "|" $1
    if (seen[key] == 1)
        print $2 "|" $1 "|" $6 "|" $5 "|" $3 "|" $4 "|R"
    else
    {
        print $1 "|" $2 "|" $5 "|" $6 "|" $3 "|" $4 "|O"
        key= $1 "|" $2
        seen[key] = 1
    }
}' | sort | nawk -F\| 'function clrvar() {
    olen = 0
    ocnt = 0
    rlen = 0
    rcnt = 0
    onlen = 0
    oncnt = 0
    rnlen = 0
    rncnt = 0
    return
}
BEGIN { clrvar()
    eth_to = ""
    eth_from = ""
    ip_to = ""
    ip_from = ""
}
# Combine from and to, and IP and non-IP traffic
{
    if (eth_from != $1 || eth_to != $2)
    {
        if (eth_to != "")
        {
             print eth_from "|" eth_to "|" ip_from "|" ip_to "|" ocnt "|" olen "|" rcnt "|" rlen "|" oncnt "|" onlen "|" rncnt "|" rnlen
        }
        clrvar()
        eth_from = $1
        eth_to = $2
        ip_from = ""
        ip_to = ""
    }
    if ($4 != "")
    {
        ip_from = $3
        ip_to = $4
        if ($NF == "O")
        {
            ocnt += $5
            olen += $6
        }
        else
        {
            rcnt += $5
            rlen += $6
        }
    }
    else
    {
        if ($NF == "O")
        {
            oncnt += $5
            onlen += $6
        }
        else
        {
            rncnt += $5
            rnlen += $6
        }
    }
}
END {
    print eth_from "|" eth_to "|" ip_from "|" ip_to "|" ocnt "|" olen "|" rcnt "|" rlen "|" oncnt "|" onlen "|" rncnt "|" rnlen
}' | nawk -F\| '{
#
# Re-order so that all inter-sub-network traffic has the same orientation.
#
    if ($3 != "")
    {
        split($4,from,".")
        split($3,to,".")
        key = from[1] "." from[2] "." from[3] "." to[1] "." to[2] "." to[3]
        if (seen[key] == 1)
            print $2 "|" $1 "|" $4 "|" $3 "|" $9 "|" $10 "|" $11 "|" $12 "|" $5 "|" $6 "|" $7 "|" $8
        else
        {
            print
            key = to[1] "." to[2] "." to[3] "." from[1] "." from[2] "." from[3]
            seen[key] = 1
        }
    }
    else print
}' | sort -t\| +2 >$ofname
    return
}
# *****************************************************************
# Invocations of the above
do_snoop_fix aefd.snp sess.lis
do_traff_sum sess.lis summar.lis

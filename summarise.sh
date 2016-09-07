#!/bin/sh
# summarise.sh - summarise the trace results.
#
# Summarise by conversation fragment. We want to know, for each
# conversation fragment (ie. Sequence of messages between the same two
# peers):
# - Packet No. of first packet
# - Time from previous packet
# - Number of packets out
# - Number of packets in
# - Volume out
# - Volume in
# - Time on Source
# - Time on destination
#
sort -t \| -n +0 -1 sess.lis | nawk -F\| 'BEGIN {
last_sip=""
last_dip=""
last_sport=""
last_dport=""
}
function output_dets() {
#
#
print first_pack "|" last_sport "|" last_dip "|" last_dport "|" first_run "|" first_gap "|" tsrc "|" tdst "|" nout "|" nin "|" vout "|" vin "|"
    return
}
NF > 1 {
    np = $1
    len = $4
    intv = $5
    vol = $6
    run = $7
    sip = $8
    dip = $9
    sport = $11
    dport = $12 
    if ((last_sip != sip && last_sip != dip) ||  \
        (last_dip != sip && last_dip != dip) ||  \
        (last_dport != dport && last_dport != sport) ||  \
        (last_sport != dport && last_sport != sport))
    {
        if (last_sip != "")
            output_dets()
        else
        {
            intv = 0
            run = 0
        }
        first_pack = np
        first_gap = intv
        first_run = run
        nout = 1
        vout = len
        nin = 0
        vin = 0
        last_sip= sip
        last_dip= dip
        last_sport= sport
        last_dport= dport
        tsrc = 0
        tdst = 0
    }
    else
    {
#
# Packet going to server
#
        if (sip == last_sip)
        {
           nout++
           vout += len
           tsrc += intv
        }
#
# Packet coming back from server
#
        else
        {
           nin++
           vin += len
           tdst += intv
        }
    }
}
END {
    output_dets()
}' | sed 's/|1525|/|SQL*NET V.1|/
s/|139|/|LMX|/
s/|1521|/|SQL*NET V.2|/'

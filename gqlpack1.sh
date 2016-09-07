#!/bin/sh
# gqlpack1.sh - pick out the useful data from the trace.
#
# The -V option to snoop gives one line per protocol layer recognised in
# each captured packet.
#
snoop -i pc.snp -V | nawk 'BEGIN { cnt = 0}
#
# We look at the TCP packets only
#
$6 == "TCP" {
cnt++
len = 0
#
# The line may have TCP flags on it, and thus the length is not always the
# same field number. It is noted as a name=value pair. Therefore, we find the
# length by searching for the name=value entry
#
for (i = 11; i <= NF; i++)
    if (substr($i,1,4) == "Len=")
    {
        len = substr($i,5)
        break
    }
#
# In this particular trace, we were only interested in packets from 130 to
# 1873
# For the packets of interest, output:
# - Packet number
# - Time gap since last packet
# - Source host
# - Destination host
# - Source port
# - Destination port
# - Packet length
#
# We have thus ignored the actual seq and ack values.
#
  if (cnt > 130)
 print $1 "|" $2 "|" $3 "|" $5 "|" substr($8,3) "|" substr($7,3) "|" len
if (cnt == 1873)
    exit
}' | nawk -F "|" 'BEGIN { see_cnt = 0 
OFMT = "%13.6f"
CONVFMT = "%13.6f"
run_time = 0}
#
# We have a series of session objects, keyed by both directions of traffic.
#
# To work things out, we need to also keep:
# - last run time by direction.
# - who has the ball.
#
# This function initialises a session.
# The sessions are notionally in an array, and are keyed by the packet
# source and destination address details. Two key entries, one for each
# direction.
#
# The first packet seen defines the direction "from".
# - Count of packets in each direction
# - Count of bytes in each direction
# - Total Network Time
# - Total One end time
# - Total Other end time 
# We have pf_cnt, packets from, and pt_cnt, packets to, bf_cnt bytes from,
# bt_cnt, bytes to.
#
function ini_sess() {
# Increment the array reference
    see_cnt++
# Generate the two search keys
    from_to = $3 "|" $4 "|" $5 "|" $6
    to_from = $4 "|" $3 "|" $6 "|" $5
    sess_id[from_to] = see_cnt
    sess_id[to_from] = see_cnt
# Packets from = 1
    pf_cnt[see_cnt] = 1
    pt_cnt[see_cnt] = 0
# Bytes from = packet length
    bf_cnt[see_cnt] = $7
    bt_cnt[see_cnt] = 0
# Use the from to order as the session label
    lab[see_cnt] = from_to
# Identify the From address as being the one with the ball
    ball[see_cnt] = "from"
# Note when the last from packet was seen
    lastf[see_cnt] = run_time
    lastt[see_cnt] = 0
    ntf_time[see_cnt] = 0
    ntt_time[see_cnt] = 0
    htf_time[see_cnt] = 0
    htt_time[see_cnt] = 0
# Note that the "From" is not acknowledged
    unack[see_cnt] = "from"
    return see_cnt
}
{
# The messages have a time difference; generate a running time.
    run_time += $2
# Construct the search key and look for it.
    from_to = $3 "|" $4 "|" $5 "|" $6
    s = sess_id[from_to] + 0
#
# Per-line output details
# - pack_no
# - when (run_time)
# - sess_id
# - packs from
# - packs to
# - bytes from
# - bytes to
# - host time from
# - host time to
# - net time from
# - net time to
# A Positive s means we have found the session.
    if (s > 0)
    {
#
# If the message is zero length (acknowledgement only) then the host
# time element associated with the message must be zero
#
        if ($7 == 0)
            ht = 0
        else
#
# Otherwise, we associate the time since the last message with whichever end
# had the ball at that point. This is right. It is independent of which host
# it gets accumulated to. This depends on the direction of this message. Note
# that the host time calculated here includes the network time. We need to
# make some kind of adjustment to separate them.
#
        if (ball[s] == "from")
        {
            ht = run_time - lastf[s] 
            lastf[s] = run_time
        }
        else
        {
            ht = run_time - lastt[s] 
            lastt[s] = run_time
        }
#
# If this message is in the same direction as the original message.
        if (from_to == lab[s])
        {
#
# If there is an unacknowledged message in the other direction, add the time
# interval to the network time, otherwise the network contribution is zero.
            if (unack[s] == "to")
                nt = run_time - lastt[s] 
            else
                nt = 0
#
# If the message is an acknowledgement only, clear the outstanding flag
            if ($7 == 0)
                unack[s] = ""
            else
            {
#
# Otherwise, if there is data, the ball is with the from, and the from is
# unacknowledged.
                ball[s] = "from"
                unack[s] = "from"
            }
            lastf[s] = run_time
#
# Re-output the message with a host and network time contribution
            print $1 "|" run_time "|" lab[s] "|1|0|" $7 "|0|" ht "|0|" nt "|0"
#
# Increment packet count, byte count, network time and host time
            pf_cnt[s]++
            bf_cnt[s] += $7
            ntf_time[s] += nt
            htf_time[s] += ht
        }
        else
        {
#
# If there is an unacknowledged message in the other direction, add the time
# interval to the network time, otherwise the network contribution is zero.
            if (unack[s] == "from")
                nt = run_time - lastf[s] 
            else
                nt = 0
#
# If the message is an acknowledgement only, clear the outstanding flag
            if ($7 == 0)
                unack[s] = ""
            else
            {
                ball[s] = "to"
                unack[s] = "to"
            }
            lastt[s] = run_time
            print $1 "|" run_time "|" lab[s] "|0|1|0|" $7 "|0|" ht "|0|" nt

            pt_cnt[s]++
            bt_cnt[s] += $7
            ntt_time[s] += nt
            htt_time[s] += ht
        }
    }
    else
    {
        s = ini_sess()
        print $1 "|" run_time "|" lab[s] "|1|0|" $7 "|0|0|0|0"
    }
}
END {
print "SESSION SUMMARY"
    for (i = 1; i <= see_cnt; i++)
            print lab[i] "|" pf_cnt[i] "|" pt_cnt[i] "|" bf_cnt[i] "|" bt_cnt[i] "|" htf_time[i] "|" htt_time[i] "|" ntf_time[i] "|" ntt_time[i]

}' > anatomy.txt

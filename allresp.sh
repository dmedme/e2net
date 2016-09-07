#!/bin/sh
# Network summary for the application
#
# @(#) $Name$ $Id$
# Copyright (c) E2 Systems 1997
#
# Parameters:
# 1      - File to process
# 2      - Client Net Mask
# 3      - File of Net Names
# 4 ...  - Server IP Addresses
#
# The output appears on stdout
#
# The program:
# - Makes sure that the conversations are all the same way round (ie. Client/
#   Server), rather than having the order depend on the packet that is seen
#   first
# - Weeds out sessions with low numbers of packets (< 5)
# - Reduces the numbers of columns, by discarding the client port and server
#   MAC and IP Address, and the TCP label.
# - The client MAC address stays, so that sessions through the same router
#   can be identified
# - The Net Mask (specified as a number of bits) parameter tags each session
#   with a Network ID, to facilitate reporting by source network. An obvious
#   problem with the GE Capital network is that the Net Mask varies across the
#   physical network. Perhaps this can be fixed up by hand.
# - The script assumes that the packets are captured on the server, thus,
#   the server and server network times are added together.
#
#set -x
if [ $# -lt 4 ]
then
    echo Provide a file to process, a net mask, a file of net names, and at least one server IP address
    exit
fi
fname=$1
shift
nmask=$1
shift
nname=$1
shift
host_exp="\$6 == \"$1\""
shift
for i in $*
do
    host_exp="$host_exp || \$6 == \"$1\""
done
gawk -F "|" 'BEGIN {
   nmask='"$nmask"' + 0
   if (nmask > 24)
   {
       dv=nmask - 24
   }
   else
   if (nmask > 16)
   {
       dv=nmask - 16
   }
   else
   if (nmask > 8)
   {
       dv=nmask - 8
   }
   else
   {
       dv=nmask
   }
   dv = 2^(8 - dv)
   while((getline<"'"$nname"'") > 0)
   {
       nname[$1] = $2
#       print nname[$1] "|" $1
   }
   print "End Time|MAC|Net|Client|Server port|Client packs|Server packs|Client bytes|Server bytes|Client time|Net Time|Server Time"
}
function get_net(ip) {
   split(ip, arr, ".")
   if (nmask > 24)
   {
       ret = arr[1] "." arr[2] "." arr[3] "." int(arr[4]/dv)*dv
   }
   else
   if (nmask > 16)
   {
       ret = arr[1] "." arr[2] "." int(arr[3]/dv)*dv
   }
   else
   if (nmask > 8)
   {
       ret = arr[1] "." int(arr[2]/dv)*dv
   }
   else
   {
       ret = int(arr[1]/dv)*dv
   }
   x = nname[ret]
   if (x != "")
       return x
   else
       return ret
}
$5 == "TCP" && ($10 + $11) > 2 && $16 >= 0 && $17 >= 0 && $18 >= 0 && $19 >= 0 {
# Sample Input
#14 Oct 1998 11:49:13.174444|Session Complete|08:00:2b:e7:36:cb|00:e0:29:00:b6:d7|TCP|192.0.0.14|192.0.0.233|1075|23|44|26|2816|1654|0|0|9.014392|2.181480|0.015099|0.071009|
#
# For a long trace, nearly all of them must be the right way round
#
#if (('"$host_exp"') && (($8+0) < ($9+0)))
#{
#    net = get_net($7)
#    print $1 "|" $4 "|" net "|" $7 "|" $8 "|" $11 "|" $10 "|" $13 "|" $12 "|" $19 "|" $18 "|" ($17 + $16)
#}
#    else
{
    net = get_net($6)
    print $1 "|" $3 "|" net "|" $6 "|" $9 "|" $10 "|" $11 "|" $12 "|" $13 "|" $16 "|" $17 "|" ($18 + $19)
}
}' $fname
exit

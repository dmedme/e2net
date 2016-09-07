#!/bin/sh
# traftest.sh - test out the Traffic Generator
# Copyright (c) E2 Systems 1995
#
# Four actors work through the facilities of the IP Traffic Generator
#
cat << EOF > traftest
DT|0|.5
EP|0|0|2|localhost|tcp|C|10000
EP|0|1|2|localhost|udp|P|10001
EP|1|2|2|localhost|tcp|L|10002
EP|1|3|2|localhost|tcp|C|10003
EP|2|4|2|localhost|tcp|L|10004
EP|3|5|2|localhost|udp|P|10005
EP|0|6|2|localhost|tcp|C|10006
EP|0|7|2|localhost|tcp|C|10007
ST|0|A1|First Test Time
SR|0|2|64
SR|6|2|64
SR|2|6|64
SR|7|2|64
DT|1|5.5
SR|3|4|64
SR|2|7|64
SC|2|7
SR|6|2|64
SR|2|6|64
DT|3|6.5
SR|6|2|64
SR|2|6|64
SR|4|3|64
SR|2|0|64
SR|1|5|64
SR|5|1|64
TT|0|A1
ST|0|A2|Second Test Time
SR|0|2|64
DT|1|7.5
SR|3|4|64
DT|3|8.5
SR|4|3|64
SR|2|0|64
SR|1|5|64
SR|5|1|64
SC|0|2
SC|3|4
SC|6|2
SC|1|5
TT|0|A2
EOF
ipdrive -v -d 4 traf1 1 1 1 traftest 1 > act1.log 2>&1 &
l1pid=$!
ipdrive -v -d 4 traf2 1 1 1 traftest 2 > act2.log 2>&1 &
l2pid=$!
ipdrive -v -d 4 traf3 1 1 1 traftest 3 > act3.log 2>&1 &
l3pid=$!
sleep 1
if ipdrive -v -d 4 traf0 1 1 1 traftest 0 > act0.log 2>&1
then
kill -15 $l1pid $l2pid $l3pid
kill -9 $l1pid $l2pid $l3pid
fi
exit

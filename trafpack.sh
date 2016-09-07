#!/bin/sh
# trafpack.sh - Summarise the traffic by event.
#
nawk -F\| 'BEGIN {
flag = 0
}
/^ST/ { act = $NF
flag = 1
packs = 0
bytes = 0
next
}
/^SR/ && (flag == 1) { packs++
bytes = bytes + $4
}
/^TT/ { flag = 0
print $NF ":" act ":" packs ":" bytes
}' $* | sort
exit

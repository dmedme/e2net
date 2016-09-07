#!/bin/sh
# capt3.sh - Look for rogue transactions
save_id=0
trap "" 1 2
rm -f snoop.fifo
export E2_T3_PORTS
while :
do
    mkfifo snoop.fifo
    snoop -o snoop.fifo port 80 or port 9000 or port 9500 2>/dev/null &
    p=$!
#    t3mon -l 8 snoop.fifo
    genconv -l 8 snoop.fifo >t3mon.log 2>&1
    kill -9 $p
    rm -f snoop.fifo
    mkdir save.$save_id
    mv core t3_*.msg t3mon.log save.$save_id
    save_id=`expr $save_id + 1`
done

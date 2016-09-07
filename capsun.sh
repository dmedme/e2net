#!/bin/sh
# capture.sh - Look for rogue transactions
trap "" 1 2
rm -f snoop.fifo
while :
do
    mkfifo snoop.fifo
    snoop -o snoop.fifo host 192.0.0.14 2>/dev/null &
    p=$!
    genconv snoop.fifo
    kill -9 $p
    rm -f snoop.fifo
done

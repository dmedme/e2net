#!/bin/sh
# capsql.sh - Log SQL sessions in human readable form.
trap "" 1 2
loop=1
rm -f snoop.fifo
while :
do
    mkfifo snoop.fifo
    snoop -o snoop.fifo 2>/dev/null &
    p=$!
    sqlmul snoop.fifo
    kill -9 $p
    rm -f snoop.fifo
    for i in sql_*.sql
    do
       mv $i ${loop}_$i
    done
    loop=`expr $loop + 1`
done

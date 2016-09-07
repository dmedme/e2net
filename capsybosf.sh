#!/usr/bin/posix/sh
# Process Sybase SQL usage in real-time, continuously
save_id=0
E2_SYB_PORTS=4100
export E2_SYB_PORTS
trap "break" 1 2 15
pfconfig +promisc +copyall tu0
while :
do
    rm -f badcap1.fifo badcap2.fifo
    mkfifo badcap1.fifo badcap2.fifo
    tcpdump -s 1600 -w badcap1.fifo host asp and \( port $E2_SYB_PORTS or port 23 \) &
    tcp_pid=$!
    aixdump2snp -o badcap2.fifo badcap1.fifo &
    aix_pid=$!
#
# The process of looking up plans seems to cause lots of dropped packets.
#
#    badsort -m badsort.exp -q automation/hourly21/channel4/sams badcap2.fifo &
    badsort -m badsort.exp badcap2.fifo &
    bad_pid=$!
    wait
    kill -15 $aix_pid $tcp_pid
    mkdir save.$save_id
    mv core chan4_* syb_*.sql save.$save_id
    cp badsort.exp save.$save_id
    save_id=`expr $save_id + 1`
done
kill -15 $tcp_pid $aix_pid
rm -f badcap1.fifo badcap2.fifo
pfconfig -promisc -copyall tu0

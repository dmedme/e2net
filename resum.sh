#!/bin/sh
# For a file extracted from a genconv log by resum, work out:
# - How much traffic there was for our troubled session
# - Link  traffic over the same time
#
for i in /oracle/glas_swdswis1/capture/cap*/badsam*.dat
do
echo $i
nawk -F"|" 'function get_net(x) {
    split(x, arr, ".")
    net = arr[1] "." arr[2] "." arr[3]
    return net
}
NR == 1 { if ($4 == "144.2.1.29")
        host = $5
    else
        host = $4
    link = get_net(host)
    host_cnt = 0
    host_bytes = 0
    link_cnt = 0
    link_bytes = 0
    ft = ""
}
NF == 20 {
    if (ft == "")
        ft = $2
    lt = $2
    if ($16 == host || $17 == host)
    {
        host_cnt++
        host_bytes += $3
        print $2 "|" host "|" $3
    }
    else
    if (get_net($16) == link || get_net($17) == link)
    {
        link_cnt++
        link_bytes += $3
        print $2 "|" net "|" $3
    }
}
END {
   print "Summary|" ft "|" lt "|" host "|" host_cnt "|" host_bytes "|" link "|" link_cnt "|" link_bytes
}' $i
done  | tee fred.log | egrep 'glas_|Summary' > fred1.log

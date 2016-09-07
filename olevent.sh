#!/bin/sh
# olevent.sh
# This program takes the list of timing points for a script, and inserts
# them in the SQL at the appropriate place.
if [ $# -lt 3 ]
then
    echo Provide an SQL file and its corresponding Event file and a starting event
    exit 1
fi
sqln=$1
trfn=$2
nawk -F: -v trfn=$trfn -v ev_cnt=$3 'BEGIN {
    ev_cnt = 160 + ev_cnt
    stform = "\\S%2X:1800:%s\\\n"
    ttform = "\\T%2X:\\\n"
    pack_no = 0
    ext_from_file(trfn)
}
function ext_from_file(trfn)
{
    if (pack_no != 0)
    {
        printf ttform, ev_cnt
        ev_cnt ++
    }
    if (( getline<trfn) < 1)
    {
        nxt_pack = 9999999
        return
    }
    nxt_pack = $1
    desc = $2
    printf stform,ev_cnt,desc
    return
}
/^\\C:/ { pack_no = $2
    print
    if (pack_no > nxt_pack)
        ext_from_file(trfn)
    next
}
{ print }
END { ext_from_file(trfn) }' $sqln >temp$$
mv temp$$ $sqln
exit

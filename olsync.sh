#!/bin/sh
# olsync.sh
# This program identifies the timing points in SQL scripts, and places
# them in the corresponding positions in packet scripts.
# They may need to be moved slightly by hand, because the SQL packet is not
# the first in the dialogue.
if [ $# -lt 2 ]
then
    echo Provide an SQL file and its corresponding Traffic file
    exit 1
fi
sqln=$1
trfn=$2
nawk -v sqln=$sqln 'function ext_from_file(fname) {
    FS=":"
    while((getline<fname)>0)
    {
        if ($1 == "\\C")
        {
            pn = $2 + 0
            for(i = 0; i < 3; i++)
            {
                getline<fname
                if ($0 == "/")
                    break
                if (substr($1,1,2) == "\\S")
                    st[pn] = sprintf(stform,substr($1,3,2),
                                  substr($3,1,length($3) - 1))
                else
                if (substr($1,1,2) == "\\T")
                    tt[pn] = sprintf(ttform, substr($1,3,2))
            }
        }
    }
    close(fname)
}
function catch_up(arg) {
    if (backlog)
        print ln[0]
    if (arg != "")
        print arg
    for (i = 1; i < backlog; i++)
         print ln[i]
    backlog = 0
    return
}
BEGIN {
    ev_cnt = 0
    stform = "ST|0         |%2.2s|%-32.32s"
    ttform = "TT|0         |%2.2s"
    ext_from_file(sqln)
    backlog = 0
    FS="|"
    flag = 0
    pack_no = 0
}
/^DT/ {
    if ($3 > 1)
    {
        catch_up("")
        ln[0] = $0
        backlog = 1
    }
    else
    if (backlog)
        ln[backlog++] = $0
    else
        print
    next
}
/^SR/ {
    pack_no++
    if (st[pack_no] != "" || tt[pack_no] != "")
    {
        if (tt[pack_no] != "")
            print tt[pack_no]
        catch_up(st[pack_no])
    }
    if (backlog)
        ln[backlog++] = $0
    else
        print
    next
}
END {
    catch_up("")
}
{ print }' $trfn >temp$$
mv temp$$ $trfn
exit

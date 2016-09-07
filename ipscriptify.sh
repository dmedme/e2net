#!/bin/sh
# ipscriptify.sh - create a network script from a snoop file
#
# Parameters:
# 1  -  snoop file to process
# 2  -  root output file name
# 3  -  IP address of the PC that defines the flow of control
# 4  -  IP address of the application server
# 5  -  IP address of the database server
# 6  -  Base port for re-allocating port numbers
# 7 ... extra arguments needed by trafmul (eg. -l 8 (input aligned on
#       64 bit boundaries, a la Solaris 8) or -s (snap headers present))
#
# Create a directory to correspond to the root output file name, set up
# the appropriate environment variables, and then process the snoop file with
# trafmul. Process the trafmul output so that:
# -  We get a script ready for ipdrive
# -  We get the session summary, as recorded
# -  We get a traffic summary (produced by ipdanal)
# -  We get runout file fragments, named by host (make this a separate
#    function, since we may want to redo this automatically?).
#
# We would routinely expect to see three different runout fragments, assuming
# that, as has been found to be the optimum case, the web server and the 
# application server are the same system
# - The client (actor 0). A line would be:
#    - number of users (default 10)
#    - the script name (as provided)
#    - the number of transactions (default 10)
#    - think time (default 10)
#    - actor ID (must be 0)
#    - 3 more rubbish values
# - The application server, web server and database servers would have
#    - number of users (ignored, should be 1)
#    - the script name (as provided)
#    - the number of transactions (should be the same in all fragments, so 10)
#    - think time (default 10)
#    - actor count (1, 2 or 3)
#    - Up to 3 actor values, padded out with rubbish values to give 3 in all
#
if [ $# -lt 6 ]
then
    echo "Provide a snoop file name, a script name, the PC IP address, the"
    echo "Application Server's IP address, the Database Servers IP address"
    echo "and a base port number for re-mapping the captured port numbers"
    exit
fi
if [ ! -f "$1" ]
then
     echo snoop file \'$1\' does not exist
     exit
fi
snp=$1
shift
dir=$1
shift
if [ ! -d "$dir" ]
then
    if mkdir "$dir"
    then
        :
    else
        echo Script name does not correspond to a directory
        exit
    fi
fi
script=`basename $dir`
#
# Passed host addresses
#
E2_USER_HOST=$1
export E2_USER_HOST
shift
E2_APP_SERVER=$1
export E2_APP_SERVER
shift
E2_DB_SERVER=$1
export E2_DB_SERVER
shift
E2_BASE_PORT=$1
export E2_BASE_PORT
shift
echo E2_USER_HOST=$E2_USER_HOST >$dir/capset.sh
echo E2_APP_SERVER=$E2_APP_SERVER >>$dir/capset.sh
echo E2_DB_SERVER=$E2_DB_SERVER >>$dir/capset.sh
echo E2_BASE_PORT=$E2_BASE_PORT >>$dir/capset.sh
#
# Extra arguments for trafmul
#
extra_args=$*
PATH_AWK=${PATH_AWK:-gawk}
export PATH_AWK
# ******************************************************************* 
# Process the snoop file with trafmul
#
trafmul $extra_args $snp 2>/dev/null | $PATH_AWK -F"|" 'BEGIN {
    h_cnt=0
    e_cnt=0
    e2sync_flag = 0
}
e2sync_flag == 0 {
    if ($0 ~ "ST")
        e2sync_flag = 1
    else
    if ($0 ~ /^EP/)
        print
    else
        next
}
/^ST/ { print $NF >"'$dir/narr.txt'" }
/^DT/ { if ($2 != 0) next }
/^\\C:/ { print substr($0,4,length($0) - 4) >"'$dir/sess.txt'"
    next
}
/^\\Corruption/ { print "At input line " NR " " substr($0,2,length($0) - 2) >"'$dir/errs.txt'"
    next
}
/^\\X:/ {
    next
}
/^#EP/ {
    old_port = $NF
    getline
#
# Ignore the e2sync packets
#
    if (old_port == 7 || ($6 == "udp" && $5 == "'$E2_USER_HOST'"))
        next
    host = $5
    if (ep[$0] == 0)
    {
        e_cnt++
        ep[$0] = e_cnt
        if ( host != "'$E2_USER_HOST'")
        {
            print host " " old_port " => " $NF >"'$dir/port_remap.txt'"
            i = h[host]
            if (i == 0)
            {
#
# This should be a listen
#
                h_cnt++
                h[host] = h_cnt
                hst[h_cnt] = host
                act_cnt[h_cnt] = 1
                acts[h_cnt] = $2
                lastl[h_cnt] = $2
                print
            }
            else
            {
#
# If this is a connect, assign the actor from the last listen if there is one
#
                if ($7 == "C" && lastl[i] != "")
                {
                    print $1 "|" lastl[i] "|" $3 "|" $4 "|" $5 "|" $6 "|C|" $8
                }
                else
                {
                    act_cnt[i]++
                    acts[i] = acts[i] " " $2
                    print
                }
            }
        }
        else
            print
    }
    else
    if ($7 == "L")
    {
        i = h[host]
        if (i != 0)
            lastl[i] = $2
    }
    next
}
{ print >"'$dir/bulk.tmp'" }
END {
# ****************************************************************************
# Append the bulk to the list of End Points
#
    close("'$dir/bulk.tmp'")
    while ((getline<"'$dir/bulk.tmp'") > 0)
        print
# ****************************************************************************
# Produce the runout entries
# - The client (actor 0). A line would be:
#    - number of users (default 10)
#    - the script name (as provided)
#    - the number of transactions (default 10)
#    - think time (default 10)
#    - actor ID (must be 0)
#    - 3 more rubbish values
#
    print "10 '$script' 10 10 0 must have three" >"'$dir/client.run'"
    close("'$dir/client.run'")
# ****************************************************************************
# - The application server, web server and database servers would have
#    - number of users (ignored, should be 1)
#    - the script name (as provided)
#    - the number of transactions (should be the same in all fragments, so 10)
#    - think time (default 10)
#    - actor count (1, 2 or 3)
#    - Up to 3 actor values, padded out with rubbish values to give 3 in all
#
    for (i = 1; i <= h_cnt; i++)
    {
        if (hst[i] == "'$E2_APP_SERVER'")
            fname = "'$dir/app_server.run'"
        else
        if (hst[i] == "'$E2_DB_SERVER'")
            fname = "'$dir/db_server.run'"
        else
            fname = "'$dir/'" hst[i] ".run"
        if (act_cnt[i] == 1)
            acts[i] = acts[i] " must have"
        else
        if (act_cnt[i] == 2)
            acts[i] = acts[i] " must"
        print "1 '$script' 10 10 " act_cnt[i] " " acts[i] >fname
        close(fname)
    }
}' >$dir/$script.trf
#
# Now process the script with ipdanal to give a second by second plot
#
cd $dir
rm -f bulk.tmp
ipdanal -t $script.trf >$script.sbs

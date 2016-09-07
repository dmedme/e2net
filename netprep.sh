#!/bin/sh
# Do some work on snoop files for the purpose of exmining the network traffic
# patterns.
case $PATH in
*/e2soft/e2net*)
    ;;
*)
    PATH=$PATH:/cygdrive/c/e2soft/e2net
    export PATH
esac
if [ $# -lt 1 ]
then
    echo Provide a list of snoop files to be processed in the current directory
    exit
fi
args=$*
for i in $args
do
#
# We are going to process each file with ipscriptify.sh
#
#
# It will create a directory to correspond to the root output file name, set up
# the appropriate environment variables, and then process the snoop file with
# trafmul. It will then process the trafmul output so that:
# -  We get a script ready for ipdrive
# -  We get the session summary, as recorded
# -  We get a traffic summary (produced by ipdanal)
# -  We get runout file fragments, named by host
# ****************************************************************************
root_fname=`echo $i | sed 's=.*/\([^.]*\)\.[^.]*$=\1='`
if [ "$root_fname" = "$i" ]
then
    echo Name clash between snoop file $i and target script directory
    continue
fi
# ****************************************************************************
# In order to be able to use ipscriptify.sh, we need to work out what the other
# parameters are. We do this by using snoopfix to pick out the first comment
# packet. The from is the PC IP Address, the to is the server.
#
set -- `snoopfix -a 7 $i | gawk -F"|" '{ print $3 " " $4 ; exit}'`
if [ $# -ne 2 ]
then
    echo $i has no script comments so cannot be processed
    continue
fi
pc_ip=$1
apps_ip=$2
# ****************************************************************************
# Run ipscriptify.sh to do the real work
# Parameters:
# 1  -  snoop file to process
# 2  -  root output file name
# 3  -  IP address of the PC that defines the flow of control
# 4  -  IP address of the application server
# 5  -  IP address of the database server
# 6  -  Base port for re-allocating port numbers
# 7 ... extra arguments needed by trafmul (eg. -l 8 (input aligned on
#       64 bit boundaries, a la Solaris 8) or -s (snap headers present))
ipscriptify.sh  $i $root_fname $pc_ip $apps_ip 127.0.0.1 10000
#
# Pick out the relevant lines from the .sbs file produced by ipdanal
gawk '/^END: / { printf "%d|%d|",$(NF - 1),$NF
for (i = 2; i < NF - 2; i++)
    printf "%s ",$i
printf "%s\n", $(NF - 2)
}' $root_fname/$root_fname.sbs >$root_fname/breakdown.txt
done

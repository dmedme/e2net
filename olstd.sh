#!/bin/sh
# olstd.sh
# This program attempts to identify timing points in sql scripts that
# have already been allocated in other scripts, giving some uniformity,
# and reducing the effort to check out the scripts.
#
# Once this has been done, the events will automatically be dropped in to
# the traffic simulation using the packet numbers.
#
# Initialise - Identify events in existing scripts, and (up to) the first 3
# lines of the following SQL statement.
#
# Then, scan through the passed file. Whenever a timing point is encountered,
# read the following three lines. If they match any of the defined events,
# write out the new event. Now search ahead for the \\T, and edit that as
# well.
if [ $# -lt 2 ]
then
    echo Provide an Input and an Output file
    exit 1
fi
nawk 'function ext_from_file(fname) {
    while((getline<fname)>0)
    {
        if (substr($1,1,2) == "\\S")
        {
            def[ev_cnt] = $0
            for(i = 0; i < 3; i++)
            {
                getline<fname
                if ($0 == "/")
                    break
                ln[mt_cnt++] = $0
            }
            if (i > 0)
            {
                cnt[ev_cnt] = i
                ev_cnt++
            }
        }
    }
    close(fname)
}
function search_list() {
    getline
    ln1 = $0
    getline
    if ($0 == "/")
    {
        ln2 = ""
        ln3 = ""
    }
    else
    {
        ln2 = $0
        getline
        if ($0 == "/")
            ln3 = ""
        else
            ln3 = $0
    }
#
# j is the corresponding event, i is the match line
#
    i = 0
    for (j = 0; i < ev_cnt; j++)
    {
         if (ln[i]==ln1&&(ln2==""||ln2==ln[i+1])&&(ln3==""||substr(ln3,1,10)==substr(ln[i+2],1,10)))
             return 1
         i += cnt[j]
    }
    return 0
}
function catch_up() {
    print ln1
    if (ln2 != "")
    {
        print ln2
        if (ln3 != "")
            print ln3
        else
            print "/"
    }
    else
        print "/"
    return
}
BEGIN {
    ev_cnt = 0
    mt_cnt = 0
    ext_from_file("sql/script1.sql")
    ext_from_file("sql/script2.sql")
    ext_from_file("sql/script3.sql")
}
/^\\S/ {
    sav = $0
    if (search_list())
    {
#
# We have found a match
#
        print def[j] 
        catch_up()
        while(0 < getline)
        {
            if (substr($0,1,2) == "\\T")
            {
                print "\\T" substr(def[j],3,2) ":\\"
                next
            }
            else
                print $0
        }
    }
    else
    print sav
    catch_up()
    next
}
{ print }' $1 > $2
exit

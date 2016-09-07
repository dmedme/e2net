#!/sbin/sh
# Generate a path script from the snoop trace
#
if [ $# != 1 ]
then
    echo Provide a snoop file
    exit
fi
in=$1
bpcs -n $in | nawk -F\| '{flag = 0}
/^$/ { flag = 1
next
}
/\|/ { if (flag == 0)
    lst = $5
else
{
    diff = $5 - lst
    if (diff > 0)
        print "\\W " int(diff) "\\"
    lst = $5
    next
}
flag = 0
next
}
{ if (flag == 1)
    print "'\''\n'\''"
flag = 0
    print $0
}' | sed 's/:1200:/:20:/' | nawk 'BEGIN {snum = 0
fbase="'$in'"}
/^\\S..:20:.*_U/ {
if (snum != 0)
{
    getline
    print "\\TM1:\\">outf
    next
}
}
/11110/ {
    if (snum != 0)
    {
    getline
    print "tab">outf
    next
    }
}
/119810/ {
    if (snum != 0)
    {
    getline
    print "ent">outf
    next
    }
}
/:::/ {
    if (snum != 0)
    {
    getline
    print "\\TM0:\\">outf
    next
    }
}
/SBGUI/ {if (snum > 0)
    close(outf)
snum++
outf=fbase "." snum ".ech"
print "\\Mtab=11110\\">outf
print "\\Ment=119810\\">outf
print "\\SM0:20:.::Echo\\">outf
print "\\SM1:20:_U::Entry Acknowledge\\">outf
print "'\''telnet localhost'\''">outf
print "\\SM3:20:login::Login prompt\\">outf
print "\\TM3:\\">outf
print "``\n">outf
print "\\SM4:20:assword::Password prompt\\\n">outf
print "\\TM4:\\">outf
print "`train1">outf
print "`">outf
print "\\SN1:20:_W:SBGUI SBClient-Rel-2.4.1.2/VT220/GeminiHR/ WNR :_TM1::GUI Prompt\\">outf
print "\\TN1:\\">outf
print "`train1">outf
print "`">outf
getline
next
}
snum != 0 {print $0>outf}'

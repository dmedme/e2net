#!/bin/sh
nawk 'BEGIN {
x1 = ""
x2 = ""
x3 = ""
x4 = ""
x5 = ""
x6 = ""
}
{ x1 = x2
x2 = x3
x3 = x4
x4 = x5
x5 = x6
x6 = $0
}
/EJB Exception/ { print x1
print x2
print x3
print x4
print x5
print x6
for (i = 6; i > 0; i--)
{
    getline
    print $0
}}' /bea/wlserver6.1/config/StellarLive/logs/StellarLiveManaged1.log*  >norm_except.log
nawk 'BEGIN {
x1 = ""
x2 = ""
x3 = ""
x4 = ""
x5 = ""
x6 = ""
}
{ x1 = x2
x2 = x3
x3 = x4
x4 = x5
x5 = x6
x6 = $0
}
/Exception/ { print x1
print x2
print x3
print x4
print x5
print x6
for (i = 30; i > 0; i--)
{
    getline
    print $0
}}' /bea/wlserver6.1/config/StellarLive/logs/JDBC*.log* > sql_except.log

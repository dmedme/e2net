#!/bin/sh
# Check for unreported List elements
nawk '/^DispAction/ {flag = 1
next
}
flag == 1 && $0 ~ /^\\D:E\\$/ {
    getline
    if ($0 !~ "RESPONSE")
        print FILENAME "|" FNR
    flag = 0
}' save.1/*.msg save.1/*.log >fred.log

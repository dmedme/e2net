#!/bin/sh
# Produce a moderately cleaned up SQL Trace from a snoop packet trace for
# an Openlink dialogue.
olsql $* | sed 's/
//g
s/[ 	][ 	]*$//
/^$/d
s/^[ ]*[Ss][Ee][Ll][Ee][Cc][Tt]/SELECT/
s/^[ ]*[Uu][Pp][Dd][Aa][Tt][Ee]/UPDATE/
s/^[ ]*[Dd][Ee][Ll][Ee][Tt][Ee]/DELETE/
s/^[ ]*[Ii][Nn][Ss][Ee][Rr][Tt]/INSERT/
s/^[ ]*[Bb][Ee][Gg][Ii][Nn]/BEGIN/
s/^[ ]*[Aa][Ll][Tt][Ee][Rr]/ALTER/
s/^[ 	][ 	]*/ /'

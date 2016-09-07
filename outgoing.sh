#!/bin/bash
sqlite3 capsess_vlan68.db << EOF
.output posstunnel.lis
select * from capsess where
 dip in ( '10.200.34.75','10.200.68.75')
   and sip not like '10.%'
   and sip not like '192.168.%'
   and sport in (80,443)
   and pin > 10
   and pout > 10
   and bout < bin
union 
select * from capsess where
 sip in ( '10.200.34.75','10.200.68.75')
   and dip not like '10.%'
   and dip not like '192.168.%'
   and dport in (80,443)
   and pin > 10
   and pout > 10
   and bout > bin;
select distinct sip from capsess where
 dip in ( '10.200.34.75','10.200.68.75')
   and sip not like '10.%'
   and sip not like '192.168.%'
   and sport in (80,443)
   and pin > 10
   and pout > 10
   and bout < bin
union 
select distinct dip from capsess where
 sip in ( '10.200.34.75','10.200.68.75')
   and dip not like '10.%'
   and dip not like '192.168.%'
   and dport in (80,443)
   and pin > 10
   and pout > 10
   and bout > bin;
EOF

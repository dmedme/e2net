#!/bin/sh
# rootthings.sh - E2 Healthcheck commands that need to be executed by root
# Assemble the data on a (currently) free disk
PATH=/u/users/e2dxe/e2net:$PATH
export PATH
cd /u/prod/dbs/vol_t/e2
rm -f netsam.snp
mkfifo netsam.snp
llctrace2snp netsamaa.enc netsamab.enc netsamac.enc netsamad.enc netsamae.enc >netsam.snp &
genconv netsam.snp  2>&1 | grep '|Session ' > sessum.txt
wait
llctrace2snp netsamaa.enc netsamab.enc netsamac.enc netsamad.enc netsamae.enc >netsam.snp &
sqlmul netsam.snp >netsam.log 2>&1
wait
grep '|RESPONSE|' sql_*.sql path_* netsam.log > allresp.txt
exit

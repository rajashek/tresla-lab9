#!/bin/bash
make clean; make
echo "Sender"
date1=$(date +"%s")
date
echo "sending data $2"
./fscp -s -h $1 -f $2 -ack 3 >/dev/null 2>&1 
echo "receiving data $3"
./fscp -r -f $3 > /dev/null 2>&1 
date2=$(date +"%s")
date
diff=$(($date2-$date1))
echo "$(($diff / 60)) minutes and $(($diff % 60)) seconds elapsed."
echo "comparison results "
cmp $2 $3
echo $?
echo "done" 

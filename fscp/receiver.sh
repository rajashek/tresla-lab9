#!/bin/bash
make clean; make
echo "Receiver!"
echo "Receiving $2"
./fscp -r -f $2 > /dev/null 2>&1
echo "Sending $2 back to the sender" 
./fscp -s -h $1 -f $2 -ack 3 > /dev/null 2>&1

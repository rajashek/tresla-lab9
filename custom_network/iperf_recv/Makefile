CC = gcc
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
PCAPFLAGS=-lpcap

iperf_recv: main.o interface.o
	$(CC) $(CFLAGS) -o iperf_recv main.o interface.o $(PCAPFLAGS) -lrt

main.o: main.c
	$(CC) $(CFLAGS) -c main.c $(PCAPFLAGS)

interface.o: ../interface.h ../interface.c
	$(CC) $(CFLAGS) -c ../interface.c

clean:
	rm -f *.o iperf_recv
CC = gcc
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
PCAPFLAGS=-lpcap

ping: main.o interface.o
	$(CC) $(CFLAGS) -o ping main.o interface.o $(PCAPFLAGS) -lrt

main.o: main.c
	$(CC) $(CFLAGS) -c main.c $(PCAPFLAGS)

interface.o: ../interface.h ../interface.c
	$(CC) $(CFLAGS) -c ../interface.c

clean:
	rm -f *.o ping
CC = gcc
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
PCAPFLAGS=-lpcap

pong: main.o interface.o
	$(CC) $(CFLAGS) -o pong main.o interface.o $(PCAPFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c $(PCAPFLAGS)

interface.o: ../interface.h ../interface.c
	$(CC) $(CFLAGS) -c ../interface.c

clean:
	rm -f *.o pong
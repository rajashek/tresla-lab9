CC = gcc
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
PCAPFLAGS=-lpcap

router: main.o interface.o sniffer.o utils.o
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -o router main.o interface.o sniffer.o $(PCAPFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

interface.o: ../interface.h ../interface.c
	$(CC) $(CFLAGS) -c ../interface.c

sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -c sniffer.c $(PCAPFLAGS)

clean:
	rm -f *.o router

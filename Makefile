CC = gcc
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
PCAPFLAGS=-lpcap

router: main.o interface.o utils.o route.o sniffer.o
	$(CC) -g $(CFLAGS) $(PTHREADFLAGS) -o router main.o interface.o utils.o route.o sniffer.o $(PCAPFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -g -c main.c

interface.o: interface.c interface.h
	$(CC) $(CFLAGS) -g -c interface.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -g -c utils.c


route.o: route.c route.h
	$(CC) $(CFLAGS) -g -c route.c


sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -g -c sniffer.c $(PCAPFLAGS) 

clean:
	rm -f *.o router

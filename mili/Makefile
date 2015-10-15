CC = g++
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
GDBFLAGS =-g
fscp: main.o receiver.o ack.o interface.o
	$(CC) $(CFLAGS) $(GDBFLAGS) $(PTHREADFLAGS) -o fscp main.o  receiver.o ack.o interface.o

interface.o: interface.c
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(GDBFLAGS) -c interface.c
main.o: main.c
	$(CC) $(CFLAGS) $(GDBFLAGS) -c main.c 


receiver.o: receiver.c
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(GDBFLAGS) -c receiver.c

ack.o: ack.c
	$(CC) $(CFLAGS) $(GDBFLAGS) -c ack.c

clean:
	rm -f *.o

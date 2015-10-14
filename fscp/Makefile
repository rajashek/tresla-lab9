CC = g++
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
GDBFLAGS =-g
fscp: main.o sender.o receiver.o ack.o interface.o
	$(CC) $(CFLAGS) $(GDBFLAGS) $(PTHREADFLAGS) -o fscp main.o sender.o receiver.o ack.o interface.o

interface.o: interface.c
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(GDBFLAGS) -c interface.c
main.o: main.cpp
	$(CC) $(CFLAGS) $(GDBFLAGS) -c main.cpp 

sender.o: sender.cpp
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(GDBFLAGS) -c sender.cpp

receiver.o: receiver.cpp
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(GDBFLAGS) -c receiver.cpp

ack.o: ack.cpp
	$(CC) $(CFLAGS) $(GDBFLAGS) -c ack.cpp

clean:
	rm -f *.o

CC = g++
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS = -pthread
TIMEFLAGS = -lrt

fscp: main.o sender.o receiver.o ack.o interface.o
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -o fscp main.o sender.o receiver.o ack.o interface.o $(TIMEFLAGS)

main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp

sender.o: sender.cpp
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -c sender.cpp

receiver.o: receiver.cpp
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -c receiver.cpp

ack.o: ack.cpp
	$(CC) $(CFLAGS) -c ack.cpp

interface.o: ../interface.h ../interface.c
	$(CC) $(CFLAGS) -c ../interface.c

clean:
	rm -f *.o
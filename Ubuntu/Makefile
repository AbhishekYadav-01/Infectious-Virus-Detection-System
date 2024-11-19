CC = gcc
CFLAGS = -lssl -lcrypto -ltlsh   
LDFLAGS = -ltlsh                

all: main

main: main.o scan.o process.o
	$(CC) -o virus_scan main.o scan.o process.o $(CFLAGS)

main.o: main.c scan.h process.h
	$(CC) -c main.c

scan.o: scan.c scan.h
	$(CC) -c scan.c $(CFLAGS)

process.o: process.c process.h
	$(CC) -c process.c

clean:
	rm -f *.o virus_scan

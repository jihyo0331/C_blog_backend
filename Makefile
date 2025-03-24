CC = gcc
CFLAGS = -Wall -O2 -D_GNU_SOURCE
LIBS = -lmicrohttpd -lcrypt

OBJS = main.o http.o db.o

all: main

main: $(OBJS)
	$(CC) $(CFLAGS) -o main $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o main

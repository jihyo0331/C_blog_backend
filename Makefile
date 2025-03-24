CC = gcc
CFLAGS = -Wall -O2 -D_GNU_SOURCE
LIBS = -lmicrohttpd -lcrypt

OBJS = blog_backend.o http.o db.o

all: blog_backend

blog_backend: $(OBJS)
	$(CC) $(CFLAGS) -o blog_backend $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o blog_backend

#
# Makefile
#

all: add-server add-client

%.o:%.c
	gcc -Wall -I/usr/include/dbus-1.0 -I/usr/lib/aarch64-linux-gnu/dbus-1.0/include -c $< -o $@

add-server: add-server.o
	gcc add-server.o -o add-server -ldbus-1

add-server.o:add-server.c

add-client: add-client.o
	gcc add-client.o -o add-client -ldbus-1

add-client.o:add-client.c

.PHONY: clean
clean:
	rm *.o add-server add-client

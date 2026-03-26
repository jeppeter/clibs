

all:getaddrinfoa

getaddrinfoa:main.o
	gcc -Wall -o $@ $^ -lanl -lpthread

main.o:main.c
	gcc -Wall -c $< -o $@

clean:
	rm -f getaddrinfoa *.o
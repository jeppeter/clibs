

all:getaddrinfoa

getaddrinfoa:main.o
	g++ -Wall -o $@ $^ -lanl -lpthread

main.o:main.c
	g++ -Wall -c $< -o $@

clean:
	rm -f getaddrinfoa *.o
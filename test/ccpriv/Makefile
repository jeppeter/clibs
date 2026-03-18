

all:ccrun

ccrun:cc.o main.o
	gcc -Wall -o ccrun cc.o main.o

%.o:%.c
	gcc -Wall -c $< -o $@

clean:
	rm -f ccrun
	rm -f *.o
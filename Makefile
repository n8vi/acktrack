CFLAGS=-ggdb
LDLIBS = -lpcap

all: demo

demo: acktrack.o demo.o
	gcc -o demo acktrack.o demo.o -lpcap

clean:
	rm -fr *.o $(BINS)

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex=r --args ./demo google.com 80

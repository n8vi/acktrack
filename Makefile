CFLAGS=-ggdb
LDLIBS = -lpcap

all: demo

demo: pcapsocket.o demo.o
	gcc -o demo pcapsocket.o demo.o -lpcap

clean:
	rm -fr *.o $(BINS)

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex=r --args ./demo google.com 80

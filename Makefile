CFLAGS=-ggdb
LDLIBS = -lpcap
SRC=$(wildcard *.c)
BINS=$(patsubst %.c,%,$(SRC))


all: $(BINS)

clean:
	rm -fr *.o $(BINS)

test: all
	# make a connnection to freenode IRC as a demo.  IRC servers immediately send packets on connect, so
	# you can see the sniffer code in action.
	sudo gdb -ex=r --args ./pcapsocket google.com 80

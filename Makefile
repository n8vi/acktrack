CFLAGS=-ggdb
LDLIBS = -lpcap
SRC=$(wildcard *.c)
BINS=$(patsubst %.c,%,$(SRC))


all: $(BINS)

clean:
	rm -fr *.o $(BINS)

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex=r --args ./pcapsocket google.com 80

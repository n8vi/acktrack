CFLAGS=-ggdb
LDLIBS = -lpcap

all: client testpcap1

clean:
	rm -fr *.o client

test: all
	sudo ./client irc.freenode.net 6667

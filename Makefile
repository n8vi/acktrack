CFLAGS=-ggdb
LDLIBS = -lpcap

all: client

clean:
	rm -fr *.o client

test: all
	# make a connnection to freenode IRC as a demo.  IRC servers immediately send packets on connect, so
	# you can see the sniffer code in action.
	sudo ./client irc.freenode.net 6667

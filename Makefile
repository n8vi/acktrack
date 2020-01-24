CFLAGS=-ggdb
LDLIBS = -lpcap

all: client

clean:
	rm -fr *.o client

test: all
	./client 127.0.0.1 22

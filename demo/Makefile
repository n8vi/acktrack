CFLAGS=-ggdb
LDLIBS = -lpcap

all: cdemo

cdemo:  
	(cd ..; make acktrack.o)
	gcc -o cdemo -I.. ../acktrack.o cdemo.cpp $(LDLIBS)

clean:
	rm -fr *.o  cdemo

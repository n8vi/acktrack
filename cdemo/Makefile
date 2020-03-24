CFLAGS=-ggdb
LDLIBS = -lacktrack

all: cdemo

cdemo: ../libacktrack.so
	gcc -o cdemo -I.. cdemo.cpp -L.. $(LDLIBS)

../acktrack.o: ../acktrack.cpp
	(cd ..; make acktrack.o)

../libacktrack.so: ../acktrack.o
	(cd ..; make libacktrack.so)

clean:
	rm -fr *.o *.so cdemo

CFLAGS=-ggdb
LDLIBS = -lacktrack
LDFLAGS = -L..

LOGFILE?=\"acktrack.log\"

ifeq ($(LOG),1)
DEFS=-DLOGFILE=$(LOGFILE)
else
DEFS=
endif

all: cdemo

cdemo: cdemo.o ../libacktrack.so
	gcc -o cdemo -I.. cdemo.o ../libacktrack.so 

cdemo.o: cdemo.cpp ../acktrack.h
	gcc -c cdemo.cpp -I.. $(DEFS)

../acktrack.o: ../acktrack.cpp
	(cd ..; make acktrack.o)

../libacktrack.so: ../acktrack.o
	(cd ..; make libacktrack.so)

clean:
	rm -fr *.o *.so cdemo

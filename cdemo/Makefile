CFLAGS=-ggdb
LDLIBS = -lacktrack

LOGFILE?=\"acktrack.log\"

ifeq ($(LOG),1)
DEFS=-DLOGFILE=$(LOGFILE)
else
DEFS=
endif

all: cdemo

cdemo: cdemo.cpp ../libacktrack.so
	gcc -o cdemo -I.. cdemo.cpp -L.. $(LDLIBS) $(DEFS)

../acktrack.o: ../acktrack.cpp
	(cd ..; make acktrack.o)

../libacktrack.so: ../acktrack.o
	(cd ..; make libacktrack.so)

clean:
	rm -fr *.o *.so cdemo

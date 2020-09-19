LDLIBS=-lpcap
CFLAGS=-ggdb
CC:=$(CC) $(CFLAGS)
SUDO=$(shell which sudo)

all: fixture

fixture: fixture.o acktrack.o
	$(CC) -o fixture fixture.o acktrack.o $(LDLIBS)

acktrack.o: ../acktrack.cpp
	$(CC) -c ../acktrack.cpp $(LDLIBS)

test: fixture
	(cd ../cdemo; make)
	$(SUDO) pytest-3 -p no:logging -v

clean:
	$(SUDO) rm -fr *.o fixture __pycache__

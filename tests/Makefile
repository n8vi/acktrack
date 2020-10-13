LDLIBS=-lpcap -lcunit
CFLAGS=-ggdb
CC:=$(CC) $(CFLAGS)
SUDO=$(shell which sudo)

all: fixture

fixture: fixture.o acktrack.o
	$(CC) -o fixture fixture.o acktrack.o $(LDLIBS)

unittest: unittest.o acktrack.o
	$(CC) -o unittest unittest.o acktrack.o $(LDLIBS)

acktrack.o: ../acktrack.cpp
	$(CC) -c ../acktrack.cpp $(LDLIBS)

cunit: unittest
	./unittest

test: fixture
	(cd ../cdemo; make)
	$(SUDO) pytest-3 -p no:logging -v

clean:
	$(SUDO) rm -fr *.o fixture __pycache__

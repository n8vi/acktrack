LDLIBS=-lpcap -lcunit
CFLAGS=-ggdb
CC:=$(CC) $(CFLAGS)
SUDO=$(shell which sudo)

all: unittest

fixture: fixture.o acktrack.o
	$(CC) -o fixture fixture.o acktrack.o $(LDLIBS)

unittest: unittest.o acktrack.o
	$(CC) -o unittest unittest.o acktrack.o $(LDLIBS)

acktrack.o: ../acktrack.cpp
	$(CC) -c ../acktrack.cpp $(LDLIBS)

test: unittest
	(cd ../cdemo; make)
	$(SUDO) pytest-3 -p no:logging -v
	$(SUDO) valgrind --leak-check=full --error-exitcode=1 ./unittest

clean:
	$(SUDO) rm -fr *.o fixture __pycache__

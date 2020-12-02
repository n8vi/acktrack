LDLIBS=-lpcap -lcunit
CFLAGS=-ggdb
CC:=g++ --coverage $(CFLAGS)
SUDO=$(shell which sudo)

all: unittest

fixture: fixture.o acktrack.o
	$(CC) -o fixture fixture.o acktrack.o $(LDLIBS)

unittest: unittest.o acktrack.o
	$(CC) -o unittest unittest.o acktrack.o $(LDLIBS)

acktrack.o: ../acktrack.cpp
	$(CC) -c ../acktrack.cpp # $(LDLIBS)

unittest.o: unittest.cpp acktrack.o
	$(CC) -c unittest.cpp # $(LDLIBS)

test: unittest
	(cd ../cdemo; make)
	$(SUDO) pytest-3 -p no:logging -v
	make testunits

testunits:
	# $(SUDO) valgrind --suppressions=libpcap.supp --track-origins=yes --log-file="valgrind.log" --leak-check=full --error-exitcode=1 ./unittest
	$(SUDO) valgrind --main-stacksize=500000000 --suppressions=libpcap.supp --track-origins=yes --leak-check=full --error-exitcode=1 ./unittest

clean:
	$(SUDO) rm -fr *.o fixture __pycache__ *.gcda *.gcno *.info valgrind.log




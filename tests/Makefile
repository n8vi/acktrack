LDLIBS=-lpcap
CFLAGS=-ggdb
CC:=$(CC) $(CFLAGS)

all: fixture

fixture: fixture.o acktrack.o
	$(CC) -o fixture fixture.o acktrack.o $(LDLIBS)

acktrack.o: ../acktrack.cpp
	$(CC) -c ../acktrack.cpp $(LDLIBS)

unittests: fixture
	pytest-3 -p no:logging -v

functests:
	@echo
	@../cdemo/cdemo ipv4.google.com 80
	@echo
	@./loopdemo.py
	@echo
	@../cdemo/cdemo ipv6.google.com 80
	@echo


clean:
	sudo rm -fr *.o fixture __pycache__

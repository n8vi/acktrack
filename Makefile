CFLAGS=-ggdb
DESTDIR=/usr/local

all: cdemo/cdemo

cdemo/cdemo: 
	(cd cdemo; make cdemo)

clean:
	(cd cdemo; make clean)
	rm -fr *.o *.so

acktrack.o: acktrack.cpp
	gcc -fPIC -c acktrack.cpp

libacktrack.so: acktrack.o
	gcc -shared -o libacktrack.so acktrack.o -lpcap

install: libacktrack.so
	sudo cp libacktrack.so $(DESTDIR)/lib/

uninstall:
	sudo rm -f $(DESTDIR)/lib/libacktrack.so

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex='set env LD_LIBRARY_PATH $(CURDIR)' -ex=r --args cdemo/cdemo google.com 80

# set env LD_LIBRARY_PATH $(CURDIR)



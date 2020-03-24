CFLAGS=-ggdb
LDLIBS = -lpcap

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

test: all
        #
	# make a connnection to google as a demo. 
        #
	export LD_LIBRARY_PATH=$(CURDIR)
	sudo ldconfig
	sudo gdb -ex='set env LD_LIBRARY_PATH $(CURDIR)' -ex=r --args cdemo/cdemo google.com 80

# set env LD_LIBRARY_PATH $(CURDIR)



CFLAGS=-ggdb
# CFLAGS=-ggdb -Wall -Wextra -Wformat-nonliteral -Wcast-align -Wpointer-arith -Wbad-function-cast -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Winline -Wundef -Wnested-externs -Wcast-qual -Wshadow -Wwrite-strings -Wno-unused-parameter -Wfloat-equal -pedantic -ansi
DESTDIR=/usr/local
SUDO?=sudo
SRCDIR=$(shell pwd)
PROJECT=$(notdir $(SRCDIR))
PROJDESC="A cross-platform library for keeping track of TCP ACKs in response to data sent on a socket."
CC=cc $(CFLAGS)

all: libacktrack.so demo

demo:
	(cd cdemo; make cdemo)

clean:
	(cd cdemo; make clean)
	rm -fr *.o *.so $(PROJECT) *.deb

acktrack.o: acktrack.cpp
	# gcc -fPIC -c acktrack.cpp
	$(CC) -fPIC -c acktrack.cpp

libacktrack.so: acktrack.o
	# gcc -shared -o libacktrack.so acktrack.o -lpcap
	$(CC) -shared -o libacktrack.so acktrack.o -lpcap

install: libacktrack.so
	$(SUDO) cp libacktrack.so $(DESTDIR)/lib/

uninstall:
	$(SUDO) rm -f $(DESTDIR)/lib/libacktrack.so

citest: all
	# needs to run as root, sudo not included here as gitlab-ci doesn't have it.
	# LD_LIBRARY_PATH=$(CURDIR) cdemo/cdemo ipv4.google.com 80
	# LD_LIBRARY_PATH=$(CURDIR) cdemo/loopdemo.py 127.0.0.1
	# LD_LIBRARY_PATH=$(CURDIR) cdemo/loopdemo.py ::1
	LD_LIBRARY_PATH=$(CURDIR) cdemo/cdemo ipv6.google.com 80

test: all
        #
	# make a connnection to google as a demo. 
        #
	# $(SUDO) gdb -ex='set env LD_LIBRARY_PATH $(CURDIR)' -ex=r --args cdemo/cdemo google.com 80
	sudo make citest

deb: libacktrack.so
	mkdir -p $(PROJECT)/DEBIAN
	mkdir -p $(PROJECT)/usr/local/bin
	mkdir -p $(PROJECT)/usr/local/lib
	mkdir -p $(PROJECT)/usr/local/include
	mkdir -p $(PROJECT)/etc/profile.d/
	mkdir -p $(PROJECT)/etc/init.d/
	echo "Package: $(PROJECT)" > $(PROJECT)/DEBIAN/control
	echo "Version: 0.$(shell git log | head -1 | cut -d' ' -f2)" >> $(PROJECT)/DEBIAN/control
	echo "Maintainer: Brad Tarratt" >> $(PROJECT)/DEBIAN/control
	echo "Architecture: $(shell dpkg --print-architecture)" >> $(PROJECT)/DEBIAN/control
	echo "Description: $(PROJDESC)" >> $(PROJECT)/DEBIAN/control
	$(eval DESTDIR=$(shell pwd)/$(PROJECT)/usr/local)
	make DESTDIR=$(DESTDIR) install
	dpkg-deb --build $(PROJECT)


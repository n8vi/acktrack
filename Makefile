CFLAGS=-ggdb
LDLIBS = -lpcap

all: cdemo/cdemo

cdemo/cdemo: 
	(cd cdemo; make cdemo)

clean:
	(cd cdemo; make clean)
	rm -fr *.o 

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex=r --args cdemo/cdemo google.com 80

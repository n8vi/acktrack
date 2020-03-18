CFLAGS=-ggdb
LDLIBS = -lpcap

all: demo

demo: 
	(cd demo; make demo)
	cp demo/demo .

clean:
	(cd demo; make clean)
	rm -fr *.o 

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex=r --args ./demo google.com 80

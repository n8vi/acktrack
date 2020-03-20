CFLAGS=-ggdb
LDLIBS = -lpcap

all: demo/cdemo

demo/cdemo: 
	(cd demo; make cdemo)

clean:
	(cd demo; make clean)
	rm -fr *.o 

test: all
        #
	# make a connnection to google as a demo. 
        #
	sudo gdb -ex=r --args demo/cdemo google.com 80

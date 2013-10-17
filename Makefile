WARN := -W -Wall -Wstrict-prototypes -Wmissing-prototypes
KINC := -I/lib/modules/`uname -r`/build/include
CFLAGS := -O2 -DMODULE -D__KERNEL__ ${KINC}
CC := gcc

all: ipsniff.o 

ipsniff.o :  ipsniff_drv.c sniff.h ioctl.h filter.h
	${CC} ${CFLAGS} -c ipsniff_drv.c -o ipsniff.o
	
clean:
	rm -f *.o  

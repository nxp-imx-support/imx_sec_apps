KBUILD_CFLAGS += -I${KERNEL_SRC}/include/
KBUILD_CFLAGS += -I$(src) -I${KERNEL_SRC}/drivers/crypto 

obj-m += caam-ecdsa.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

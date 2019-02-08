KBUILD_CFLAGS += -I$(src)/include/
KBUILD_CFLAGS += -I${KERNEL_SRC}/include/
KBUILD_CFLAGS += -I$(src) -I${KERNEL_SRC}/drivers/crypto
KBUILD_CFLAGS += -w 
TARGET = caam_sm2

obj-m += $(TARGET).o

caamsm2_drv-objs := caam_sm2.o

all:
	make -C ${KERNEL_SRC} M=$(PWD) modules

clean:
	make -C ${KERNEL_SRC} M=$(PWD) clean

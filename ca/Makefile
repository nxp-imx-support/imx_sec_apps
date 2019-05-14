CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,%.o, $(SRC))

CFLAGS += -I. -I../ta/include -I$(OPTEE_CLIENT_EXPORT)/include -Wall
CFLAGS += -I../../optee-test-imx/host/openssl/include

LDADD += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec -lpthread -lm

LDADDLIB = $(LDADD) -shared -fPIC

ifeq ($(CFG_ARM32_core),y)
COMPILE_NS_USER ?= 32
else
COMPILE_NS_USER ?= 64
endif #CFG_ARM32_core
#ifeq ($(COMPILE_NS_USER),32)
#LDADD += ../../optee-test-imx/host/openssl/lib/arm/libcrypto.a -ldl
#else
#LDADD += ../../optee-test-imx/host/openssl/lib/aarch64/libcrypto.a -ldl
#endif #COMPILE_NS_USER

TARGET_LIB = libcast_auth_imx.so

.PHONY: all
all: $(TARGET_LIB)

$(TARGET_LIB): $(SRC)
	$(CC) $(CFLAGS) ${LDADDLIB} -o $@ $^

.PHONY: clean
clean:
	rm -f *.o *.so


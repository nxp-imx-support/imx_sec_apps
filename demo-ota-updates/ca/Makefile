
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
CFLAGS += -I${OPENSSL_INCLUDE}

LDADD += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec -lpthread -lm

LDADDLIB = $(LDADD) -shared -fPIC

ifeq ($(CFG_ARM32_core),y)
COMPILE_NS_USER ?= 32
else
COMPILE_NS_USER ?= 64
endif

TARGET_LIB = libsecure_ota_optee.so

.PHONY: all
all: $(TARGET_LIB)

$(TARGET_LIB): $(SRC)
	$(CC) $(CFLAGS) ${LDADDLIB} -o $@ $^

.PHONY: clean
clean:
	rm -f *.o *.so

out-dir := $(O)
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

LIB = $(out-dir)/libcast_auth_imx.so
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,$(out-dir)/%.o, $(SRC))

CFLAGS += -I./ -I../ta/include -I$(OPTEE_CLIENT_EXPORT)/include -Wall

LDADD += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec -lpthread -lm
LDADD += -ldl

.PHONY: all
all: $(LIB)

$(LIB): $(OBJ)
	$(CC) $(LDADD) -shared -fPIC -o $@ $^

$(out-dir)/%.o : %.c
	mkdir -p $(out-dir)
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -rf $(out-dir)



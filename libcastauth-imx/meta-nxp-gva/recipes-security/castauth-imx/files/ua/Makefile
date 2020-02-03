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

EXEC = $(out-dir)/castauth
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,$(out-dir)/%.o, $(SRC))

CFLAGS += -I../ca -I../ta/include -I$(OPTEE_CLIENT_EXPORT)/include -Wall
LDFLAGS += -L$(out-dir)/../ca

LDADD += -lcast_auth_imx -lssl -lcrypto -lpthread -lm
LDADD += -ldl

.PHONY: all
all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(LDFLAGS) $(LDADD) -o $@ $^

$(out-dir)/%.o : %.c
	mkdir -p $(out-dir)
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -rf $(out-dir)


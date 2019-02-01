CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g 
LDFLAGS =  -lcrypto
RM = rm -f
DEMO = caam_sm2

ifeq ($(OPENSSL_PATH),)
OPENSSL_PATH := $(ROOTPATH)/../openssl
endif

CFLAGS  += -I$(OPENSSL_PATH)/include -Wno-unused-parameter
LDFLAGS += -L$(OPENSSL_PATH)/lib

SRCS = demo.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${DEMO}

$(DEMO): $(OBJS)
		$(CC) ${LDFLAGS} -o $@ $(OBJS)

$(SRCS:.c=.d):%.d:%.c
		$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
		-${RM} ${DEMO} ${OBJS} $(SRCS:.c=.d)

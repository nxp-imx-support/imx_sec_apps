# Default out dir.
O               ?= out

include flags.mk

#########################################################################
# Set Internal Variables						#
#########################################################################
BUILD_VERBOSE	?= 0
VPREFIX		?= @
ifeq ($(BUILD_VERBOSE),1)
VPREFIX:=
endif

EXPORT_DIR ?= $(O)/export
OUT_DIR ?= $(O)/securekey_lib

.PHONY: all securekey_lib install \
	clean distclean sobj_app

all: securekey_lib securekey_static_lib install sobj_app app

LIB_NAME	:= libsecure_obj.so
STATIC_LIB_NAME        := libsecure_obj.a

SECUREKEY_SRCS	:= securekey.c
OPTEE_CLIENT_EXPORT := 
SECURE_STORAGE_PATH ?=
OPENSSL_LIB_PATH ?=
OPENSSL_PATH ?= 

SECUREKEY_SRC_DIR	:= src
SECUREKEY_OBJ_DIR	:= $(OUT_DIR)
SECUREKEY_OBJS		:= $(patsubst %.c,$(SECUREKEY_OBJ_DIR)/%.o, $(SECUREKEY_SRCS))
SECUREKEY_INCLUDES	:= $(OPTEE_CLIENT_EXPORT)/include \
			   ${CURDIR}/include \
			   $(SECURE_STORAGE_PATH)/include

SECUREKEY_CFLAGS	:= $(addprefix -I, $(SECUREKEY_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE

SECUREKEY_LFLAGS	:= -L$(OPTEE_CLIENT_EXPORT)/lib -lteec

SECUREKEY_LIBRARY	:= $(OUT_DIR)/$(LIB_NAME)
SECUREKEY_STATIC_LIBRARY	:= $(OUT_DIR)/$(STATIC_LIB_NAME)


securekey_lib: $(SECUREKEY_LIBRARY)

$(SECUREKEY_LIBRARY): $(SECUREKEY_OBJS)
	@echo "  LD      $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_NAME) -o $@ $+ $(SECUREKEY_LFLAGS)

securekey_static_lib: $(SECUREKEY_STATIC_LIBRARY)

$(SECUREKEY_STATIC_LIBRARY): $(SECUREKEY_OBJS)
	@echo "  LD      $@"
	$(VPREFIX)$(AR) -rcs ${OUT_DIR}/$(STATIC_LIB_NAME) -o $+
	@echo ""

$(SECUREKEY_OBJ_DIR)/%.o: ${SECUREKEY_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(SECUREKEY_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(SECUREKEY_CFLAGS) -c $< -o $@

sobj_app:
	@echo "Building Secure Object APP: sobj_app"
		$(VPREFIX)$(CC) -I$(OPENSSL_PATH)/include -Iinclude/ \
	-o app/utils.o app/utils.c \
	-o app/sobj_app app/sobj_app.c \
	-lsecure_obj -Lout/securekey_lib/ $(SECUREKEY_LFLAGS) -L$(OPENSSL_LIB_PATH) -lssl -lcrypto
	mv app/sobj_app ${EXPORT_DIR}/app

test_app:
	@echo "Building Secure Obj Test APP"
	$(VPREFIX)$(CC) -Iinclude/ -o app/test app/test.c -lsecure_obj -Lout/securekey_lib/ $(SECUREKEY_LFLAGS)
	mv app/test ${EXPORT_DIR}/app

install:
	mkdir -p ${EXPORT_DIR}/lib ${EXPORT_DIR}/include ${EXPORT_DIR}/app
	cp ${OUT_DIR}/libsecure_obj.so ${EXPORT_DIR}/lib
	cp ${OUT_DIR}/libsecure_obj.a ${EXPORT_DIR}/lib
	cp ${CURDIR}/include/*.h ${EXPORT_DIR}/include

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(O)

distclean: clean

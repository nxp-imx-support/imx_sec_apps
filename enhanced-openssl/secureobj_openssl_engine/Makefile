#Makefile for eng_secure_obj

CC := $(CROSS_COMPILE)gcc
INCLUDES = -I./ -I${OPENSSL_PATH}/ -I${OPENSSL_PATH}/include/ -I${OPENSSL_PATH}/crypto/include/ -I../SecureKey_Lib/include/

all : engine sobj_eng_app

engine:
	${CC} -fPIC -g -o eng_secure_obj.o -c eng_secure_obj.c $(INCLUDES)
	${CC} -shared -fPIC -o libeng_secure_obj.so *.o -lpthread -L${OPENSSL_LIB_PATH} -lcrypto -L../SecureKey_Lib/out/securekey_lib -lsecure_obj

sobj_eng_app:
	@echo "Building Secure Object OpenSSL Engine App"
	$(CC) -I$(OPENSSL_PATH)/include -o app/sobj_eng_app app/sobj_eng_app.c -L$(OPENSSL_LIB_PATH) -lssl -lcrypto

clean :
	rm -f *.o *.so app/sobj_eng_app

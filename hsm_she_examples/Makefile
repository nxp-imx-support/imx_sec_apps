

#change only SECO_LIBS_DIR with the path of the seco_libs repo
SECO_LIBS_DIR = ~/seco_libs
INCLUDEDIR ?= $(SECO_LIBS_DIR)/export/usr/include
LIBS_DIR = $(SECO_LIBS_DIR)/export/usr/lib
LIBS = $(LIBS_DIR)/hsm_lib.a $(LIBS_DIR)/seco_nvm_manager.a $(LIBS_DIR)/she_lib.a
CFLAGS = -Werror
BIN = hsm_test she_test

ifdef COVERAGE
GCOV_FLAGS=-fprofile-arcs -ftest-coverage
endif

all: $(BIN)

%.o: %.c
	$(CC) $^  -c -o $@ -I $(INCLUDEDIR) -I $(INCLUDEDIR)/hsm $(CFLAGS) $(GCOV_FLAGS)

ifdef DEBUG
DEFINES=-DDEBUG
endif
HSM_TEST_OBJ=$(wildcard hsm/*.c)
hsm_test: $(HSM_TEST_OBJ)
	$(CC) $^  $(LIBS) -o $@ $(CFLAGS) -I $(INCLUDEDIR) -I $(INCLUDEDIR)/hsm -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

SHE_TEST_OBJ=$(wildcard she/*.c)
she_test: $(SHE_TEST_OBJ)
	$(CC) $^  $(LIBS) -o $@ $(CFLAGS) -I $(INCLUDEDIR) -I $(INCLUDEDIR)/hsm -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

clean:
	rm -rf *.o *.a $(BIN)
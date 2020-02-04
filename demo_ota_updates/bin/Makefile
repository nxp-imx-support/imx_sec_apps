FLAGS = -I${OPENSSL_INCLUDE} -L${OPENSSL_LIBS}
INCL   = 
SRC    = $(wildcard *.c)
OBJ    = $(SRC:.c=.o)
LIBS   = -lsecure_ota_optee -lssl -lcrypto -lpthread -lm
EXE    = secureota

CC      = $(CROSS_COMPILE)gcc
CFLAGS  = -pedantic -Wall -O2 -Wno-variadic-macros $(FLAGS)
LIBPATH = -L.
LDFLAGS = -o $(EXE) $(LIBPATH) $(FLAGS) $(LIBS) 
CFDEBUG = -pedantic -Wall -g -DDEBUG $(LDFLAGS)
RM      = /bin/rm -f

%.o: %.c
		$(CC) -c $(CFLAGS) $*.c

$(EXE): $(OBJ)
		$(CC) $(LDFLAGS) $(OBJ)

$(OBJ): $(INCL)

debug:
		$(CC) $(CFDEBUG) $(SRC)

clean:
		$(RM) $(OBJ) $(EXE)
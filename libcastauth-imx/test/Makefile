INCL   = 
SRC    = $(wildcard *.c)
OBJ    = $(SRC:.c=.o)
LIBS   = -lcast_auth_imx -lssl -lcrypto -lpthread -lm
EXE    = castauth

CC      = gcc
CFLAGS  = -pedantic -Wall -O2 -Wno-variadic-macros
LIBPATH = -L.
LDFLAGS = -o $(EXE) $(LIBPATH) $(LIBS)
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

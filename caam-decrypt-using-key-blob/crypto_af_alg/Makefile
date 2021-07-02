OBJS = app.o

TARGET = caam-decrypt

CFLAGS += -Wall -Werror
LFLAGS += -L -lcrypto

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LFLAGS)

.PHONY: clean
clean :
	rm -f $(OBJS) $(TARGET)

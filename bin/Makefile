OBJS = eckey.o

TARGET = eckey

CFLAGS = -lcrypto

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -O2 -o $(TARGET) $(OBJS) $(CFLAGS)

.PHONY: clean
clean :
	rm -f $(OBJS) $(TARGET)

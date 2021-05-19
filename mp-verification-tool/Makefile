OBJS = main.o

TARGET = verify

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) -L/usr/lib -lssl -lcrypto

.PHONY: clean
clean :
	rm -f $(OBJS) $(TARGET)

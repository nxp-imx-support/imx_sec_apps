OBJS = kb_test.o

TARGET = kb_test

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -O2 -o $(TARGET) $(OBJS)

.PHONY: clean
clean :
	rm -f $(OBJS) $(TARGET)

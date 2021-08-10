OBJS = caam-decrypt.o

TARGET = caam-decrypt

CFLAGS += -Wall -Werror
LFLAGS += -L -lcrypto

PREFIX ?= /usr

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LFLAGS)

.PHONY: install
install: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/$(TARGET)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

.PHONY: clean
clean :
	rm -f $(OBJS) $(TARGET)

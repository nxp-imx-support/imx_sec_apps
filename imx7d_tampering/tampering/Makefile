.PHONY: clean 
# list of platforms which want this test case
INCLUDE_LIST:= IMX6UL IMX7D

ifneq ($(filter $(PLATFORM),$(INCLUDE_LIST)),)
TARGET = tamp
ifeq ($(PLATFORM),IMX6UL)
CARG = CONFIG_IMX6
else
ifeq ($(PLATFORM),IMX7D)
CARG = CONFIG_IMX7
endif
endif
else
ifndef PLATFORM
ifneq (clean,$(firstword $(MAKECMDGOALS)))
$(info PLATFORM was not set. PLATFORM will be set to IMX7D by default.)
endif
TARGET = tamp
CARG = CONFIG_IMX7
else
$(info Unknown PLATFORM)
TARGET = 
CARG = 
endif
endif

ifdef QT
QT5 = 1
else
QT5 = 0
endif

all : $(TARGET)

$(TARGET) : commands.o mem.o snvs_security.o tamp.o tpsv.o utils.o 
	$(CC) -o $(TARGET) commands.o mem.o snvs_security.o tamp.o tpsv.o utils.o -I. -Wall

commands.o : commands.c tpsv.h utils.h commands.h mem.h
	$(CC) -c commands.c -D$(CARG) -Wall
	
tamp.o : tamp.c tpsv.h commands.h utils.h
	$(CC) -c tamp.c -D$(CARG) -Wall

utils.o : utils.c utils.h
	$(CC) -c utils.c -D$(CARG) -DQT5=$(QT5) -Wall

tpsv.o : tpsv.c tpsv.h snvs_security.h
	$(CC) -c tpsv.c -D$(CARG) -Wall
	
snvs_security.o : snvs_security.c snvs_security.h mem.h
	$(CC) -c snvs_security.c -D$(CARG) -Wall
	
mem.o : mem.c mem.h
	$(CC) -c mem.c -D$(CARG) -Wall
	
clean :
	rm -f $(TARGET) *.o

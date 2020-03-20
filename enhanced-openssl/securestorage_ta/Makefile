
export V?=0

.PHONY: all
all:
	make -C host CROSS_COMPILE=$(CROSS_COMPILE_HOST)
	make -C ta CROSS_COMPILE=$(CROSS_COMPILE_TA)

.PHONY: clean
clean:
	make -C host clean
	make -C ta clean

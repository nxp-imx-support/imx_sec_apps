ifeq ($O,)
out-dir := $(CURDIR)/out
else
out-dir := $(O)
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif
endif

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
CROSS_COMPILE_HOST ?= $(CROSS_COMPILE)
CROSS_COMPILE_TA ?= $(CROSS_COMPILE)

export V?=0

.PHONY: all
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/host_include/conf.mk),)
all: ua ca ta
else
all:
	echo "TA_DEV_KIT_DIR is not correctly defined" && false
endif

.PHONY: ua
ua:
	make -C ua CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			--no-builtin-variables \
			O=$(out-dir)/ua \
			all
.PHONY: ca
ca:
	make -C ca CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			--no-builtin-variables \
			O=$(out-dir)/ca \
			all
.PHONY: ta
ta:
	make -C ta CROSS_COMPILE="$(CROSS_COMPILE_TA)" \
			O=$(out-dir)/ta \
			all
.PHONY: clean
clean:
	make -C ua O=$(out-dir)/ua clean
	make -C ca O=$(out-dir)/ca clean
	make -C ta O=$(out-dir)/ta clean
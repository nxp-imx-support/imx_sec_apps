# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

CC ?= gcc
CXX ?= g++
BIN = bin/smw_key_import
PRJ_DIR ?= .

SRC_DIR := $(PRJ_DIR)/src

GITVERSION := $(shell git rev-parse --is-inside-work-tree 2>/dev/null | grep true >/dev/null && git rev-parse --short HEAD || echo 0)

# ----------- Library/Include Path Check -----------
SMW_ROOT ?= /path/to/imx-smw
SMW_FOUND := $(shell find $(SMW_ROOT) -name "libsmw.so" 2>/dev/null)
SMW_INCLUDE_FOUND := $(shell find $(SMW_ROOT) -name "smw_keymgr.h" 2>/dev/null)

ELE_ROOT ?= /path/to/secure_enclave
ELE_FOUND := $(shell find $(ELE_ROOT) -name "libele_hsm.so" 2>/dev/null)
ELE_INCLUDE_FOUND := $(shell find $(ELE_ROOT) -name "nvm.h" 2>/dev/null)

TEEC_ROOT ?= /path/to/teec
TEEC_FOUND := $(shell find $(TEEC_ROOT) -name "libteec.so" 2>/dev/null)

SQLITE_ROOT ?= /path/to/sqlite
SQLITE_FOUND := $(shell find $(SQLITE_ROOT) -name "libsqlite3.so" 2>/dev/null)

ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifeq ($(strip $(SMW_FOUND)),)
$(error libsmw.so not found in $(SMW_ROOT). Please set SMW_ROOT to the correct path.)
endif
ifeq ($(strip $(ELE_FOUND)),)
$(error libele_hsm.so not found in $(ELE_ROOT). Please set ELE_ROOT to the correct path.)
endif
ifeq ($(strip $(TEEC_FOUND)),)
$(error libteec.so not found in $(TEEC_ROOT). Please set TEEC_ROOT to the correct path.)
endif
ifeq ($(strip $(SQLITE_FOUND)),)
$(error libsqlite3.so not found in $(SQLITE_ROOT). Please set SQLITE_ROOT to the correct path.)
endif
endif

SMW_LIBRARIES := $(dir $(SMW_FOUND))
SMW_INCLUDE_DIR := $(dir $(SMW_INCLUDE_FOUND))
ELE_LIBRARIES := $(dir $(ELE_FOUND))
ELE_INCLUDE := $(dir $(ELE_INCLUDE_FOUND))
TEEC_LIBRARIES := $(dir $(TEEC_FOUND))
SQLITE_LIBRARIES := $(dir $(SQLITE_FOUND))

INCLUDE_PATHS :=	-I$(SMW_INCLUDE_DIR) \
					-I$(ELE_INCLUDE) \
					-I$(ELE_INCLUDE)/hsm \
					-I$(ELE_INCLUDE)/common \
					-I$(ELE_INCLUDE)/hsm/internal \
					-I./include

LDFLAGS := -L$(SMW_LIBRARIES) -L$(ELE_LIBRARIES) -L$(TEEC_LIBRARIES) -L$(SQLITE_LIBRARIES) -lcrypto -lsmw -lele_hsm -lteec -lsqlite3

CFLAGS += ${INCLUDE_PATHS}

DEFINES = -DGITVERSION=\"$(GITVERSION)\" -DPSA_COMPLIANT -DSECONDARY_API_SUPPORTED

CFLAGS += ${DEFINES} -Wno-deprecated-declarations -Wall -MMD -MP

# Collect the files to compile
MAINSRC = ./app/main_device.c
CSRCS := $(wildcard $(SRC_DIR)/*.c)

OBJEXT ?= .o

AOBJS := $(ASRCS:.S=$(OBJEXT))
COBJS = $(CSRCS:.c=$(OBJEXT))
MAINOBJ = $(MAINSRC:.c=$(OBJEXT))

SRCS = $(ASRCS) $(CSRCS) $(MAINSRC)
OBJS = $(AOBJS) $(COBJS)

all: default

%.o: %.c
	@echo "  "CC"\t"$<
	@$(CC)  $(CFLAGS)  -c $< -o $@

%.o: %.cpp
	@echo "  "CXX"\t"$@
	@${CXX} -c ${CPPFLAGS}   $< -o $@

default: $(AOBJS) $(COBJS) $(MAINOBJ)
	@echo "  "CXX"\t"$(BIN)
	@mkdir -p $(dir $(BIN))
	@$(CXX) -o $(BIN) $(MAINOBJ) $(AOBJS) $(COBJS) $(LDFLAGS) $(CPPFLAGS)

-include $(OBJS:.o=.d)

clean:
	rm -rf $(BIN) $(AOBJS) $(COBJS) $(MAINOBJ) $(dir $(BIN)) $(SRC_DIR)/*.d app/*.d
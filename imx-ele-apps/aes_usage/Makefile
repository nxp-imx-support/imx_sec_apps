# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

CC ?= gcc
CXX ?= g++
BIN = bin/ele_aes_usage
PRJ_DIR ?= .

SRC_DIR := $(PRJ_DIR)/src

GITVERSION := $(shell git rev-parse --is-inside-work-tree 2>/dev/null | grep true >/dev/null && git rev-parse --short HEAD || echo 0)

ELE_ROOT ?= /path/to/secure_enclave
ELE_FOUND := $(shell find $(ELE_ROOT) -name "libele_hsm.so" 2>/dev/null)
ELE_INCLUDE_FOUND := $(shell find $(ELE_ROOT) -name "nvm.h" 2>/dev/null)

ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifeq ($(strip $(ELE_FOUND)),)
$(error libele_hsm.so not found in $(ELE_ROOT). Please set ELE_ROOT to the correct path.)
endif
endif

ELE_LIBRARIES := $(dir $(ELE_FOUND))
ELE_INCLUDE := $(dir $(ELE_INCLUDE_FOUND))

INCLUDE_PATHS :=	-I$(ELE_INCLUDE) \
					-I$(ELE_INCLUDE)/hsm \
					-I$(ELE_INCLUDE)/common \
					-I$(ELE_INCLUDE)/hsm/internal \
					-I./include

LDFLAGS := -L$(ELE_LIBRARIES) -lele_hsm

CFLAGS += ${INCLUDE_PATHS}

DEFINES = -DGITVERSION=\"$(GITVERSION)\" -DPSA_COMPLIANT -DSECONDARY_API_SUPPORTED

CFLAGS += ${DEFINES} -Wall -MMD -MP

#Collect the files to compile
MAINSRC = ./app/main.c
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

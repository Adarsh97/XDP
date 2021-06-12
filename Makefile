# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)


XDP_TARGETS  := kernal_xdp
USER_TARGETS := user_xdp

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
LIBS += -lpthread

#
# Copyright (C) 2021 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

always-y += probe.o
# kept for compatibility with kernels < 5.11
always = $(always-y)

LLC ?= llc
CLANG ?= clang

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# DEBUG = -DBPF_DEBUG

#
# https://chromium.googlesource.com/chromiumos/third_party/kernel/+/096925a44076ba5c52faa84d255a847130ff341e%5E%21/#F2
# This commit diverged the ChromiumOS kernel from stock in the area of audit information, which this probe accesses.
# 
# This enables the workaround for this divergence.
#
NEEDS_COS_73_WORKAROUND = $(shell expr `grep -sc "^\s*struct\s\+audit_task_info\s\+\*audit;\s*$$" $(KERNELDIR)/include/linux/sched.h` = 1)
ifeq ($(NEEDS_COS_73_WORKAROUND), 1)
	KBUILD_CPPFLAGS += -DCOS_73_WORKAROUND
endif

# -fmacro-prefix-map is not supported on version of clang older than 10
# so remove it if necessary.
IS_CLANG_OLDER_THAN_10 := $(shell expr `$(CLANG) -dumpversion | cut -f1 -d.` \<= 10)
ifeq ($(IS_CLANG_OLDER_THAN_10), 1)
	KBUILD_CPPFLAGS := $(filter-out -fmacro-prefix-map=%,$(KBUILD_CPPFLAGS))
endif

all:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

clean:
	$(MAKE) -C $(KERNELDIR) M=$$PWD clean
	@rm -f *~

$(obj)/probe.o: $(src)/probe.c \
		$(src)/bpf_helpers.h \
		$(src)/filler_helpers.h \
		$(src)/fillers.h \
		$(src)/maps.h \
		$(src)/plumbing_helpers.h \
		$(src)/quirks.h \
		$(src)/ring_helpers.h \
		$(src)/types.h
	$(CLANG) $(LINUXINCLUDE) \
		$(KBUILD_CPPFLAGS) \
		$(KBUILD_EXTRA_CPPFLAGS) \
		$(DEBUG) \
		-D__KERNEL__ \
		-D__BPF_TRACING__ \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-fno-jump-tables \
		-fno-stack-protector \
		-Wno-tautological-compare \
		-O2 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	$(LLC) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

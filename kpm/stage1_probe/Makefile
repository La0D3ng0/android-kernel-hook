ifndef TARGET_COMPILE
$(error TARGET_COMPILE not set)
endif

KP_DIR ?= ../../third_party/KernelPatch-0.13.9
OUT_DIR ?= ../../out/kpm-stage1-probe-pixel8

CC := $(TARGET_COMPILE)gcc
READELF := $(TARGET_COMPILE)readelf
STRIP := $(TARGET_COMPILE)strip

INCLUDE_DIRS := \
	$(KP_DIR)/kernel \
	$(KP_DIR)/kernel/include \
	$(KP_DIR)/kernel/patch/include \
	$(KP_DIR)/kernel/linux/include \
	$(KP_DIR)/kernel/linux/arch/arm64/include \
	$(KP_DIR)/kernel/linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(dir))
CFLAGS := -O2 -Wall -Wextra -Werror -fno-pic -fno-asynchronous-unwind-tables \
	-fno-stack-protector -fno-common $(INCLUDE_FLAGS)

KPM := $(OUT_DIR)/rtgum-stage1-probe.kpm

.PHONY: all verify
all: $(KPM) verify

$(OUT_DIR):
	mkdir -p $@

$(OUT_DIR)/stage1_probe.o: stage1_probe.c Makefile | $(OUT_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(KPM): $(OUT_DIR)/stage1_probe.o
	$(CC) -r -o $@ $^
	$(STRIP) --strip-debug $@

verify: $(KPM)
	$(READELF) -h $(KPM) | grep -q 'Machine:.*AArch64'
	$(READELF) -h $(KPM) | grep -q 'Type:.*REL'
	$(READELF) -S $(KPM) | grep -q '.kpm.ctl0'
	@echo "verified read-only probe KPM: $(KPM)"

ifndef TARGET_COMPILE
$(error TARGET_COMPILE not set; point it at the aarch64-none-elf- prefix)
endif

KP_DIR ?= ../../third_party/KernelPatch-0.12.2
OUT_DIR ?= ../../out/kpm-stage0

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

CFLAGS := -O2 -Wall -Wextra -fno-pic -fno-asynchronous-unwind-tables \
	-fno-stack-protector -fno-common $(INCLUDE_FLAGS) -Tstage0.lds
KPM := $(OUT_DIR)/rtgum-stage0.kpm

.PHONY: all clean verify

all: $(KPM) verify

$(OUT_DIR):
	mkdir -p $@

$(OUT_DIR)/stage0.o: stage0.c stage0.lds | $(OUT_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(KPM): $(OUT_DIR)/stage0.o
	$(CC) -r -o $@ $^
	$(STRIP) --strip-debug $@

verify: $(KPM)
	$(READELF) -h $(KPM) | grep -q 'Machine:.*AArch64'
	$(READELF) -h $(KPM) | grep -q 'Type:.*REL'
	$(READELF) -S $(KPM) | grep -q '.kpm.info'
	@echo "verified KPM: $(KPM)"

clean:
	rm -f $(OUT_DIR)/stage0.o $(OUT_DIR)/rtgum-stage0.kpm

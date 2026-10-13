ifndef TARGET_COMPILE
$(error TARGET_COMPILE not set; point it at the aarch64-none-elf- prefix)
endif

KP_DIR ?= ../../third_party/KernelPatch-0.13.9
OUT_DIR ?= ../../out/kpm-stage1-pixel8-review

CXX := $(TARGET_COMPILE)g++
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

CXXFLAGS := -std=gnu++17 -O2 -Wall -Wextra -Werror -fno-builtin -mno-outline-atomics \
	-fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-use-cxa-atexit \
	-fno-pic -fno-asynchronous-unwind-tables -fno-unwind-tables \
	-fno-stack-protector -fno-common -nostdinc++ $(INCLUDE_FLAGS) -Tstage1.lds
KPM := $(OUT_DIR)/rtgum-stage1.kpm

.PHONY: all clean verify

all: $(KPM) verify

$(OUT_DIR):
	mkdir -p $@

$(OUT_DIR)/stage1.o: stage1.cpp stage1.lds Makefile | $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(KPM): $(OUT_DIR)/stage1.o
	$(CXX) -r -o $@ $^
	$(STRIP) --strip-debug $@

verify: $(KPM)
	$(READELF) -h $(KPM) | grep -q 'Machine:.*AArch64'
	$(READELF) -h $(KPM) | grep -q 'Type:.*REL'
	$(READELF) -S $(KPM) | grep -q '.kpm.info'
	$(READELF) -S $(KPM) | grep -q '.kpm.ctl0'
	@echo "verified C++ KPM: $(KPM)"

clean:
	rm -f $(OUT_DIR)/stage1.o $(OUT_DIR)/rtgum-stage1.kpm

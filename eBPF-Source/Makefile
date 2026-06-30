# Re:Kernel eBPF build — Android NDK.
#
#   make                 -> out/rekernel.bpf.o + out/rekerneld_$(ARCH)
#   make clean
#
# Vendored, target-specific inputs you provide (see README):
#   include/             libbpf headers (bpf/*.h) + a device-generated vmlinux.h
#   lib/$(ARCH)/         prebuilt static libbpf.a, libelf.a, libzstd.a (aarch64-android)
#
# Override on the command line as needed, e.g.:
#   make ARCH=aarch64 API=35 NDK_PATH=$HOME/android-ndk-r27d

ARCH        ?= aarch64
API         ?= 35
NDK_PATH    ?= $(HOME)/android-ndk-r27d
NDK_HOST    ?= linux-x86_64

TOOLCHAIN   := $(NDK_PATH)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin
CLANG       := $(TOOLCHAIN)/clang
TARGET_CC   := $(TOOLCHAIN)/$(ARCH)-linux-android$(API)-clang

INC_DIR     := ./include
LIB_DIR     := ./lib/$(ARCH)
OUT_DIR     := out

# aarch64 -> arm64 for the BPF kprobe register ABI (-D__TARGET_ARCH_arm64)
BPF_ARCH    := $(patsubst aarch64,arm64,$(ARCH))

BPF_OBJ     := $(OUT_DIR)/rekernel.bpf.o
USER_BIN    := $(OUT_DIR)/rekerneld_$(ARCH)

# EXTRA_BPF_CFLAGS: e.g. -DRK_DEFINE_BINDER_TYPES when building against a BTF that
# lacks the binder structs (a vendored device vmlinux.h already has them).
EXTRA_BPF_CFLAGS ?=
BPF_CFLAGS  := -target bpf -g -O2 -D__TARGET_ARCH_$(BPF_ARCH) \
               -Wall -Wno-unused-function -I$(INC_DIR) -I. $(EXTRA_BPF_CFLAGS)

USER_CFLAGS  := -O2 -Wall -I$(INC_DIR) -I.
USER_LDFLAGS := -L$(LIB_DIR) -l:libbpf.a -l:libelf.a -l:libzstd.a -lz -static

.PHONY: all clean prepare
all: prepare $(BPF_OBJ) $(USER_BIN)

prepare:
	@mkdir -p $(OUT_DIR)

$(BPF_OBJ): rekernel.bpf.c $(wildcard *.bpf.h) rekernel.h | prepare
	@echo "[+] BPF  $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): rekerneld.c rekernel.h rk_format.h | prepare
	@echo "[+] USER $@"
	$(TARGET_CC) $(USER_CFLAGS) $< $(USER_LDFLAGS) -o $@

clean:
	rm -rf $(OUT_DIR)

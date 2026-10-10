obj-m := rekernel.o
rekernel-y := rekernel_main.o rekernel_netlink.o rekernel_binder.o rekernel_signal.o rekernel_netfilter.o
# Binder's private headers must come from the kernel being built against.
REKERNEL_BINDER_DIR ?= $(srctree)/drivers/android
ccflags-y += -I$(REKERNEL_BINDER_DIR)
ifdef REKERNEL_VERSION
ccflags-y += -DREKERNEL_VERSION=\"$(REKERNEL_VERSION)\"
endif

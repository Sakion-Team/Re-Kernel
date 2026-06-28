obj-m := rekernel.o

ccflags-$(CONFIG_REKERNEL_NETWORK) += -DNETWORK_FILTER

ifdef REKERNEL_VERSION
ccflags-y += -DREKERNEL_VERSION=\"$(REKERNEL_VERSION)\"
endif

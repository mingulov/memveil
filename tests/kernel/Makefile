# SPDX-License-Identifier: GPL-2.0-only
# Test-only oracle module build. KDIR defaults to the running
# kernel's build tree; the VM harness overrides it for the guest
# kernel. This makefile never installs or loads the module.

obj-m += memveil_dma_oracle.o
obj-m += memveil_region_oracle.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

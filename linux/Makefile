obj-m := portac.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
modules:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
modules_install:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

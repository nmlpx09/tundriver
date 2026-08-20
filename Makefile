obj-m += vnet.o

vnet-y := main.o sock/impl.o crypt/impl.o utils/impl.o

ccflags-y += -I$(src) -I$(src)/sock -I$(src)/crypt  -I$(src)/utils

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean

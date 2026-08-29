obj-m += tnet.o

tnet-y := main.o sock/impl.o crypt/impl.o ips/impl.o utils/impl.o

ccflags-y += -O2 -I$(src) -I$(src)/sock -I$(src)/crypt -I$(src)/utils

ifdef SERVER
ccflags-y += -DSERVER
endif

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

client:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

server:
	$(MAKE) SERVER=1 -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: server client clean

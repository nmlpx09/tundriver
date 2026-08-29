KVER ?= $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD := $(shell pwd)
DESTDIR ?=

obj-m += tnet.o

tnet-y := main.o sock/impl.o crypt/impl.o ips/impl.o utils/impl.o

ccflags-y += -O2 -I$(src) -I$(src)/sock -I$(src)/crypt -I$(src)/ips -I$(src)/utils

ifdef SERVER
ccflags-y += -DSERVER
endif

client:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

server:
	$(MAKE) SERVER=1 -C $(KDIR) M=$(PWD) modules

install_client: client
	$(MAKE) -C $(KDIR) M=$(PWD) CONFIG_MODULE_COMPRESS_NONE=y modules_install
	depmod -a $(KVER)
	install -D -m 0755 client.sh $(DESTDIR)/usr/bin/tun

install_server: server
	$(MAKE) -C $(KDIR) M=$(PWD) CONFIG_MODULE_COMPRESS_NONE=y modules_install
	depmod -a $(KVER)
	install -D -m 0755 server.sh $(DESTDIR)/usr/bin/tun

install_service: install_server
	install -D -m 0644 tunnel.service $(DESTDIR)/etc/systemd/system/tunnel.service

uninstall:
	rm -f $(DESTDIR)/usr/bin/tun
	rm -f $(DESTDIR)/etc/systemd/system/tunnel.service
	rm -f $(DESTDIR)/lib/modules/$(KVER)/extra/tnet.ko
	depmod -a $(KVER)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: client server install_client install_server install_service uninstall clean

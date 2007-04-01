default: config.dat

clean:
	$(MAKE) -C linux clean
	rm -f config config.dat

modules:
	$(MAKE) -C linux modules
modules_install:
	$(MAKE) -C linux modules_install

CFLAGS=-Wall -Werror

config: config.c config.h
config.dat: config
	./$< >$@ || rm -f $@
install: config.dat
	[ -s config.dat ] && cat config.dat >/proc/net/portac

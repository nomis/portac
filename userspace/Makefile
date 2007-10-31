.POSIX:
# $Id$
VER=1.0

LEX=flex
YACC=bison
LFLAGS=-i --nounput
YFLAGS=-v -d
CFLAGS=-I/usr/local/include -Wall -g -O0
LDFLAGS=-L/usr/local/lib -lnl
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/man
.PHONY: all clean install dist distclean
.SUFFIXES: %.l __%-l.c %.y __%-y.c __%-y.h

portac: src/portac.o src/__commands-l.o src/__commands-y.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^

src/portac.c: src/portac.h
src/__commands.y: src/portac.h

__%-l.c: %.l __%-y.c
	$(LEX) $(LFLAGS) -o$@ $<

__%-y.c: %.y
	$(YACC) $(YFLAGS) -o $@ $<

all: portac

clean:
	rm -f src/__*.c src/__*.h src/__*.output src/*.o portac

distclean:

install:
	install -m 755 -d $(BINDIR)/ $(MANDIR)/man8/
	install -m 755 portac $(BINDIR)/portac
#	install -m 644 doc/portac.8 $(MANDIR)/man8/

dist:

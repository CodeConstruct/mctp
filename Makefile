INSTALL = install
CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wno-unused-parameter -ggdb
prefix ?= /usr/local
bindir ?= $(prefix)/bin

SD_LIBS := $(shell pkg-config --libs libsystemd)
SD_CFLAGS := $(shell pkg-config --cflags libsystemd)

binaries = mctp mctp-req mctp-echo

extras = mctp-util.o

.PHONY: all
all: $(binaries)

.PHONY: clean
clean:
	rm -f $(binaries) $(extras)

.PHONY: install
install: install-binaries

.PHONY: install-binaries
install-binaries: $(binaries)
	$(INSTALL) --mode 0755 --directory "$(DESTDIR)$(bindir)"
	for b in $(binaries); do \
		$(INSTALL) --mode 0755 $$b "$(DESTDIR)$(bindir)/$$b"; \
	done

mctpd: LDLIBS += $(SD_LIBS)
mctpd: CFLAGS += $(SD_CFLAGS)

$(binaries): $(extras)


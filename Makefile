INSTALL = install
CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wno-unused-parameter -ggdb
prefix ?= /usr/local
bindir ?= $(prefix)/bin

ifdef STATIC_LIBSYSTEMD
SD_LIBS := -Wl,-Bstatic $(shell pkg-config --libs libsystemd) -Wl,-Bdynamic -lcap -lrt -lpthread
else
SD_LIBS := $(shell pkg-config --libs libsystemd)
endif
SD_CFLAGS := $(shell pkg-config --cflags libsystemd)

ifdef BUILT_LIBSYSTEMD
SD_LIBS := /home/matt/3rd/systemd/build/libsystemd.a -lcap -lrt -lpthread -lselinux
endif

LDLIBS += -Wl,--gc-sections

utils = mctp mctp-req mctp-echo
extras = mctp-util.o mctp-netlink.o
binaries = mctpd $(utils)

.PHONY: all
all: $(utils)

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



INSTALL = install
CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -Wno-unused-parameter -ggdb
prefix ?= /usr/local
bindir ?= $(prefix)/bin

binaries = mctp mctp-req mctp-echo

.PHONY: all
all: $(binaries)

.PHONY: clean
clean:
	rm -f $(binaries)

.PHONY: install
install: install-binaries

.PHONY: install-binaries
install-binaries: $(binaries)
	$(INSTALL) --mode 0755 --directory "$(DESTDIR)$(bindir)"
	for b in $(binaries); do \
		$(INSTALL) --mode 0755 $$b "$(DESTDIR)$(bindir)/$$b"; \
	done

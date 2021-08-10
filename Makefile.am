bin_PROGRAMS = mctp
sbin_PROGRAMS =

if HAVE_SYSTEMD
sbin_PROGRAMS += mctpd
endif

noinst_PROGRAMS = mctp-req mctp-echo

util_sources = src/mctp-util.c src/mctp-util.h
netlink_sources = src/mctp-netlink.c src/mctp-netlink.h

mctp_SOURCES = src/mctp.c $(netlink_sources) $(util_sources)

mctpd_SOURCES = src/mctpd.c $(netlink_sources) $(util_sources)
mctpd_CPPFLAGS = $(SYSTEMD_CFLAGS)
mctpd_LDADD = $(SYSTEMD_LIBS)

mctp_req_SOURCES = src/mctp-req.c $(util_sources)
mctp_echo_SOURCES = src/mctp-echo.c $(util_sources)

EXTRA_DIST = conf/mctpd-dbus.conf conf/mctpd.service

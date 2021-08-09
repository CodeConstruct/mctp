bin_PROGRAMS = mctp
sbin_PROGRAMS =

if HAVE_SYSTEMD
sbin_PROGRAMS += mctpd
endif

noinst_PROGRAMS = mctp-req mctp-echo

util_sources = mctp-util.c mctp-util.h
netlink_sources = mctp-netlink.c mctp-netlink.h

mctp_SOURCES = mctp.c $(netlink_sources) $(util_sources)

mctpd_SOURCES = mctpd.c $(netlink_sources) $(util_sources)
mctpd_CPPFLAGS = $(SYSTEMD_CFLAGS)
mctpd_LDADD = $(SYSTEMD_LIBS)

mctp_req_SOURCES = mctp-req.c $(util_sources)
mctp_echo_SOURCES = mctp-echo.c $(util_sources)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sys/socket.h>

#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>

#include "mctp.h"

struct ctx {
	sd_event *event;
	sd_bus *bus;
};

static int cb_configure_endpoint(sd_bus_message *sdmsg) {
	return -ENOSYS;
}

static int method_configure_endpoint(sd_bus_message *sdmsg, void *data, sd_bus_error *sderr) {
	int rc;
	const char *ifname, *physaddr;
	struct ctx *ctx = data;

	rc = sd_bus_message_read(sdmsg, "ss", &ifname, &physaddr);
	if (rc < 0)
		return rc;

	// sd_event_add_io(ctx->event, NULL, fd, EPOLLIN, cb_configure_endpoint,


	return 0;
}

static int cb_test_timer(sd_event_source *s, uint64_t t,
	void* data) {
	sd_bus_message *call = data;
	sd_bus *bus = sd_bus_message_get_bus(call);
	int rc;

	rc = sd_bus_reply_method_return(call, "i", (int)(t % 11111));
	if (rc < 0)
		return rc;
	return 0;
}

static int method_test_timer(sd_bus_message *sdmsg, void *data, sd_bus_error *sderr) {
	int rc;
	int seconds;
	struct ctx *ctx = data;

	rc = sd_bus_message_read(sdmsg, "i", &seconds);
	if (rc < 0)
		return rc;

	rc = sd_event_add_time_relative(ctx->event, NULL,
		CLOCK_MONOTONIC, 1000000ULL * seconds, 0,
		cb_test_timer, sdmsg);
	if (rc < 0)
		return rc;

	// reply later
	return 1;
}

static const sd_bus_vtable mctpd_vtable[] = {
	SD_BUS_VTABLE_START(),
	SD_BUS_METHOD_WITH_NAMES("ConfigureEndpoint",
		"ss",
		SD_BUS_PARAM("ifname")
		SD_BUS_PARAM("physaddr"),
		"ib",
		SD_BUS_PARAM("eid")
		SD_BUS_PARAM("new"),
		method_configure_endpoint),
	SD_BUS_METHOD_WITH_NAMES("TestTimer",
		"i",
		SD_BUS_PARAM("seconds"),
		"i",
		SD_BUS_PARAM("secondsx10"),
		method_test_timer),
	SD_BUS_VTABLE_END
};

static int setup(struct ctx *ctx)
{
	int rc;

	rc = sd_event_new(&ctx->event);
	if (rc < 0) {
		warnx("sd_event failed");
		return rc;
	}

	rc = sd_bus_default(&ctx->bus);
	if (rc < 0) {
		warnx("Couldn't get bus");
		return rc;
	}

	rc = sd_bus_attach_event(ctx->bus, ctx->event,
		SD_EVENT_PRIORITY_NORMAL);
	if (rc < 0) {
		warnx("Failed attach");
		return rc;
	}

	/*
	rc = listen_get_endpoint(ctx);
	if (rc)
		return rc;

	rc = listen_resolve_endpoint(ctx);
	if (rc)
		return rc;

	rc = listen_get_mctp_version(ctx);
	if (rc)
		return rc;
		*/

	return 0;
}

int main(int argc, char **argv) {
	int rc;

	struct ctx ctxi, *ctx = &ctxi;

	rc = setup(ctx);
	if (rc < 0) {
		warnx("Error in setup, returned %s", strerror(-rc));
		return 1;
	}

	rc = sd_event_loop(ctx->event);
	if (rc < 0) {
		warnx("Error in loop, returned %s", strerror(-rc));
		return 1;
	}

	return 0;
}

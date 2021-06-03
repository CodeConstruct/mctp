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
#include "mctp-netlink.h"

static const char* mctpd_obj_path = "/BusOwner";
static const char* mctpd_iface_busowner = "au.com.codeconstruct.mctpd.BusOwner";

struct peer {
	int ifindex;
	uint8_t hwaddr[MAX_ADDR_LEN];

	mctp_eid_t eid;
	uint32_t net;

	enum {
		UNUSED = 0,
		NEW,
		ASSIGNED,
		// CONFLICT,
	} state;
};

#define MAX_PEERS 1024

struct ctx {
	sd_event *event;
	sd_bus *bus;
	mctp_nl *nl;

	struct peer *peers[MAX_PEERS];
	size_t num_peers;
};

static int method_configure_endpoint(sd_bus_message *call, void *data,
	sd_bus_error *sderr) {
	int rc;
	const char *ifname, *physaddr;
	int ifindex;
	struct ctx *ctx = data;

	rc = sd_bus_message_read(call, "ss", &ifname, &physaddr);
	if (rc < 0)
		return rc;

	// TODO: if we take too long waiting for timeouts here we might
	// need to make it asynchronous with callbacks. We can only have
	// one request at a time per endpoint though.

	ifindex = mctp_nl_ifindex_byname(ctx->nl, ifname);

	return 0;
}

static int cb_test_timer(sd_event_source *s, uint64_t t,
	void* data) {
	sd_bus_message *call = data;
	// sd_bus *bus = sd_bus_message_get_bus(call);
	int rc;

	rc = sd_bus_reply_method_return(call, "i", (int)(t % 11111));
	sd_bus_message_unref(call);
	if (rc < 0)
		return rc;
	return 0;
}

static int method_test_timer_async(sd_bus_message *call, void *data, sd_bus_error *sderr) {
	int rc;
	int seconds;
	struct ctx *ctx = data;

	rc = sd_bus_message_read(call, "i", &seconds);
	if (rc < 0)
		return rc;

	rc = sd_event_add_time_relative(ctx->event, NULL,
		CLOCK_MONOTONIC, 1000000ULL * seconds, 0,
		cb_test_timer, call);
	if (rc < 0)
		return rc;

	sd_bus_message_ref(call);

	// reply later
	return 1;
}

static int method_test_timer(sd_bus_message *call, void *data, sd_bus_error *sderr) {
	int rc;
	int seconds;
	// struct ctx *ctx = data;

	rc = sd_bus_message_read(call, "i", &seconds);
	if (rc < 0)
		return rc;

	sleep(seconds);

	rc = sd_bus_reply_method_return(call, "i", seconds*10);
	return rc;
}

static const sd_bus_vtable mctpd_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_NAMES("ConfigureEndpoint",
		"ss",
		SD_BUS_PARAM(ifname)
		SD_BUS_PARAM(physaddr),
		"ib",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(new),
		method_configure_endpoint,
		0),
	SD_BUS_METHOD_WITH_NAMES("TestTimer",
		"i",
		SD_BUS_PARAM(seconds),
		"i",
		SD_BUS_PARAM(secondsx10),
		method_test_timer,
		0),
	SD_BUS_METHOD_WITH_NAMES("TestTimerAsync",
		"i",
		SD_BUS_PARAM(seconds),
		"i",
		SD_BUS_PARAM(secondsx10),
		method_test_timer_async,
		0),
	SD_BUS_VTABLE_END
};

static int setup_bus(struct ctx *ctx)
{
	int rc;
	sd_bus_slot *slot = NULL;

	rc = sd_event_new(&ctx->event);
	if (rc < 0) {
		warnx("sd_event failed");
		goto out;
	}

	rc = sd_bus_default(&ctx->bus);
	if (rc < 0) {
		warnx("Couldn't get bus");
		goto out;
	}

	rc = sd_bus_attach_event(ctx->bus, ctx->event,
		SD_EVENT_PRIORITY_NORMAL);
	if (rc < 0) {
		warnx("Failed attach");
		goto out;
	}

	rc = sd_bus_add_object_vtable(ctx->bus, &slot,
		mctpd_obj_path, mctpd_iface_busowner, mctpd_vtable, ctx);
	if (rc < 0) {
		warnx("Failed object");
		goto out;
	}

	rc = sd_bus_request_name(ctx->bus, mctpd_iface_busowner, 0);
	if (rc < 0) {
		warnx("Failed requesting name %s", mctpd_iface_busowner);
		goto out;
	}

	sd_bus_slot_set_floating(slot, 0);

	rc = 0;
out:
	if (rc < 0 && slot) {
		sd_bus_slot_unref(slot);
	}

	return rc;
}

int main(int argc, char **argv) {
	int rc;

	struct ctx ctxi = {0}, *ctx = &ctxi;

	ctx->nl = mctp_nl_new(false);
	if (!ctx->nl) {
		warnx("Failed creating netlink object");
		return 1;
	}

	rc = setup_bus(ctx);
	if (rc < 0) {
		warnx("Error in setup, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	rc = sd_event_loop(ctx->event);
	if (rc < 0) {
		warnx("Error in loop, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	return 0;
}

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
#include "mctp-util.h"
#include "mctp-netlink.h"
#include "libmctp-cmds.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

static const char* mctpd_obj_path = "/BusOwner";
static const char* mctpd_iface_busowner = "au.com.codeconstruct.mctpd.BusOwner";

struct dest_phys {
	int ifindex;
	const uint8_t *hwaddr;
	size_t hwaddr_len;
};
typedef struct dest_phys dest_phys;

struct peer {
	int ifindex;
	uint8_t hwaddr[MAX_ADDR_LEN];
	uint8_t hwaddr_len;

	mctp_eid_t eid;
	uint32_t net;

	enum {
		UNUSED = 0,
		NEW,
		ASSIGNED,
		// CONFLICT,
	} state;

	// bitmap of supported message types
	uint8_t message_types[32];
};
typedef struct peer peer;


#define MAX_PEERS 1024

struct ctx {
	sd_event *event;
	sd_bus *bus;
	mctp_nl *nl;

	struct peer peers[MAX_PEERS];
	size_t num_peers;

	// Timeout in usecs for a MCTP response
	uint64_t mctp_timeout;
};
typedef struct ctx ctx;

static struct peer * find_peer_by_phys(ctx *ctx, const dest_phys *dest)
{
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = &ctx->peers[i];
		if (peer->state == UNUSED)
			continue;
		if (peer->ifindex == dest->ifindex &&
			peer->hwaddr_len == dest->hwaddr_len &&
			!memcmp(peer->hwaddr, dest->hwaddr, peer->hwaddr_len))
			return peer;
	}
	return NULL;
}

static char* dest_phys_tostr(const dest_phys *dest) {
	char hex[MAX_ADDR_LEN*4];
	char* buf;
	size_t l = 50 + sizeof(hex);
	buf = malloc(l);
	write_hex_addr(dest->hwaddr, dest->hwaddr_len, hex, sizeof(hex));
	snprintf(buf, l, "physaddr if %d hw len %zu 0x%s", dest->ifindex, dest->hwaddr_len, hex);
	return buf;
}

static int defer_free_handler(sd_event_source *s, void *userdata) {
	free(userdata);
	return 0;
}

/* Returns ptr, frees it on the next default event loop cycle */
static void* defer_free(void* ptr) {
	sd_event *e;
	int rc;
	rc = sd_event_default(&e);
	if (rc < 0) {
		warnx("defer_free no event loop");
		return ptr;
	}
	rc = sd_event_add_defer(e, NULL, defer_free_handler, ptr);
	if (rc < 0) {
		warnx("defer_free failed adding");
		return ptr;
	}
	return ptr;
}

static int cb_exit_loop_io(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	return sd_event_exit(sd_event_source_get_event(s), 0);
}

static int cb_exit_loop_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
	return sd_event_exit(sd_event_source_get_event(s), -ETIMEDOUT);
}

/* Events are EPOLLIN, EPOLLOUT etc.
   Returns 0 on ready, negative on error. -ETIMEDOUT on timeout */
int wait_fd_timeout(int fd, short events, uint64_t timeout_usec)
{
	int rc;
	sd_event *ev = NULL;

	rc = sd_event_new(&ev);
	if (rc < 0)
		goto out;

	rc = sd_event_add_time_relative(ev, NULL, CLOCK_MONOTONIC,
		timeout_usec, 0, cb_exit_loop_timeout, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_io(ev, NULL, fd, events, cb_exit_loop_io, NULL);
	if (rc < 0)
		goto out;

	// TODO: maybe need to break the loop on SIGINT event too?
	rc = sd_event_loop(ev);

out:
	if (ev)
		sd_event_unref(ev);
	return rc;
}

/* req and resp buffers include the initial message type byte.
 * This is ignored, the addr.smctp_type is used instead.
 */
static int endpoint_query_phys(ctx *ctx, const dest_phys *dest,
	uint8_t req_type, const void* req, size_t req_len,
	uint8_t **resp, size_t *resp_len, struct _sockaddr_mctp_ext *resp_addr)
{
	struct _sockaddr_mctp_ext addr;
	socklen_t addrlen;
	int sd = -1;
	ssize_t rc;
	uint8_t *send_ptr;
	size_t send_len, buf_size;
	char* dest_str;

	uint8_t* buf = NULL;

	dest_str = defer_free(dest_phys_tostr(dest));

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0x0, sizeof(addr));
	addrlen = sizeof(struct _sockaddr_mctp_ext);
	addr.smctp_family = AF_MCTP;
	addr.smctp_network = 0;
	addr.smctp_addr.s_addr = 0;

	addr.smctp_ifindex = dest->ifindex;
	addr.smctp_halen = dest->hwaddr_len;
	memcpy(addr.smctp_haddr, dest->hwaddr, dest->hwaddr_len);

	addr.smctp_type = req_type;
	addr.smctp_tag = MCTP_TAG_OWNER;

	if (req_len == 0) {
		warnx("BUG: zero length request");
		rc = -EPROTO;
		goto out;
	}
	send_len = req_len - 1;
	send_ptr = (uint8_t*)req + 1;
	rc = sendto(sd, send_ptr, send_len, 0, (struct sockaddr *)&addr,
			sizeof(struct _sockaddr_mctp_ext));
	if (rc < 0) {
		rc = -errno;
		goto out;
	}
	if ((size_t)rc != send_len) {
		warnx("BUG: incorrect sendto %zd, expected %zu", rc, send_len);
		rc = -EPROTO;
		goto out;
	}

	rc = wait_fd_timeout(sd, EPOLLIN, ctx->mctp_timeout);
	if (rc < 0)
		goto out;

	rc = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
	if (rc < 0) {
		rc = -errno;
		goto out;
	}

	// +1 for space for addition type prefix byte
	buf_size = rc+1;
	buf = malloc(buf_size);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	addrlen = sizeof(struct _sockaddr_mctp_ext);
	memset(resp_addr, 0x0, addrlen);
	// skip the initial prefix byte
	rc = recvfrom(sd, buf+1, buf_size-1, MSG_TRUNC, (struct sockaddr *)&resp_addr,
		&addrlen);
	if (rc < 0)
		return -errno;
	if ((size_t)rc != buf_size-1) {
		warnx("BUG: incorrect recvfrom %zd, expected %zu", rc, buf_size-1);
		return -EPROTO;
	}

	// populate it for good measure
	buf[0] = resp_addr->smctp_type;

	if (resp_addr->smctp_type != req_type) {
		warnx("Mismatching response type %d for request type %d. dest %s",
			resp_addr->smctp_type, req_type, dest_str);
		rc = -ENOMSG;
	}

	rc = 0;
out:
	close(sd);
	if (rc) {
		*resp = NULL;
		*resp_len = 0;
		free(buf);
	} else {
		*resp = buf;
		*resp_len = buf_size;
	}

	return rc;
}

/* Returns the maximum version supported */
static int endpoint_send_get_mctp_version(ctx *ctx, const dest_phys *dest,
	uint8_t query_type,
	bool *ret_supported, uint8_t *ret_max_version)
{
	struct _sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_mctp_ver_support req = {0};
	struct mctp_ctrl_resp_get_mctp_ver_support *resp = NULL;
	ssize_t rc;
	uint8_t* buf = NULL;
	size_t buf_size, expect_size;
	uint8_t max_vers, i;
	char *dest_str;

	dest_str = defer_free(dest_phys_tostr(dest));
	req.ctrl_msg_hdr.rq_dgram_inst = 1<<7;
	req.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req, sizeof(req),
		&buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	if (buf_size < sizeof(*resp)) {
		warnx("%s: short reply %zu bytes. dest %s", __func__, buf_size, dest_str);
		rc = -ENOMSG;
		goto out;
	}
	resp = (void*)buf;

	expect_size = sizeof(resp) + resp->number_of_entries;
	if (buf_size != expect_size) {
		warnx("%s: bad reply length. got %zu, expected %zu, %d entries. dest %s",
			__func__, buf_size, expect_size, resp->number_of_entries, dest_str);
		rc = -ENOMSG;
		goto out;
	}

	if (resp->completion_code == 0x80) {
		*ret_supported = false;
	}

	max_vers = 0x00;
	for (i = 0; i < resp->number_of_entries; i++) {
		max_vers = max(max_vers, *(uint8_t*)(resp+1));
	}
	*ret_max_version = max_vers;
	*ret_supported = true;
	rc = 0;
out:
	free(buf);
	return rc;
}

static int configure_peer(ctx *ctx, sd_bus_message *call, const dest_phys *dest)
{
	int rc;
	bool supported;
	uint8_t max_version;
	rc = endpoint_send_get_mctp_version(ctx, dest, 0xff, &supported, &max_version);

	return -ENOSYS;
}

int validate_dest_phys(const dest_phys *dest) {
	if (dest->hwaddr_len > MAX_ADDR_LEN)
		return -EINVAL;
	if (dest->ifindex <= 0)
		return -EINVAL;
	return 0;
}

static int method_configure_endpoint(sd_bus_message *call, void *data,
	sd_bus_error *sderr)
{
	int rc;
	const char *ifname;
	dest_phys desti, *dest = &desti;
	ctx *ctx = data;
	peer *peer = NULL;

	rc = sd_bus_message_read(call, "s", &ifname);
	if (rc < 0)
		return rc;

	rc = sd_bus_message_read_array(call, 'y',
		(const void**)&dest->hwaddr, &dest->hwaddr_len);
	if (rc < 0)
		return rc;

	dest->ifindex = mctp_nl_ifindex_byname(ctx->nl, ifname);
	if (dest->ifindex < 0) {
		return sd_bus_reply_method_errorf(call, SD_BUS_ERROR_INVALID_ARGS,
			"Unknown MCTP ifname '%s'", ifname);
	}

	rc = validate_dest_phys(dest);
	if (rc < 0) {
		return sd_bus_reply_method_errorf(call, SD_BUS_ERROR_INVALID_ARGS,
			"Bad physaddr");
	}

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		// Return existing record.
		if (peer->state != ASSIGNED) {
			warnx("BUG: Bad state for peer %d, eid %d", peer->state, peer->eid);
			return -EINVAL;
		}
		return sd_bus_reply_method_return(call, "yib", peer->eid, peer->net, 0);
	}

	return configure_peer(ctx, call, dest);
}

// Testing code
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

// Testing code
static int method_test_timer_async(sd_bus_message *call, void *data, sd_bus_error *sderr) {
	int rc;
	int seconds;
	ctx *ctx = data;

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

// Testing code
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
		"say",
		SD_BUS_PARAM(ifname)
		SD_BUS_PARAM(physaddr),
		"yib",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(new), // TODO, better semantics?
		method_configure_endpoint,
		0),

	// Testing code
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

static int setup_bus(ctx *ctx)
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

	ctx ctxi = {0}, *ctx = &ctxi;

	ctx->mctp_timeout = 1000000; // TODO: 1 second

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

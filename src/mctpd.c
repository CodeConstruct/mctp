/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctpd: bus owner for MCTP using Linux kernel
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <systemd/sd-bus-vtable.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-id128.h>

#include "toml.h"

#include "mctp.h"
#include "mctp-util.h"
#include "mctp-netlink.h"
#include "mctp-control-spec.h"
#include "mctp-ops.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define MCTP_DBUS_PATH "/au/com/codeconstruct/mctp1"
#define MCTP_DBUS_PATH_NETWORKS "/au/com/codeconstruct/mctp1/networks"
#define MCTP_DBUS_PATH_LINKS "/au/com/codeconstruct/mctp1/interfaces"
#define CC_MCTP_DBUS_IFACE_BUSOWNER "au.com.codeconstruct.MCTP.BusOwner1"
#define CC_MCTP_DBUS_IFACE_ENDPOINT "au.com.codeconstruct.MCTP.Endpoint1"
#define CC_MCTP_DBUS_IFACE_BRIDGE "au.com.codeconstruct.MCTP.Bridge1"
#define CC_MCTP_DBUS_IFACE_TESTING "au.com.codeconstruct.MCTPTesting"
#define MCTP_DBUS_NAME "au.com.codeconstruct.MCTP1"
#define MCTP_DBUS_IFACE_ENDPOINT "xyz.openbmc_project.MCTP.Endpoint"
#define OPENBMC_IFACE_COMMON_UUID "xyz.openbmc_project.Common.UUID"
#define CC_MCTP_DBUS_IFACE_INTERFACE "au.com.codeconstruct.MCTP.Interface1"
#define CC_MCTP_DBUS_NETWORK_INTERFACE "au.com.codeconstruct.MCTP.Network1"

// an arbitrary constant for use with sd_id128_get_machine_app_specific()
static const char *mctpd_appid = "67369c05-4b97-4b7e-be72-65cfd8639f10";

static const char *conf_file_default = MCTPD_CONF_FILE_DEFAULT;

static mctp_eid_t eid_alloc_min = 0x08;
static mctp_eid_t eid_alloc_max = 0xfe;

// arbitrary sanity
static size_t MAX_PEER_SIZE = 1000000;

static const uint8_t RQDI_REQ = 1 << 7;
static const uint8_t RQDI_RESP = 0x0;
static const uint8_t IID_MASK = 0x1f;
static const uint8_t RQDI_IID_MASK = 0x1f;

struct dest_phys {
	int ifindex;
	uint8_t hwaddr[MAX_ADDR_LEN];
	size_t hwaddr_len;
};
typedef struct dest_phys dest_phys;

/* Table of per-network details */
struct net {
	struct ctx *ctx;
	uint32_t net;

	// EID mappings, NULL is unused.
	struct peer *peers[256];

	sd_bus_slot *slot;
	char *path;
};

struct ctx;

// all local peers have the same phys
static const dest_phys local_phys = { .ifindex = 0 };

enum endpoint_role {
	ENDPOINT_ROLE_UNKNOWN,
	ENDPOINT_ROLE_BUS_OWNER,
	ENDPOINT_ROLE_ENDPOINT,
};

struct role {
	enum endpoint_role role;
	const char *conf_val;
	const char *dbus_val;
};

static const struct role roles[] = {
	[ENDPOINT_ROLE_UNKNOWN] = {
		.role = ENDPOINT_ROLE_UNKNOWN,
		.conf_val = "unknown",
		.dbus_val = "Unknown",
	},
	[ENDPOINT_ROLE_BUS_OWNER] = {
		.role = ENDPOINT_ROLE_BUS_OWNER,
		.conf_val = "bus-owner",
		.dbus_val = "BusOwner",
	},
	[ENDPOINT_ROLE_ENDPOINT] = {
		.role = ENDPOINT_ROLE_ENDPOINT,
		.conf_val = "endpoint",
		.dbus_val = "Endpoint",
	},
};

struct link {
	bool published;
	int ifindex;
	enum endpoint_role role;

	char *path;
	sd_bus_slot *slot_iface;
	sd_bus_slot *slot_busowner;

	struct ctx *ctx;
};

struct peer {
	uint32_t net;
	mctp_eid_t eid;

	// multiple local interfaces can have the same eid,
	// so we store a refcount to use when removing peers.
	int local_count;

	// Only set for .state == REMOTE
	dest_phys phys;

	enum {
		REMOTE,
		// Local address. Note that multiple interfaces
		// in a network may have the same local address.
		LOCAL,
	} state;

	// visible to dbus, set by publish/unpublish_peer()
	bool published;
	sd_bus_slot *slot_obmc_endpoint;
	sd_bus_slot *slot_cc_endpoint;
	sd_bus_slot *slot_bridge;
	sd_bus_slot *slot_uuid;
	char *path;

	bool have_neigh;
	bool have_route;

	// MTU for the route. Set to the interface's minimum MTU initially,
	// or changed by .SetMTU method
	uint32_t mtu;

	// malloc()ed list of supported message types, from Get Message Type
	uint8_t *message_types;
	size_t num_message_types;

	// From Get Endpoint ID
	uint8_t endpoint_type;
	uint8_t medium_spec;

	// From Get Endpoint UUID. A malloced 16 bytes */
	uint8_t *uuid;

	// Stuff the ctx pointer into peer for tidier parameter passing
	struct ctx *ctx;

	// Connectivity state
	bool degraded;
	struct {
		uint64_t delay;
		sd_event_source *source;
		int npolls;
		mctp_eid_t eid;
		uint8_t endpoint_type;
		uint8_t medium_spec;
	} recovery;

	// Pool size
	uint8_t pool_size;
	uint8_t pool_start;
};

struct ctx {
	sd_event *event;
	sd_bus *bus;

	// Configuration
	char *config_filename;

	mctp_nl *nl;

	// Default BMC role in All of MCTP medium interface
	enum endpoint_role default_role;

	// An allocated array of peers, changes address (reallocated) during runtime
	struct peer **peers;
	size_t num_peers;

	struct net **nets;
	size_t num_nets;

	// Timeout in usecs for a MCTP response
	uint64_t mctp_timeout;

	// Next IID to use
	uint8_t iid;

	uint8_t uuid[16];

	// Verbose logging
	bool verbose;

	//  maximum pool size for assumed MCTP Bridge
	uint8_t max_pool_size;
};

static int emit_endpoint_added(const struct peer *peer);
static int emit_endpoint_removed(const struct peer *peer);
static int emit_interface_added(struct link *link);
static int emit_interface_removed(struct link *link);
static int emit_net_added(struct ctx *ctx, struct net *net);
static int emit_net_removed(struct ctx *ctx, struct net *net);
static int query_peer_properties(struct peer *peer);
static int setup_added_peer(struct peer *peer);
static void add_peer_route(struct peer *peer);
static int publish_peer(struct peer *peer, bool add_route);
static int unpublish_peer(struct peer *peer);
static int peer_route_update(struct peer *peer, uint16_t type);
static int peer_neigh_update(struct peer *peer, uint16_t type);

static int add_interface_local(struct ctx *ctx, int ifindex);
static int del_interface(struct link *link);
static int rename_interface(struct ctx *ctx, struct link *link, int ifindex);
static int change_net_interface(struct ctx *ctx, int ifindex, uint32_t old_net);
static int add_local_eid(struct ctx *ctx, uint32_t net, int eid);
static int del_local_eid(struct ctx *ctx, uint32_t net, int eid);
static int add_net(struct ctx *ctx, uint32_t net);
static void del_net(struct net *net);
static int add_interface(struct ctx *ctx, int ifindex);
static int endpoint_allocate_eid(struct peer *peer);

static const sd_bus_vtable bus_endpoint_obmc_vtable[];
static const sd_bus_vtable bus_endpoint_cc_vtable[];
static const sd_bus_vtable bus_endpoint_bridge[];
static const sd_bus_vtable bus_endpoint_uuid_vtable[];

__attribute__((format(printf, 1, 2))) static void bug_warn(const char *fmt, ...)
{
	char *bug_fmt = NULL;
	va_list ap;
	int rc;

	rc = asprintf(&bug_fmt, "BUG: %s", fmt);
	if (rc < 0)
		return;

	va_start(ap, fmt);
	mctp_ops.bug_warn(bug_fmt, ap);
	va_end(ap);

	free(bug_fmt);
}

mctp_eid_t local_addr(const struct ctx *ctx, int ifindex)
{
	mctp_eid_t *eids, ret = 0;
	size_t num;

	eids = mctp_nl_addrs_byindex(ctx->nl, ifindex, &num);
	if (num)
		ret = eids[0];
	free(eids);
	return ret;
}

static void *dfree(void *ptr);

static struct net *lookup_net(struct ctx *ctx, uint32_t net)
{
	size_t i;
	for (i = 0; i < ctx->num_nets; i++)
		if (ctx->nets[i]->net == net)
			return ctx->nets[i];
	return NULL;
}

static bool match_phys(const dest_phys *d1, const dest_phys *d2)
{
	return d1->ifindex == d2->ifindex && d1->hwaddr_len == d2->hwaddr_len &&
	       (d2->hwaddr_len == 0 ||
		!memcmp(d1->hwaddr, d2->hwaddr, d1->hwaddr_len));
}

static struct peer *find_peer_by_phys(struct ctx *ctx, const dest_phys *dest)
{
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		if (peer->state != REMOTE)
			continue;
		if (match_phys(&peer->phys, dest))
			return peer;
	}
	return NULL;
}

static struct peer *find_peer_by_addr(struct ctx *ctx, mctp_eid_t eid,
				      uint32_t net)
{
	struct net *n = lookup_net(ctx, net);

	if (eid != 0 && n && n->peers[eid])
		return n->peers[eid];
	return NULL;
}

static int find_local_eids_by_net(struct net *net, size_t *local_eid_cnt,
				  mctp_eid_t *ret_eids)
{
	size_t local_count = 0;
	struct peer *peer;

	*local_eid_cnt = 0;

	for (size_t t = 0; t < 256; t++) {
		peer = net->peers[t];
		if (!peer)
			continue;

		if (peer && (peer->state == LOCAL))
			ret_eids[local_count++] = t;
	}
	*local_eid_cnt = local_count;

	return 0;
}

/* Returns a deferred free pointer */
static const char *dest_phys_tostr(const dest_phys *dest)
{
	char hex[MAX_ADDR_LEN * 4];
	char *buf;
	size_t l = 50 + sizeof(hex);
	buf = malloc(l);
	if (!buf) {
		return "Out of memory";
	}
	write_hex_addr(dest->hwaddr, dest->hwaddr_len, hex, sizeof(hex));
	snprintf(buf, l, "physaddr if %d hw len %zu 0x%s", dest->ifindex,
		 dest->hwaddr_len, hex);
	return dfree(buf);
}

static const char *ext_addr_tostr(const struct sockaddr_mctp_ext *addr)
{
	char hex[MAX_ADDR_LEN * 4];
	char *buf;
	size_t l = 256;
	buf = malloc(l);
	if (!buf) {
		return "Out of memory";
	}

	write_hex_addr(addr->smctp_haddr, addr->smctp_halen, hex, sizeof(hex));
	snprintf(
		buf, l,
		"sockaddr_mctp_ext eid %d net %u type 0x%02x if %d hw len %hhu 0x%s",
		addr->smctp_base.smctp_addr.s_addr,
		addr->smctp_base.smctp_network, addr->smctp_base.smctp_type,
		addr->smctp_ifindex, addr->smctp_halen, hex);
	return dfree(buf);
}

static const char *peer_tostr(const struct peer *peer)
{
	size_t l = 300;
	char *str = NULL;

	str = malloc(l);
	if (!str) {
		return "Out of memory";
	}
	snprintf(str, l, "peer eid %d net %u phys %s state %d", peer->eid,
		 peer->net, dest_phys_tostr(&peer->phys), peer->state);
	return dfree(str);
}

static const char *peer_tostr_short(const struct peer *peer)
{
	size_t l = 30;
	char *str = NULL;

	str = malloc(l);
	if (!str) {
		return "Out of memory";
	}
	snprintf(str, l, "%u:%d", peer->net, peer->eid);
	return dfree(str);
}

static int defer_free_handler(sd_event_source *s, void *userdata)
{
	free(userdata);
	sd_event_source_unref(s);
	return 0;
}

/* Returns ptr, frees it on the next default event loop cycle (defer)*/
static void *dfree(void *ptr)
{
	sd_event *e = NULL;
	int rc;

	if (!ptr)
		return NULL;
	rc = sd_event_default(&e);
	if (rc < 0) {
		warnx("defer_free no event loop");
		goto out;
	}
	rc = sd_event_add_defer(e, NULL, defer_free_handler, ptr);
	if (rc < 0) {
		warnx("defer_free failed adding");
		goto out;
	}

out:
	if (e)
		sd_event_unref(e);
	return ptr;
}

static int cb_exit_loop_io(sd_event_source *s, int fd, uint32_t revents,
			   void *userdata)
{
	sd_event_exit(sd_event_source_get_event(s), 0);
	return 0;
}

static int cb_exit_loop_timeout(sd_event_source *s, uint64_t usec,
				void *userdata)
{
	sd_event_exit(sd_event_source_get_event(s), -ETIMEDOUT);
	return 0;
}

/* Events are EPOLLIN, EPOLLOUT etc.
   Returns 0 on ready, negative on error. -ETIMEDOUT on timeout */
static int wait_fd_timeout(int fd, short events, uint64_t timeout_usec)
{
	int rc;
	sd_event *ev = NULL;

	// Create a new event loop just for the event+timeout
	rc = sd_event_new(&ev);
	if (rc < 0)
		goto out;

	rc = sd_event_add_time_relative(ev, NULL, CLOCK_MONOTONIC, timeout_usec,
					0, cb_exit_loop_timeout, NULL);
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

static const char *path_from_peer(const struct peer *peer)
{
	if (!peer->published) {
		bug_warn("%s on peer %s", __func__, peer_tostr(peer));
		return NULL;
	}
	return peer->path;
}

static int get_role(const char *mode, struct role *role)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(roles); i++) {
		if (roles[i].dbus_val &&
		    (strcmp(roles[i].dbus_val, mode) == 0)) {
			memcpy(role, &roles[i], sizeof(struct role));
			return 0;
		}
	}

	return -1;
}

/* Returns the message from a socket.
   ret_buf is allocated, should be freed by the caller */
static int read_message(struct ctx *ctx, int sd, uint8_t **ret_buf,
			size_t *ret_buf_size,
			struct sockaddr_mctp_ext *ret_addr)
{
	int rc;
	socklen_t addrlen;
	ssize_t len;
	uint8_t *buf = NULL;
	size_t buf_size;

	len = mctp_ops.mctp.recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL,
				     0);
	if (len < 0) {
		rc = -errno;
		goto out;
	}

	if (len == 0) {
		*ret_buf = NULL;
		*ret_buf_size = 0;
		rc = 0;
		goto out;
	}

	buf_size = len;
	buf = malloc(buf_size);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	addrlen = sizeof(struct sockaddr_mctp_ext);
	memset(ret_addr, 0x0, addrlen);
	len = mctp_ops.mctp.recvfrom(sd, buf, buf_size, MSG_TRUNC,
				     (struct sockaddr *)ret_addr, &addrlen);
	if (len < 0) {
		rc = -errno;
		goto out;
	}
	if ((size_t)len != buf_size) {
		bug_warn("incorrect recvfrom %zd, expected %zu", len, buf_size);
		rc = -EPROTO;
		goto out;
	}
	if (addrlen != sizeof(struct sockaddr_mctp_ext)) {
		warnx("Unexpected address size %u.", addrlen);
		rc = -EPROTO;
		goto out;
	}

	if (ctx->verbose) {
		warnx("read_message got from %s len %zu",
		      ext_addr_tostr(ret_addr), buf_size);
	}

	*ret_buf = buf;
	*ret_buf_size = buf_size;
	rc = 0;
out:
	if (rc < 0) {
		if (ctx->verbose) {
			warnx("read_message returned error: %s", strerror(-rc));
		}
		free(buf);
	}
	return rc;
}

/* Replies to a physical address */
static int reply_message_phys(struct ctx *ctx, int sd, const void *resp,
			      size_t resp_len,
			      const struct sockaddr_mctp_ext *addr)
{
	ssize_t len;
	struct sockaddr_mctp_ext reply_addr = *addr;

	reply_addr.smctp_base.smctp_tag &= ~MCTP_TAG_OWNER;

	len = mctp_ops.mctp.sendto(sd, resp, resp_len, 0,
				   (struct sockaddr *)&reply_addr,
				   sizeof(reply_addr));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != resp_len) {
		bug_warn("short sendto %zd, expected %zu", len, resp_len);
		return -EPROTO;
	}
	return 0;
}

/* Replies to a real EID, not physical addressing */
static int reply_message(struct ctx *ctx, int sd, const void *resp,
			 size_t resp_len, const struct sockaddr_mctp_ext *addr)
{
	ssize_t len;
	struct sockaddr_mctp reply_addr;

	memcpy(&reply_addr, &addr->smctp_base, sizeof(reply_addr));
	reply_addr.smctp_tag &= ~MCTP_TAG_OWNER;

	if (reply_addr.smctp_addr.s_addr == 0 ||
	    reply_addr.smctp_addr.s_addr == 0xff) {
		bug_warn("reply_message can't take EID %d",
			 reply_addr.smctp_addr.s_addr);
		return -EPROTO;
	}

	len = mctp_ops.mctp.sendto(sd, resp, resp_len, 0,
				   (struct sockaddr *)&reply_addr,
				   sizeof(reply_addr));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != resp_len) {
		bug_warn("short sendto %zd, expected %zu", len, resp_len);
		return -EPROTO;
	}
	return 0;
}

// Handles new Incoming Set Endpoint ID request
static int handle_control_set_endpoint_id(struct ctx *ctx, int sd,
					  struct sockaddr_mctp_ext *addr,
					  const uint8_t *buf,
					  const size_t buf_size)
{
	struct mctp_ctrl_cmd_set_eid *req = NULL;
	struct mctp_ctrl_resp_set_eid respi = { 0 }, *resp = &respi;
	size_t resp_len;

	if (buf_size < sizeof(*req)) {
		warnx("short Set Endpoint ID message");
		return -ENOMSG;
	}
	req = (void *)buf;

	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst =
		(req->ctrl_hdr.rq_dgram_inst & IID_MASK) | RQDI_RESP;
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->status = 0x01 << 4; // Already assigned, TODO
	resp->eid_set = local_addr(ctx, addr->smctp_ifindex);
	resp->eid_pool_size = 0;
	resp_len = sizeof(struct mctp_ctrl_resp_set_eid);

	// TODO: learn busowner route and neigh

	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int
handle_control_get_version_support(struct ctx *ctx, int sd,
				   const struct sockaddr_mctp_ext *addr,
				   const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_mctp_ver_support *req = NULL;
	struct mctp_ctrl_resp_get_mctp_ver_support *resp = NULL;
	uint32_t *versions = NULL;
	// space for 4 versions
	uint8_t respbuf[sizeof(*resp) + 4 * sizeof(*versions)];
	size_t resp_len;

	if (buf_size < sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support)) {
		warnx("short Get Version Support message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp = (void *)respbuf;
	memset(resp, 0x0, sizeof(*resp));
	versions = (void *)(resp + 1);
	switch (req->msg_type_number) {
	case 0xff: // Base Protocol
	case 0x00: // Control protocol
		// from DSP0236 1.3.1  section 12.6.2. Big endian.
		versions[0] = htonl(0xF1F0FF00);
		versions[1] = htonl(0xF1F1FF00);
		versions[2] = htonl(0xF1F2FF00);
		versions[3] = htonl(0xF1F3F100);
		resp->number_of_entries = 4;
		resp->completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_len = sizeof(*resp) + 4 * sizeof(*versions);
		break;
	default:
		// Unsupported message type
		resp->completion_code =
			MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE;
		resp_len = sizeof(*resp);
	}

	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst =
		(req->ctrl_hdr.rq_dgram_inst & IID_MASK) | RQDI_RESP;
	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_get_endpoint_id(struct ctx *ctx, int sd,
					  const struct sockaddr_mctp_ext *addr,
					  const uint8_t *buf,
					  const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_eid *req = NULL;
	struct mctp_ctrl_resp_get_eid respi = { 0 }, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint ID message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst =
		(req->ctrl_hdr.rq_dgram_inst & IID_MASK) | RQDI_RESP;

	resp->eid = local_addr(ctx, addr->smctp_ifindex);
	if (ctx->default_role == ENDPOINT_ROLE_BUS_OWNER)
		SET_ENDPOINT_TYPE(resp->eid_type, MCTP_BUS_OWNER_BRIDGE);
	// 10b = 2 = static EID supported, matches currently assigned.
	SET_ENDPOINT_ID_TYPE(resp->eid_type, 2);
	// TODO: medium specific information

	// Get Endpoint ID is typically send and reply using physical addressing.
	return reply_message_phys(ctx, sd, resp, sizeof(*resp), addr);
}

static int
handle_control_get_endpoint_uuid(struct ctx *ctx, int sd,
				 const struct sockaddr_mctp_ext *addr,
				 const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_uuid *req = NULL;
	;
	struct mctp_ctrl_resp_get_uuid respi = { 0 }, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint UUID message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst =
		(req->ctrl_hdr.rq_dgram_inst & IID_MASK) | RQDI_RESP;
	memcpy(resp->uuid, ctx->uuid, sizeof(resp->uuid));
	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

static int handle_control_get_message_type_support(
	struct ctx *ctx, int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_msg_type_support *req = NULL;
	;
	struct mctp_ctrl_resp_get_msg_type_support *resp = NULL;
	uint8_t resp_buf[sizeof(*resp) + 1];
	size_t resp_len;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Message Type Support message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp = (void *)resp_buf;
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst =
		(req->ctrl_hdr.rq_dgram_inst & IID_MASK) | RQDI_RESP;

	// Only control messages supported
	resp->msg_type_count = 1;
	*((uint8_t *)(resp + 1)) = MCTP_CTRL_HDR_MSG_TYPE;
	resp_len = sizeof(*resp) + resp->msg_type_count;

	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int
handle_control_resolve_endpoint_id(struct ctx *ctx, int sd,
				   const struct sockaddr_mctp_ext *addr,
				   const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_resolve_endpoint_id *req = NULL;
	struct mctp_ctrl_resp_resolve_endpoint_id *resp = NULL;
	uint8_t resp_buf[sizeof(*resp) + MAX_ADDR_LEN];
	size_t resp_len;
	struct peer *peer = NULL;

	if (buf_size < sizeof(*req)) {
		warnx("short Resolve Endpoint ID message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp = (void *)resp_buf;
	memset(resp, 0x0, sizeof(*resp));
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst =
		(req->ctrl_hdr.rq_dgram_inst & IID_MASK) | RQDI_RESP;

	peer = find_peer_by_addr(ctx, req->eid, addr->smctp_base.smctp_network);
	if (!peer) {
		resp->completion_code = MCTP_CTRL_CC_ERROR;
		resp_len = sizeof(*resp);
	} else {
		// TODO: bridging
		resp->eid = req->eid;
		memcpy((void *)(resp + 1), peer->phys.hwaddr,
		       peer->phys.hwaddr_len);
		resp_len = sizeof(*resp) + peer->phys.hwaddr_len;
	}

	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_unsupported(struct ctx *ctx, int sd,
				      const struct sockaddr_mctp_ext *addr,
				      const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_msg_hdr *req = NULL;
	struct mctp_ctrl_generic {
		struct mctp_ctrl_msg_hdr ctrl_hdr;
		uint8_t completion_code;
	} __attribute__((__packed__));
	struct mctp_ctrl_generic respi = { 0 }, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short unsupported control message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp->ctrl_hdr.command_code = req->command_code;
	resp->ctrl_hdr.rq_dgram_inst = (req->rq_dgram_inst & IID_MASK) |
				       RQDI_RESP;
	resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

static int cb_listen_control_msg(sd_event_source *s, int sd, uint32_t revents,
				 void *userdata)
{
	struct sockaddr_mctp_ext addr = { 0 };
	struct ctx *ctx = userdata;
	uint8_t *buf = NULL;
	size_t buf_size;
	struct mctp_ctrl_msg_hdr *ctrl_msg = NULL;
	int rc;

	rc = read_message(ctx, sd, &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	if (buf_size == 0)
		errx(EXIT_FAILURE, "Control socket returned EOF");

	if (addr.smctp_base.smctp_type != MCTP_CTRL_HDR_MSG_TYPE) {
		bug_warn("Wrong message type for listen socket");
		rc = -EINVAL;
		goto out;
	}

	if (buf_size < sizeof(struct mctp_ctrl_msg_hdr)) {
		warnx("Short message %zu bytes from %s", buf_size,
		      ext_addr_tostr(&addr));
		rc = -EINVAL;
		goto out;
	}

	ctrl_msg = (void *)buf;
	if (ctx->verbose) {
		warnx("Got control request command code %hhd",
		      ctrl_msg->command_code);
	}
	switch (ctrl_msg->command_code) {
	case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
		rc = handle_control_get_version_support(ctx, sd, &addr, buf,
							buf_size);
		break;
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		rc = handle_control_set_endpoint_id(ctx, sd, &addr, buf,
						    buf_size);
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		rc = handle_control_get_endpoint_id(ctx, sd, &addr, buf,
						    buf_size);
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
		rc = handle_control_get_endpoint_uuid(ctx, sd, &addr, buf,
						      buf_size);
		break;
	case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
		rc = handle_control_get_message_type_support(ctx, sd, &addr,
							     buf, buf_size);
		break;
	case MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID:
		rc = handle_control_resolve_endpoint_id(ctx, sd, &addr, buf,
							buf_size);
		break;
	default:
		if (ctx->verbose) {
			warnx("Ignoring unsupported command code 0x%02x",
			      ctrl_msg->command_code);
			rc = -ENOTSUP;
		}
		rc = handle_control_unsupported(ctx, sd, &addr, buf, buf_size);
	}

	if (ctx->verbose && rc < 0) {
		warnx("Error handling command code %02x from %s: %s",
		      ctrl_msg->command_code, ext_addr_tostr(&addr),
		      strerror(-rc));
	}

out:
	free(buf);
	return 0;
}

static int listen_control_msg(struct ctx *ctx, uint32_t net)
{
	struct sockaddr_mctp addr = { 0 };
	int rc, sd = -1, val;

	sd = mctp_ops.mctp.socket();
	if (sd < 0) {
		rc = -errno;
		warn("%s: socket() failed", __func__);
		goto out;
	}

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = net;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = MCTP_CTRL_HDR_MSG_TYPE;
	addr.smctp_tag = MCTP_TAG_OWNER;

	rc = mctp_ops.mctp.bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		rc = -errno;
		warn("%s: bind() failed", __func__);
		goto out;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				      sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

	rc = sd_event_add_io(ctx->event, NULL, sd, EPOLLIN,
			     cb_listen_control_msg, ctx);
	return rc;
out:
	if (rc < 0) {
		close(sd);
	}
	return rc;
}

static int cb_listen_monitor(sd_event_source *s, int sd, uint32_t revents,
			     void *userdata)
{
	struct ctx *ctx = userdata;
	mctp_nl_change *changes = NULL;
	size_t num_changes;
	int rc;
	bool any_error = false;

	rc = mctp_nl_handle_monitor(ctx->nl, &changes, &num_changes);
	if (rc < 0) {
		warnx("Error handling update from netlink, link state may now be outdated. %s",
		      strerror(-rc));
		return rc;
	}

	for (size_t i = 0; i < num_changes; i++) {
		struct mctp_nl_change *c = &changes[i];
		switch (c->op) {
		case MCTP_NL_ADD_LINK: {
			rc = add_interface_local(ctx, c->ifindex);
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_DEL_LINK: {
			// Local addresses have already been deleted with DEL_EID
			if (c->link_userdata) {
				rc = del_interface(c->link_userdata);
			} else {
				// Would have expected to have seen it in previous
				// MCTP_NL_ADD_LINK or setup_nets().
				rc = -ENOENT;
				bug_warn("delete unconfigured interface %d",
					 c->ifindex);
			}
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_CHANGE_NET: {
			// Local addresses have already been deleted with DEL_EID
			rc = add_interface_local(ctx, c->ifindex);
			any_error |= (rc < 0);

			// Move remote endpoints
			rc = change_net_interface(ctx, c->ifindex, c->old_net);
			any_error |= (rc < 0);

			break;
		}

		case MCTP_NL_CHANGE_NAME: {
			if (c->link_userdata) {
				rc = rename_interface(ctx, c->link_userdata,
						      c->ifindex);
			} else {
				rc = -ENOENT;
				bug_warn(
					"name change for unconfigured interface %d",
					c->ifindex);
			}

			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_ADD_EID: {
			uint32_t net = mctp_nl_net_byindex(ctx->nl, c->ifindex);
			rc = add_local_eid(ctx, net, c->eid);
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_DEL_EID: {
			rc = del_local_eid(ctx, c->old_net, c->eid);
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_CHANGE_UP: {
			// 'up' state is currently unused
			break;
		}
		}
	}

	if (ctx->verbose && any_error) {
		warnx("Error handling netlink update");
		mctp_nl_changes_dump(ctx->nl, changes, num_changes);
		mctp_nl_linkmap_dump(ctx->nl);
	}

	free(changes);
	return 0;
}

static int listen_monitor(struct ctx *ctx)
{
	int rc, sd;

	sd = mctp_nl_monitor(ctx->nl, true);
	if (sd < 0) {
		return sd;
	}

	rc = sd_event_add_io(ctx->event, NULL, sd, EPOLLIN, cb_listen_monitor,
			     ctx);
	return rc;
}

static uint8_t mctp_next_iid(struct ctx *ctx)
{
	uint8_t iid = ctx->iid;

	ctx->iid = (iid + 1) & RQDI_IID_MASK;
	return iid;
}

static const char *command_str(uint8_t cmd)
{
	static char unknown_cmd_str[32];

	switch (cmd) {
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		return "Set Endpoint ID";
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		return "Get Endpoint ID";
	case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
		return "Get Endpoint UUID";
	case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
		return "Get Version Support";
	case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
		return "Get Message Type Support";
	case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT:
		return "Get Vendor Message Support";
	case MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID:
		return "Resolve Endpoint ID";
	case MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS:
		return "Allocate Endpoint ID ";
	case MCTP_CTRL_CMD_ROUTING_INFO_UPDATE:
		return "Routing Info Update";
	case MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES:
		return "Get Routing Table Entries";
	case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY:
		return "Prepare Endpoint Discovery";
	case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:
		return "Endpoint Discovery";
	case MCTP_CTRL_CMD_DISCOVERY_NOTIFY:
		return "Discovery Notify";
	case MCTP_CTRL_CMD_GET_NETWORK_ID:
		return "Get Network ID";
	case MCTP_CTRL_CMD_QUERY_HOP:
		return "Query Hop";
	case MCTP_CTRL_CMD_RESOLVE_UUID:
		return "Resolve UUID";
	case MCTP_CTRL_CMD_QUERY_RATE_LIMIT:
		return "Query Rate Limit";
	case MCTP_CTRL_CMD_REQUEST_TX_RATE_LIMIT:
		return "Request TX Rate Limit";
	case MCTP_CTRL_CMD_UPDATE_RATE_LIMIT:
		return "Update Rate Limit";
	case MCTP_CTRL_CMD_QUERY_SUPPORTED_INTERFACES:
		return "Query Supported Interfaces";
	}

	sprintf(unknown_cmd_str, "Unknown command [0x%02x]", cmd);

	return unknown_cmd_str;
}

static const char *peer_cmd_prefix(const char *peer, uint8_t cmd)
{
	static char pfx_str[64];

	snprintf(pfx_str, sizeof(pfx_str), "[peer %s, cmd %s]", peer,
		 command_str(cmd));

	return pfx_str;
}

/* Common checks for responses: that we have enough data for a response,
 * the expected IID and opcode, and that the response indicated success.
 */
static int mctp_ctrl_validate_response(uint8_t *buf, size_t rsp_size,
				       size_t exp_size, const char *peer,
				       uint8_t iid, uint8_t cmd)
{
	struct mctp_ctrl_resp *rsp;

	if (exp_size <= sizeof(*rsp)) {
		warnx("invalid expected response size!");
		return -EINVAL;
	}

	/* Error responses only need to include the completion code */
	if (rsp_size < MCTP_CTRL_ERROR_RESP_LEN) {
		warnx("%s: Wrong reply length (%zu bytes)",
		      peer_cmd_prefix(peer, cmd), rsp_size);
		return -ENOMSG;
	}

	/* we have enough for the smallest common response message */
	rsp = (void *)buf;

	if ((rsp->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK) != iid) {
		warnx("%s: Wrong IID (0x%02x, expected 0x%02x)",
		      peer_cmd_prefix(peer, cmd),
		      rsp->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK, iid);
		return -ENOMSG;
	}

	if (rsp->ctrl_hdr.command_code != cmd) {
		warnx("%s: Wrong opcode (0x%02x) in response",
		      peer_cmd_prefix(peer, cmd), rsp->ctrl_hdr.command_code);
		return -ENOMSG;
	}

	if (rsp->completion_code) {
		warnx("%s: Command failed, completion code 0x%02x",
		      peer_cmd_prefix(peer, cmd), rsp->completion_code);
		return -ECONNREFUSED;
	}

	/* Non-error responses must be full sized */
	if (rsp_size < exp_size) {
		warnx("%s: Wrong reply length (%zu bytes)",
		      peer_cmd_prefix(peer, cmd), rsp_size);
		return -ENOMSG;
	}

	return 0;
}

/* Use endpoint_query_peer() or endpoint_query_phys() instead.
 *
 * resp buffer is allocated, caller to free.
 * Extended addressing is used optionally, depending on ext_addr arg. */
static int endpoint_query_addr(struct ctx *ctx,
			       const struct sockaddr_mctp_ext *req_addr,
			       bool ext_addr, const void *req, size_t req_len,
			       uint8_t **resp, size_t *resp_len,
			       struct sockaddr_mctp_ext *resp_addr)
{
	size_t req_addr_len;
	int sd = -1, val;
	ssize_t rc;
	size_t buf_size;

	uint8_t *buf = NULL;

	*resp = NULL;
	*resp_len = 0;

	sd = mctp_ops.mctp.socket();
	if (sd < 0) {
		warn("socket");
		rc = -errno;
		goto out;
	}

	// We want extended addressing on all received messages
	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				      sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

	if (ext_addr) {
		req_addr_len = sizeof(struct sockaddr_mctp_ext);
	} else {
		req_addr_len = sizeof(struct sockaddr_mctp);
	}

	if (req_len == 0) {
		bug_warn("zero length request");
		rc = -EPROTO;
		goto out;
	}
	rc = mctp_ops.mctp.sendto(sd, req, req_len, 0,
				  (struct sockaddr *)req_addr, req_addr_len);
	if (rc < 0) {
		rc = -errno;
		if (ctx->verbose) {
			warnx("%s: sendto(%s) %zu bytes failed. %s", __func__,
			      ext_addr_tostr(req_addr), req_len, strerror(-rc));
		}
		goto out;
	}
	if ((size_t)rc != req_len) {
		bug_warn("incorrect sendto %zd, expected %zu", rc, req_len);
		rc = -EPROTO;
		goto out;
	}

	rc = wait_fd_timeout(sd, EPOLLIN, ctx->mctp_timeout);
	if (rc < 0) {
		if (rc == -ETIMEDOUT && ctx->verbose) {
			warnx("%s: receive timed out from %s", __func__,
			      ext_addr_tostr(req_addr));
		}
		goto out;
	}

	rc = read_message(ctx, sd, &buf, &buf_size, resp_addr);
	if (rc < 0) {
		goto out;
	}

	if (resp_addr->smctp_base.smctp_type !=
	    req_addr->smctp_base.smctp_type) {
		warnx("Mismatching response type %d for request type %d. dest %s",
		      resp_addr->smctp_base.smctp_type,
		      req_addr->smctp_base.smctp_type,
		      ext_addr_tostr(req_addr));
		rc = -ENOMSG;
	}

	rc = 0;
out:
	close(sd);
	if (rc) {
		free(buf);
	} else {
		*resp = buf;
		*resp_len = buf_size;
	}

	return rc;
}

/* Queries an endpoint peer. Addressing is standard eid/net.
 */
static int endpoint_query_peer(const struct peer *peer, uint8_t req_type,
			       const void *req, size_t req_len, uint8_t **resp,
			       size_t *resp_len,
			       struct sockaddr_mctp_ext *resp_addr)
{
	struct sockaddr_mctp_ext addr = { 0 };

	if (peer->state != REMOTE) {
		bug_warn("%s bad peer %s", __func__, peer_tostr(peer));
		return -EPROTO;
	}

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = peer->net;
	addr.smctp_base.smctp_addr.s_addr = peer->eid;

	addr.smctp_base.smctp_type = req_type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	return endpoint_query_addr(peer->ctx, &addr, false, req, req_len, resp,
				   resp_len, resp_addr);
}

/* Queries an endpoint using physical addressing, null EID.
 */
static int endpoint_query_phys(struct ctx *ctx, const dest_phys *dest,
			       uint8_t req_type, const void *req,
			       size_t req_len, uint8_t **resp, size_t *resp_len,
			       struct sockaddr_mctp_ext *resp_addr)
{
	struct sockaddr_mctp_ext addr = { 0 };

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = 0;
	// Physical addressed requests may receive a response where the
	// source-eid that isn't the same as the dest-eid of the request,
	// for example Set Endpoint Id.
	// The kernel mctp stack has special handling for eid=0 to make sure we
	// can recv a response on the socket, so it's important to set eid=0
	// here in the request.
	addr.smctp_base.smctp_addr.s_addr = 0;

	addr.smctp_ifindex = dest->ifindex;
	addr.smctp_halen = dest->hwaddr_len;
	memcpy(addr.smctp_haddr, dest->hwaddr, dest->hwaddr_len);

	addr.smctp_base.smctp_type = req_type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	return endpoint_query_addr(ctx, &addr, true, req, req_len, resp,
				   resp_len, resp_addr);
}

/* returns -ECONNREFUSED if the endpoint returns failure. */
static int endpoint_send_set_endpoint_id(struct peer *peer,
					 mctp_eid_t *new_eidp)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_set_eid req = { 0 };
	struct mctp_ctrl_resp_set_eid *resp = NULL;
	int rc;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid, stat, alloc;
	const dest_phys *dest = &peer->phys;
	mctp_eid_t new_eid;

	rc = -1;

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	req.operation =
		mctp_ctrl_cmd_set_eid_set_eid; // TODO: do we want Force?
	req.eid = peer->eid;
	rc = endpoint_query_phys(peer->ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest), iid,
					 MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	if (rc)
		goto out;

	resp = (void *)buf;

	stat = resp->status >> 4 & 0x3;
	new_eid = resp->eid_set;

	// For both accepted and rejected cases, we learn the new EID of the
	// endpoint. If this is a valid ID, we are likely to be able to handle
	// this, as the caller may be able to change_peer_eid() to the
	// newly-reported eid
	if (stat == 0x01) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s rejected assignment eid %d, and reported invalid eid %d",
			      dest_phys_tostr(dest), peer->eid, new_eid);
			rc = -ECONNREFUSED;
			goto out;
		}
	} else if (stat == 0x00) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s eid %d replied with invalid eid %d, but 'accepted'",
			      dest_phys_tostr(dest), peer->eid, new_eid);
			rc = -ECONNREFUSED;
			goto out;
		} else if (new_eid != peer->eid) {
			warnx("%s eid %d replied with different eid %d, but 'accepted'",
			      dest_phys_tostr(dest), peer->eid, new_eid);
		}
	} else {
		warnx("%s unexpected status 0x%02x", dest_phys_tostr(dest),
		      resp->status);
	}
	*new_eidp = new_eid;

	alloc = resp->status & 0x3;
	if (alloc != 0) {
		peer->pool_size = resp->eid_pool_size;
		if (peer->ctx->verbose) {
			warnx("%s requested allocation of pool size = %d",
			      dest_phys_tostr(dest), peer->pool_size);
		}
	}

	rc = 0;
out:
	free(buf);
	return rc;
}

/* Returns the newly added peer.
 * Error is -EEXISTS if it exists */
static int add_peer(struct ctx *ctx, const dest_phys *dest, mctp_eid_t eid,
		    uint32_t net, struct peer **ret_peer)
{
	struct peer *peer, **tmp;
	struct net *n;

	n = lookup_net(ctx, net);
	if (!n) {
		bug_warn("%s Bad net %u", __func__, net);
		return -EPROTO;
	}

	peer = n->peers[eid];
	if (peer) {
		if (!match_phys(&peer->phys, dest)) {
			return -EEXIST;
		}
		*ret_peer = peer;
		return 0;
	}

	if (ctx->num_peers == MAX_PEER_SIZE)
		return -ENOMEM;

	// Allocate the peer itself
	peer = calloc(1, sizeof(*peer));
	if (!peer)
		return -ENOMEM;

	// Add it to our peers array
	tmp = realloc(ctx->peers, (ctx->num_peers + 1) * sizeof(*ctx->peers));
	if (!tmp)
		return -ENOMEM;
	ctx->peers = tmp;
	ctx->peers[ctx->num_peers] = peer;
	ctx->num_peers++;

	// Populate it
	peer->eid = eid;
	peer->net = net;
	memcpy(&peer->phys, dest, sizeof(*dest));
	peer->state = REMOTE;
	peer->ctx = ctx;

	// Update network eid map
	n->peers[eid] = peer;

	*ret_peer = peer;
	return 0;
}

static int check_peer_struct(const struct peer *peer, const struct net *n)
{
	if (n->net != peer->net) {
		bug_warn("Mismatching net %d vs peer net %u", n->net,
			 peer->net);
		return -1;
	}

	if (peer != n->peers[peer->eid]) {
		bug_warn("Bad peer: net %u eid %02x", peer->net, peer->eid);
		return -1;
	}

	return 0;
}

static int remove_peer(struct peer *peer)
{
	struct ctx *ctx = peer->ctx;
	struct net *n = NULL;
	struct peer **tmp;
	size_t idx;

	n = lookup_net(peer->ctx, peer->net);
	if (!n) {
		bug_warn("%s: Bad net %u", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(peer, n) != 0) {
		bug_warn("%s: Inconsistent state", __func__);
		return -EPROTO;
	}

	unpublish_peer(peer);

	// Clear it
	if (peer->degraded) {
		int rc;

		rc = sd_event_source_set_enabled(peer->recovery.source,
						 SD_EVENT_OFF);
		if (rc < 0) {
			/* XXX: Fix caller assumptions? */
			warnx("Failed to stop recovery timer while removing peer: %d",
			      rc);
		}
		sd_event_source_unref(peer->recovery.source);
	}

	n->peers[peer->eid] = NULL;
	free(peer->message_types);
	free(peer->uuid);

	for (idx = 0; idx < ctx->num_peers; idx++) {
		if (ctx->peers[idx] == peer)
			break;
	}

	if (idx == ctx->num_peers) {
		bug_warn("peer net %u, eid %d not found on remove!", peer->net,
			 peer->eid);
		return -EPROTO;
	}

	// remove from peers array & resize
	ctx->num_peers--;
	memmove(ctx->peers + idx, ctx->peers + idx + 1,
		(ctx->num_peers - idx) * sizeof(struct peer *));

	if (ctx->num_peers > 0) {
		tmp = realloc(ctx->peers,
			      ctx->num_peers * sizeof(struct peer *));
		if (!tmp) {
			warn("%s: peer realloc(reduce!) failed", __func__);
			// we'll re-try on next add/remove
		} else {
			ctx->peers = tmp;
		}
	} else {
		free(ctx->peers);
		ctx->peers = NULL;
	}

	free(peer);

	return 0;
}

static void free_peers(struct ctx *ctx)
{
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		free(peer->message_types);
		free(peer->uuid);
		free(peer->path);
		sd_bus_slot_unref(peer->slot_obmc_endpoint);
		sd_bus_slot_unref(peer->slot_cc_endpoint);
		sd_bus_slot_unref(peer->slot_bridge);
		sd_bus_slot_unref(peer->slot_uuid);
		free(peer);
	}

	free(ctx->peers);
}

/* Returns -EEXIST if the new_eid is already used */
static int change_peer_eid(struct peer *peer, mctp_eid_t new_eid)
{
	struct net *n = NULL;
	int rc;

	if (!mctp_eid_is_valid_unicast(new_eid))
		return -EINVAL;

	n = lookup_net(peer->ctx, peer->net);
	if (!n) {
		bug_warn("%s: Bad net %u", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(peer, n) != 0) {
		bug_warn("%s: Inconsistent state", __func__);
		return -EPROTO;
	}

	if (n->peers[new_eid])
		return -EEXIST;

	/* publish & unpublish will update peer->path */
	unpublish_peer(peer);
	n->peers[new_eid] = n->peers[peer->eid];
	n->peers[peer->eid] = NULL;
	peer->eid = new_eid;
	rc = publish_peer(peer, true);
	if (rc)
		return rc;

	return 0;
}

static int peer_set_mtu(struct ctx *ctx, struct peer *peer, uint32_t mtu)
{
	int rc;

	if (!mctp_nl_if_exists(peer->ctx->nl, peer->phys.ifindex)) {
		bug_warn("%s: no interface for ifindex %d", __func__,
			 peer->phys.ifindex);
		return -EPROTO;
	}

	rc = mctp_nl_route_del(ctx->nl, peer->eid, 0, peer->phys.ifindex, NULL);
	if (rc < 0 && rc != -ENOENT) {
		warnx("%s, Failed removing existing route for eid %d %s",
		      __func__, peer->phys.ifindex,
		      mctp_nl_if_byindex(ctx->nl, peer->phys.ifindex));
		// Continue regardless, route_add will likely fail with EEXIST
	}

	rc = mctp_nl_route_add(ctx->nl, peer->eid, 0, peer->phys.ifindex, NULL,
			       mtu);
	if (rc >= 0) {
		peer->mtu = mtu;
	}
	return rc;
}

// checks if EIDs from bridge + 1 has contiguous max_pool_size available eids
// returns next candidate eid for pool start
static int get_next_pool_start(mctp_eid_t bridge_eid, struct net *n,
			       int max_pool_size)
{
	if (bridge_eid + 1 + max_pool_size > eid_alloc_max) {
		return -EADDRNOTAVAIL;
	}
	for (mctp_eid_t e = bridge_eid + 1; e <= bridge_eid + max_pool_size;
	     e++) {
		// found a bridge in between, need to skip its pool range
		if (n->peers[e] != NULL) {
			e += n->peers[e]->pool_size;
			return e;
		}
	}
	/* possible to have contiguous eids within
	  bridge_eid to bridge_eid + max_pool_size */
	return bridge_eid + 1;
}

static int endpoint_assign_eid(struct ctx *ctx, sd_bus_error *berr,
			       const dest_phys *dest, struct peer **ret_peer,
			       mctp_eid_t static_eid, bool assign_bridge)
{
	mctp_eid_t e, new_eid;
	struct net *n = NULL;
	struct peer *peer = NULL;
	uint32_t net;
	int rc;
	bool is_pool_possible = false;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (!net) {
		bug_warn("No net known for ifindex %d", dest->ifindex);
		return -EPROTO;
	}

	n = lookup_net(ctx, net);
	if (!n) {
		bug_warn("Unknown net %d", net);
		return -EPROTO;
	}

	if (static_eid) {
		rc = add_peer(ctx, dest, static_eid, net, &peer);
		if (rc < 0)
			return rc;

		new_eid = static_eid;
	} else {
		/* Find an unused EID */
		for (e = eid_alloc_min; e <= eid_alloc_max; e++) {
			if (n->peers[e]) {
				// used peer may be a bridge, skip its eid range
				e += n->peers[e]->pool_size;
				continue;
			}

			// check for max sized pool from e + 1
			if (assign_bridge) {
				int next_pool_start = get_next_pool_start(
					e, n, ctx->max_pool_size);
				if (next_pool_start < 0) {
					warnx("Ran out of EIDs from net %d while"
					      "allocating bridge downstream endpoint at %s ",
					      net, dest_phys_tostr(dest));
					is_pool_possible = false;
					/*ran out of pool eid : set only bridge eid then
					find first available bridge eid which is not part of any pool*/
					for (e = eid_alloc_min;
					     e <= eid_alloc_max; e++) {
						if (n->peers[e]) {
							// used peer may be a bridge, skip its eid range
							e += n->peers[e]
								     ->pool_size;
							continue;
						}
						break;
					}
				} else if (next_pool_start != e + 1) {
					// e doesn't have any contiguous max pool size eids available
					e += next_pool_start;
					continue;
				} else {
					// found contigous eids of max_pool_size from bridge_eid
					is_pool_possible = true;
				}
			}

			rc = add_peer(ctx, dest, e, net, &peer);
			if (rc < 0)
				return rc;
			if (assign_bridge && is_pool_possible) {
				peer->pool_size = ctx->max_pool_size;
				peer->pool_start = e + 1;
			}
			break;
		}
		if (e > eid_alloc_max) {
			warnx("Ran out of EIDs for net %d, allocating %s", net,
			      dest_phys_tostr(dest));
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "Ran out of EIDs");
			return -EADDRNOTAVAIL;
		}
	}

	rc = endpoint_send_set_endpoint_id(peer, &new_eid);
	if (rc == -ECONNREFUSED)
		sd_bus_error_setf(
			berr, SD_BUS_ERROR_FAILED,
			"Endpoint returned failure to Set Endpoint ID");
	if (rc < 0) {
		remove_peer(peer);
		return rc;
	}

	if (new_eid != peer->eid) {
		// avoid allocation for any different EID in response
		warnx("Mismatch of requested from received EID, resetting the pool");
		peer->pool_size = 0;
		peer->pool_start = 0;
		rc = change_peer_eid(peer, new_eid);
		if (rc == -EEXIST) {
			sd_bus_error_setf(
				berr, SD_BUS_ERROR_FAILED,
				"Endpoint requested EID %d instead of assigned %d, already used",
				new_eid, peer->eid);
		}
		if (rc < 0) {
			remove_peer(peer);
			return rc;
		}
	}

	rc = setup_added_peer(peer);
	if (rc < 0)
		return rc;
	*ret_peer = peer;

	return 0;
}

/* Populates a sd_bus_error based on mctpd's convention for error codes.
 * Does nothing if berr is already set.
 */
static void set_berr(struct ctx *ctx, int errcode, sd_bus_error *berr)
{
	bool existing = false;

	if (sd_bus_error_is_set(berr)) {
		existing = true;
	} else
		switch (errcode) {
		case -ETIMEDOUT:
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "MCTP Endpoint did not respond");
			break;
		case -ECONNREFUSED:
			// MCTP_CTRL_CC_ERROR or others
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "MCTP Endpoint replied with failure");
			break;
		case -EBUSY:
			// MCTP_CTRL_CC_ERROR_NOT_READY
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "MCTP Endpoint busy");
			break;
		case -ENOTSUP:
			// MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "Endpoint replied 'unsupported'");
			break;
		case -EPROTO:
			// BUG
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "Internal error");
			break;
		default:
			if (errcode < 0)
				sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
						  "Request failed");
			break;
		}

	if (ctx->verbose && sd_bus_error_is_set(berr)) {
		if (existing) {
			warnx("Returning existing dbus error '%s'. ignored errcode=%d (%s)",
			      berr->message, errcode, strerror(-errcode));
		} else {
			warnx("Returning dbus error '%s', errcode=%d (%s)",
			      berr->message, errcode, strerror(-errcode));
		}
	}
}

static int query_get_endpoint_id(struct ctx *ctx, const dest_phys *dest,
				 mctp_eid_t *ret_eid, uint8_t *ret_ep_type,
				 uint8_t *ret_media_spec)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_eid req = { 0 };
	struct mctp_ctrl_resp_get_eid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(ctx);

	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest), iid,
					 MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	if (rc)
		goto out;

	resp = (void *)buf;

	*ret_eid = resp->eid;
	*ret_ep_type = resp->eid_type;
	*ret_media_spec = resp->medium_data;
out:
	free(buf);
	return rc;
}

/* Returns 0, and ret_peer associated with the endpoint.
 * Returns 0, ret_peer=NULL if the endpoint successfully replies "not yet assigned".
 * Returns negative error code on failure.
 */
static int get_endpoint_peer(struct ctx *ctx, sd_bus_error *berr,
			     const dest_phys *dest, struct peer **ret_peer,
			     mctp_eid_t *ret_cur_eid)
{
	mctp_eid_t eid;
	uint8_t ep_type, medium_spec;
	struct peer *peer = NULL;
	uint32_t net;
	int rc;

	*ret_peer = NULL;
	rc = query_get_endpoint_id(ctx, dest, &eid, &ep_type, &medium_spec);
	if (rc)
		return rc;

	if (ret_cur_eid)
		*ret_cur_eid = eid;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (!net) {
		return -EPROTO;
	}

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		/* Existing entry */
		if (eid == 0) {
			// EID not yet assigned
			remove_peer(peer);
			return 0;
		} else if (peer->eid != eid) {
			rc = change_peer_eid(peer, eid);
			/* Conflict while changing EIDs: the new EID already
			 * exists in our local table. We can only delete the
			 * entry because it's no longer valid, and the caller
			 * will handle the error */
			if (rc < 0) {
				remove_peer(peer);
				return rc;
			}
		}
	} else {
		if (eid == 0) {
			// Not yet assigned.
			return 0;
		}
		/* New endpoint */
		rc = add_peer(ctx, dest, eid, net, &peer);
		if (rc < 0)
			return rc;
	}

	peer->endpoint_type = ep_type;
	peer->medium_spec = medium_spec;
	rc = setup_added_peer(peer);
	if (rc < 0)
		return rc;

	*ret_peer = peer;
	return 0;
}

static int query_get_peer_msgtypes(struct peer *peer)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_msg_type_support req;
	struct mctp_ctrl_resp_get_msg_type_support *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size, expect_size;
	uint8_t iid;
	int rc;

	peer->num_message_types = 0;
	free(peer->message_types);
	peer->message_types = NULL;
	iid = mctp_next_iid(peer->ctx);

	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT;

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(
		buf, buf_size, sizeof(*resp), peer_tostr_short(peer), iid,
		MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	if (rc)
		goto out;

	resp = (void *)buf;
	expect_size = sizeof(*resp) + resp->msg_type_count;
	if (buf_size != expect_size) {
		warnx("%s: bad reply length. got %zu, expected %zu, %d entries. dest %s",
		      __func__, buf_size, expect_size, resp->msg_type_count,
		      peer_tostr(peer));
		rc = -ENOMSG;
		goto out;
	}

	peer->message_types = malloc(resp->msg_type_count);
	if (!peer->message_types) {
		rc = -ENOMEM;
		goto out;
	}
	peer->num_message_types = resp->msg_type_count;
	memcpy(peer->message_types, (void *)(resp + 1), resp->msg_type_count);
	rc = 0;
out:
	free(buf);
	return rc;
}

static int peer_set_uuid(struct peer *peer, const uint8_t uuid[16])
{
	if (!peer->uuid) {
		peer->uuid = malloc(16);
		if (!peer->uuid)
			return -ENOMEM;
	}
	memcpy(peer->uuid, uuid, 16);
	return 0;
}

static int query_get_peer_uuid_by_phys(struct ctx *ctx, const dest_phys *dest,
				       uint8_t uuid[16])
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_uuid req;
	struct mctp_ctrl_resp_get_uuid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;

	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest), iid,
					 MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	if (rc)
		goto out;

	resp = (void *)buf;
	memcpy(uuid, resp->uuid, 16);

out:
	free(buf);
	return rc;
}

static int query_get_peer_uuid(struct peer *peer)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_uuid req;
	struct mctp_ctrl_resp_get_uuid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	if (peer->state != REMOTE) {
		warnx("%s: Wrong state for peer %s", __func__,
		      peer_tostr(peer));
		return -EPROTO;
	}

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer), iid,
					 MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	if (rc)
		goto out;

	resp = (void *)buf;

	rc = peer_set_uuid(peer, resp->uuid);
	if (rc < 0)
		goto out;
	rc = 0;

out:
	free(buf);
	return rc;
}

static int validate_dest_phys(struct ctx *ctx, const dest_phys *dest)
{
	if (dest->hwaddr_len > MAX_ADDR_LEN) {
		warnx("bad hwaddr_len %zu", dest->hwaddr_len);
		return -EINVAL;
	}
	if (dest->ifindex <= 0) {
		warnx("bad ifindex %d", dest->ifindex);
		return -EINVAL;
	}
	if (!mctp_nl_net_byindex(ctx->nl, dest->ifindex)) {
		warnx("unknown ifindex %d", dest->ifindex);
		return -EINVAL;
	}
	return 0;
}

static int message_read_hwaddr(sd_bus_message *call, dest_phys *dest)
{
	int rc;
	const void *msg_hwaddr = NULL;
	size_t msg_hwaddr_len;

	rc = sd_bus_message_read_array(call, 'y', &msg_hwaddr, &msg_hwaddr_len);
	if (rc < 0)
		return rc;
	if (msg_hwaddr_len > MAX_ADDR_LEN)
		return -EINVAL;

	memset(dest->hwaddr, 0x0, MAX_ADDR_LEN);
	memcpy(dest->hwaddr, msg_hwaddr, msg_hwaddr_len);
	dest->hwaddr_len = msg_hwaddr_len;
	return 0;
}

/* SetupEndpoint method tries the following in order:
  - request Get Endpoint ID to add to the known table, return that
  - request Set Endpoint ID, return that */
static int method_setup_endpoint(sd_bus_message *call, void *data,
				 sd_bus_error *berr)
{
	dest_phys desti = { 0 }, *dest = &desti;
	const char *peer_path = NULL;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	int rc;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	/* Get Endpoint ID */
	rc = get_endpoint_peer(ctx, berr, dest, &peer, NULL);
	if (rc >= 0 && peer) {
		if (ctx->verbose)
			fprintf(stderr,
				"%s returning from get_endpoint_peer %s\n",
				__func__, peer_tostr(peer));
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;
		return sd_bus_reply_method_return(call, "yisb", peer->eid,
						  peer->net, peer_path, 0);
	} else if (rc == -EEXIST) {
		// EEXISTS is OK, we will assign a new eid instead.
	} else if (rc < 0) {
		// Unhandled error, fail.
		goto err;
	}

	/* Set Endpoint ID */
	rc = endpoint_assign_eid(ctx, berr, dest, &peer, 0, false);
	if (rc < 0)
		goto err;

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;
	if (ctx->verbose)
		fprintf(stderr, "%s returning from endpoint_assign_eid %s\n",
			__func__, peer_tostr(peer));
	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);

err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_assign_endpoint(sd_bus_message *call, void *data,
				  sd_bus_error *berr)
{
	dest_phys desti, *dest = &desti;
	const char *peer_path = NULL;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	int rc;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		// Return existing record.
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;

		return sd_bus_reply_method_return(call, "yisb", peer->eid,
						  peer->net, peer_path, 0);
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, 0, true);
	if (rc < 0)
		goto err;

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;

	if (peer->pool_size > 0) {
		// Call for Allocate EndpointID
		rc = endpoint_allocate_eid(peer);
		if (rc < 0) {
			warnx("Failed to allocate downstream EIDs");
		} else {
			if (peer->ctx->verbose) {
				fprintf(stderr,
					"Downstream EIDs assigned from %d to %d : pool size %d\n",
					peer->pool_start,
					peer->pool_start + peer->pool_size - 1,
					peer->pool_size);
			}
		}
	}

	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

// Checks if given EID belongs to any bridge's pool range
static bool is_eid_in_bridge_pool(struct net *n, mctp_eid_t eid)
{
	for (int i = eid_alloc_min; i <= eid; i++) {
		struct peer *peer = n->peers[i];
		if (peer && peer->pool_size > 0) {
			if (eid >= peer->pool_start &&
			    eid < peer->pool_start + peer->pool_size) {
				return true;
			}
			i += peer->pool_size;
		}
	}
	return false;
}

static int method_assign_endpoint_static(sd_bus_message *call, void *data,
					 sd_bus_error *berr)
{
	dest_phys desti, *dest = &desti;
	const char *peer_path = NULL;
	struct peer *peer = NULL;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	uint8_t eid;
	int rc;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read(call, "y", &eid);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		if (peer->eid != eid) {
			return sd_bus_error_setf(
				berr, SD_BUS_ERROR_INVALID_ARGS,
				"Already assigned a different EID");
		}

		// Return existing record.
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;

		return sd_bus_reply_method_return(call, "yisb", peer->eid,
						  peer->net, peer_path, 0);
	} else {
		uint32_t netid;

		// is the requested EID already in use? if so, reject
		netid = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
		peer = find_peer_by_addr(ctx, eid, netid);
		if (peer) {
			return sd_bus_error_setf(berr,
						 SD_BUS_ERROR_INVALID_ARGS,
						 "Address in use");
		} else {
			// is requested EID part of any bridge pool range
			struct net *n = lookup_net(ctx, netid);
			if (!n) {
				bug_warn("%s: Bad old net %d", __func__, netid);
				return -EPROTO;
			}
			if (is_eid_in_bridge_pool(n, eid)) {
				return sd_bus_error_setf(
					berr, SD_BUS_ERROR_INVALID_ARGS,
					"EID belongs to another MCTP bridge pool");
			}
		}
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, eid, false);
	if (rc < 0) {
		goto err;
	}

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;

	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_learn_endpoint(sd_bus_message *call, void *data,
				 sd_bus_error *berr)
{
	int rc;
	const char *peer_path = NULL;
	dest_phys desti, *dest = &desti;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	mctp_eid_t eid = 0;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	rc = get_endpoint_peer(ctx, berr, dest, &peer, &eid);
	if (rc == -EEXIST) {
		/* We have a conflict with an existing endpoint, so can't
		 * learn; recovery would requre a Set Endpoint ID. */
		return sd_bus_error_setf(
			berr, SD_BUS_ERROR_FILE_EXISTS,
			"Endpoint claimed EID %d which is already used", eid);
	}
	if (rc < 0)
		goto err;
	if (!peer)
		return sd_bus_reply_method_return(call, "yisb", 0, 0, "", 0);

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;
	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

// Query various properties of a peer.
// To be called when a new peer is discovered/assigned, once an EID is known
// and routable.
static int query_peer_properties(struct peer *peer)
{
	int rc;

	rc = query_get_peer_msgtypes(peer);
	if (rc < 0) {
		// Warn here, it's a mandatory command code.
		// It might be too noisy if some devices don't implement it.
		warnx("Error getting endpoint types for %s. Ignoring error %d %s",
		      peer_tostr(peer), rc, strerror(-rc));
		rc = 0;
	}

	rc = query_get_peer_uuid(peer);
	if (rc < 0) {
		if (peer->ctx->verbose)
			warnx("Error getting UUID for %s. Ignoring error %d %s",
			      peer_tostr(peer), rc, strerror(-rc));
		rc = 0;
	}

	// TODO: emit property changed? Though currently they are all const.
	return rc;
}

static int peer_neigh_update(struct peer *peer, uint16_t type)
{
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndmsg;
		uint8_t rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
	} msg = { 0 };
	size_t rta_len = sizeof(msg.rta_buff);
	struct rtattr *rta = (void *)msg.rta_buff;

	msg.nh.nlmsg_type = type;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ndmsg.ndm_ifindex = peer->phys.ifindex;
	msg.ndmsg.ndm_family = AF_MCTP;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
		&rta, &rta_len, NDA_DST, &peer->eid, sizeof(peer->eid));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_LLADDR,
						  peer->phys.hwaddr,
						  peer->phys.hwaddr_len);
	return mctp_nl_send(peer->ctx->nl, &msg.nh);
}

// type is RTM_NEWROUTE or RTM_DELROUTE
static int peer_route_update(struct peer *peer, uint16_t type)
{
	if (!mctp_nl_if_exists(peer->ctx->nl, peer->phys.ifindex)) {
		bug_warn("%s: Unknown ifindex %d", __func__,
			 peer->phys.ifindex);
		return -ENODEV;
	}

	if (type == RTM_NEWROUTE) {
		return mctp_nl_route_add(peer->ctx->nl, peer->eid, 0,
					 peer->phys.ifindex, NULL, peer->mtu);
	} else if (type == RTM_DELROUTE) {
		if (peer->pool_size > 0) {
			int rc = 0;
			struct mctp_fq_addr gw_addr = { 0 };
			gw_addr.net = peer->net;
			gw_addr.eid = peer->eid;
			rc = mctp_nl_route_del(peer->ctx->nl, peer->pool_start,
					       peer->pool_size - 1,
					       peer->phys.ifindex, &gw_addr);
			if (rc < 0)
				warnx("failed to delete route for peer pool eids %d-%d %s",
				      peer->pool_start,
				      peer->pool_start + peer->pool_size - 1,
				      strerror(-rc));
		}
		return mctp_nl_route_del(peer->ctx->nl, peer->eid, 0,
					 peer->phys.ifindex, NULL);
	}

	bug_warn("%s: bad type %d", __func__, type);
	return -EPROTO;
}

/* Called when a new peer is discovered. Queries properties and publishes */
static int setup_added_peer(struct peer *peer)
{
	int rc;

	// Set minimum MTU by default for compatibility. Clients can increase
	// this with .SetMTU as needed
	peer->mtu = mctp_nl_min_mtu_byindex(peer->ctx->nl, peer->phys.ifindex);

	// add route before querying
	add_peer_route(peer);

	rc = query_peer_properties(peer);
	if (rc < 0)
		goto out;

	rc = publish_peer(peer, true);
out:
	if (rc < 0) {
		remove_peer(peer);
	}
	return rc;
}

static void add_peer_neigh(struct peer *peer)
{
	size_t if_hwaddr_len;
	int rc;

	rc = mctp_nl_hwaddr_len_byindex(peer->ctx->nl, peer->phys.ifindex,
					&if_hwaddr_len);
	if (rc) {
		warnx("Missing neigh ifindex %d", peer->phys.ifindex);
		return;
	}

	if (peer->phys.hwaddr_len == 0 && if_hwaddr_len == 0) {
		// Don't add neigh entries for address-less transports
		// We'll let the kernel reject mismatching entries.
		return;
	}

	if (peer->ctx->verbose) {
		fprintf(stderr, "Adding neigh to %s\n", peer_tostr(peer));
	}
	rc = peer_neigh_update(peer, RTM_NEWNEIGH);
	if (rc < 0 && rc != -EEXIST) {
		warnx("Failed adding neigh for %s: %s", peer_tostr(peer),
		      strerror(-rc));
	} else {
		peer->have_neigh = true;
	}
}

/* Adds routes/neigh. This is separate from
   publish_peer() because we want a two stage setup of querying
   properties (routed packets) then emitting dbus once finished */
static void add_peer_route(struct peer *peer)
{
	int rc;

	// We always try to add routes/neighs, ignoring if they
	// already exist.

	add_peer_neigh(peer);

	if (peer->ctx->verbose) {
		fprintf(stderr, "Adding route to %s\n", peer_tostr(peer));
	}
	rc = peer_route_update(peer, RTM_NEWROUTE);
	if (rc < 0 && rc != -EEXIST) {
		warnx("Failed adding route for %s: %s", peer_tostr(peer),
		      strerror(-rc));
	} else {
		peer->have_route = true;
	}
}

/* Sets up routes/neigh, creates dbus object and emits added signal */
static int publish_peer(struct peer *peer, bool add_route)
{
	int rc = 0;

	if (add_route && peer->state == REMOTE) {
		add_peer_route(peer);
	}

	if (peer->published)
		return 0;

	rc = asprintf(&peer->path, "%s/networks/%d/endpoints/%d",
		      MCTP_DBUS_PATH, peer->net, peer->eid);
	if (rc < 0)
		return -ENOMEM;

	peer->published = true;

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_obmc_endpoint,
				 peer->path, MCTP_DBUS_IFACE_ENDPOINT,
				 bus_endpoint_obmc_vtable, peer);

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_cc_endpoint,
				 peer->path, CC_MCTP_DBUS_IFACE_ENDPOINT,
				 bus_endpoint_cc_vtable, peer);

	if (peer->pool_size > 0) {
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_bridge,
					 peer->path, CC_MCTP_DBUS_IFACE_BRIDGE,
					 bus_endpoint_bridge, peer);
	}
	if (peer->uuid) {
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_uuid,
					 peer->path, OPENBMC_IFACE_COMMON_UUID,
					 bus_endpoint_uuid_vtable, peer);
	}

	rc = emit_endpoint_added(peer);
	if (rc > 0)
		rc = 0;

	return rc;
}

/* removes route, neigh, dbus entry for the peer */
static int unpublish_peer(struct peer *peer)
{
	int rc;
	if (peer->have_neigh) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "Deleting neigh to %s\n",
				peer_tostr(peer));
		}
		rc = peer_neigh_update(peer, RTM_DELNEIGH);
		if (rc < 0) {
			warnx("Failed removing neigh for %s: %s",
			      peer_tostr(peer), strerror(-rc));
		} else {
			peer->have_neigh = false;
		}
	}

	if (peer->have_route) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "Deleting route to %s\n",
				peer_tostr(peer));
		}
		rc = peer_route_update(peer, RTM_DELROUTE);
		if (rc < 0) {
			warnx("Failed removing route for %s: %s",
			      peer_tostr(peer), strerror(-rc));
		} else {
			peer->have_route = false;
		}
	}
	if (peer->published) {
		emit_endpoint_removed(peer);
		sd_bus_slot_unref(peer->slot_obmc_endpoint);
		peer->slot_obmc_endpoint = NULL;
		sd_bus_slot_unref(peer->slot_cc_endpoint);
		peer->slot_cc_endpoint = NULL;
		sd_bus_slot_unref(peer->slot_bridge);
		peer->slot_bridge = NULL;
		sd_bus_slot_unref(peer->slot_uuid);
		peer->slot_uuid = NULL;
		peer->published = false;
		free(peer->path);
	}

	return 0;
}

static int method_endpoint_remove(sd_bus_message *call, void *data,
				  sd_bus_error *berr)
{
	struct peer *peer = data;
	int rc;
	struct ctx *ctx = peer->ctx;

	if (peer->state == LOCAL)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					 "Cannot remove mctpd-local endpoint");
	if (!peer->published) {
		rc = -EPROTO;
		goto out;
	}

	rc = remove_peer(peer);
	if (rc < 0)
		goto out;

	rc = sd_bus_reply_method_return(call, "");
out:
	set_berr(ctx, rc, berr);
	return rc;
}

/* FIXME: I2C-specific */
/* DSP0237 v1.2.0 Table 9 */
#define MCTP_I2C_TSYM_TRECLAIM_MIN_US 5000000
#define MCTP_I2C_TSYM_MN1_MIN 2
#define MCTP_I2C_TSYM_MT1_MAX_US 100000
#define MCTP_I2C_TSYM_MT3_MAX_US 100000
#define MCTP_I2C_TSYM_MT4_MIN_US 5000000
#define MCTP_I2C_TSYM_MT2_MIN_US \
	(MCTP_I2C_TSYM_MT1_MAX_US + 2 * MCTP_I2C_TSYM_MT3_MAX_US)
#define MCTP_I2C_TSYM_MT2_MAX_MS MCTP_I2C_TSYM_MT4_MIN_US

static int peer_endpoint_recover(sd_event_source *s, uint64_t usec,
				 void *userdata)
{
	struct peer *peer = userdata;
	struct ctx *ctx = peer->ctx;
	const char *peer_path;
	int rc;

	/*
	 * Error handling policy:
	 *
	 * 1. Any resource management error prior to Treclaim is handled by
	 *    rescheduling the poll query, unless it is scheduling the poll
	 *    query itself that fails.
	 *
	 * 2. If scheduling the poll query fails then the endpoint is removed.
	 */

	peer->recovery.npolls--;

	/*
	 * Test if we still have connectivity to the endpoint. If we do, we will get a
	 * response reporting the current EID. This is the test recommended by 8.17.6
	 * of DSP0236 v1.3.1.
	 */
	rc = query_get_endpoint_id(ctx, &peer->phys, &peer->recovery.eid,
				   &peer->recovery.endpoint_type,
				   &peer->recovery.medium_spec);
	if (rc < 0) {
		goto reschedule;
	}

	/*
	 * If we've got a response there are two scenarios:
	 *
	 * 1. The device responds with the EID that we expect it to have
	 * 2. The device responds with an unexpected EID, e.g. 0
	 *
	 * For scenario 1 we're done as the device is responsive and has the expected
	 * address. For scenario 2, we may not yet consider the EID assignment as
	 * expired, so check the UUID for a match. If the UUID matches we reassign the
	 * expected EID to the device. If the UUID does not match we allocate a new
	 * EID for the exchanged device, given it is responsive.
	 */
	if (peer->recovery.eid != peer->eid) {
		static const uint8_t nil_uuid[16] = { 0 };
		bool uuid_matches_peer = false;
		bool uuid_matches_nil = false;
		uint8_t uuid[16] = { 0 };
		mctp_eid_t new_eid;

		rc = query_get_peer_uuid_by_phys(ctx, &peer->phys, uuid);
		if (!rc && peer->uuid) {
			static_assert(sizeof(uuid) == sizeof(nil_uuid),
				      "Unsynchronized UUID sizes");
			uuid_matches_peer =
				memcmp(uuid, peer->uuid, sizeof(uuid)) == 0;
			uuid_matches_nil =
				memcmp(uuid, nil_uuid, sizeof(uuid)) == 0;
		}

		if (rc || !uuid_matches_peer ||
		    (uuid_matches_nil && !MCTPD_RECOVER_NIL_UUID)) {
			/* It's not known to be the same device, allocate a new EID */
			dest_phys phys = peer->phys;

			assert(sd_event_source_get_enabled(
				       peer->recovery.source, NULL) == 0);
			remove_peer(peer);
			/*
			 * The representation of the old peer is now gone. Set up the new peer,
			 * after which we immediately return as there's no old peer state left to
			 * maintain.
			 */
			return endpoint_assign_eid(ctx, NULL, &phys, &peer, 0,
						   false);
		}

		/* Confirmation of the same device, apply its already allocated EID */
		rc = endpoint_send_set_endpoint_id(peer, &new_eid);
		if (rc < 0) {
			goto reschedule;
		}

		if (new_eid != peer->eid) {
			rc = change_peer_eid(peer, new_eid);
			if (rc < 0) {
				goto reclaim;
			}
		}
	}

	peer->degraded = false;

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto reschedule;

	rc = sd_bus_emit_properties_changed(ctx->bus, peer_path,
					    CC_MCTP_DBUS_IFACE_ENDPOINT,
					    "Connectivity", NULL);
	if (rc < 0) {
		goto reschedule;
	}

	assert(sd_event_source_get_enabled(peer->recovery.source, NULL) == 0);
	sd_event_source_unref(peer->recovery.source);
	peer->recovery.delay = 0;
	peer->recovery.source = NULL;
	peer->recovery.npolls = 0;

	return rc;

reschedule:
	if (peer->recovery.npolls > 0) {
		rc = sd_event_source_set_time_relative(peer->recovery.source,
						       peer->recovery.delay);
		if (rc >= 0) {
			rc = sd_event_source_set_enabled(peer->recovery.source,
							 SD_EVENT_ONESHOT);
		}
	}
	if (rc < 0) {
reclaim:
		/* Recovery unsuccessful, clean up the peer */
		assert(sd_event_source_get_enabled(peer->recovery.source,
						   NULL) == 0);
		remove_peer(peer);
	}
	return rc < 0 ? rc : 0;
}

static int method_endpoint_recover(sd_bus_message *call, void *data,
				   sd_bus_error *berr)
{
	struct peer *peer;
	bool previously;
	struct ctx *ctx;
	int rc;

	peer = data;
	ctx = peer->ctx;
	previously = peer->degraded;

	if (!previously) {
		assert(!peer->recovery.delay);
		assert(!peer->recovery.source);
		assert(!peer->recovery.npolls);
		peer->recovery.npolls = MCTP_I2C_TSYM_MN1_MIN + 1;
		peer->recovery.delay =
			(MCTP_I2C_TSYM_TRECLAIM_MIN_US / 2) - ctx->mctp_timeout;
		rc = sd_event_add_time_relative(
			ctx->event, &peer->recovery.source, CLOCK_MONOTONIC, 0,
			ctx->mctp_timeout, peer_endpoint_recover, peer);
		if (rc < 0) {
			goto out;
		}

		peer->degraded = true;

		rc = sd_bus_emit_properties_changed(
			sd_bus_message_get_bus(call),
			sd_bus_message_get_path(call),
			sd_bus_message_get_interface(call), "Connectivity",
			NULL);
		if (rc < 0) {
			goto out;
		}
	}

	rc = sd_bus_reply_method_return(call, NULL);

out:
	if (rc < 0 && !previously) {
		if (peer->degraded) {
			/* Cleanup the timer if it was setup successfully. */
			sd_event_source_set_enabled(peer->recovery.source,
						    SD_EVENT_OFF);
			sd_event_source_unref(peer->recovery.source);
		}
		peer->degraded = previously;
		peer->recovery.delay = 0;
		peer->recovery.source = NULL;
		peer->recovery.npolls = 0;
	}
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_endpoint_set_mtu(sd_bus_message *call, void *data,
				   sd_bus_error *berr)
{
	struct peer *peer = data;
	struct ctx *ctx = peer->ctx;
	int rc;
	uint32_t mtu;

	if (peer->state == LOCAL)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					 "Cannot set local endpoint MTU");

	rc = sd_bus_message_read(call, "u", &mtu);
	if (rc < 0)
		goto out;

	rc = peer_set_mtu(ctx, peer, mtu);
	if (rc < 0)
		goto out;

	rc = sd_bus_reply_method_return(call, "");
out:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_net_learn_endpoint(sd_bus_message *call, void *data,
				     sd_bus_error *berr)
{
	const char *peer_path = NULL;
	struct net *net = data;
	struct ctx *ctx = net->ctx;
	dest_phys dest = { 0 };
	mctp_eid_t eid = 0;
	struct peer *peer;
	int rc;

	rc = sd_bus_message_read(call, "y", &eid);
	if (rc < 0)
		goto err;

	peer = find_peer_by_addr(ctx, eid, net->net);
	/* already known? */
	if (peer)
		return sd_bus_reply_method_return(call, "sb",
						  path_from_peer(peer), false);

	rc = add_peer(ctx, &dest, eid, net->net, &peer);
	if (rc) {
		warnx("can't add peer: %s", strerror(-rc));
		goto err;
	}

	query_peer_properties(peer);

	publish_peer(peer, false);

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;
	return sd_bus_reply_method_return(call, "sb", peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

// clang-format off
static const sd_bus_vtable bus_link_owner_vtable[] = {
	SD_BUS_VTABLE_START(0),

	SD_BUS_METHOD_WITH_NAMES("SetupEndpoint",
		"ay",
		SD_BUS_PARAM(physaddr),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(new),
		method_setup_endpoint,
		0),

	SD_BUS_METHOD_WITH_NAMES("AssignEndpoint",
		"ay",
		SD_BUS_PARAM(physaddr),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(new),
		method_assign_endpoint,
		0),

	SD_BUS_METHOD_WITH_NAMES("AssignEndpointStatic",
		"ayy",
		SD_BUS_PARAM(physaddr)
		SD_BUS_PARAM(eid),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(new),
		method_assign_endpoint_static,
		0),

	SD_BUS_METHOD_WITH_NAMES("LearnEndpoint",
		"ay",
		SD_BUS_PARAM(physaddr),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(found),
		method_learn_endpoint,
		0),
	SD_BUS_VTABLE_END,

};
// clang-format on

static int bus_endpoint_get_prop(sd_bus *bus, const char *path,
				 const char *interface, const char *property,
				 sd_bus_message *reply, void *userdata,
				 sd_bus_error *berr)
{
	struct peer *peer = userdata;
	int rc;

	if (strcmp(property, "NetworkId") == 0) {
		rc = sd_bus_message_append(reply, "u", peer->net);
	} else if (strcmp(property, "EID") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->eid);
	} else if (strcmp(property, "SupportedMessageTypes") == 0) {
		rc = sd_bus_message_append_array(reply, 'y',
						 peer->message_types,
						 peer->num_message_types);
	} else if (strcmp(property, "UUID") == 0 && peer->uuid) {
		const char *s = dfree(bytes_to_uuid(peer->uuid));
		rc = sd_bus_message_append(reply, "s", s);
	} else if (strcmp(property, "Connectivity") == 0) {
		rc = sd_bus_message_append(
			reply, "s", peer->degraded ? "Degraded" : "Available");
	} else {
		warnx("Unknown property '%s' for %s iface %s", property, path,
		      interface);
		rc = -ENOENT;
	}

	return rc;
}

static int bus_bridge_get_prop(sd_bus *bus, const char *path,
			       const char *interface, const char *property,
			       sd_bus_message *reply, void *userdata,
			       sd_bus_error *berr)
{
	struct peer *peer = userdata;
	int rc;

	if (strcmp(property, "PoolStart") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->pool_start);
	} else if (strcmp(property, "PoolSize") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->pool_size);
	} else if (strcmp(property, "PoolEnd") == 0) {
		uint8_t pool_end =
			peer->pool_size ?
				peer->pool_start + peer->pool_size - 1 :
				0;
		rc = sd_bus_message_append(reply, "y", pool_end);
	} else {
		warnx("Unknown bridge property '%s' for %s iface %s", property,
		      path, interface);
		rc = -ENOENT;
	}

	return rc;
}

static int bus_network_get_prop(sd_bus *bus, const char *path,
				const char *interface, const char *property,
				sd_bus_message *reply, void *userdata,
				sd_bus_error *berr)
{
	struct net *net = userdata;
	int rc = -ENOENT;

	if (strcmp(property, "LocalEIDs") == 0) {
		mctp_eid_t *eids = dfree(malloc(256));
		size_t num;

		rc = find_local_eids_by_net(net, &num, eids);
		if (rc < 0)
			return -ENOENT;

		rc = sd_bus_message_append_array(reply, 'y', eids, num);
	}

	return rc;
}

static int bus_link_get_prop(sd_bus *bus, const char *path,
			     const char *interface, const char *property,
			     sd_bus_message *reply, void *userdata,
			     sd_bus_error *berr)
{
	struct link *link = userdata;
	int rc = 0;

	if (link->published && strcmp(property, "Role") == 0) {
		rc = sd_bus_message_append(reply, "s",
					   roles[link->role].dbus_val);
	} else if (strcmp(property, "NetworkId") == 0) {
		uint32_t net =
			mctp_nl_net_byindex(link->ctx->nl, link->ifindex);
		rc = sd_bus_message_append_basic(reply, 'u', &net);
	} else {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				  "Unknown property.");
		rc = -ENOENT;
	}

	set_berr(link->ctx, rc, berr);
	return rc;
}

static int bus_link_set_prop(sd_bus *bus, const char *path,
			     const char *interface, const char *property,
			     sd_bus_message *value, void *userdata,
			     sd_bus_error *berr)
{
	struct link *link = userdata;
	struct ctx *ctx = link->ctx;
	const char *state;
	struct role role;
	int rc = -1;

	if (strcmp(property, "Role") != 0) {
		warnx("Unknown property '%s' for %s iface %s", property, path,
		      interface);
		rc = -ENOENT;
		goto out;
	}

	if (link->role != ENDPOINT_ROLE_UNKNOWN) {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				  "Role is already set.");
		rc = -ENOENT;
		goto out;
	}

	rc = sd_bus_message_read(value, "s", &state);
	if (rc < 0) {
		sd_bus_error_setf(
			berr, SD_BUS_ERROR_INVALID_ARGS,
			"Unknown Role. Only Support BusOwner/EndPoint.");
		goto out;
	}

	rc = get_role(state, &role);
	if (rc < 0) {
		warnx("Invalid property value '%s' for property '%s' from interface '%s' on object '%s'",
		      state, property, interface, path);
		rc = -EINVAL;
		goto out;
	}
	link->role = role.role;

out:
	set_berr(ctx, rc, berr);
	return rc;
}

__attribute__((unused)) static int
bus_endpoint_set_prop(sd_bus *bus, const char *path, const char *interface,
		      const char *property, sd_bus_message *value,
		      void *userdata, sd_bus_error *ret_error)
{
	struct peer *peer = userdata;
	const char *connectivity;
	struct ctx *ctx = peer->ctx;
	int rc;

	if (strcmp(property, "Connectivity") == 0) {
		bool previously = peer->degraded;
		rc = sd_bus_message_read(value, "s", &connectivity);
		if (rc < 0) {
			goto out;
		}
		if (strcmp(connectivity, "Available") == 0) {
			peer->degraded = false;
		} else if (strcmp(connectivity, "Degraded") == 0) {
			peer->degraded = true;
		} else {
			warnx("Invalid property value '%s' for property '%s' from interface '%s' on object '%s'",
			      connectivity, property, interface, path);
			rc = -EINVAL;
			goto out;
		}
		if (previously != peer->degraded) {
			rc = sd_bus_emit_properties_changed(
				bus, path, interface, "Connectivity", NULL);
		}
	} else {
		warnx("Unknown property '%s' in interface '%s' on object '%s'",
		      property, interface, path);
		rc = -ENOENT;
	}
out:
	set_berr(ctx, rc, ret_error);
	return rc;
}

// clang-format off
static const sd_bus_vtable bus_endpoint_obmc_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("NetworkId",
			"u",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("EID",
			"y",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("SupportedMessageTypes",
			"ay",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_endpoint_uuid_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("UUID",
			"s",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_endpoint_cc_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_ARGS("SetMTU",
		SD_BUS_ARGS("u", mtu),
		SD_BUS_NO_RESULT,
		method_endpoint_set_mtu,
		0),
	SD_BUS_METHOD_WITH_ARGS("Remove",
		SD_BUS_NO_ARGS,
		SD_BUS_NO_RESULT,
		method_endpoint_remove,
		0),
	SD_BUS_METHOD("Recover",
		SD_BUS_NO_ARGS,
		SD_BUS_NO_RESULT,
		method_endpoint_recover,
		0),
#if MCTPD_WRITABLE_CONNECTIVITY
	SD_BUS_WRITABLE_PROPERTY("Connectivity",
		"s",
		bus_endpoint_get_prop,
		bus_endpoint_set_prop,
		0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
#else
	SD_BUS_PROPERTY("Connectivity",
		"s",
		bus_endpoint_get_prop,
		0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
#endif
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_endpoint_bridge[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("PoolStart",
			"y",
			bus_bridge_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("PoolSize",
			"y",
			bus_bridge_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("PoolEnd",
			"y",
			bus_bridge_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_link_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_WRITABLE_PROPERTY("Role",
			"s",
			bus_link_get_prop,
			bus_link_set_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("NetworkId",
			"u",
			bus_link_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_network_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_NAMES("LearnEndpoint",
		"y",
		SD_BUS_PARAM(physaddr),
		"sb",
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(found),
		method_net_learn_endpoint,
		0),
	SD_BUS_PROPERTY("LocalEIDs",
			"ay",
			bus_network_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};
// clang-format on

static int emit_endpoint_added(const struct peer *peer)
{
	const char *path = NULL;
	int rc;

	path = path_from_peer(peer);
	if (!path)
		return -1;

	if (peer->ctx->verbose)
		warnx("emitting endpoint add: %s", path);

	rc = sd_bus_emit_object_added(peer->ctx->bus, path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_endpoint_removed(const struct peer *peer)
{
	const char *path = NULL;
	int rc;

	path = path_from_peer(peer);
	if (!path)
		return -1;

	if (peer->ctx->verbose)
		warnx("emitting endpoint remove: %s", path);

	rc = sd_bus_emit_object_removed(peer->ctx->bus, path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_net_added(struct ctx *ctx, struct net *net)
{
	int rc;

	if (ctx->verbose)
		warnx("emitting net add: %s", net->path);

	rc = sd_bus_emit_object_added(ctx->bus, net->path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_interface_added(struct link *link)
{
	int rc;

	if (link->ctx->verbose)
		warnx("emitting interface add: %s", link->path);

	rc = sd_bus_emit_object_added(link->ctx->bus, link->path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));

	return rc;
}

static int emit_net_removed(struct ctx *ctx, struct net *net)
{
	int rc;

	if (ctx->verbose)
		warnx("emitting net remove: %s", net->path);

	rc = sd_bus_emit_object_removed(ctx->bus, net->path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_interface_removed(struct link *link)
{
	struct ctx *ctx = link->ctx;
	int rc;

	if (link->ctx->verbose)
		warnx("emitting interface remove: %s", link->path);

	rc = sd_bus_emit_object_removed(ctx->bus, link->path);
	if (rc < 0) {
		errno = -rc;
		warn("%s: error emitting", __func__);
	}

	return rc;
}

static int setup_bus(struct ctx *ctx)
{
	sigset_t sigset;
	int rc;

	// Must use the default loop so that dfree() can use it without context.
	rc = sd_event_default(&ctx->event);
	if (rc < 0) {
		warnx("Failed creating event loop");
		goto out;
	}

	rc = sigemptyset(&sigset);
	if (rc < 0)
		goto out;

	rc = sigaddset(&sigset, SIGTERM);
	if (rc < 0)
		goto out;

	rc = sigaddset(&sigset, SIGINT);
	if (rc < 0)
		goto out;

	rc = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_signal(ctx->event, NULL, SIGTERM, NULL, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_signal(ctx->event, NULL, SIGINT, NULL, NULL);
	if (rc < 0)
		goto out;

	rc = sd_bus_default(&ctx->bus);
	if (rc < 0) {
		warnx("Couldn't connect to D-Bus");
		goto out;
	}

	rc = sd_bus_attach_event(ctx->bus, ctx->event,
				 SD_EVENT_PRIORITY_NORMAL);
	if (rc < 0) {
		warnx("Failed attach to event loop");
		goto out;
	}

	rc = sd_bus_add_object_manager(ctx->bus, NULL, MCTP_DBUS_PATH);
	if (rc < 0) {
		warnx("Adding object manager failed: %s", strerror(-rc));
		goto out;
	}

	rc = 0;
out:
	return rc;
}

int request_dbus(struct ctx *ctx)
{
	int rc;

	rc = sd_bus_request_name(ctx->bus, MCTP_DBUS_NAME, 0);
	if (rc < 0) {
		warnx("Failed requesting dbus name %s", MCTP_DBUS_NAME);
		return rc;
	}

	return 0;
}

// Deletes one local EID.
static int del_local_eid(struct ctx *ctx, uint32_t net, int eid)
{
	struct peer *peer = NULL;
	int rc;

	peer = find_peer_by_addr(ctx, eid, net);
	if (!peer) {
		bug_warn("local eid %d net %d to delete is missing", eid, net);
		return -ENOENT;
	}

	if (peer->state != LOCAL) {
		bug_warn("local eid %d net %d to delete is incorrect", eid,
			 net);
		return -EPROTO;
	}

	peer->local_count--;
	if (peer->local_count < 0) {
		bug_warn("local eid %d net %d bad refcount %d", eid, net,
			 peer->local_count);
	}

	rc = 0;
	if (peer->local_count <= 0) {
		if (ctx->verbose) {
			fprintf(stderr, "Removing local eid %d net %d\n", eid,
				net);
		}

		rc = remove_peer(peer);
	}
	return rc;
}

// Remove nets that have no interfaces
static int prune_old_nets(struct ctx *ctx)
{
	size_t i, j, num_list;
	uint32_t *net_list;

	net_list = mctp_nl_net_list(ctx->nl, &num_list);

	// iterate and discard unused nets
	for (i = 0, j = 0; i < ctx->num_nets; i++) {
		struct net *net = ctx->nets[i];

		bool found = false;
		for (size_t n = 0; n < num_list && !found; n++)
			if (net_list[n] == net->net)
				found = true;

		if (found) {
			// isn't stale
			ctx->nets[j] = net;
			j++;
		} else {
			// stale, don't keep
			for (size_t p = 0; p < 256; p++) {
				// Sanity check that no peers are used
				if (ctx->nets[i]->peers[p]) {
					bug_warn(
						"stale entry for eid %zd in deleted net %d",
						p, net->net);
				}
			}
			emit_net_removed(ctx, net);
			del_net(net);
		}
	}
	free(net_list);
	ctx->num_nets = j;
	return 0;
}

static void free_link(struct link *link)
{
	sd_bus_slot_unref(link->slot_iface);
	sd_bus_slot_unref(link->slot_busowner);
	free(link->path);
	free(link);
}

// Removes remote peers associated with an old interface.
// Note that this link has already been removed from ctx->nl */
static int del_interface(struct link *link)
{
	struct ctx *ctx = link->ctx;
	int ifindex = link->ifindex;

	if (ctx->verbose) {
		fprintf(stderr, "Deleting interface #%d\n", ifindex);
	}
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *p = ctx->peers[i];
		if (p->state == REMOTE && p->phys.ifindex == ifindex) {
			// Linux removes routes to deleted links, so no need to request removal.
			p->have_neigh = false;
			p->have_route = false;
			remove_peer(p);
		}
	}

	if (emit_interface_removed(link) < 0)
		warnx("Failed to remove D-Bus interface of ifindex %d",
		      link->ifindex);
	prune_old_nets(ctx);
	free_link(link);

	return 0;
}

static int rename_interface(struct ctx *ctx, struct link *link, int ifindex)
{
	const char *ifname;
	char *path;
	int rc;

	ifname = mctp_nl_if_byindex(ctx->nl, ifindex);
	if (!ifname) {
		warnx("no name for interface %d during rename?", ifindex);
		return -ENODEV;
	}

	rc = asprintf(&path, "%s/%s", MCTP_DBUS_PATH_LINKS, ifname);
	if (rc < 0)
		return -ENOMEM;

	/* remove existing dbus object */
	emit_interface_removed(link);
	sd_bus_slot_unref(link->slot_iface);
	link->slot_iface = NULL;
	sd_bus_slot_unref(link->slot_busowner);
	link->slot_busowner = NULL;
	free(link->path);

	/* set new path and re-add */
	link->path = path;
	sd_bus_add_object_vtable(link->ctx->bus, &link->slot_iface, link->path,
				 CC_MCTP_DBUS_IFACE_INTERFACE, bus_link_vtable,
				 link);

	if (link->role == ENDPOINT_ROLE_BUS_OWNER) {
		sd_bus_add_object_vtable(link->ctx->bus, &link->slot_busowner,
					 link->path,
					 CC_MCTP_DBUS_IFACE_BUSOWNER,
					 bus_link_owner_vtable, link);
	}

	emit_interface_added(link);

	return 0;
}

// For program termination cleanup
static void free_links(struct ctx *ctx)
{
	size_t num;
	int *ifs;

	ifs = mctp_nl_if_list(ctx->nl, &num);
	for (size_t i = 0; i < num; i++) {
		struct link *link = mctp_nl_get_link_userdata(ctx->nl, ifs[i]);
		mctp_nl_set_link_userdata(ctx->nl, ifs[i], NULL);
		if (link) {
			free_link(link);
		}
	}
	free(ifs);
}

// Moves remote peers from old->new net.
static int change_net_interface(struct ctx *ctx, int ifindex, uint32_t old_net)
{
	uint32_t new_net = mctp_nl_net_byindex(ctx->nl, ifindex);
	struct net *old_n, *new_n;
	struct link *link;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Moving interface #%d %s from net %d -> %d\n",
			ifindex, mctp_nl_if_byindex(ctx->nl, ifindex), old_net,
			new_net);
	}

	link = mctp_nl_get_link_userdata(ctx->nl, ifindex);
	if (!link) {
		warnx("No link for ifindex %d", ifindex);
		return -EPROTO;
	}

	if (new_net == 0) {
		warnx("No net for ifindex %d", ifindex);
		return -EPROTO;
	}

	if (new_net == old_net) {
		// Logic below may assume they differ
		bug_warn("%s called with new=old=%d", __func__, old_net);
		return -EPROTO;
	}

	old_n = lookup_net(ctx, old_net);
	if (!old_n) {
		bug_warn("%s: Bad old net %d", __func__, old_net);
		return -EPROTO;
	}
	new_n = lookup_net(ctx, new_net);
	if (!new_n) {
		rc = add_net(ctx, new_net);
		if (rc < 0)
			return rc;
		new_n = lookup_net(ctx, new_net);
	}

	sd_bus_emit_properties_changed(ctx->bus, link->path,
				       CC_MCTP_DBUS_IFACE_INTERFACE,
				       "NetworkId", NULL);

	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		if (!(peer->state == REMOTE && peer->phys.ifindex == ifindex)) {
			// skip peers on other interfaces
			continue;
		}

		if (peer->net != old_net) {
			bug_warn("%s: Mismatch old net %d vs %d, new net %d",
				 __func__, peer->net, old_net, new_net);
			continue;
		}
		if (check_peer_struct(peer, old_n) != 0) {
			bug_warn("%s: Inconsistent state", __func__);
			return -EPROTO;
		}

		if (new_n->peers[peer->eid]) {
			// Conflict, drop it
			warnx("EID %d already exists moving net %d->%d, dropping it",
			      peer->eid, old_net, new_net);
			remove_peer(peer);
			continue;
		}

		// Move networks, change route/neigh entries, emit new dbus signals
		unpublish_peer(peer);
		new_n->peers[peer->eid] = old_n->peers[peer->eid];
		old_n->peers[peer->eid] = NULL;
		peer->net = new_net;
		rc = publish_peer(peer, true);
		if (rc) {
			warnx("Error publishing new peer eid %d, net %d after change: %s",
			      peer->eid, peer->net, strerror(-rc));
		}
	}

	prune_old_nets(ctx);
	return 0;
}

// Adds one local EID
static int add_local_eid(struct ctx *ctx, uint32_t net, int eid)
{
	struct peer *peer;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Adding local eid %d net %d\n", eid, net);
	}

	peer = find_peer_by_addr(ctx, eid, net);
	if (peer) {
		if (peer->state == LOCAL) {
			// Already exists, increment refcount
			peer->local_count++;
			return 0;
		} else {
			// TODO: remove the peer and add a new local one.
			warnx("Local eid %d net %d already exists?", eid, net);
			return -EPROTO;
		}
	}

	rc = add_peer(ctx, &local_phys, eid, net, &peer);
	if (rc < 0) {
		bug_warn("Error adding local eid %d net %d", eid, net);
		return rc;
	}
	peer->state = LOCAL;
	peer->local_count = 1;
	rc = peer_set_uuid(peer, ctx->uuid);
	if (rc < 0) {
		warnx("Failed setting local UUID: %s", strerror(-rc));
	}

	// Only advertise supporting control messages
	peer->message_types = malloc(1);
	if (peer->message_types) {
		peer->num_message_types = 1;
		peer->message_types[0] = MCTP_CTRL_HDR_MSG_TYPE;
	} else {
		warnx("Out of memory");
	}

	rc = publish_peer(peer, true);
	if (rc) {
		warnx("Error publishing local eid %d net %d", eid, net);
	}
	return 0;
}

// Adds peers for local EIDs on an interface
static int add_interface_local(struct ctx *ctx, int ifindex)
{
	mctp_eid_t *eids = NULL;
	struct link *link = NULL;
	uint32_t net;
	size_t num;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Adding interface #%d %s\n", ifindex,
			mctp_nl_if_byindex(ctx->nl, ifindex));
	}

	if (!mctp_nl_up_byindex(ctx->nl, ifindex))
		warnx("Warning, interface %s is down",
		      mctp_nl_if_byindex(ctx->nl, ifindex));

	net = mctp_nl_net_byindex(ctx->nl, ifindex);
	if (net == 0) {
		warnx("No net for ifindex %d", ifindex);
		return -EINVAL;
	}

	// Add new net if required
	if (!lookup_net(ctx, net)) {
		rc = add_net(ctx, net);
		if (rc < 0)
			return rc;
	}
	eids = mctp_nl_addrs_byindex(ctx->nl, ifindex, &num);
	for (size_t j = 0; j < num; j++) {
		add_local_eid(ctx, net, eids[j]);
	}

	// Add new link if required
	link = mctp_nl_get_link_userdata(ctx->nl, ifindex);
	if (!link || !link->published) {
		rc = add_interface(ctx, ifindex);
		if (rc < 0)
			return rc;
	}

	free(eids);
	return 0;
}

static int add_net(struct ctx *ctx, uint32_t net_id)
{
	struct net *net, **tmp;
	int rc;

	if (lookup_net(ctx, net_id) != NULL) {
		bug_warn("add_net for existing net %d", net_id);
		return -EEXIST;
	}

	net = calloc(1, sizeof(*net));
	if (!net) {
		warn("failed to allocate net");
		return -ENOMEM;
	}

	// Initialise the new entry
	net->net = net_id;
	net->ctx = ctx;
	rc = asprintf(&net->path, "%s/%d", MCTP_DBUS_PATH_NETWORKS, net->net);
	if (rc < 0) {
		warn("%s: failed to allocate net path", __func__);
		free(net);
		return -ENOMEM;
	}

	tmp = realloc(ctx->nets, sizeof(struct net *) * (ctx->num_nets + 1));
	if (!tmp) {
		warnx("Out of memory");
		return -ENOMEM;
	}
	ctx->nets = tmp;
	ctx->nets[ctx->num_nets] = net;
	ctx->num_nets++;

	if (ctx->verbose) {
		fprintf(stderr, "net %d added, path %s\n", net->net, net->path);
	}

	sd_bus_add_object_vtable(ctx->bus, &net->slot, net->path,
				 CC_MCTP_DBUS_NETWORK_INTERFACE,
				 bus_network_vtable, net);

	emit_net_added(ctx, net);
	return 0;
}

static void del_net(struct net *net)
{
	sd_bus_slot_unref(net->slot);
	net->slot = NULL;
	net->net = 0;
	free(net->path);
	free(net);
}

static int add_interface(struct ctx *ctx, int ifindex)
{
	int rc;

	uint32_t net = mctp_nl_net_byindex(ctx->nl, ifindex);
	if (!net) {
		warnx("Can't find link index %d", ifindex);
		return -ENOENT;
	}

	const char *ifname = mctp_nl_if_byindex(ctx->nl, ifindex);
	if (!ifname) {
		warnx("Can't find link name for index %d", ifindex);
		return -ENOENT;
	}

	struct link *link = calloc(1, sizeof(*link));
	if (!link)
		return -ENOMEM;

	link->published = false;
	link->ifindex = ifindex;
	link->ctx = ctx;
	/* Use the `mode` setting in conf/mctp.conf */
	link->role = ctx->default_role;
	rc = asprintf(&link->path, "%s/%s", MCTP_DBUS_PATH_LINKS, ifname);
	if (rc < 0) {
		rc = -ENOMEM;
		goto err_free;
	}

	rc = mctp_nl_set_link_userdata(ctx->nl, ifindex, link);
	if (rc < 0) {
		warnx("Failed to set UserData for link index %d", ifindex);
		goto err_free;
	}

	sd_bus_add_object_vtable(link->ctx->bus, &link->slot_iface, link->path,
				 CC_MCTP_DBUS_IFACE_INTERFACE, bus_link_vtable,
				 link);

	if (link->role == ENDPOINT_ROLE_BUS_OWNER) {
		sd_bus_add_object_vtable(link->ctx->bus, &link->slot_busowner,
					 link->path,
					 CC_MCTP_DBUS_IFACE_BUSOWNER,
					 bus_link_owner_vtable, link);
	}

	link->published = true;
	rc = emit_interface_added(link);
	if (rc < 0) {
		link->published = false;
	}

	return rc;

err_free:
	free(link);
	return rc;
}

static int setup_nets(struct ctx *ctx)
{
	size_t num_ifs;
	int *ifs;
	int rc;

	/* Set up local addresses */
	ifs = mctp_nl_if_list(ctx->nl, &num_ifs);
	rc = 0;
	for (size_t i = 0; i < num_ifs && rc == 0; i++) {
		rc = add_interface_local(ctx, ifs[i]);
	}
	free(ifs);
	if (rc < 0)
		return rc;

	if (num_ifs == 0) {
		warnx("No MCTP interfaces");
		return -ENOENT;
	}

	if (ctx->verbose) {
		mctp_nl_linkmap_dump(ctx->nl);
	}

	return 0;
}

static void free_nets(struct ctx *ctx)
{
	for (size_t i = 0; i < ctx->num_nets; i++) {
		del_net(ctx->nets[i]);
	}

	free(ctx->nets);
}

static void print_usage(struct ctx *ctx)
{
	fprintf(stderr, "mctpd [-v] [-c FILE]\n");
	fprintf(stderr, "      -v verbose\n");
	fprintf(stderr, "      -c FILE read config from FILE\n");
}

static int parse_args(struct ctx *ctx, int argc, char **argv)
{
	struct option options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = "verbose", .has_arg = no_argument, .val = 'v' },
		{ .name = "config", .has_arg = required_argument, .val = 'c' },
		{ 0 },
	};
	int c;

	for (;;) {
		c = getopt_long(argc, argv, "+hvNc:", options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			ctx->verbose = true;
			break;
		case 'c':
			ctx->config_filename = strdup(optarg);
			break;
		case 'h':
		default:
			print_usage(ctx);
			return 255;
		}
	}
	return 0;
}

static int parse_config_mode(struct ctx *ctx, const char *mode)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(roles); i++) {
		const struct role *role = &roles[i];

		if (!role->conf_val || strcmp(role->conf_val, mode))
			continue;

		ctx->default_role = role->role;
		return 0;
	}

	warnx("invalid value '%s' for mode configuration", mode);
	return -1;
}

static int fill_uuid(struct ctx *ctx)
{
	int rc;
	sd_id128_t appid;
	sd_id128_t *u = (void *)ctx->uuid;

	rc = sd_id128_from_string(mctpd_appid, &appid);
	if (rc < 0) {
		warnx("Failed to get appid");
		return rc;
	}

	rc = sd_id128_get_machine_app_specific(appid, u);
	if (rc >= 0)
		return 0;

	warnx("No machine-id, fallback to boot ID");
	rc = sd_id128_get_boot_app_specific(appid, u);
	if (rc < 0)
		warnx("Failed to get boot ID");

	return rc;
}

static int parse_config_mctp(struct ctx *ctx, toml_table_t *mctp_tab)
{
	toml_datum_t val;
	int rc;

	val = toml_int_in(mctp_tab, "message_timeout_ms");
	if (val.ok) {
		int64_t i = val.u.i;
		if (i <= 0 || i > 100 * 1000) {
			warnx("invalid message_timeout_ms value");
			return -1;
		}
		ctx->mctp_timeout = i * 1000;
	}

	val = toml_string_in(mctp_tab, "uuid");
	if (val.ok) {
		rc = sd_id128_from_string(val.u.s, (void *)&ctx->uuid);
		free(val.u.s);
		if (rc) {
			warnx("invalid UUID value");
			return rc;
		}
	} else {
		rc = fill_uuid(ctx);
		if (rc)
			return rc;
	}

	return 0;
}

static int parse_config_bus_owner(struct ctx *ctx, toml_table_t *bus_owner)
{
	toml_datum_t val;

	val = toml_int_in(bus_owner, "max_pool_size");
	if (val.ok) {
		int64_t i = val.u.i;
		if (i <= 0 || i > (eid_alloc_max - eid_alloc_min)) {
			warnx("invalid max_pool_size value (must be 1-%d)",
			      eid_alloc_max - eid_alloc_min);
			return -1;
		}
		ctx->max_pool_size = i;
	}

	return 0;
}

static int parse_config(struct ctx *ctx)
{
	toml_table_t *conf_root, *mctp_tab, *bus_owner;
	bool conf_file_specified;
	char errbuf[256] = { 0 };
	const char *filename;
	toml_datum_t val;
	FILE *fp;
	int rc;

	conf_file_specified = !!ctx->config_filename;
	filename = ctx->config_filename ?: conf_file_default;

	rc = -1;
	fp = fopen(filename, "r");
	if (!fp) {
		/* only fatal if a configuration file was specifed by args */
		rc = 0;
		if (conf_file_specified) {
			warn("can't open configuration file %s", filename);
			rc = -1;
		}
		return rc;
	}

	conf_root = toml_parse_file(fp, errbuf, sizeof(errbuf));
	if (!conf_root) {
		warnx("can't parse configuration file %s: %s", filename,
		      errbuf);
		goto out_close;
	}

	val = toml_string_in(conf_root, "mode");
	if (val.ok) {
		rc = parse_config_mode(ctx, val.u.s);
		free(val.u.s);
		if (rc)
			goto out_free;
	}

	mctp_tab = toml_table_in(conf_root, "mctp");
	if (mctp_tab) {
		rc = parse_config_mctp(ctx, mctp_tab);
		if (rc)
			goto out_free;
	}

	bus_owner = toml_table_in(conf_root, "bus-owner");
	if (bus_owner) {
		rc = parse_config_bus_owner(ctx, bus_owner);
		if (rc)
			goto out_free;
	}

	rc = 0;

out_free:
	toml_free(conf_root);
out_close:
	fclose(fp);
	return rc;
}

static void setup_config_defaults(struct ctx *ctx)
{
	ctx->mctp_timeout = 250000; // 250ms
	ctx->default_role = ENDPOINT_ROLE_BUS_OWNER;
	ctx->max_pool_size = 15;
}

static void free_config(struct ctx *ctx)
{
	free(ctx->config_filename);
}

static int endpoint_send_allocate_endpoint_id(struct peer *peer,
					      mctp_eid_t eid_start,
					      uint8_t eid_pool_size,
					      mctp_ctrl_cmd_alloc_eid_op oper,
					      uint8_t *allocated_pool_size,
					      mctp_eid_t *allocated_pool_start)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_alloc_eid req = { 0 };
	struct mctp_ctrl_resp_alloc_eid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid, stat;
	int rc;

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	req.alloc_eid_op = (uint8_t)(oper & 0x03);
	req.pool_size = eid_pool_size;
	req.start_eid = eid_start;
	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer), iid,
					 MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);

	if (rc)
		goto out;

	resp = (void *)buf;
	if (!resp) {
		warnx("%s Invalid response Buffer\n", __func__);
		return -ENOMEM;
	}

	stat = resp->status & 0x03;
	if (stat == 0x00) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "%s Allocation Accepted \n", __func__);
		}
		if (resp->eid_pool_size != eid_pool_size ||
		    resp->eid_set != eid_start) {
			warnx("Unexpected pool start %d pool size %d",
			      resp->eid_set, resp->eid_pool_size);
			rc = -1;
			goto out;
		}
	} else {
		if (stat == 0x1)
			warnx("%s Allocation was rejected: already allocated by other bus"
			      " pool start %d, pool size %d",
			      __func__, resp->eid_pool_size, resp->eid_set);
		rc = -1;
		goto out;
	}

	*allocated_pool_size = resp->eid_pool_size;
	*allocated_pool_start = resp->eid_set;
	if (peer->ctx->verbose) {
		fprintf(stderr,
			"%s Allocated size of %d, starting from EID %d\n",
			__func__, resp->eid_pool_size, resp->eid_set);
	}

out:
	free(buf);
	return rc;
}

static int endpoint_allocate_eid(struct peer *peer)
{
	uint8_t allocated_pool_size = 0;
	mctp_eid_t allocated_pool_start = 0;
	int rc = 0;

	/* Find pool sized contiguous unused eids to allocate on the bridge. */
	if (peer->pool_start >= eid_alloc_max || peer->pool_start <= 0) {
		warnx("%s Invalid Pool start %d", __func__, peer->pool_start);
		return -1;
	}
	rc = endpoint_send_allocate_endpoint_id(
		peer, peer->pool_start, peer->pool_size,
		mctp_ctrl_cmd_alloc_eid_alloc_eid, &allocated_pool_size,
		&allocated_pool_start);
	if (rc) {
		//reset peer pool
		peer->pool_size = 0;
		peer->pool_start = 0;
	} else {
		peer->pool_size = allocated_pool_size;
		peer->pool_start = allocated_pool_start;

		// add Gateway route for all Bridge's downstream eids
		if (peer->pool_size > 0) {
			struct mctp_fq_addr gw_addr = { 0 };
			gw_addr.net = peer->net;
			gw_addr.eid = peer->eid;
			rc = mctp_nl_route_add(peer->ctx->nl, peer->pool_start,
					       peer->pool_size - 1,
					       peer->phys.ifindex, &gw_addr,
					       peer->mtu);
			if (rc < 0) {
				warnx("Failed to add Gateway route for EID %d: %s",
				      gw_addr.eid, strerror(-rc));
				// If the route already exists, continue polling
				if (rc != -EEXIST) {
					return rc;
				} else {
					rc = 0;
				}
			}
			// TODO: Polling logic for downstream EID
		}
	}

	return rc;
}

int main(int argc, char **argv)
{
	struct ctx ctxi = { 0 }, *ctx = &ctxi;
	int rc;

	setlinebuf(stdout);

	setup_config_defaults(ctx);
	mctp_ops_init();

	rc = parse_args(ctx, argc, argv);
	if (rc != 0) {
		return rc;
	}

	rc = parse_config(ctx);
	if (rc) {
		err(EXIT_FAILURE, "Can't read configuration");
	}

	ctx->nl = mctp_nl_new(false);
	if (!ctx->nl) {
		warnx("Failed creating netlink object");
		return 1;
	}
	mctp_nl_warn_eexist(ctx->nl, false);

	/* D-Bus needs to be set up before setup_nets() so we
	   can populate D-Bus objects for interfaces */
	rc = setup_bus(ctx);
	if (rc < 0) {
		warnx("Error in setup, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	/* Listen prior to setup_nets() so we don't miss any updates */
	rc = listen_monitor(ctx);
	if (rc < 0) {
		warnx("Error monitoring netlink updates. State changes will be ignored. (%s)",
		      strerror(-rc));
	}

	rc = setup_nets(ctx);
	if (rc < 0)
		return 1;

	// TODO add net argument?
	rc = listen_control_msg(ctx, MCTP_NET_ANY);
	if (rc < 0) {
		warnx("Error in listen, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	// All setup must be complete by here, we might immediately
	// get requests from waiting clients.
	rc = request_dbus(ctx);
	if (rc < 0)
		return 1;

	rc = sd_event_loop(ctx->event);
	sd_event_unref(ctx->event);
	if (rc < 0) {
		warnx("Error in loop, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	sd_bus_flush_close_unrefp(&ctx->bus);

	free_links(ctx);
	free_peers(ctx);
	free_nets(ctx);
	free_config(ctx);

	mctp_nl_close(ctx->nl);

	return 0;
}

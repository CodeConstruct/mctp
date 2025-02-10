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
#define CC_MCTP_DBUS_IFACE_TESTING "au.com.codeconstruct.MCTPTesting"
#define MCTP_DBUS_NAME "au.com.codeconstruct.MCTP1"
#define MCTP_DBUS_IFACE_ENDPOINT "xyz.openbmc_project.MCTP.Endpoint"
#define OPENBMC_IFACE_COMMON_UUID "xyz.openbmc_project.Common.UUID"
#define CC_MCTP_DBUS_IFACE_INTERFACE "au.com.codeconstruct.MCTP.Interface1"
#define CC_MCTP_DBUS_NETWORK_INTERFACE "au.com.codeconstruct.MCTP.Network1"

// an arbitrary constant for use with sd_id128_get_machine_app_specific()
static const char* mctpd_appid = "67369c05-4b97-4b7e-be72-65cfd8639f10";

static const char *conf_file_default = MCTPD_CONF_FILE_DEFAULT;

static mctp_eid_t eid_alloc_min = 0x08;
static mctp_eid_t eid_alloc_max = 0xfe;

// arbitrary sanity
static size_t MAX_PEER_SIZE = 1000000;

static const uint8_t RQDI_REQ = 1<<7;
static const uint8_t RQDI_RESP = 0x0;
static const uint8_t RQDI_IID_MASK = 0x1f;

struct dest_phys {
	int ifindex;
	uint8_t hwaddr[MAX_ADDR_LEN];
	size_t hwaddr_len;
};
typedef struct dest_phys dest_phys;

/* Table of per-network details */
struct net {
	int net;
	// EID mappings, an index into ctx->peers. Value -1 is unused.
	ssize_t peeridx[256];
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
	enum endpoint_role role;
};

struct peer {
	int net;
	mctp_eid_t eid;

	// multiple local interfaces can have the same eid,
	// so we store a refcount to use when removing peers.
	int local_count;

	// Only set for .state == REMOTE
	dest_phys phys;

	enum {
		UNUSED = 0,
		REMOTE,
		// Local address. Note that multiple interfaces
		// in a network may have the same local address.
		LOCAL,
	} state;

	// visible to dbus, set by publish/unpublish_peer()
	bool published;
	sd_bus_slot *slot_obmc_endpoint;
	sd_bus_slot *slot_cc_endpoint;
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
};

struct ctx {
	sd_event *event;
	sd_bus *bus;

	// Configuration
	const char *config_filename;

	// Main instance for link/address state and listening for updates
	mctp_nl *nl;

	// Second instance for sending mctp socket requests. State is unused.
	mctp_nl *nl_query;

	// Default BMC role in All of MCTP medium interface
	enum endpoint_role default_role;

	// An allocated array of peers, changes address (reallocated) during runtime
	struct peer *peers;
	size_t size_peers;

	struct net *nets;
	size_t num_nets;

	// Timeout in usecs for a MCTP response
	uint64_t mctp_timeout;

	// Next IID to use
	uint8_t iid;

	uint8_t uuid[16];

	// Verbose logging
	bool verbose;
	bool testing;
};

static int emit_endpoint_added(const struct peer *peer);
static int emit_endpoint_removed(const struct peer *peer);
static int emit_interface_added(struct ctx *ctx, int ifindex);
static int emit_interface_removed(struct ctx *ctx, int ifindex);
static int emit_net_added(struct ctx *ctx, int net);
static int emit_net_removed(struct ctx *ctx, int net);
static int query_peer_properties(struct peer *peer);
static int setup_added_peer(struct peer *peer);
static void add_peer_route(struct peer *peer);
static int publish_peer(struct peer *peer, bool add_route);
static int unpublish_peer(struct peer *peer);
static int peer_route_update(struct peer *peer, uint16_t type);
static int peer_neigh_update(struct peer *peer, uint16_t type);

static int add_interface_local(struct ctx *ctx, int ifindex);
static int del_interface(struct ctx *ctx, int old_ifindex);
static int change_net_interface(struct ctx *ctx, int ifindex, int old_net);
static int add_local_eid(struct ctx *ctx, int net, int eid);
static int del_local_eid(struct ctx *ctx, int net, int eid);
static int add_net(struct ctx *ctx, int net);
static int add_interface(struct ctx *ctx, int ifindex);

static const sd_bus_vtable bus_endpoint_obmc_vtable[];
static const sd_bus_vtable bus_endpoint_cc_vtable[];
static const sd_bus_vtable bus_endpoint_uuid_vtable[];

mctp_eid_t local_addr(const struct ctx *ctx, int ifindex) {
	mctp_eid_t *eids, ret = 0;
	size_t num;

	eids = mctp_nl_addrs_byindex(ctx->nl, ifindex, &num);
	if (num)
		ret = eids[0];
	free(eids);
	return ret;
}

static void* dfree(void* ptr);

static struct net *lookup_net(struct ctx *ctx, int net)
{
	size_t i;
	for (i = 0; i < ctx->num_nets; i++)
		if (ctx->nets[i].net == net)
			return &ctx->nets[i];
	return NULL;
}

static bool match_phys(const dest_phys *d1, const dest_phys *d2) {
	return d1->ifindex == d2->ifindex &&
		d1->hwaddr_len == d2->hwaddr_len &&
		(d2->hwaddr_len == 0
			|| !memcmp(d1->hwaddr, d2->hwaddr, d1->hwaddr_len));
}

static struct peer *find_peer_by_phys(struct ctx *ctx, const dest_phys *dest)
{
	for (size_t i = 0; i < ctx->size_peers; i++) {
		struct peer *peer = &ctx->peers[i];
		if (peer->state != REMOTE)
			continue;
		if (match_phys(&peer->phys, dest))
			return peer;
	}
	return NULL;
}

static struct peer *find_peer_by_addr(struct ctx *ctx, mctp_eid_t eid, int net)
{
	struct net *n = lookup_net(ctx, net);

	if (eid != 0 && n && n->peeridx[eid] >= 0)
		return &ctx->peers[n->peeridx[eid]];
	return NULL;
}

static int find_local_eids_by_net(struct ctx *ctx, uint32_t net,
                                  size_t* local_eid_cnt,
                                  mctp_eid_t *ret_eids)
{
	size_t local_count = 0;
	struct net *n = lookup_net(ctx, net);
	struct peer *peer;

	*local_eid_cnt = 0;
	if (!n)
		return -EINVAL;

	for (size_t t = 0; t < 256; t++) {
		if (n->peeridx[t] < 0)
			continue;

		peer = &ctx->peers[n->peeridx[t]];
		if (peer && (peer->state == LOCAL))
			ret_eids[local_count++] = t;
	}
	*local_eid_cnt = local_count;

	return 0;
}

/* Returns a deferred free pointer */
static const char* dest_phys_tostr(const dest_phys *dest)
{
	char hex[MAX_ADDR_LEN*4];
	char* buf;
	size_t l = 50 + sizeof(hex);
	buf = malloc(l);
	if (!buf) {
		return "Out of memory";
	}
	write_hex_addr(dest->hwaddr, dest->hwaddr_len, hex, sizeof(hex));
	snprintf(buf, l, "physaddr if %d hw len %zu 0x%s", dest->ifindex, dest->hwaddr_len, hex);
	return dfree(buf);
}

static const char* ext_addr_tostr(const struct sockaddr_mctp_ext *addr)
{
	char hex[MAX_ADDR_LEN*4];
	char* buf;
	size_t l = 256;
	buf = malloc(l);
	if (!buf) {
		return "Out of memory";
	}

	write_hex_addr(addr->smctp_haddr, addr->smctp_halen, hex, sizeof(hex));
	snprintf(buf, l, "sockaddr_mctp_ext eid %d net %d type 0x%02x if %d hw len %hhu 0x%s",
		addr->smctp_base.smctp_addr.s_addr,
		addr->smctp_base.smctp_network,
		addr->smctp_base.smctp_type,
		addr->smctp_ifindex,
		addr->smctp_halen, hex);
	return dfree(buf);
}

static const char* peer_tostr(const struct peer *peer)
{
	size_t l = 300;
	char *str = NULL;

	str = malloc(l);
	if (!str) {
		return "Out of memory";
	}
	snprintf(str, l, "peer eid %d net %d phys %s state %d",
		peer->eid, peer->net, dest_phys_tostr(&peer->phys),
		peer->state);
	return dfree(str);
}

static const char* peer_tostr_short(const struct peer *peer)
{
	size_t l = 30;
	char *str = NULL;

	str = malloc(l);
	if (!str) {
		return "Out of memory";
	}
	snprintf(str, l, "%d:%d", peer->net, peer->eid);
	return dfree(str);
}

static int defer_free_handler(sd_event_source *s, void *userdata)
{
	free(userdata);
	sd_event_source_unref(s);
	return 0;
}

/* Returns ptr, frees it on the next default event loop cycle (defer)*/
static void* dfree(void* ptr)
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

static int cb_exit_loop_io(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	sd_event_exit(sd_event_source_get_event(s), 0);
	return 0;
}

static int cb_exit_loop_timeout(sd_event_source *s, uint64_t usec, void *userdata)
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

static const char *path_from_peer(const struct peer *peer)
{

	if (!peer->published) {
		warnx("BUG: %s on peer %s", __func__, peer_tostr(peer));
		return NULL;
	}
	return peer->path;
}

static int get_role(const char *mode, struct role *role)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(roles); i++) {
		if (roles[i].dbus_val && (strcmp(roles[i].dbus_val, mode) == 0)) {
			memcpy(role, &roles[i], sizeof(struct role));
			return 0;
		}
	}

	return -1;
}

/* Returns the message from a socket.
   ret_buf is allocated, should be freed by the caller */
static int read_message(struct ctx *ctx, int sd, uint8_t **ret_buf, size_t *ret_buf_size,
		struct sockaddr_mctp_ext *ret_addr)
{
	int rc;
	socklen_t addrlen;
	ssize_t len;
	uint8_t* buf = NULL;
	size_t buf_size;

	len = mctp_ops.mctp.recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC,
				     NULL, 0);
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
				     (struct sockaddr *)ret_addr,
		&addrlen);
	if (len < 0) {
		rc = -errno;
		goto out;
	}
	if ((size_t)len != buf_size) {
		warnx("BUG: incorrect recvfrom %zd, expected %zu", len, buf_size);
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
			ext_addr_tostr(ret_addr),
			buf_size);
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

/* Replies to a real EID, not physical addressing */
static int reply_message(struct ctx *ctx, int sd, const void *resp, size_t resp_len,
	const struct sockaddr_mctp_ext *addr)
{
	ssize_t len;
	struct sockaddr_mctp reply_addr;

	memcpy(&reply_addr, &addr->smctp_base, sizeof(reply_addr));
	reply_addr.smctp_tag &= ~MCTP_TAG_OWNER;

	if (reply_addr.smctp_addr.s_addr == 0 ||
		 reply_addr.smctp_addr.s_addr == 0xff) {
		warnx("BUG: reply_message can't take EID %d",
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
		warnx("BUG: short sendto %zd, expected %zu", len, resp_len);
		return -EPROTO;
	}
	return 0;
}

// Handles new Incoming Set Endpoint ID request
static int handle_control_set_endpoint_id(struct ctx *ctx,
	int sd, struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_set_eid *req = NULL;
	struct mctp_ctrl_resp_set_eid respi = {0}, *resp = &respi;
	size_t resp_len;

	if (buf_size < sizeof(*req)) {
		warnx("short Set Endpoint ID message");
		return -ENOMSG;
	}
	req = (void*)buf;

	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;
	resp->completion_code = 0;
	resp->status = 0x01 << 4; // Already assigned, TODO
	resp->eid_set = local_addr(ctx, addr->smctp_ifindex);
	resp->eid_pool_size = 0;
	resp_len = sizeof(struct mctp_ctrl_resp_set_eid);

	// TODO: learn busowner route and neigh

	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_get_version_support(struct ctx *ctx,
	int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_mctp_ver_support *req = NULL;
	struct mctp_ctrl_resp_get_mctp_ver_support *resp = NULL;
	uint32_t *versions = NULL;
	// space for 4 versions
	uint8_t respbuf[sizeof(*resp) + 4*sizeof(*versions)];
	size_t resp_len;

	if (buf_size < sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support)) {
		warnx("short Get Version Support message");
		return -ENOMSG;
	}

	req = (void*)buf;
	resp = (void*)respbuf;
	versions = (void*)(resp+1);
	switch (req->msg_type_number) {
		case 0xff: // Base Protocol
		case 0x00: // Control protocol
			// from DSP0236 1.3.1  section 12.6.2. Big endian.
			versions[0] = htonl(0xF1F0FF00);
			versions[1] = htonl(0xF1F1FF00);
			versions[2] = htonl(0xF1F2FF00);
			versions[3] = htonl(0xF1F3F100);
			resp->number_of_entries = 4;
			resp->completion_code = 0x00;
			resp_len = sizeof(*resp) + 4*sizeof(*versions);
			break;
		default:
			// Unsupported message type
			resp->completion_code = 0x80;
			resp_len = sizeof(*resp);
	}

	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;
	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_get_endpoint_id(struct ctx *ctx,
	int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_eid *req = NULL;
	struct mctp_ctrl_resp_get_eid respi = {0}, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint ID message");
		return -ENOMSG;
	}

	req = (void*)buf;
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;

	resp->eid = local_addr(ctx, addr->smctp_ifindex);
	if (ctx->default_role == ENDPOINT_ROLE_BUS_OWNER)
		SET_ENDPOINT_TYPE(resp->eid_type, MCTP_BUS_OWNER_BRIDGE);
	// 10b = 2 = static EID supported, matches currently assigned.
	SET_ENDPOINT_ID_TYPE(resp->eid_type, 2);
	// TODO: medium specific information

	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

static int handle_control_get_endpoint_uuid(struct ctx *ctx,
	int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_uuid *req = NULL;;
	struct mctp_ctrl_resp_get_uuid respi = {0}, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint UUID message");
		return -ENOMSG;
	}

	req = (void*)buf;
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;
	memcpy(resp->uuid, ctx->uuid, sizeof(resp->uuid));
	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}


static int handle_control_get_message_type_support(struct ctx *ctx,
	int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_msg_type_support *req = NULL;;
	struct mctp_ctrl_resp_get_msg_type_support *resp = NULL;
	uint8_t resp_buf[sizeof(*resp) + 1];
	size_t resp_len;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Message Type Support message");
		return -ENOMSG;
	}

	req = (void*)buf;
	resp = (void*)resp_buf;
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;

	// Only control messages supported
	resp->msg_type_count = 1;
	*((uint8_t*)(resp+1)) = MCTP_CTRL_HDR_MSG_TYPE;
	resp_len = sizeof(*resp) + resp->msg_type_count;

	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_resolve_endpoint_id(struct ctx *ctx,
	int sd, const struct sockaddr_mctp_ext *addr,
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

	req = (void*)buf;
	resp = (void*)resp_buf;
	memset(resp, 0x0, sizeof(*resp));
	resp->ctrl_hdr.command_code = req->ctrl_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;

	peer = find_peer_by_addr(ctx, req->eid,
		addr->smctp_base.smctp_network);
	if (!peer) {
		resp->completion_code = 1;
		resp_len = sizeof(*resp);
	} else {
		// TODO: bridging
		resp->eid = req->eid;
		memcpy((void*)(resp+1),
			peer->phys.hwaddr, peer->phys.hwaddr_len);
		resp_len = sizeof(*resp) + peer->phys.hwaddr_len;
	}

	printf("resp_len %zu ... 0x%02x 0x%02x\n", resp_len,
		((uint8_t*)resp)[resp_len-2],
		((uint8_t*)resp)[resp_len-1]);
	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_unsupported(struct ctx *ctx,
	int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_msg_hdr *req = NULL;
	struct mctp_ctrl_generic {
		struct mctp_ctrl_msg_hdr ctrl_hdr;
		uint8_t completion_code;
	} __attribute__((__packed__));
	struct mctp_ctrl_generic respi = {0}, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short unsupported control message");
		return -ENOMSG;
	}

	req = (void*)buf;
	resp->ctrl_hdr.command_code = req->command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;
	resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

static int cb_listen_control_msg(sd_event_source *s, int sd, uint32_t revents,
	void *userdata)
{
	struct sockaddr_mctp_ext addr = {0};
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
		warnx("BUG: Wrong message type for listen socket");
		rc = -EINVAL;
		goto out;
	}

	if (buf_size < sizeof(struct mctp_ctrl_msg_hdr)) {
		warnx("Short message %zu bytes from %s",
			buf_size, ext_addr_tostr(&addr));
		rc = -EINVAL;
		goto out;
	}

	ctrl_msg = (void*)buf;
	if (ctx->verbose) {
		warnx("Got control request command code %hhd",
			ctrl_msg->command_code);
	}
	switch (ctrl_msg->command_code) {
		case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
			rc = handle_control_get_version_support(ctx,
				sd, &addr, buf, buf_size);
			break;
		case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
			rc = handle_control_set_endpoint_id(ctx,
				sd, &addr, buf, buf_size);
			break;
		case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
			rc = handle_control_get_endpoint_id(ctx,
				sd, &addr, buf, buf_size);
			break;
		case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
			rc = handle_control_get_endpoint_uuid(ctx,
				sd, &addr, buf, buf_size);
			break;
		case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
			rc = handle_control_get_message_type_support(ctx,
				sd, &addr, buf, buf_size);
			break;
		case MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID:
			rc = handle_control_resolve_endpoint_id(ctx,
				sd, &addr, buf, buf_size);
			break;
		default:
			if (ctx->verbose) {
				warnx("Ignoring unsupported command code 0x%02x",
					ctrl_msg->command_code);
				rc = -ENOTSUP;
			}
			rc = handle_control_unsupported(ctx,
				sd, &addr, buf, buf_size);
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

static int listen_control_msg(struct ctx *ctx, int net)
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
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT,
				      &val, sizeof(val));
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
		case MCTP_NL_ADD_LINK:
		{
			rc = add_interface_local(ctx, c->ifindex);
			any_error |= (rc < 0);
		}
		break;

		case MCTP_NL_DEL_LINK:
		{
			free(c->link_userdata);
			// Local addresses have already been deleted with DEL_EID
			rc = del_interface(ctx, c->ifindex);
			any_error |= (rc < 0);
		}
		break;

		case MCTP_NL_CHANGE_NET:
		{
			// Local addresses have already been deleted with DEL_EID
			rc = add_interface_local(ctx, c->ifindex);
			any_error |= (rc < 0);

			// Move remote endpoints
			rc = change_net_interface(ctx, c->ifindex, c->old_net);
			any_error |= (rc < 0);

		}
		break;

		case MCTP_NL_ADD_EID:
		{
			int net = mctp_nl_net_byindex(ctx->nl, c->ifindex);
			rc = add_local_eid(ctx, net, c->eid);
			any_error |= (rc < 0);
		}
		break;

		case MCTP_NL_DEL_EID:
		{
			rc = del_local_eid(ctx, c->old_net, c->eid);
			any_error |= (rc < 0);
		}
		break;

		case MCTP_NL_CHANGE_UP:
		{
			// 'up' state is currently unused
		}
		break;
		}
	}

	if (ctx->verbose && any_error) {
		printf("Error handling netlink update\n");
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

	rc = sd_event_add_io(ctx->event, NULL, sd, EPOLLIN,
		cb_listen_monitor, ctx);
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

	snprintf(pfx_str, sizeof(pfx_str), "[peer %s, cmd %s]",
		 peer, command_str(cmd));

	return pfx_str;
}

/* Common checks for responses: that we have enough data for a response,
 * the expected IID and opcode, and that the response indicated success.
 */
static int mctp_ctrl_validate_response(uint8_t *buf, size_t rsp_size, size_t
				       exp_size, const char *peer, uint8_t iid,
				       uint8_t cmd)
{
	struct mctp_ctrl_resp *rsp;

	if (exp_size <= sizeof(*rsp)) {
		warnx("invalid expected response size!");
		return -EINVAL;
	}

	if (rsp_size < exp_size) {
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

	return 0;
}

/* Use endpoint_query_peer() or endpoint_query_phys() instead.
 *
 * resp buffer is allocated, caller to free.
 * Extended addressing is used optionally, depending on ext_addr arg. */
static int endpoint_query_addr(struct ctx *ctx,
	const struct sockaddr_mctp_ext *req_addr, bool ext_addr,
	const void* req, size_t req_len,
	uint8_t **resp, size_t *resp_len, struct sockaddr_mctp_ext *resp_addr)
{
	size_t req_addr_len;
	int sd = -1, val;
	ssize_t rc;
	size_t buf_size;

	uint8_t* buf = NULL;

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
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT,
				       &val, sizeof(val));
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
		warnx("BUG: zero length request");
		rc = -EPROTO;
		goto out;
	}
	rc = mctp_ops.mctp.sendto(sd, req, req_len, 0,
				  (struct sockaddr *)req_addr, req_addr_len);
	if (rc < 0) {
		rc = -errno;
		if (ctx->verbose) {
			warnx("%s: sendto(%s) %zu bytes failed. %s", __func__,
				ext_addr_tostr(req_addr), req_len,
				strerror(-rc));
		}
		goto out;
	}
	if ((size_t)rc != req_len) {
		warnx("BUG: incorrect sendto %zd, expected %zu", rc, req_len);
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

	if (resp_addr->smctp_base.smctp_type != req_addr->smctp_base.smctp_type) {
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
static int endpoint_query_peer(const struct peer *peer,
	uint8_t req_type, const void* req, size_t req_len,
	uint8_t **resp, size_t *resp_len, struct sockaddr_mctp_ext *resp_addr)
{
	struct sockaddr_mctp_ext addr = {0};

	if (peer->state != REMOTE) {
		warnx("BUG: %s bad peer %s", __func__, peer_tostr(peer));
		return -EPROTO;
	}

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = peer->net;
	addr.smctp_base.smctp_addr.s_addr = peer->eid;

	addr.smctp_base.smctp_type = req_type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	return endpoint_query_addr(peer->ctx, &addr, false, req, req_len,
		resp, resp_len, resp_addr);
}

/* Queries an endpoint using physical addressing, null EID.
 */
static int endpoint_query_phys(struct ctx *ctx, const dest_phys *dest,
	uint8_t req_type, const void* req, size_t req_len,
	uint8_t **resp, size_t *resp_len, struct sockaddr_mctp_ext *resp_addr)
{
	struct sockaddr_mctp_ext addr = {0};

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

	return endpoint_query_addr(ctx, &addr, true, req, req_len,
		resp, resp_len, resp_addr);
}

/* returns -ECONNREFUSED if the endpoint returns failure. */
static int endpoint_send_set_endpoint_id(const struct peer *peer, mctp_eid_t *new_eid)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_set_eid req = {0};
	struct mctp_ctrl_resp_set_eid *resp = NULL;
	int rc;
	uint8_t* buf = NULL;
	size_t buf_size;
	uint8_t iid, stat, alloc;
	const dest_phys *dest = &peer->phys;

	rc = -1;

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	req.operation = 0; // 00b Set EID. TODO: do we want Force?
	req.eid = peer->eid;
	rc = endpoint_query_phys(peer->ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
		sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest),
					 iid, MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	if (rc)
		goto out;

	resp = (void*)buf;

	stat = resp->status >> 4 & 0x3;
	if (stat == 0x01) {
		// changed eid
	} else if (stat == 0x00) {
		if (resp->eid_set != peer->eid) {
			warnx("%s eid %d replied with different eid %d, but 'accepted'",
				dest_phys_tostr(dest), peer->eid, resp->eid_set);
		}
	} else {
		warnx("%s unexpected status 0x%02x",
			dest_phys_tostr(dest), resp->status);
	}
	*new_eid = resp->eid_set;

	alloc = resp->status & 0x3;
	if (alloc != 0) {
		// TODO for bridges
		warnx("%s requested allocation pool, unimplemented",
			dest_phys_tostr(dest));
	}

	rc = 0;
out:
	free(buf);
	return rc;
}


/* Returns the newly added peer.
 * Error is -EEXISTS if it exists */
static int add_peer(struct ctx *ctx, const dest_phys *dest, mctp_eid_t eid,
	int net, struct peer **ret_peer)
{
	ssize_t idx;
	size_t new_size;
	struct net *n;
	void *tmp = NULL;
	struct peer *peer;

	n = lookup_net(ctx, net);
	if (!n) {
		warnx("BUG: %s Bad net %d", __func__, net);
		return -EPROTO;
	}

	idx = n->peeridx[eid];
	if (n->peeridx[eid] >= 0) {
		if (idx >= (ssize_t)ctx->size_peers) {
			warnx("BUG: Bad index %zu", idx);
			return -EPROTO;
		}
		peer = &ctx->peers[idx];
		if (!match_phys(&peer->phys, dest)) {
			return -EEXIST;
		}
		*ret_peer = peer;
		return 0;
	}

	// Find a slot
	for (idx = 0; idx < (ssize_t)ctx->size_peers; idx++) {
		if (ctx->peers[idx].state == UNUSED) {
			break;
		}
	}
	if (idx == (ssize_t)ctx->size_peers) {
		// Allocate more entries
		new_size = max(20, ctx->size_peers*2);
		if (new_size > MAX_PEER_SIZE) {
			return -ENOSPC;
		}
		tmp = realloc(ctx->peers, new_size * sizeof(*ctx->peers));
		if (!tmp)
			return -ENOMEM;
		ctx->peers = tmp;
		// Zero the new entries
		memset(&ctx->peers[ctx->size_peers], 0x0,
			sizeof(*ctx->peers) * (new_size - ctx->size_peers));
		ctx->size_peers = new_size;
	}

	// Populate it
	peer = &ctx->peers[idx];
	memset(peer, 0x0, sizeof(*peer));
	peer->eid = eid;
	peer->net = net;
	memcpy(&peer->phys, dest, sizeof(*dest));
	peer->state = REMOTE;
	peer->ctx = ctx;

	// Update network eid map
	n->peeridx[eid] = idx;

	*ret_peer = peer;
	return 0;
}

static int check_peer_struct(const struct peer *peer, const struct net *n)
{
	ssize_t idx;
	struct ctx *ctx = peer->ctx;

	if (n->net != peer->net) {
		warnx("BUG: Mismatching net %d vs peer net %d", n->net, peer->net);
		return -1;
	}

	if (((void*)peer - (void*)ctx->peers) % sizeof(struct peer) != 0) {
		warnx("BUG: Bad address alignment");
		return -1;
	}

	idx = peer - ctx->peers;
	if (idx < 0 || idx > (ssize_t)ctx->size_peers) {
		warnx("BUG: Bad address index");
		return -1;
	}

	if (idx != n->peeridx[peer->eid]) {
		warnx("BUG: Bad net %d peeridx 0x%zx vs 0x%zx",
			peer->net, n->peeridx[peer->eid], idx);
		return -1;
	}

	return 0;
}

static int remove_peer(struct peer *peer)
{
	struct net *n = NULL;

	if (peer->state == UNUSED) {
		warnx("BUG: %s: unused peer", __func__);
		return -EPROTO;
	}

	n = lookup_net(peer->ctx, peer->net);
	if (!n) {
		warnx("BUG: %s: Bad net %d", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(peer, n) != 0) {
		warnx("BUG: %s: Inconsistent state", __func__);
		return -EPROTO;
	}

	unpublish_peer(peer);

	// Clear it
	if (peer->degraded) {
		int rc;

		rc = sd_event_source_set_enabled(peer->recovery.source, SD_EVENT_OFF);
		if (rc < 0) {
			/* XXX: Fix caller assumptions? */
			warnx("Failed to stop recovery timer while removing peer: %d", rc);
		}
		sd_event_source_unref(peer->recovery.source);
	}

	n->peeridx[peer->eid] = -1;
	free(peer->message_types);
	free(peer->uuid);
	memset(peer, 0x0, sizeof(struct peer));
	return 0;
}

/* Returns -EEXIST if the new_eid is already used */
static int change_peer_eid(struct peer *peer, mctp_eid_t new_eid) {
	struct net *n = NULL;

	n = lookup_net(peer->ctx, peer->net);
	if (!n) {
		warnx("BUG: %s: Bad net %d", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(peer, n) != 0) {
		warnx("BUG: %s: Inconsistent state", __func__);
		return -EPROTO;
	}

	if (n->peeridx[new_eid] != -1)
		return -EEXIST;

	/* publish & unpublish will update peer->path */
	unpublish_peer(peer);
	n->peeridx[new_eid] = n->peeridx[peer->eid];
	n->peeridx[peer->eid] = -1;
	peer->eid = new_eid;
	publish_peer(peer, true);

	return 0;
}

static int peer_set_mtu(struct ctx *ctx, struct peer *peer, uint32_t mtu) {
	const char* ifname = NULL;
	int rc;

	ifname = mctp_nl_if_byindex(ctx->nl, peer->phys.ifindex);
	if (!ifname) {
		warnx("BUG %s: no interface for ifindex %d",
			__func__, peer->phys.ifindex);
		return -EPROTO;
	}

	rc = mctp_nl_route_del(ctx->nl_query, peer->eid, ifname);
	if (rc < 0 && rc != -ENOENT) {
		warnx("%s, Failed removing existing route for eid %d %s",
			__func__,
			peer->phys.ifindex, ifname);
		// Continue regardless, route_add will likely fail with EEXIST
	}

	rc = mctp_nl_route_add(ctx->nl_query, peer->eid, ifname, mtu);
	if (rc >= 0) {
		peer->mtu = mtu;
	}
	return rc;
}

static int endpoint_assign_eid(struct ctx *ctx, sd_bus_error *berr, const dest_phys *dest,
	struct peer **ret_peer, mctp_eid_t static_eid)
{
	mctp_eid_t e, new_eid;
	struct net *n = NULL;
	struct peer *peer = NULL;
	int net;
	int rc;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (net <= 0) {
		warnx("BUG: No net known for ifindex %d", dest->ifindex);
		return -EPROTO;
	}

	n = lookup_net(ctx, net);
	if (!n) {
		warnx("BUG: Unknown net %d", net);
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
			if (n->peeridx[e] == -1) {
				rc = add_peer(ctx, dest, e, net, &peer);
				if (rc < 0)
					return rc;
				break;
			}
		}
		if (e > eid_alloc_max) {
			warnx("Ran out of EIDs for net %d, allocating %s", net, dest_phys_tostr(dest));
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
				"Ran out of EIDs");
			return -EADDRNOTAVAIL;
		}
	}

	rc = endpoint_send_set_endpoint_id(peer, &new_eid);
	if (rc == -ECONNREFUSED)
		sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
			"Endpoint returned failure to Set Endpoint ID");
	if (rc < 0) {
		remove_peer(peer);
		return rc;
	}

	if (new_eid != peer->eid) {
		rc = change_peer_eid(peer, new_eid);
		if (rc == -EEXIST) {
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
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
static void set_berr(struct ctx *ctx, int errcode, sd_bus_error *berr) {
	bool existing = false;

	if (sd_bus_error_is_set(berr)) {
		existing = true;
	} else switch (errcode) {
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
	mctp_eid_t *ret_eid, uint8_t *ret_ep_type, uint8_t *ret_media_spec)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_eid req = {0};
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
					 dest_phys_tostr(dest),
					 iid, MCTP_CTRL_CMD_GET_ENDPOINT_ID);
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
	const dest_phys *dest, struct peer **ret_peer, mctp_eid_t *ret_cur_eid)
{
	mctp_eid_t eid;
	uint8_t ep_type, medium_spec;
	struct peer *peer = NULL;
	int net;
	int rc;

	*ret_peer = NULL;
	rc = query_get_endpoint_id(ctx, dest, &eid, &ep_type, &medium_spec);
	if (rc)
		return rc;

	if (ret_cur_eid)
		*ret_cur_eid = eid;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (net < 1) {
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

static int query_get_peer_msgtypes(struct peer *peer) {
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_msg_type_support req;
	struct mctp_ctrl_resp_get_msg_type_support *resp = NULL;
	uint8_t* buf = NULL;
	size_t buf_size, expect_size;
	uint8_t iid;
	int rc;

	peer->num_message_types = 0;
	free(peer->message_types);
	peer->message_types = NULL;
	iid = mctp_next_iid(peer->ctx);

	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT;

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE,
		&req, sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer), iid,
					 MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	if (rc)
		goto out;

	resp = (void*)buf;
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
	memcpy(peer->message_types, (void*)(resp+1), resp->msg_type_count);
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

static int
query_get_peer_uuid_by_phys(struct ctx *ctx, const dest_phys *dest, uint8_t uuid[16])
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_uuid req;
	struct mctp_ctrl_resp_get_uuid *resp = NULL;
	uint8_t* buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;

	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE,
		&req, sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest),
					 iid, MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	if (rc)
		goto out;

	resp = (void*)buf;
	memcpy(uuid, resp->uuid, 16);

out:
	free(buf);
	return rc;
}

static int query_get_peer_uuid(struct peer *peer) {
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_uuid req;
	struct mctp_ctrl_resp_get_uuid *resp = NULL;
	uint8_t* buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	if (peer->state != REMOTE) {
		warnx("%s: Wrong state for peer %s", __func__, peer_tostr(peer));
		return -EPROTO;
	}

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE,
		&req, sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer),
					 iid, MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	if (rc)
		goto out;

	resp = (void*)buf;

	rc = peer_set_uuid(peer, resp->uuid);
	if (rc < 0)
		goto out;
	rc = 0;

out:
	free(buf);
	return rc;
}

static int interface_call_to_ifindex_busowner(struct ctx *ctx, sd_bus_message *msg)
{
	const char *iface, *path;
	struct link *link;
	int rc, ifindex;

	path = sd_bus_message_get_path(msg);
	if (!path)
		return -1;

	rc = sd_bus_path_decode_many(path, MCTP_DBUS_PATH_LINKS "/%", &iface);
	if (rc <= 0)
		return -1;

	ifindex = mctp_nl_ifindex_byname(ctx->nl, iface);
	if (ifindex < 0)
		return -1;

	link = mctp_nl_get_link_userdata(ctx->nl, ifindex);
	if (!link || link->role != ENDPOINT_ROLE_BUS_OWNER)
		return -1;

	return ifindex;
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
	if (mctp_nl_net_byindex(ctx->nl, dest->ifindex) <= 0) {
		warnx("unknown ifindex %d", dest->ifindex);
		return -EINVAL;
	}
	return 0;
}

static int message_read_hwaddr(sd_bus_message *call, dest_phys* dest)
{
	int rc;
	const void* msg_hwaddr = NULL;
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
static int method_setup_endpoint(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	dest_phys desti = {0}, *dest = &desti;
	const char *peer_path = NULL;
	struct ctx *ctx = data;
	struct peer *peer = NULL;

	dest->ifindex = interface_call_to_ifindex_busowner(ctx, call);
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
			fprintf(stderr, "%s returning from get_endpoint_peer %s",
				__func__, peer_tostr(peer));
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;
		return sd_bus_reply_method_return(call, "yisb",
			peer->eid, peer->net, peer_path, 0);
	} else if (rc == -EEXIST) {
		// EEXISTS is OK, we will assign a new eid instead.
	} else if (rc < 0) {
		// Unhandled error, fail.
		goto err;
	}

	/* Set Endpoint ID */
	rc = endpoint_assign_eid(ctx, berr, dest, &peer, 0);
	if (rc < 0)
		goto err;

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;
	if (ctx->verbose)
		fprintf(stderr, "%s returning from endpoint_assign_eid %s",
			__func__, peer_tostr(peer));
	return sd_bus_reply_method_return(call, "yisb",
		peer->eid, peer->net, peer_path, 1);

err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_assign_endpoint(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	dest_phys desti, *dest = &desti;
	const char *peer_path = NULL;
	struct ctx *ctx = data;
	struct peer *peer = NULL;

	dest->ifindex = interface_call_to_ifindex_busowner(ctx, call);
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
		if (rc < 0)
			goto err;

		return sd_bus_reply_method_return(call, "yisb",
			peer->eid, peer->net, peer_path, 0);
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, 0);
	if (rc < 0)
		goto err;

	peer_path = path_from_peer(peer);
	if (rc < 0)
		goto err;

	return sd_bus_reply_method_return(call, "yisb",
		peer->eid, peer->net, peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_assign_endpoint_static(sd_bus_message *call, void *data,
					 sd_bus_error *berr)
{
	dest_phys desti, *dest = &desti;
	const char *peer_path = NULL;
	struct peer *peer = NULL;
	struct ctx *ctx = data;
	uint8_t eid;
	int rc;

	dest->ifindex = interface_call_to_ifindex_busowner(ctx, call);
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
			return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Already assigned a different EID");
		}

		// Return existing record.
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;

		return sd_bus_reply_method_return(call, "yisb",
			peer->eid, peer->net, peer_path, 0);
	} else {
		int netid;

		// is the requested EID already in use? if so, reject
		netid = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
		peer = find_peer_by_addr(ctx, eid, netid);
		if (peer) {
			return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Address in use");
		}
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, eid);
	if (rc < 0) {
		goto err;
	}

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;

	return sd_bus_reply_method_return(call, "yisb",
		peer->eid, peer->net, peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_learn_endpoint(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	const char *peer_path = NULL;
	dest_phys desti, *dest = &desti;
	struct ctx *ctx = data;
	struct peer *peer = NULL;
	mctp_eid_t eid = 0;

	dest->ifindex = interface_call_to_ifindex_busowner(ctx, call);
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
		return sd_bus_error_setf(berr, SD_BUS_ERROR_FILE_EXISTS,
					 "Endpoint claimed EID %d which is already used",
					 eid);
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
		struct nlmsghdr		nh;
		struct ndmsg		ndmsg;
		uint8_t			rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
	} msg = {0};
	size_t rta_len = sizeof(msg.rta_buff);
	struct rtattr *rta = (void*)msg.rta_buff;

	msg.nh.nlmsg_type = type;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ndmsg.ndm_ifindex = peer->phys.ifindex;
	msg.ndmsg.ndm_family = AF_MCTP;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
		NDA_DST, &peer->eid, sizeof(peer->eid));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
		NDA_LLADDR, peer->phys.hwaddr, peer->phys.hwaddr_len);
	return mctp_nl_send(peer->ctx->nl_query, &msg.nh);
}

// type is RTM_NEWROUTE or RTM_DELROUTE
static int peer_route_update(struct peer *peer, uint16_t type)
{
	const char * link;

	link = mctp_nl_if_byindex(peer->ctx->nl_query, peer->phys.ifindex);
	if (!link) {
		warnx("BUG %s: Unknown ifindex %d", __func__, peer->phys.ifindex);
		return -ENODEV;
	}

	if (type == RTM_NEWROUTE) {
		return mctp_nl_route_add(peer->ctx->nl_query,
			peer->eid, link, peer->mtu);
	} else if (type == RTM_DELROUTE) {
		return mctp_nl_route_del(peer->ctx->nl_query, peer->eid, link);
	}

	warnx("BUG %s: bad type %d", __func__, type);
	return -EPROTO;
}

/* Called when a new peer is discovered. Queries properties and publishes */
static int setup_added_peer(struct peer *peer)
{
	int rc;

	// Set minimum MTU by default for compatibility. Clients can increase
	// this with .SetMTU as needed
	peer->mtu = mctp_nl_min_mtu_byindex(peer->ctx->nl_query, peer->phys.ifindex);

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

/* Adds routes/neigh. This is separate from
   publish_peer() because we want a two stage setup of querying
   properties (routed packets) then emitting dbus once finished */
static void add_peer_route(struct peer *peer)
{
	int rc;

	// We always try to add routes/neighs, ignoring if they
	// already exist.

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
	if (add_route && peer->state == REMOTE) {
		add_peer_route(peer);
	}

	if (peer->published)
		return 0;

	asprintf(&peer->path, "%s/networks/%d/endpoints/%d",
		 MCTP_DBUS_PATH, peer->net, peer->eid);

	peer->published = true;

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_obmc_endpoint,
				 peer->path, MCTP_DBUS_IFACE_ENDPOINT,
				 bus_endpoint_obmc_vtable, peer);

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_cc_endpoint,
				 peer->path, CC_MCTP_DBUS_IFACE_ENDPOINT,
				 bus_endpoint_cc_vtable, peer);

	if (peer->uuid) {
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_uuid,
					 peer->path, OPENBMC_IFACE_COMMON_UUID,
					 bus_endpoint_uuid_vtable, peer);
	}

	return emit_endpoint_added(peer);
}

/* removes route, neigh, dbus entry for the peer */
static int unpublish_peer(struct peer *peer) {
	int rc;
	if (peer->have_neigh) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "Deleting neigh to %s\n", peer_tostr(peer));
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
			fprintf(stderr, "Deleting route to %s\n", peer_tostr(peer));
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
		sd_bus_slot_unref(peer->slot_uuid);
		peer->slot_uuid = NULL;
		peer->published = false;
		free(peer->path);
	}

	return 0;
}


// Testing code
static int method_sendto_phys(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	const char *ifname = NULL;
	struct sockaddr_mctp_ext addr;
	dest_phys desti, *dest = &desti;
	struct ctx *ctx = data;
	uint8_t type;
	uint8_t *resp = NULL;
	const uint8_t *req = NULL;
	size_t req_len, resp_len;
	sd_bus_message *m = NULL;

	rc = sd_bus_message_read(call, "s", &ifname);
	if (rc < 0)
		goto err;

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read(call, "y", &type);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read_array(call, 'y', (const void**)&req, &req_len);
	if (rc < 0)
		goto err;

	dest->ifindex = mctp_nl_ifindex_byname(ctx->nl, ifname);
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
			"Unknown MCTP ifname '%s'", ifname);

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
			"Bad physaddr");

	rc = endpoint_query_phys(ctx, dest, type, req,
		req_len, &resp, &resp_len, &addr);
	if (rc < 0)
		goto err;

	dfree(resp);
	rc = sd_bus_message_new_method_return(call, &m);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_append(m, "yi",
		addr.smctp_base.smctp_addr,
		addr.smctp_base.smctp_network);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_append_array(m, 'y', resp, resp_len);
	if (rc < 0)
		goto err;

	rc = sd_bus_send(sd_bus_message_get_bus(m), m, NULL);
	sd_bus_message_unref(m);
	return rc;

err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_sendto_addr(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	struct sockaddr_mctp_ext req_addr = {0};
	struct sockaddr_mctp_ext addr;
	struct ctx *ctx = data;
	uint8_t *req = NULL, *resp = NULL;
	size_t req_len, resp_len;
	sd_bus_message *m = NULL;

	req_addr.smctp_base.smctp_family = AF_MCTP;
	req_addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	rc = sd_bus_message_read(call, "y", &req_addr.smctp_base.smctp_addr);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read(call, "i", &req_addr.smctp_base.smctp_network);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read(call, "y", &req_addr.smctp_base.smctp_type);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read_array(call, 'y', (const void**)&req, &req_len);
	if (rc < 0)
		goto err;

	rc = endpoint_query_addr(ctx, &req_addr, false, req, req_len,
		&resp, &resp_len, &addr);
	if (rc < 0)
		goto err;

	dfree(resp);
	rc = sd_bus_message_new_method_return(call, &m);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_append_array(m, 'y', resp, resp_len);
	if (rc < 0)
		goto err;

	rc = sd_bus_send(sd_bus_message_get_bus(m), m, NULL);
	sd_bus_message_unref(m);
	return rc;

err:
	set_berr(ctx, rc, berr);
	return rc;
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

static int
peer_endpoint_recover(sd_event_source *s, uint64_t usec, void *userdata)
{
	int ev_state __attribute__((unused));
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
		&peer->recovery.endpoint_type, &peer->recovery.medium_spec);
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
		static const uint8_t nil_uuid[16] = {0};
		bool uuid_matches_peer = false;
		bool uuid_matches_nil = false;
		uint8_t uuid[16] = {0};
		mctp_eid_t new_eid;

		rc = query_get_peer_uuid_by_phys(ctx, &peer->phys, uuid);
		if (!rc && peer->uuid) {
			static_assert(sizeof(uuid) == sizeof(nil_uuid), "Unsynchronized UUID sizes");
			uuid_matches_peer = memcmp(uuid, peer->uuid, sizeof(uuid)) == 0;
			uuid_matches_nil = memcmp(uuid, nil_uuid, sizeof(uuid)) == 0;
		}

		if (rc || !uuid_matches_peer ||
				(uuid_matches_nil && !MCTPD_RECOVER_NIL_UUID)) {
			/* It's not known to be the same device, allocate a new EID */
			dest_phys phys = peer->phys;

			assert(sd_event_source_get_enabled(peer->recovery.source, &ev_state) == 0);
			remove_peer(peer);
			/*
			 * The representation of the old peer is now gone. Set up the new peer,
			 * after which we immediately return as there's no old peer state left to
			 * maintain.
			 */
			return endpoint_assign_eid(ctx, NULL, &phys, &peer, 0);
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
		CC_MCTP_DBUS_IFACE_ENDPOINT, "Connectivity", NULL);
	if (rc < 0) {
		goto reschedule;
	}

	assert(sd_event_source_get_enabled(peer->recovery.source, &ev_state) == 0);
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
			rc = sd_event_source_set_enabled(peer->recovery.source, SD_EVENT_ONESHOT);
		}
	}
	if (rc < 0) {
reclaim:
		/* Recovery unsuccessful, clean up the peer */
		assert(sd_event_source_get_enabled(peer->recovery.source, &ev_state) == 0);
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
		rc = sd_event_add_time_relative(ctx->event, &peer->recovery.source,
			CLOCK_MONOTONIC, 0, ctx->mctp_timeout, peer_endpoint_recover, peer);
		if (rc < 0) {
			goto out;
		}

		peer->degraded = true;

		rc = sd_bus_emit_properties_changed(sd_bus_message_get_bus(call),
				sd_bus_message_get_path(call),
				sd_bus_message_get_interface(call),
				"Connectivity",
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
			sd_event_source_set_enabled(peer->recovery.source, SD_EVENT_OFF);
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

// Testing code
static int cb_test_timer(sd_event_source *s, uint64_t t, void* data)
{
	sd_bus_message *call = data;
	// sd_bus *bus = sd_bus_message_get_bus(call);
	int rc;

	rc = sd_bus_reply_method_return(call, "i", (int)(t % 11111));
	sd_bus_message_unref(call);
	if (rc < 0)
		return rc;
	return 0;
}

static int method_test_timer_async(sd_bus_message *call, void *data, sd_bus_error *sderr)
{
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

// Testing code
static int method_test_timer(sd_bus_message *call, void *data, sd_bus_error *sderr)
{
	int rc;
	int seconds;
	// struct struct ctx *ctx = data;

	rc = sd_bus_message_read(call, "i", &seconds);
	if (rc < 0)
		return rc;

	sleep(seconds);

	rc = sd_bus_reply_method_return(call, "i", seconds*10);
	return rc;
}

static const sd_bus_vtable bus_owner_vtable[] = {
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

static const sd_bus_vtable testing_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_NAMES("SendToPhys",
		"sayyay",
		SD_BUS_PARAM(ifname)
		SD_BUS_PARAM(physaddr)
		SD_BUS_PARAM(type)
		SD_BUS_PARAM(req),
		"yiay",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(resp),
		method_sendto_phys,
		0),
	SD_BUS_METHOD_WITH_NAMES("SendTo",
		"yiyay",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(type)
		SD_BUS_PARAM(req),
		"ay",
		SD_BUS_PARAM(resp),
		method_sendto_addr,
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

static bool is_endpoint_path(const char *path)
{
	char *netstr = NULL, *eidstr = NULL;
	uint32_t tmp, net;
	int rc;

	rc = sd_bus_path_decode_many(path,
				     MCTP_DBUS_PATH "/networks/%/endpoints/%",
				     &netstr, &eidstr);

	if (rc == 0)
		return false;
	if (rc < 0)
		return false;

	dfree(netstr);
	dfree(eidstr);

	if (parse_uint32(eidstr, &tmp) < 0 || tmp > 0xff)
		return false;

	if (parse_uint32(netstr, &net) < 0)
		return false;

	return true;
}

static bool get_networkid_from_path(const char *path, uint32_t* netid)
{
	char *netstr = NULL;
	int rc;

	rc = sd_bus_path_decode_many(path,
				     MCTP_DBUS_PATH "/networks/%",
				     &netstr);

	if (rc <= 0)
		return false;

	dfree(netstr);

	if (parse_uint32(netstr, netid) < 0)
		return false;

	return true;
}

static bool is_interfaces_path(const char *path)
{
	char *intfName = NULL;
	int rc;

	rc = sd_bus_path_decode_many(path,
				     MCTP_DBUS_PATH "/interfaces/%",
				     &intfName);

	if (rc == 0)
		return false;

	if (rc < 0)
		return false;

	dfree(intfName);

	return true;
}

static int bus_endpoint_get_prop(sd_bus *bus,
		const char *path, const char *interface, const char *property,
		sd_bus_message *reply, void *userdata, sd_bus_error *berr)
{
	struct peer *peer = userdata;
	int rc;

	if (!is_endpoint_path(path)) {
		return -ENOENT;
	}

	if (strcmp(property, "NetworkId") == 0) {
		rc = sd_bus_message_append(reply, "u", peer->net);
	} else if (strcmp(property, "EID") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->eid);
	} else if (strcmp(property, "SupportedMessageTypes") == 0) {
		rc = sd_bus_message_append_array(reply, 'y',
			peer->message_types, peer->num_message_types);
	} else if (strcmp(property, "UUID") == 0 && peer->uuid) {
		const char *s = dfree(bytes_to_uuid(peer->uuid));
		rc = sd_bus_message_append(reply, "s", s);
	} else if (strcmp(property, "Connectivity") == 0) {
		rc = sd_bus_message_append(reply, "s", peer->degraded ? "Degraded" : "Available");
	} else {
		printf("Unknown property '%s' for %s iface %s\n", property, path, interface);
		rc = -ENOENT;
	}

	return rc;
}

static int bus_network_get_prop(sd_bus *bus,
		const char *path, const char *interface, const char *property,
		sd_bus_message *reply, void *userdata, sd_bus_error *berr)
{
	struct ctx *ctx = userdata;
	int rc = 0;
	uint32_t netid;
	mctp_eid_t *eids = (mctp_eid_t *)malloc(256);
	size_t num;

	if (!get_networkid_from_path(path, &netid)) {
		return -ENOENT;
	}

	if (strcmp(property, "LocalEIDs") == 0) {
		rc = find_local_eids_by_net(ctx, netid, &num, eids);
		if (rc < 0) {
			return -ENOENT;
		}

		dfree(eids);
		rc = sd_bus_message_append_array(reply, 'y', eids, num);
	}

	return rc;
}

static int bus_link_get_prop(sd_bus *bus,
		const char *path, const char *interface, const char *property,
		sd_bus_message *reply, void *userdata, sd_bus_error *berr)
{
	struct ctx *ctx = userdata;
	char *tmpstr = NULL;
	char *link_name = NULL;
	struct link *link = NULL;
	int rc = 0;

	if (!is_interfaces_path(path)) {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Invalid Object Path");
		goto out;
	}

	rc = sd_bus_path_decode_many(path, MCTP_DBUS_PATH "/%/%", &tmpstr,
		&link_name);
	if (rc <= 0) {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Invalid Object Path");
		goto out;
	}

	link = mctp_nl_get_link_userdata_byname(ctx->nl, link_name);
	if (!link) {
		rc = -ENOENT;
		goto out;
	}

	if (link->published && strcmp(property, "Role") == 0) {
		rc = sd_bus_message_append(reply, "s", roles[link->role].dbus_val);
	} else {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Unknown property.");
		rc = -ENOENT;
	}

out:
	set_berr(ctx, rc, berr);

	return rc;
}

static int bus_link_set_prop(sd_bus *bus,
		const char *path, const char *interface, const char *property,
		sd_bus_message *value, void *userdata, sd_bus_error *berr)
{
	struct ctx *ctx = userdata;
	const char *state;
	char *tmpstr = NULL;
	char *link_name = NULL;
	struct link *link;
	int rc = -1;
	struct role role;

	if (!is_interfaces_path(path)) {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Invalid Object Path");
		goto out;
	}

	rc = sd_bus_path_decode_many(path, MCTP_DBUS_PATH "/%/%", &tmpstr,
		&link_name);
	if (rc <= 0) {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Invalid Object Path");
		goto out;
	}

	link = mctp_nl_get_link_userdata_byname(ctx->nl, link_name);
	if (!link) {
		rc = -ENOENT;
		goto out;
	}

	if (strcmp(property, "Role") != 0) {
		printf("Unknown property '%s' for %s iface %s\n", property, path, interface);
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
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				"Unknown Role. Only Support BusOwner/EndPoint.");
		goto out;
	}

	rc = get_role(state, &role);
	if (rc < 0) {
		printf("Invalid property value '%s' for property '%s' from interface '%s' on object '%s'\n",
			state, property, interface, path);
		rc = -EINVAL;
		goto out;
	}
	link->role = role.role;

out:
	set_berr(ctx, rc, berr);
	return rc;
}

__attribute__((unused))
static int bus_endpoint_set_prop(sd_bus *bus, const char *path,
                                 const char *interface,
                                 const char *property,
                                 sd_bus_message *value,
                                 void *userdata,
                                 sd_bus_error *ret_error)
{
	struct peer *peer = userdata;
	const char *connectivity;
	struct ctx *ctx = peer->ctx;
	int rc;

	if (!is_endpoint_path(path)) {
		rc = -ENOENT;
		goto out;
	}

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
			printf("Invalid property value '%s' for property '%s' from interface '%s' on object '%s'\n",
				connectivity, property, interface, path);
			rc = -EINVAL;
			goto out;
		}
		if (previously != peer->degraded)
		{
			rc = sd_bus_emit_properties_changed(bus, path, interface, "Connectivity", NULL);
		}
	} else {
		printf("Unknown property '%s' in interface '%s' on object '%s'\n", property,
			interface, path);
		rc = -ENOENT;
	}
out:
	set_berr(ctx, rc, ret_error);
	return rc;
}

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

static const sd_bus_vtable bus_endpoint_link_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_WRITABLE_PROPERTY("Role",
			"s",
			bus_link_get_prop,
			bus_link_set_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_network_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("LocalEIDs",
			"ay",
			bus_network_get_prop,
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

static int bus_mctp_network_find(sd_bus *bus, const char *path,
	const char *interface, void *userdata, void **ret_found,
	sd_bus_error *ret_error)
{
	struct ctx *ctx = userdata;
	uint32_t netid;

	printf("%s: find %s\n", __func__, path);

	if (!get_networkid_from_path(path, &netid)) {
		return 0;
	}

	struct net *n = lookup_net(ctx, netid);
	if (n) {
		*ret_found = ctx;
		return 1;
	}

	return 0;
}

static char* root_endpoints_path(int net)
{
	size_t l;
	char *buf = NULL;

	l = strlen(MCTP_DBUS_PATH) + 30;
	buf = malloc(l);
	if (!buf) {
		return NULL;
	}
	snprintf(buf, l, "%s/networks/%d/endpoints", MCTP_DBUS_PATH, net);
	return buf;
}

/* au.com.codeconstruct.MCTP.Interface1 interface */
static int __bus_mctp_link_find(sd_bus *bus, const char *path,
	const char *interface, void *userdata, bool owner_only,
	void **ret_found, sd_bus_error *ret_error)
{
	struct ctx *ctx = userdata;
	char *tmpstr = NULL;
	char *link_name = NULL;
	struct link *link = NULL;
	int rc = 0;

	if (!is_interfaces_path(path)) {
		return 0;
	}

	rc = sd_bus_path_decode_many(path, MCTP_DBUS_PATH "/%/%", &tmpstr,
		&link_name);
	if (rc == 0)
		return -ENOENT;
	if (rc < 0)
		return rc;

	link = mctp_nl_get_link_userdata_byname(ctx->nl, link_name);
	if (!link) {
		warnx("No linkmap entry for link %s\n", link_name);
		return -ENOENT;
	}

	if (owner_only && link->role != ENDPOINT_ROLE_BUS_OWNER)
		return 0;

	if (link->published) {
		*ret_found = ctx;
		return 1;
	}

	return 0;
}

static int bus_mctp_link_find(sd_bus *bus, const char *path,
	const char *interface, void *userdata,
	void **ret_found, sd_bus_error *ret_error)
{
	return __bus_mctp_link_find(bus, path, interface, userdata, false,
				    ret_found, ret_error);
}

static int bus_mctp_link_busowner_find(sd_bus *bus, const char *path,
	const char *interface, void *userdata, void **ret_found,
	sd_bus_error *ret_error)
{
	return __bus_mctp_link_find(bus, path, interface, userdata, true,
				    ret_found, ret_error);
}

static char* net_path(int net)
{
	size_t l;
	char *buf = NULL;

	l = strlen(MCTP_DBUS_PATH) + 30;
	buf = malloc(l);
	if (!buf) {
		return NULL;
	}
	/* can't use sd_bus_path_encode_many() since it escapes
	   leading digits */
	snprintf(buf, l, "%s/networks/%d", MCTP_DBUS_PATH, net);
	return buf;
}

static char* interface_path(const char* link_name)
{
	size_t l;
	char *buf = NULL;

	l = strlen(MCTP_DBUS_PATH) + 30;
	buf = malloc(l);
	if (!buf) {
		return NULL;
	}

	snprintf(buf, l, "%s/interfaces/%s", MCTP_DBUS_PATH, link_name);
	return buf;
}

static int emit_endpoint_added(const struct peer *peer) {
	const char *path = NULL;
	int rc;

	path = path_from_peer(peer);
	if (!path)
		return -1;
	if (peer->ctx->verbose)
		warnx("%s: %s", __func__, path);
	rc = sd_bus_emit_object_added(peer->ctx->bus, path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_endpoint_removed(const struct peer *peer) {
	const char *path = NULL;
	int rc;

	path = path_from_peer(peer);
	if (!path)
		return -1;
	if (peer->ctx->verbose)
		warnx("%s: %s", __func__, path);
	rc = sd_bus_emit_object_removed(peer->ctx->bus, path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_net_added(struct ctx *ctx, int net) {
	char *path = NULL;
	int rc;

	path = net_path(net);
	if (path == NULL) {
		warnx("%s: out of memory", __func__);
		return -ENOMEM;
	}
	rc = sd_bus_emit_object_added(ctx->bus, dfree(path));
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_interface_added(struct ctx *ctx, int ifindex) {
	const char* ifname = NULL;
	char *path = NULL;
	int rc;

	ifname = mctp_nl_if_byindex(ctx->nl, ifindex);
	if (!ifname) {
		warnx("BUG %s: no interface for ifindex %d", __func__, ifindex);
		return -EPROTO;
	}

	path = interface_path(ifname);
	if (path == NULL) {
		warnx("%s: out of memory", __func__);
		return -ENOMEM;
	}
	rc = sd_bus_emit_object_added(ctx->bus, dfree(path));
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));

	return rc;
}

static int emit_net_removed(struct ctx *ctx, int net) {
	char *path = NULL;
	int rc;

	path = net_path(net);
	if (path == NULL) {
		warnx("%s: out of memory", __func__);
		return -ENOMEM;
	}
	rc = sd_bus_emit_object_removed(ctx->bus, dfree(path));
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_interface_removed(struct ctx *ctx, int ifindex) {
	const char* ifname = NULL;
	char *path = NULL;
	int rc;

	ifname = mctp_nl_if_byindex(ctx->nl_query, ifindex);
	if (!ifname) {
		warnx("BUG %s: no interface for ifindex %d", __func__, ifindex);
		return -EPROTO;
	}

	path = interface_path(ifname);
	if (path == NULL) {
		warnx("%s: out of memory", __func__);
		return -ENOMEM;
	}
	rc = sd_bus_emit_object_removed(ctx->bus, dfree(path));
	if (rc < 0) {
		errno = -rc;
		warn("%s: error emitting", __func__);
	}

	return rc;
}

static int bus_mctpd_find(sd_bus *bus, const char *path,
	const char *interface, void *userdata, void **ret_found,
	sd_bus_error *ret_error)
{
	if (strcmp(path, MCTP_DBUS_PATH) == 0) {
		*ret_found = userdata;
		return 1;
	}
	return 0;
}

static int mctpd_dbus_enumerate(sd_bus *bus, const char* path,
	void *data, char ***out, sd_bus_error *err)
{
	struct ctx *ctx = data;
	struct link *link = NULL;
	size_t num_nodes, i, j;
	char **nodes = NULL;
	const char* ifname = NULL;
	int rc;
	size_t num_ifs;
	int *ifs;

	/* Set up local addresses */
	ifs = mctp_nl_if_list(ctx->nl, &num_ifs);

	// NULL terminator
	num_nodes = 1;
	// .../mctp1 object
	num_nodes++;
	// .../mctp1/networks object
	num_nodes++;

	// .../mctp1/networks/<NetID>
	for (i = 0; i < ctx->num_nets; i++) {
		num_nodes++;
		for (size_t t = 0; t < 256; t++) {
			if (ctx->nets[i].peeridx[t] != -1) {
				// .../mctp1/networks/<NetID>/endpoints object
				num_nodes++;
				break;
			}
		}
	}

	// .../mctp1/networks/<NetID>/endpoints/<EID> object
	for (i = 0; i < ctx->size_peers; i++)
		if (ctx->peers[i].published)
			num_nodes++;

	// .../mctp1/interfaces object
	num_nodes++;

	// .../mctp1/interface/<name>
	for (size_t i = 0; i < num_ifs; i++) {
		link = mctp_nl_get_link_userdata(ctx->nl, ifs[i]);
		if (link && link->published) {
			num_nodes++;
		}
	}

	nodes = malloc(sizeof(*nodes) * num_nodes);
	if (!nodes) {
		rc = -ENOMEM;
		goto out;
	}

	j = 0;
	// .../mctp1
	nodes[j] = strdup(MCTP_DBUS_PATH);
	if (!nodes[j]) {
		rc = -ENOMEM;
		goto out;
	}
	j++;

	// .../mctp1/networks
	nodes[j] = strdup(MCTP_DBUS_PATH_NETWORKS);
	if (!nodes[j]) {
		rc = -ENOMEM;
		goto out;
	}
	j++;

	for (i = 0; i < ctx->num_nets; i++) {
		// .../mctp1/networks/<NetId>
		nodes[j] = net_path(ctx->nets[i].net);
		if (nodes[j] == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		j++;

		for (size_t t = 0; t < 256; t++) {
			if (ctx->nets[i].peeridx[t] == -1) {
				continue;
			}
			// .../mctp1/networks/<NetID>/endpoints object
			nodes[j] = root_endpoints_path(ctx->nets[i].net);
			if (nodes[j] == NULL) {
				rc = -ENOMEM;
				goto out;
			}
			j++;
			break;
		}
	}

	// Peers
	for (i = 0; i < ctx->size_peers; i++) {
		struct peer *peer = &ctx->peers[i];
		const char *tmp;

		if (!peer->published)
			continue;

		tmp = path_from_peer(peer);
		if (!tmp) {
			rc = -1;
			goto out;
		}
		nodes[j] = strdup(tmp);
		j++;
	}

	// .../mctp1/interfaces object
	nodes[j] = strdup(MCTP_DBUS_PATH_LINKS);
	if (!nodes[j]) {
		rc = -ENOMEM;
		goto out;
	}
	j++;

	for (size_t i = 0; i < num_ifs; i++) {
		link = mctp_nl_get_link_userdata(ctx->nl, ifs[i]);
		if (!link || !link->published)
			continue;
		ifname = mctp_nl_if_byindex(ctx->nl, ifs[i]);
		if (!ifname) {
			continue;
		}
		nodes[j] = interface_path(ifname);
		if (nodes[j] == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		j++;
	}

	free(ifs);
	// NULL terminator
	nodes[j] = NULL;
	j++;
	rc = 0;
	*out = nodes;
out:
	if (rc < 0) {
		for (i = 0; nodes && i < j; i++) {
			free(nodes[i]);
		}
		free(nodes);
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

	rc = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_signal(ctx->event, NULL, SIGTERM, NULL, NULL);
	if (rc < 0) {
		goto out;
	}

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

	/* mctp object needs to use _fallback_vtable() since we can't
	   mix non-fallback and fallback vtables on MCTP_DBUS_PATH */

	rc = sd_bus_add_fallback_vtable(ctx->bus, NULL,
					MCTP_DBUS_PATH,
					CC_MCTP_DBUS_IFACE_INTERFACE,
					bus_endpoint_link_vtable,
					bus_mctp_link_find,
					ctx);
	if (rc < 0) {
		warnx("Failed adding link D-Bus interface: %s", strerror(-rc));
		goto out;
	}

	rc = sd_bus_add_fallback_vtable(ctx->bus, NULL,
					MCTP_DBUS_PATH,
					CC_MCTP_DBUS_IFACE_BUSOWNER,
					bus_owner_vtable,
					bus_mctp_link_busowner_find,
					ctx);
	if (rc < 0) {
		warnx("Failed creating D-Bus object");
		goto out;
	}

	rc = sd_bus_add_fallback_vtable(ctx->bus, NULL,
					MCTP_DBUS_PATH,
					CC_MCTP_DBUS_NETWORK_INTERFACE,
					bus_network_vtable,
					bus_mctp_network_find,
					ctx);
	if (rc < 0) {
		warnx("Failed adding Network D-Bus interface: %s", strerror(-rc));
		goto out;
	}

	rc = sd_bus_add_object_manager(ctx->bus, NULL, MCTP_DBUS_PATH);
	if (rc < 0) {
		warnx("Adding object manager failed: %s", strerror(-rc));
		goto out;
	}

	rc = sd_bus_add_node_enumerator(ctx->bus, NULL,
		MCTP_DBUS_PATH, mctpd_dbus_enumerate, ctx);
	if (rc < 0) {
		warnx("Failed to add node enumerator: %s", strerror(-rc));
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
static int del_local_eid(struct ctx *ctx, int net, int eid)
{
	struct peer *peer = NULL;
	int rc;

	peer = find_peer_by_addr(ctx, eid, net);
	if (!peer) {
		warnx("BUG: local eid %d net %d to delete is missing", eid, net);
		return -ENOENT;
	}

	if (peer->state != LOCAL) {
		warnx("BUG: local eid %d net %d to delete is incorrect", eid, net);
		return -EPROTO;
	}

	peer->local_count--;
	if (peer->local_count < 0) {
		warnx("BUG: local eid %d net %d bad refcount %d",
			eid, net, peer->local_count);
	}

	rc = 0;
	if (peer->local_count <= 0) {
		if (ctx->verbose) {
			fprintf(stderr, "Removing local eid %d net %d\n", eid, net);
		}

		rc = remove_peer(peer);
	}
	return rc;
}

// Remove nets that have no interfaces
static int prune_old_nets(struct ctx *ctx)
{
	int *net_list;
	size_t i, j, num_list;

	net_list = mctp_nl_net_list(ctx->nl, &num_list);

	// iterate and discard unused nets
	for (i = 0, j = 0; i < ctx->num_nets; i++) {
		bool found = false;
		for (size_t n = 0; n < num_list && !found; n++)
			if (net_list[n] == ctx->nets[i].net)
				found = true;

		if (found) {
			// isn't stale
			memmove(&ctx->nets[j], &ctx->nets[i], sizeof(*ctx->nets));
			j++;
		} else {
			// stale, don't keep
			for (size_t p = 0; p < 256; p++) {
				// Sanity check that no peers are used
				if (ctx->nets[i].peeridx[p] != -1) {
					warnx("BUG: stale entry for eid %zd in deleted net %d",
						p, ctx->nets[i].net);
				}
			}
			emit_net_removed(ctx, ctx->nets[i].net);
		}
	}
	ctx->num_nets = j;
	return 0;
}

// Removes remote peers associated with an old interface.
// Note that this old_ifindex has already been removed from ctx->nl */
static int del_interface(struct ctx *ctx, int old_ifindex)
{
	if (ctx->verbose) {
		fprintf(stderr, "Deleting interface #%d\n", old_ifindex);
	}
	for (size_t i = 0; i < ctx->size_peers; i++) {
		struct peer *p = &ctx->peers[i];
		if (p->state == REMOTE && p->phys.ifindex == old_ifindex) {
			remove_peer(p);
		}
	}

	if (emit_interface_removed(ctx, old_ifindex) < 0)
		warnx("Failed to remove D-Bus interface of ifindex %d", old_ifindex);
	prune_old_nets(ctx);

	return 0;
}

// Moves remote peers from old->new net.
static int change_net_interface(struct ctx *ctx, int ifindex, int old_net)
{
	int rc;
	struct net *old_n, *new_n;
	int new_net = mctp_nl_net_byindex(ctx->nl, ifindex);

	if (ctx->verbose) {
		fprintf(stderr, "Moving interface #%d %s from net %d -> %d\n",
			ifindex, mctp_nl_if_byindex(ctx->nl, ifindex),
			old_net, new_net);
	}

	if (new_net == 0) {
		warnx("No net for ifindex %d", ifindex);
		return -EPROTO;
	}

	if (new_net == old_net) {
		// Logic below may assume they differ
		warnx("BUG: %s called with new=old=%d", __func__, old_net);
		return -EPROTO;
	}

	old_n = lookup_net(ctx, old_net);
	if (!old_n) {
		warnx("BUG: %s: Bad old net %d", __func__, old_net);
		return -EPROTO;
	}
	new_n = lookup_net(ctx, new_net);
	if (!new_n) {
		rc = add_net(ctx, new_net);
		if (rc < 0)
			return rc;
		new_n = lookup_net(ctx, new_net);
	}

	for (size_t i = 0; i < ctx->size_peers; i++) {
		struct peer *peer = &ctx->peers[i];
		if (!(peer->state == REMOTE && peer->phys.ifindex == ifindex)) {
			// skip peers on other interfaces
			continue;
		}

		if (peer->net != old_net) {
			warnx("BUG: %s: Mismatch old net %d vs %d, new net %d",
				__func__, peer->net, old_net, new_net);
			continue;

		}
		if (check_peer_struct(peer, old_n) != 0) {
			warnx("BUG: %s: Inconsistent state", __func__);
			return -EPROTO;
		}

		if (new_n->peeridx[peer->eid] != -1) {
			// Conflict, drop it
			warnx("EID %d already exists moving net %d->%d, dropping it",
				peer->eid, old_net, new_net);
			remove_peer(peer);
			continue;
		}

		// Move networks, change route/neigh entries, emit new dbus signals
		unpublish_peer(peer);
		new_n->peeridx[peer->eid] = old_n->peeridx[peer->eid];
		old_n->peeridx[peer->eid] = -1;
		peer->net = new_net;
		publish_peer(peer, true);
	}

	prune_old_nets(ctx);
	return 0;
}

// Adds one local EID
static int add_local_eid(struct ctx *ctx, int net, int eid)
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
			warnx("Local eid %d net %d already exists?",
				eid, net);
			return -EPROTO;
		}
	}

	rc = add_peer(ctx, &local_phys, eid, net, &peer);
	if (rc < 0) {
		warn("BUG: Error adding local eid %d net %d", eid, net);
		return rc;
	}
	peer->state = LOCAL;
	peer->local_count = 1;
	rc = peer_set_uuid(peer, ctx->uuid);
	if (rc < 0) {
		warnx("Failed setting local UUID: %s",
			strerror(-rc));
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
	if (rc < 0) {
		warnx("BUG: Error publishing local eid %d net %d", eid, net);
	}
	return 0;

}

// Adds peers for local EIDs on an interface
static int add_interface_local(struct ctx *ctx, int ifindex)
{
	mctp_eid_t *eids = NULL;
	struct link *link = NULL;
	size_t num;
	int net;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Adding interface #%d %s\n",
			ifindex, mctp_nl_if_byindex(ctx->nl, ifindex));
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

static int add_net(struct ctx *ctx, int net)
{
	struct net *n, *tmp;
	if (lookup_net(ctx, net) != NULL) {
		warnx("BUG: add_net for existing net %d", net);
		return -EEXIST;
	}
	tmp = realloc(ctx->nets, sizeof(struct net) * (ctx->num_nets+1));
	if (!tmp) {
		warnx("Out of memory");
		return -ENOMEM;
	}
	ctx->nets = tmp;
	ctx->num_nets++;

	// Initialise the new entry
	n = &ctx->nets[ctx->num_nets-1];
	memset(n, 0x0, sizeof(*n));
	n->net = net;
	for (size_t j = 0; j < 256; j++) {
		n->peeridx[j] = -1;
	}
	emit_net_added(ctx, net);
	return 0;
}

static int add_interface(struct ctx *ctx, int ifindex)
{
	struct link *link = malloc(sizeof(*link));
	int rc;

	int net = mctp_nl_net_byindex(ctx->nl, ifindex);
	if (net <= 0) {
		warnx("Can't find link index %d\n", ifindex);
		return -ENOMEM;
	}

	/* Use the `mode` setting in conf/mctp.conf */
	link->role = ctx->default_role;
	link->published = true;

	rc = mctp_nl_set_link_userdata(ctx->nl, ifindex, link);
	if (rc < 0) {
		warnx("Failed to set UserData for link index %d", ifindex);
		return -ENOMEM;
	}

	rc = emit_interface_added(ctx, ifindex);
	if (rc < 0) {
		link->published = false;
		rc = mctp_nl_set_link_userdata(ctx->nl, ifindex, link);
		if (rc < 0) {
			warnx("Failed to set UserData for link index %d\n", ifindex);
			return -ENOMEM;
		}
		return -ENOMEM;
	}

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

static int setup_testing(struct ctx *ctx) {
	dest_phys dest = {};
	struct peer *peer;
	size_t i, j;
	int rc;

	if (!ctx->testing)
		return 0;

	warnx("Running in development testing mode. Not safe for production");

	if (ctx->num_nets > 0) {
		warnx("Not populating fake MCTP nets, real ones exist");
	} else {
		warnx("Populating fake MCTP nets");

		ctx->num_nets = 2;
		ctx->nets = calloc(ctx->num_nets, sizeof(struct net));
		if (!ctx->nets) {
			warnx("calloc failed");
			ctx->num_nets = 0;
			return -ENOMEM;
		}
		ctx->nets[0].net = 10;
		ctx->nets[1].net = 12;
		for (j = 0; j < ctx->num_nets; j++)
			for (i = 0; i < 256; i++)
				ctx->nets[j].peeridx[i] = -1;

		rc = add_peer(ctx, &dest, 7, 10, &peer);
		if (rc < 0) {
			warnx("%s failed add_peer, %s", __func__, strerror(-rc));
			return rc;
		}
		peer->state = REMOTE;
		peer->uuid = malloc(16);
		sd_id128_randomize((void*)peer->uuid);
		publish_peer(peer, false);

		rc = add_peer(ctx, &dest, 7, 12, &peer);
		if (rc < 0) {
			warnx("%s failed add_peer, %s", __func__, strerror(-rc));
			return rc;
		}
		peer->state = REMOTE;
		peer->num_message_types = 3;
		peer->message_types = malloc(3);
		peer->message_types[0] = 0x00;
		peer->message_types[1] = 0x03;
		peer->message_types[2] = 0x04;
		publish_peer(peer, false);

		rc = add_peer(ctx, &dest, 9, 12, &peer);
		if (rc < 0) {
			warnx("%s failed add_peer, %s", __func__, strerror(-rc));
			return rc;
		}
		peer->state = REMOTE;
		peer->uuid = malloc(16);
		// a UUID that remains constant across runs
		memcpy(peer->uuid, ctx->uuid, 16);
		publish_peer(peer, false);
	}

	/* Add extra interface with test methods */
	rc = sd_bus_add_fallback_vtable(ctx->bus, NULL,
					MCTP_DBUS_PATH,
					CC_MCTP_DBUS_IFACE_TESTING,
					testing_vtable,
					bus_mctpd_find,
					ctx);
	if (rc < 0) {
		warnx("Failed testing dbus object");
		return rc;
	}


	return 0;
}

static void print_usage(struct ctx *ctx)
{
	fprintf(stderr, "mctpd [-v] [-N] [-c FILE]\n");
	fprintf(stderr, "      -v verbose\n");
	fprintf(stderr, "      -N testing mode. Not safe for production\n");
	fprintf(stderr, "      -c FILE read config from FILE\n");
}

static int parse_args(struct ctx *ctx, int argc, char **argv)
{
	struct option options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = "verbose", .has_arg = no_argument, .val = 'v' },
		{ .name = "testing", .has_arg = no_argument, .val = 'N' },
		{ .name = "config", .has_arg = required_argument, .val = 'c' },
		{ 0 },
	};
	int c;

	for (;;) {
		c = getopt_long(argc, argv, "+hvNc:", options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'N':
			ctx->testing = true;
			break;
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
	sd_id128_t *u = (void*)ctx->uuid;

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

static int parse_config(struct ctx *ctx)
{
	toml_table_t *conf_root, *mctp_tab;
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
}

int main(int argc, char **argv)
{
	struct ctx ctxi = {0}, *ctx = &ctxi;
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

	ctx->nl_query = mctp_nl_new(false);
	if (!ctx->nl_query) {
		warnx("Failed creating 2nd netlink object");
		return 1;
	}
	mctp_nl_warn_eexist(ctx->nl_query, false);

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
	if (rc < 0 && !ctx->testing)
		return 1;

	// TODO add net argument?
	rc = listen_control_msg(ctx, MCTP_NET_ANY);
	if (rc < 0) {
		warnx("Error in listen, returned %s %d", strerror(-rc), rc);
		if (!ctx->testing)
			return 1;
	}

	rc = setup_testing(ctx);
	if (rc < 0)
		return 1;

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

	return 0;
}

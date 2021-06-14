/* SPDX-License-Identifier: GPL-2.0 */
/*

 * mctpd: bus owner for MCTP using Linux kernel
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#define _GNU_SOURCE

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

static mctp_eid_t eid_alloc_min = 0x08;
static mctp_eid_t eid_alloc_max = 0xfe;

// arbitrary sanity
static size_t MAX_PEER_SIZE = 1000000;

static const uint8_t RQDI_REQ = 1<<7;
static const uint8_t RQDI_RESP = 0x0;
static const uint8_t RQDI_MASK = 0xc0;

struct dest_phys {
	int ifindex;
	const uint8_t *hwaddr;
	size_t hwaddr_len;
};
typedef struct dest_phys dest_phys;

/* Table of per-network details */
struct net_det {
	int net;
	// EID mappings, an index into ctx->peers. Value -1 is unused.
	ssize_t peeridx[0xff];
};
typedef struct net_det net_det;

struct peer {
	int net;
	mctp_eid_t eid;

	dest_phys phys;

	enum {
		UNUSED = 0,
		NEW,
		ASSIGNED,
		// Own address placeholder. Only (net, eid) are used.
		// Note that multiple interfaces in a network may have
		// the same local address.
		LOCAL,
		// CONFLICT,
	} state;

	// bitmap of supported message types, from Get Message Type
	uint8_t message_types[32];

	// from Get Endpoint ID
	uint8_t endpoint_type;
	uint8_t medium_spec;
};
typedef struct peer peer;

struct ctx {
	sd_event *event;
	sd_bus *bus;
	mctp_nl *nl;

	// Whether we are running as the bus owner
	bool bus_owner;

	// An allocated array of peers, changes address (reallocated) during runtime
	struct peer *peers;
	size_t size_peers;

	struct net_det *nets;
	size_t num_nets;

	// Timeout in usecs for a MCTP response
	uint64_t mctp_timeout;

	// Verbose logging
	bool verbose;
	bool testing;
};
typedef struct ctx ctx;

mctp_eid_t local_addr(const ctx *ctx, int ifindex) {
	mctp_eid_t *eids, ret = 0;
	size_t num;

	eids = mctp_nl_addrs_byindex(ctx->nl, ifindex, &num);
	if (num)
		ret = eids[0];
	free(eids);
	return ret;
}

static void* dfree(void* ptr);

static net_det *lookup_net(ctx *ctx, int net)
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
		!memcmp(d1->hwaddr, d2->hwaddr, d1->hwaddr_len);

}

static peer * find_peer_by_phys(ctx *ctx, const dest_phys *dest)
{
	for (size_t i = 0; i < ctx->size_peers; i++) {
		peer *peer = &ctx->peers[i];
		if (peer->state != ASSIGNED)
			continue;
		if (match_phys(&peer->phys, dest))
			return peer;
	}
	return NULL;
}

static peer * find_peer_by_addr(ctx *ctx, mctp_eid_t eid, int net)
{
	net_det *n = lookup_net(ctx, net);

	if (eid != 0 && n && n->peeridx[eid] >= 0)
		return &ctx->peers[n->peeridx[eid]];
	return NULL;
}

/* Returns a deferred free pointer */
static const char* dest_phys_tostr(const dest_phys *dest)
{
	char hex[MAX_ADDR_LEN*4];
	char* buf;
	size_t l = 50 + sizeof(hex);
	buf = malloc(l);
	write_hex_addr(dest->hwaddr, dest->hwaddr_len, hex, sizeof(hex));
	snprintf(buf, l, "physaddr if %d hw len %zu 0x%s", dest->ifindex, dest->hwaddr_len, hex);
	return dfree(buf);
}

static const char* ext_addr_tostr(const struct _sockaddr_mctp_ext *addr)
{
	char hex[MAX_ADDR_LEN*4];
	char* buf;
	size_t l = 100;
	buf = malloc(l);

	write_hex_addr(addr->smctp_haddr, addr->smctp_halen, hex, sizeof(hex));
	snprintf(buf, l, "sockaddr_mctp_ext eid %d net %d if %d hw len %hhu 0x%s",
		addr->smctp_base.smctp_addr.s_addr, 
		addr->smctp_base.smctp_network, addr->smctp_ifindex,
		addr->smctp_halen, hex);
	return dfree(buf);
}

static int defer_free_handler(sd_event_source *s, void *userdata)
{
	free(userdata);
	return 0;
}

/* Returns ptr, frees it on the next default event loop cycle (defer)*/
static void* dfree(void* ptr)
{
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
int wait_fd_timeout(int fd, short events, uint64_t timeout_usec)
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

/* Returns the message from a socket.
   The first byte is filled with the message type byte.
   ret_buf is allocated, should be freed by the caller */
int read_message(ctx *ctx, int sd, uint8_t **ret_buf, size_t *ret_buf_size,
		struct _sockaddr_mctp_ext *ret_addr)
{
	int rc;
	socklen_t addrlen;
	ssize_t len;
	uint8_t* buf = NULL;
	size_t buf_size;
	// struct iovec v;
	// struct msghdr msg = {0};

	len = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
	if (len < 0) {
		rc = -errno;
		goto out;
	}

	// +1 for space for addition type prefix byte
	buf_size = len+1;
	buf = malloc(buf_size);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	addrlen = sizeof(struct _sockaddr_mctp_ext);
	memset(ret_addr, 0x0, addrlen);
	// skip the initial prefix byte
	// msg.msg_name = ret_addr;
	// msg.msg_namelen = sizeof(struct _sockaddr_mctp_ext);
	// msg.msg_iov = &v;
	// msg.msg_iovlen = 1;
	// v.iov_base = buf+1;
	// v.iov_len = buf_size-1
	// len = recvmsg(sd, &msg, MSG_TRUNC);
	len = recvfrom(sd, buf+1, buf_size-1, MSG_TRUNC, (struct sockaddr *)ret_addr,
		&addrlen);
	if (len < 0) {
		rc = -errno;
		goto out;
	}
	if ((size_t)len != buf_size-1) {
		warnx("BUG: incorrect recvfrom %zd, expected %zu", len, buf_size-1);
		rc = -EPROTO;
		goto out;
	}
	if (addrlen != sizeof(struct _sockaddr_mctp_ext)) {
		warnx("Unexpected address size %u.", addrlen);
		rc = -EPROTO;
		goto out;
	}

	if (ctx->verbose) {
		warnx("read_message got from %s type 0x%02x, len %zu",
			ext_addr_tostr(ret_addr),
			ret_addr->smctp_base.smctp_type,
			buf_size);
	}

	// populate it for good measure
	buf[0] = ret_addr->smctp_base.smctp_type;
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

/* First byte of resp is the type. It is ignored, addr smctp_type is used */
/* Replies to a real EID, not physical addressing */
static int reply_message(ctx *ctx, int sd, const void *resp, size_t resp_len, 
	const struct _sockaddr_mctp_ext *addr)
{
	uint8_t *send_ptr;
	size_t send_len;
	ssize_t len;
	struct _sockaddr_mctp reply_addr;

	memcpy(&reply_addr, &addr->smctp_base, sizeof(reply_addr));
	reply_addr.smctp_tag &= ~MCTP_TAG_OWNER;

	if (reply_addr.smctp_addr.s_addr == 0 ||
		 reply_addr.smctp_addr.s_addr == 0xff) {
		warnx("BUG: reply_message can't take EID %d",
			reply_addr.smctp_addr.s_addr);
		return -EPROTO;
	}

	if (resp_len < 1) {
		warnx("BUG: reply_message requires type in first byte");
		return -EPROTO;
	}

	send_len = resp_len - 1;
	send_ptr = (uint8_t*)resp + 1;
	len = sendto(sd, send_ptr, send_len, 0,
		(struct sockaddr*)&reply_addr, sizeof(reply_addr));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != send_len) {
		warnx("BUG: short sendto %zd, expected %zu", len, send_len);
		return -EPROTO;
	}
	return 0;
}

// Handles new Incoming Set Endpoint ID request
int handle_control_set_endpoint_id(ctx *ctx,
	int sd, struct _sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_set_eid *req = NULL;
	struct mctp_ctrl_resp_set_eid respi, *resp = &respi;
	size_t resp_len;

	if (buf_size < sizeof(*req)) {
		warnx("short Set Endpoint ID message");
		return -ENOMSG;
	}
	req = (void*)buf;

	resp->ctrl_hdr.command_code = req->ctrl_msg_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;
	resp->completion_code = 0;
	resp->status = 0x01 << 4; // Already assigned, TODO
	resp->eid_set = local_addr(ctx, addr->smctp_ifindex);
	resp->eid_pool_size = 0;
	resp_len = sizeof(struct mctp_ctrl_resp_set_eid);

	// TODO: learn busowner route and neigh

	return reply_message(ctx, sd, resp, resp_len, addr);
}

int handle_control_get_version_support(ctx *ctx,
	int sd, const struct _sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_mctp_ver_support *req = NULL;
	struct mctp_ctrl_resp_get_mctp_ver_support *resp = NULL;
	uint32_t version;
	// space for a single version
	uint8_t buffer[sizeof(*resp) + sizeof(version)];
	size_t resp_len;

	if (buf_size < sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support)) {
		warnx("short Get Version Support message");
		return -ENOMSG;
	}

	req = (void*)buf;
	// TODO: check these version numbers
	switch (req->msg_type_number) {
		case 0xff: // Base Protocol
		case 0x00: // Control protocol
			version = 0xf1f3f100; // 1.3.1
			break;
		default:
			version = 0;
	}

	resp = (void*)buffer;
	resp->ctrl_hdr.command_code = req->ctrl_msg_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;

	if (version == 0) {
		// Unsupported message type
		resp->completion_code = 0x80;
		resp->number_of_entries = 0;
		resp_len = sizeof(*resp);
	} else {
		resp->completion_code = 0x00;
		resp->number_of_entries = 1;
		resp_len = sizeof(*resp) + sizeof(version);
		*((uint32_t*)(resp+1)) = htonl(version);
	}
	return reply_message(ctx, sd, resp, resp_len, addr);
}

int handle_control_get_endpoint_id(ctx *ctx,
	int sd, const struct _sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_eid *req = NULL;
	struct mctp_ctrl_resp_get_eid respi = {0}, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint ID message");
		return -ENOMSG;
	}

	req = (void*)buf;
	resp->ctrl_hdr.command_code = req->ctrl_msg_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;

	resp->eid = local_addr(ctx, addr->smctp_ifindex);
	if (ctx->bus_owner)
		SET_ENDPOINT_TYPE(resp->eid_type, MCTP_BUS_OWNER_BRIDGE);
	// TODO: dynamic EID?
	SET_ENDPOINT_ID_TYPE(resp->eid_type, MCTP_STATIC_EID);
	// TODO: medium specific information

	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

static int cb_listen_control_msg(sd_event_source *s, int sd, uint32_t revents, 
	void *userdata)
{
	struct _sockaddr_mctp_ext addr = {0};
	ctx *ctx = userdata;
	uint8_t *buf = NULL;
	size_t buf_size;
	struct mctp_ctrl_msg_hdr *ctrl_msg = NULL;
	int rc;

	rc = read_message(ctx, sd, &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

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
		// case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
		// 	rc = handle_control_get_endpoint_uuid(ctx,
		// 		sd, &addr, buf, buf_size);
		// 	break;
		default:
			if (ctx->verbose) {
				warnx("Ignoring unsupported command code 0x%02x",
					ctrl_msg->command_code);
				rc = -ENOTSUP;
			}
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

static int listen_control_msg(ctx *ctx, int net)
{
	struct _sockaddr_mctp addr;
	int rc, sd = -1, val;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
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

	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		rc = -errno;
		warn("%s: bind() failed", __func__);
		goto out;
	}

	val = 1;
	rc = setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val, sizeof(val));
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

/* Queries an endpoint using physical addressing, null EID.
 * req and resp buffers include the initial message type byte.
 * This is ignored, the addr.smctp_type is used instead.
 */
static int endpoint_query_phys(ctx *ctx, const dest_phys *dest,
	uint8_t req_type, const void* req, size_t req_len,
	uint8_t **resp, size_t *resp_len, struct _sockaddr_mctp_ext *resp_addr)
{
	struct _sockaddr_mctp_ext addr = {0};
	int sd = -1, val;
	ssize_t rc;
	uint8_t *send_ptr = NULL;
	size_t send_len, buf_size;

	uint8_t* buf = NULL;

	*resp = NULL;
	*resp_len = 0;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0) {
		warn("socket");
		rc = -errno;
		goto out;
	}

	val = 1;
	rc = setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val, sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = 0;
	addr.smctp_base.smctp_addr.s_addr = 0;

	addr.smctp_ifindex = dest->ifindex;
	addr.smctp_halen = dest->hwaddr_len;
	memcpy(addr.smctp_haddr, dest->hwaddr, dest->hwaddr_len);

	addr.smctp_base.smctp_type = req_type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

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
		if (ctx->verbose) {
			warnx("%s: sendto() to %s returned %s", __func__,
				dest_phys_tostr(dest), strerror(errno));
		}
		goto out;
	}
	if ((size_t)rc != send_len) {
		warnx("BUG: incorrect sendto %zd, expected %zu", rc, send_len);
		rc = -EPROTO;
		goto out;
	}

	rc = wait_fd_timeout(sd, EPOLLIN, ctx->mctp_timeout);
	if (rc < 0) {
		if (rc == -ETIMEDOUT && ctx->verbose) {
			warnx("%s: receive timed out from %s", __func__,
				dest_phys_tostr(dest));
		}
		goto out;
	}

	rc = read_message(ctx, sd, &buf, &buf_size, resp_addr);
	if (rc < 0) {
		goto out;
	}

	if (resp_addr->smctp_base.smctp_type != req_type) {
		warnx("Mismatching response type %d for request type %d. dest %s",
			resp_addr->smctp_base.smctp_type, req_type, dest_phys_tostr(dest));
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

static uint32_t version_val(const struct version_entry *vers)
{
	return ntohl(*((uint32_t*)vers));
}

/* Returns the min version supported */
static int endpoint_send_get_mctp_version(ctx *ctx, const dest_phys *dest,
	uint8_t query_type,
	bool *ret_supported, struct version_entry *ret_version)
{
	struct _sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_mctp_ver_support req = {0};
	struct mctp_ctrl_resp_get_mctp_ver_support *resp = NULL;
	int rc;
	uint8_t* buf = NULL;
	size_t buf_size, expect_size;
	uint8_t i;
	struct version_entry *v;

	memset(ret_version, 0x0, sizeof(*ret_version));
	*ret_supported = false;

	req.ctrl_msg_hdr.rq_dgram_inst = RQDI_REQ;
	req.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;
	req.msg_type_number = query_type;
	// TODO: shouldn't use query_phys, can use normal addressing.
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
		sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	if (buf_size < sizeof(*resp)) {
		warnx("%s: short reply %zu bytes. dest %s", __func__, buf_size,
			dest_phys_tostr(dest));
		rc = -ENOMSG;
		goto out;
	}
	resp = (void*)buf;

	expect_size = sizeof(resp) + resp->number_of_entries 
					* sizeof(struct version_entry);
	if (buf_size != expect_size) {
		warnx("%s: bad reply length. got %zu, expected %zu, %d entries. dest %s",
			__func__, buf_size, expect_size, resp->number_of_entries,
			dest_phys_tostr(dest));
		rc = -ENOMSG;
		goto out;
	}

	if (resp->completion_code != 0x80)
		*ret_supported = true;

	/* Entries are in ascending version order */
	v = (void*)(resp+1);
	for (i = 0; i < resp->number_of_entries; i++) {
		if (ctx->verbose)
			fprintf(stderr, "%s: %s supports 0x%08x\n", __func__,
				dest_phys_tostr(dest), version_val(&v[i]));
		if (i == 0)
			memcpy(ret_version, &v[i], sizeof(struct version_entry));
	}
	rc = 0;
out:
	free(buf);
	return rc;
}

/* returns -ECONNREFUSED if the endpoint returns failure. */
static int endpoint_send_set_endpoint_id(ctx *ctx, const peer *peer,
	mctp_eid_t *new_eid)
{
	struct _sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_set_eid req = {0};
	struct mctp_ctrl_resp_set_eid *resp = NULL;
	int rc;
	uint8_t* buf = NULL;
	size_t buf_size;
	uint8_t stat, alloc;
	const dest_phys *dest = &peer->phys;

	rc = -1;

	req.ctrl_msg_hdr.rq_dgram_inst = RQDI_REQ;
	req.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	req.operation = 0; // 00b Set EID. TODO: do we want Force?
	req.eid = peer->eid;
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
		sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	if (buf_size != sizeof(*resp)) {
		warnx("%s: wrong reply length %zu bytes. dest %s", __func__, 
			buf_size, dest_phys_tostr(dest));
		rc = -ENOMSG;
		goto out;
	}
	resp = (void*)buf;

	if (resp->completion_code != 0) {
		// TODO: make this a debug message?
		warnx("Failure completion code 0x%02x from %s",
			resp->completion_code, dest_phys_tostr(dest));
		rc = -ECONNREFUSED;
		goto out;
	}

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
static int add_peer(ctx *ctx, const dest_phys *dest, mctp_eid_t eid,
	int net, peer **ret_peer)
{
	ssize_t idx;
	size_t new_size;
	net_det *n;
	void *tmp = NULL;
	peer *peer;

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
			warnx("BUG: %s eid %hhu net %d peer already exists", __func__, eid, net);
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
	peer->eid = eid;
	peer->net = net;
	memcpy(&peer->phys, dest, sizeof(*dest));
	peer->state = NEW;

	// Update network eid map
	n->peeridx[eid] = idx;

	*ret_peer = peer;
	return 0;
}

static int check_peer_struct(const ctx *ctx, const peer *peer, const struct net_det *n)
{
	ssize_t idx;
	if (n->net != peer->net) {
		warnx("BUG: Mismatching net %d vs peer net %d", n->net, peer->net);
		return -1;
	}

	if ((peer - ctx->peers) % sizeof(struct peer) != 0) {
		warnx("BUG: Bad address alignment");
		return -1;
	}

	idx = (peer - ctx->peers) / sizeof(struct peer);
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

static int remove_peer(ctx *ctx, peer *peer)
{
	net_det *n = NULL;

	if (peer->state == UNUSED) {
		warnx("BUG: %s: unused peer", __func__);
		return -1;
	}

	n = lookup_net(ctx, peer->net);
	if (!n) {
		warnx("BUG: %s: Bad net %d", __func__, peer->net);
		return -1;
	}

	if (check_peer_struct(ctx, peer, n) != 0) {
		warnx("BUG: %s: Inconsistent state", __func__);
		return -1;
	}

	// Clear it
	n->peeridx[peer->eid] = -1;
	memset(peer, 0x0, sizeof(struct peer));
	return 0;
}

/* Returns -EEXIST if the new_eid is already used */
static int change_peer_eid(ctx *ctx, peer *peer, mctp_eid_t new_eid) {
	net_det *n = NULL;

	if (peer->state == UNUSED) {
		warnx("BUG: %s: unused peer", __func__);
		return -EPROTO;
	}

	n = lookup_net(ctx, peer->net);
	if (!n) {
		warnx("BUG: %s: Bad net %d", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(ctx, peer, n) != 0) {
		warnx("BUG: %s: Inconsistent state", __func__);
		return -EPROTO;
	}

	if (n->peeridx[new_eid] != -1) {
		return -EEXIST;
	}

	n->peeridx[new_eid] = n->peeridx[peer->eid];
	n->peeridx[peer->eid] = -1;
	peer->eid = new_eid;
	return 0;
}

static int endpoint_assign_eid(ctx *ctx, sd_bus_error *berr, const dest_phys *dest,
	peer **ret_peer)
{
	mctp_eid_t e, new_eid;
	net_det *n = NULL;
	peer *peer = NULL;
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

	/* Find an unused EID */
	for (e = eid_alloc_min; e <= eid_alloc_max; e++) {
		if (n->peeridx[e] == -1) {
			rc = add_peer(ctx, dest, e, net, &peer);
			if (rc < 0)
				return rc;
		}
	}
	if (e > eid_alloc_max) {
		warnx("Ran out of EIDs for net %d, allocating %s", net, dest_phys_tostr(dest));
		sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
			"Ran out of EIDs");
		return -EADDRNOTAVAIL;
	}

	rc = endpoint_send_set_endpoint_id(ctx, peer, &new_eid);
	if (rc == -ECONNREFUSED)
		sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
			"Endpoint returned failure to Set Endpoint ID");
	if (rc < 0) {
		remove_peer(ctx, peer);
		return rc;
	}

	if (new_eid != peer->eid) {
		rc = change_peer_eid(ctx, peer, new_eid);
		if (rc == -EEXIST) {
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
				"Endpoint requested EID %d instead of assigned %d, already used",
				new_eid, peer->eid);
		}
		if (rc < 0) {
			remove_peer(ctx, peer);
			return rc;
		}
	}
	peer->state = ASSIGNED;

	return 0;
}

/* Populates a sd_bus_error based on mctpd's convention for error codes.
 * Does nothing if berr is already set.
 */
static void set_berr(ctx *ctx, int errcode, sd_bus_error *berr) {
	bool existing = false;

	if (sd_bus_error_is_set(berr)) {
		existing = true;
	} else switch (errcode) {
		case 0:
			break;
		case -ETIMEDOUT:
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
				"Endpoint did not respond");
			break;
		case -ECONNREFUSED:
			// MCTP_CTRL_CC_ERROR or others
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
				"Endpoint replied with failure");
			break;
		case -EBUSY:
			// MCTP_CTRL_CC_ERROR_NOT_READY
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
				"Endpoint busy");
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

static int query_get_endpoint_id(ctx *ctx, const dest_phys *dest,
	mctp_eid_t *ret_eid, uint8_t *ret_ep_type, uint8_t *ret_media_spec)
{
	struct _sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_eid req = {0};
	struct mctp_ctrl_resp_get_eid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	int rc;

	req.ctrl_msg_hdr.rq_dgram_inst = RQDI_REQ;
	req.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
		sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	if (buf_size != sizeof(*resp)) {
		warnx("%s: wrong reply length %zu bytes. dest %s", __func__, buf_size,
			dest_phys_tostr(dest));
		rc = -ENOMSG;
		goto out;
	}
	resp = (void*)buf;

	if (resp->completion_code != 0) {
		warnx("Failure completion code 0x%02x from %s",
			resp->completion_code, dest_phys_tostr(dest));
		rc = -ECONNREFUSED;
		goto out;
	}

	*ret_eid = resp->eid;
out:
	free(buf);
	return rc;
}

/* Returns the peer associated with the endpoint.
 * Returns NULL if the endpoint successfully replies "not yet assigned".
 */
static int get_endpoint_peer(ctx *ctx, sd_bus_error *berr,
	const dest_phys *dest, peer **ret_peer)
{
	mctp_eid_t eid;
	uint8_t ep_type, medium_spec;
	peer *peer = NULL;
	int net;
	int rc;

	*ret_peer = NULL;
	rc = query_get_endpoint_id(ctx, dest, &eid, &ep_type, &medium_spec);
	if (rc < 0)
		return rc;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (net < 1) {
		return -EPROTO;
	}

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		/* Existing entry */
		if (peer->state != ASSIGNED) {
			warnx("BUG: Bad state %d for peer, eid %d",
				peer->state, peer->eid);
			return -EPROTO;
		}

		if (eid == 0) {
			// EID not yet assigned
			remove_peer(ctx, peer);
			return 0;
		} else if (peer->eid != eid) {
			rc = change_peer_eid(ctx, peer, eid);
			if (rc == -EEXIST)
				return sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					"Endpoint previously EID %d claimed EID %d which is already used",
					peer->eid, eid);
			else if (rc < 0)
				return rc;
		}
	} else {
		if (eid == 0) {
			// Not yet assigned.
			return 0;
		}
		/* New endpoint */
		rc = add_peer(ctx, dest, eid, net, &peer);
		if (rc == -EEXIST)
			return sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					"Endpoint claimed EID %d which is already used",
					eid);
		else if (rc < 0)
			return rc;
	}

	peer->endpoint_type = ep_type;
	peer->medium_spec = medium_spec;

	*ret_peer = peer;
	return 0;
}

static int assign_peer(ctx *ctx, sd_bus_error *berr, 
	const dest_phys *dest, peer **ret_peer)
{
	int rc;
	// bool supported;
	// struct version_entry min_version;

	*ret_peer = NULL;

	rc = endpoint_assign_eid(ctx, berr, dest, ret_peer);
	if (rc)
		return rc;

	// rc = endpoint_send_get_mctp_version(ctx, dest, 0xff, &supported, &min_version);
	// if (rc == -ETIMEDOUT) {
	// 	sd_bus_error_setf(berr, SD_BUS_ERROR_TIMEOUT,
	// 		"No response from %s", dest_phys_tostr(dest));
	// 	return rc;
	// } else if (rc < 0) {
	// 	sd_bus_error_setf(berr, SD_BUS_ERROR_NO_SERVER,
	// 		"Bad response from %s", dest_phys_tostr(dest));
	// 	return rc;
	// }

	// if (!supported) {
	// 	// Just warn and keep going
	// 	warn("Incongruous response, no MCTP support from %s", dest_phys_tostr(dest));
	// }

	// // TODO: disregard mismatch for now
	// if ((min_version.major & 0xf) != 0x01)
	// 		warn("Unexpected version 0x%08x from %s", version_val(&min_version),
	// 			dest_phys_tostr(dest));
	return 0;
}

int validate_dest_phys(ctx *ctx, const dest_phys *dest)
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

static int method_assign_endpoint(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	const char *ifname = NULL;
	dest_phys desti, *dest = &desti;
	ctx *ctx = data;
	peer *peer = NULL;

	rc = sd_bus_message_read(call, "s", &ifname);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read_array(call, 'y',
		(const void**)&dest->hwaddr, &dest->hwaddr_len);
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

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		// Return existing record.
		if (peer->state != ASSIGNED) {
			warnx("BUG: Bad state for peer %d, eid %d", 
				peer->state, peer->eid);
			rc = -EPROTO;
			goto err;
		}
		return sd_bus_reply_method_return(call, "yib",
			peer->eid, peer->net, 0);
	}

	rc = assign_peer(ctx, berr, dest, &peer);
	if (rc == 0)
		return sd_bus_reply_method_return(call, "yib",
			peer->eid, peer->net, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_learn_endpoint(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	const char *ifname = NULL;
	dest_phys desti, *dest = &desti;
	ctx *ctx = data;
	peer *peer = NULL;

	rc = sd_bus_message_read(call, "s", &ifname);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read_array(call, 'y',
		(const void**)&dest->hwaddr, &dest->hwaddr_len);
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

	rc = get_endpoint_peer(ctx, berr, dest, &peer);
	if (rc < 0)
		goto err;
	if (!peer)
		return sd_bus_reply_method_return(call, "byi", 0, 0, 0);

	return sd_bus_reply_method_return(call, "byi", 1, peer->eid, peer->net);
err:
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

// Testing code
static int method_test_timer_async(sd_bus_message *call, void *data, sd_bus_error *sderr)
{
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
static int method_test_timer(sd_bus_message *call, void *data, sd_bus_error *sderr)
{
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

	SD_BUS_METHOD_WITH_NAMES("AssignEndpoint",
		"say",
		SD_BUS_PARAM(ifname)
		SD_BUS_PARAM(physaddr),
		"yib",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(new), // TODO, better semantics?
		method_assign_endpoint,
		0),

	SD_BUS_METHOD_WITH_NAMES("LearnEndpoint",
		"say",
		SD_BUS_PARAM(ifname)
		SD_BUS_PARAM(physaddr),
		"byi",
		SD_BUS_PARAM(found)
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net),
		method_learn_endpoint,
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

int setup_nets(ctx *ctx)
{
	int *netlist = NULL;
	size_t num_nets, i, j, num_ifs;
	int *ifs;
	int rc = -1;

	netlist = mctp_nl_net_list(ctx->nl, &num_nets);
	ctx->nets = calloc(num_nets, sizeof(net_det));
	if (!ctx->nets) {
		warnx("Allocation failed");
		goto out;
	}

	if (num_nets == 0) {
		warnx("No MCTP interfaces");
		goto out;
	}

	for (i = 0; i < num_nets; i++) {
		ctx->nets[i].net = netlist[i];
		for (j = 0; j < 0xff; j++) {
			ctx->nets[i].peeridx[j] = -1;
		}
	}

	/* Set up local addresses */
	ifs = mctp_nl_if_list(ctx->nl, &num_ifs);
	for (i = 0; i < num_ifs; i++) {
		mctp_eid_t *eids = NULL;
		size_t num;
		peer *peer = NULL;

		eids = mctp_nl_addrs_byindex(ctx->nl, ifs[i], &num);
		for (j = 0; j < num; j++) {
			int net = mctp_nl_net_byindex(ctx->nl, ifs[i]);
			dest_phys dest = { .ifindex = 0 };

			if (net == 0) {
				warnx("No net for ifindex %d", ifs[i]);
				continue;
			}

			peer = find_peer_by_addr(ctx, eids[j], net);
			if (peer) {
				if (peer->state != LOCAL)
					warnx("BUG: Local eid %d net %d already exists?",
						eids[j], net);
				continue;
			}

			rc = add_peer(ctx, &dest, eids[j], net, &peer);
			if (rc < 0) {
				warn("BUG: Error adding local eid %d net %d for ifindex %d",
					eids[j], net, ifs[i]);
				continue;
			}
			peer->state = LOCAL;
		}
		free(eids);
	}
	free(ifs);

	ctx->num_nets = num_nets;
	if (ctx->verbose) {
		mctp_nl_linkmap_dump(ctx->nl);
	}

	rc = 0;
out:
	free(netlist);
	return rc;
}

static void print_usage(ctx *ctx)
{
	fprintf(stderr, "mctpd [-v] [-N]\n");
	fprintf(stderr, "      -v verbose\n");
	fprintf(stderr, "      -N testing mode, no MTCP required to start\n");
}

static int parse_args(ctx *ctx, int argc, char **argv)
{
	struct option options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = "verbose", .has_arg = no_argument, .val = 'v' },
		{ .name = "testing", .has_arg = no_argument, .val = 'N' },
		{ 0 },
	};
	int c;

	for (;;) {
		c = getopt_long(argc, argv, "+hvN", options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'N':
			ctx->testing = true;
			break;
		case 'v':
			ctx->verbose = true;
			break;
		case 'h':
		default:
			print_usage(ctx);
			return 255;
		}
	}
	return 0;
}

static int setup_config(ctx *ctx)
{
	// TODO: this will go in a config file or arguments.
	ctx->mctp_timeout = 250000; // 250ms
	ctx->bus_owner = true;
	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	ctx ctxi = {0}, *ctx = &ctxi;

	setlinebuf(stdout);

	setup_config(ctx);

	rc = parse_args(ctx, argc, argv);
	if (rc != 0) {
		return rc;
	}

	ctx->nl = mctp_nl_new(false);
	if (!ctx->nl) {
		warnx("Failed creating netlink object");
		return 1;
	}

	rc = setup_nets(ctx);
	if (rc < 0 && !ctx->testing)
		return 1;

	rc = setup_bus(ctx);
	if (rc < 0) {
		warnx("Error in setup, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	// TODO add net argument
	rc = listen_control_msg(ctx, MCTP_NET_ANY);
	if (rc < 0) {
		warnx("Error in listen, returned %s %d", strerror(-rc), rc);
		if (!ctx->testing)
			return 1;
	}

	rc = sd_event_loop(ctx->event);
	if (rc < 0) {
		warnx("Error in loop, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	return 0;
}

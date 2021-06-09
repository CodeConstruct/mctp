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

// arbitrary sanity, also ensures net_eids.peeridx fits int32
static size_t MAX_PEER_SIZE = 1000000;

static const uint8_t RQDI_REQ = 1<<7;
static const uint8_t RQDI_RESP = 0;
static const uint8_t RQDI_MASK = 0xc0;

struct dest_phys {
	int ifindex;
	const uint8_t *hwaddr;
	size_t hwaddr_len;
};
typedef struct dest_phys dest_phys;

/* Table of EIDs per network */
struct net_eids {
	int net;
	// EID mappings, an index into ctx->peers. Value -1 is unused.
	int32_t peeridx[0xff];

	mctp_eid_t eid_busowner;
	uint8_t hwaddr_busowner[MAX_ADDR_LEN];
	uint8_t hwaddr_len_busowner;
};
typedef struct net_eids net_eids;

struct peer {
	int ifindex;
	uint8_t hwaddr[MAX_ADDR_LEN];
	uint8_t hwaddr_len;

	mctp_eid_t eid;
	int net;

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

struct ctx {
	sd_event *event;
	sd_bus *bus;
	mctp_nl *nl;

	// An allocated array of peers, changes address (reallocated) during runtime
	struct peer *peers;
	size_t size_peers;

	struct net_eids *nets;
	size_t num_nets;

	// Timeout in usecs for a MCTP response
	uint64_t mctp_timeout;

	// Verbose logging
	bool verbose;
	bool testing;
};
typedef struct ctx ctx;

static void* dfree(void* ptr);

static struct peer * find_peer_by_phys(ctx *ctx, const dest_phys *dest)
{
	for (size_t i = 0; i < ctx->size_peers; i++) {
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
		addr->smctp_addr.s_addr, addr->smctp_network, addr->smctp_ifindex,
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
			ret_addr->smctp_type,
			buf_size);
	}

	// populate it for good measure
	buf[0] = ret_addr->smctp_type;
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

int handle_control_set_endpoint_id(ctx *ctx,
	int sd, struct _sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_set_eid *req = NULL;
	struct mctp_ctrl_resp_set_eid respi, *resp = &respi;
	size_t resp_len, send_len;
	uint8_t *send_ptr = NULL;
	ssize_t len;

	if (buf_size < sizeof(*req)) {
		warnx("short Set Endpoint ID message");
		return -ENOMSG;
	}

	req = (void*)buf;

	resp->ctrl_hdr.command_code = req->ctrl_msg_hdr.command_code;
	resp->ctrl_hdr.rq_dgram_inst = RQDI_RESP;
	resp->completion_code = 0;
	resp->status = 0x01 << 4; // Already assigned
	resp->eid_set = 161; // XXX TODO
	resp->eid_pool_size = 0;
	resp_len = sizeof(struct mctp_ctrl_resp_set_eid);

	// TODO:
	// Special case because the request destination was 0x00 but our response
	// is from a real eid.
	addr->smctp_tag |= MCTP_TAG_OWNER;

	send_len = resp_len - 1;
	send_ptr = (uint8_t*)resp + 1;
	len = sendto(sd, send_ptr, send_len, 0, 
		(struct sockaddr*)addr, sizeof(struct _sockaddr_mctp_ext));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != send_len) {
		warnx("BUG: short sendto %zd, expected %zu", len, send_len);
		return -EPROTO;
	}

	return 0;
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
	size_t resp_len, send_len;
	uint8_t *send_ptr = NULL;
	ssize_t len;

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
		resp->completion_code = 0x80;
		resp->number_of_entries = 0;
		resp_len = sizeof(*resp);
	} else {
		resp->completion_code = 0x00;
		resp->number_of_entries = 1;
		resp_len = sizeof(*resp) + sizeof(version);
		*((uint32_t*)(resp+1)) = htonl(version);
	}

	send_len = resp_len - 1;
	send_ptr = (uint8_t*)resp + 1;
	len = sendto(sd, send_ptr, send_len, 0, 
		(struct sockaddr*)addr, sizeof(struct _sockaddr_mctp_ext));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != send_len) {
		warnx("BUG: short sendto %zd, expected %zu", len, send_len);
		return -EPROTO;
	}

	return 0;
}

static int cb_listen_control_msg(sd_event_source *s, int sd, uint32_t revents, void *userdata)
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

	if (addr.smctp_type != MCTP_CTRL_HDR_MSG_TYPE) {
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

	addr.smctp_tag &= ~MCTP_TAG_OWNER;
	ctrl_msg = (void*)buf;
	switch (ctrl_msg->command_code) {
		case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
			rc = handle_control_get_version_support(ctx, sd, &addr, buf, buf_size);
			break;
		case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
			if ((ctrl_msg->rq_dgram_inst & RQDI_MASK) == RQDI_REQ) {
				rc = handle_control_set_endpoint_id(ctx, sd, &addr, buf, buf_size);
			} else {
				rc = handle_control_set_endpoint_id_resp(ctx, sd, &addr, buf, buf_size);
			}
			break;
		default:
			if (ctx->verbose) {
				warnx("Ignoring unsupported command code 0x%02x",
					ctrl_msg->command_code);
				rc = -ENOTSUP;
			}
	}

	if (ctx->verbose && rc < 0) {
		warnx("Error handling command code %02x from %s: %s",
			ctrl_msg->command_code, ext_addr_tostr(&addr), strerror(-rc));
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

	/* TODO: level is arbitrary */
	val = 1;
	rc = setsockopt(sd, SOL_SOCKET+1, MCTP_OPT_ADDR_EXT, &val, sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

	rc = sd_event_add_io(ctx->event, NULL, sd, EPOLLIN, cb_listen_control_msg, ctx);
	return rc;
out:
	if (rc < 0) {
		close(sd);
	}
	return rc;
}

/* req and resp buffers include the initial message type byte.
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

	/* TODO: level is arbitrary */
	val = 1;
	rc = setsockopt(sd, SOL_SOCKET+1, MCTP_OPT_ADDR_EXT, &val, sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

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

	if (resp_addr->smctp_type != req_type) {
		warnx("Mismatching response type %d for request type %d. dest %s",
			resp_addr->smctp_type, req_type, dest_phys_tostr(dest));
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
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req, sizeof(req),
		&buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	if (buf_size < sizeof(*resp)) {
		warnx("%s: short reply %zu bytes. dest %s", __func__, buf_size, 
			dest_phys_tostr(dest));
		rc = -ENOMSG;
		goto out;
	}
	resp = (void*)buf;

	expect_size = sizeof(resp) + resp->number_of_entries * sizeof(struct version_entry);
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
static int endpoint_send_set_endpoint_id(ctx *ctx, struct peer *peer,
	mctp_eid_t *new_eid)
{
	struct _sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_set_eid req = {0};
	struct mctp_ctrl_resp_set_eid *resp = NULL;
	int rc;
	uint8_t* buf = NULL;
	size_t buf_size;
	uint8_t stat, alloc;
	const dest_phys desti = {.ifindex = peer->ifindex,
		.hwaddr = peer->hwaddr, .hwaddr_len = peer->hwaddr_len}, *dest = &desti;

	rc = -1;

	req.ctrl_msg_hdr.rq_dgram_inst = RQDI_REQ;
	req.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	req.operation = 0; // 00b Set EID. TODO: do we want Force?
	req.eid = peer->eid;
	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req, sizeof(req),
		&buf, &buf_size, &addr);
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
		// TODO: make this a debug message?
		warnx("Failure completion code 0x%02x from %s", resp->completion_code,
			dest_phys_tostr(dest));
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
		warnx("%s unexpected status 0x%02x", dest_phys_tostr(dest), resp->status);
	}
	*new_eid = resp->eid_set;

	alloc = resp->status & 0x3;
	if (alloc != 0) {
		// TODO for bridges
		warnx("%s requested allocation pool, unimplemented", dest_phys_tostr(dest));
	}

	rc = 0;
out:
	free(buf);
	return rc;
}


net_eids *lookup_net(ctx *ctx, int net)
{
	size_t i;
	for (i = 0; i < ctx->num_nets; i++)
		if (ctx->nets[i].net == net)
			return &ctx->nets[i];
	return NULL;
}

/* Returns the newly added peer, or NULL (BUG) */
static peer *add_peer(ctx *ctx, const dest_phys *dest, mctp_eid_t eid, int net)
{
	size_t idx;
	size_t new_size;
	net_eids *n;
	void *tmp = NULL;
	peer *peer;

	n = lookup_net(ctx, net);
	if (!n) {
		warnx("BUG: %s Bad net %d", __func__, net);
		return NULL;
	}

	idx = n->peeridx[eid];
	if (n->peeridx[eid] >= 0) {
		warnx("BUG: %s eid %hhu net %d peer already exists", __func__, eid, net);
		if (idx >= ctx->size_peers) {
			warnx("BUG: Bad index %zu", idx);
			return NULL;
		}
		return &ctx->peers[idx];
	}

	// Find a slot
	for (idx = 0; idx < ctx->size_peers; idx++) {
		if (ctx->peers[idx].state == UNUSED) {
			break;
		}
	}
	if (idx == ctx->size_peers) {
		// Allocate more entries
		new_size = max(20, ctx->size_peers*2);
		if (new_size > MAX_PEER_SIZE) {
			return NULL;
		}
		tmp = realloc(ctx->peers, new_size * sizeof(*ctx->peers));
		if (!tmp)
			return NULL;
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
	peer->ifindex = dest->ifindex;
	if (dest->hwaddr_len > sizeof(peer->hwaddr)) {
		warnx("BUG: %s bad hwaddrlen %zu", __func__, dest->hwaddr_len);
		return NULL;
	}
	memcpy(peer->hwaddr, dest->hwaddr, dest->hwaddr_len);
	peer->hwaddr_len = (uint8_t)dest->hwaddr_len;
	peer->state = NEW;

	// Update network eid map
	n->peeridx[eid] = idx;

	return peer;
}

static int check_peer_struct(const ctx *ctx, const peer *peer, const struct net_eids *n)
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
		warnx("BUG: Bad net %d peeridx 0x%x vs 0x%lx",
			peer->net, n->peeridx[peer->eid], (long)idx);
		return -1;
	}

	return 0;
}

static int remove_peer(ctx *ctx, peer *peer)
{
	net_eids *n = NULL;

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
	net_eids *n = NULL;

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

	if (n->peeridx[new_eid] != -1) {
		return -EEXIST;
	}

	n->peeridx[new_eid] = n->peeridx[peer->eid];
	n->peeridx[peer->eid] = -1;
	peer->eid = new_eid;
	return 0;
}

static int endpoint_assign_eid(ctx *ctx, sd_bus_error *berr, const dest_phys *dest,
	struct peer **ret_peer)
{
	mctp_eid_t e, new_eid;
	net_eids *n = NULL;
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

	/* Find an unused EID */
	for (e = eid_alloc_min; e <= eid_alloc_max; e++) {
		if (n->peeridx[e] == -1) {
			peer = add_peer(ctx, dest, e, net);
			break;
		}
	}
	if (e > eid_alloc_max) {
		warnx("Ran out of EIDs for net %d, allocating %s", net, dest_phys_tostr(dest));
		return -EADDRNOTAVAIL;
	}
	if (!peer) {
		warnx("BUG: Failed to add peer");
		return -EPROTO;
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

static int configure_peer(ctx *ctx, sd_bus_error *berr, const dest_phys *dest, peer **ret_peer)
{
	int rc;
	bool supported;
	struct version_entry min_version;

	*ret_peer = NULL;

	rc = endpoint_assign_eid(ctx, berr, dest, ret_peer);

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

	return rc;
}

int validate_dest_phys(ctx *ctx, const dest_phys *dest)
{
	if (dest->hwaddr_len > MAX_ADDR_LEN)
		return -EINVAL;
	if (dest->ifindex <= 0)
		return -EINVAL;
	if (mctp_nl_net_byindex(ctx->nl, dest->ifindex) <= 0)
		return -EINVAL;
	return 0;
}

static int method_configure_endpoint(sd_bus_message *call, void *data, sd_bus_error *berr)
{
	int rc;
	const char *ifname = NULL;
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
	if (dest->ifindex <= 0) {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
			"Unknown MCTP ifname '%s'", ifname);
	}

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0) {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS, "Bad physaddr");
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

	rc = configure_peer(ctx, berr, dest, &peer);
	if (rc == 0) {
		return sd_bus_reply_method_return(call, "yib", peer->eid, peer->net, 1);
	}
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

int setup_nets(ctx *ctx)
{
	int *netlist = NULL;
	size_t num_nets, i, j;
	int rc = -1;

	netlist = mctp_nl_net_list(ctx->nl, &num_nets);
	ctx->nets = calloc(num_nets, sizeof(net_eids));
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

int main(int argc, char **argv)
{
	int rc;
	ctx ctxi = {0}, *ctx = &ctxi;

	ctx->mctp_timeout = 1000000; // TODO: 1 second

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

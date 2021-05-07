/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp: userspace utility for managing the kernel MCTP stack.
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/socket.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>

#include "mctp.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

struct linkmap_entry {
	int	ifindex;
	char	ifname[IFNAMSIZ+1];
};

struct ctx {
	int			sd;
	bool			verbose;
	struct linkmap_entry	*linkmap;
	int			linkmap_count;
	int			linkmap_alloc;
	const char* 		top_cmd; // main() argv[0]
};

typedef int (*display_fn_t)(struct ctx *ctx, void* msg, size_t len);


static int linkmap_lookup_byname(struct ctx *ctx, const char *ifname);
static const char* linkmap_lookup_byindex(struct ctx *ctx, int index);

static void hexdump(void *b, int len, const char *indent) {
	char* buf = b;
	const int row_len = 16;
	int i, j;

	for (i = 0; i < len; i += row_len) {
		char hbuf[row_len * strlen("00 ") + 1];
		char cbuf[row_len + strlen("|") + 1];

		for (j = 0; (j < row_len) && ((i+j) < len); j++) {
			unsigned char c = buf[i + j];

			sprintf(hbuf + j * 3, "%02x ", c);

			if (!isprint(c))
				c = '.';

			sprintf(cbuf + j, "%c", c);
		}

		strcat(cbuf, "|");

		printf("%s%08x  %*s |%s\n", indent, i,
				(int)(0 - sizeof(hbuf) + 1), hbuf, cbuf);
	}
}

static void print_hex_addr(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (i > 0) {
			putchar(':');
		}
		printf("%02x", data[i]);
	}
}

// Accepts colon separated hex bytes
static int parse_hex_addr(const char* in, char* out, size_t *out_len)
{
	int rc = -1;
	size_t out_pos = 0;
	while (1) {
		if (*in == '\0') {
			rc = 0;
			break;
		}
		else if (*in == ':') {
			in++;
			if (*in == ':' || *in == '\0' || out_pos == 0) {
				// can't have repeated ':' or ':' at start or end.
				break;
			}
		} else {
			char* endp;
			int tmp;
			tmp = strtoul(in, &endp, 16);
			if (endp == in || tmp > 0xff) {
				break;
			}
			if (out_pos >= *out_len) {
				break;
			}
			*out = tmp & 0xff;
			out++;
			out_pos++;
			in = endp;
		}
	}

	if (rc) {
		*out_len = 0;
	} else {
		*out_len = out_pos;
	}
	return rc;
}


enum attrgroup {
	RTA_GROUP_IFLA,
	RTA_GROUP_IFA,
	RTA_GROUP_NDA,
};

static const char *ifla_attrnames[] = {
	[IFLA_UNSPEC] = "IFLA_UNSPEC",
	[IFLA_ADDRESS] = "IFLA_ADDRESS",
	[IFLA_BROADCAST] = "IFLA_BROADCAST",
	[IFLA_IFNAME] = "IFLA_IFNAME",
	[IFLA_MTU] = "IFLA_MTU",
	[IFLA_LINK] = "IFLA_LINK",
	[IFLA_QDISC] = "IFLA_QDISC",
	[IFLA_STATS] = "IFLA_STATS",
	[IFLA_COST] = "IFLA_COST",
	[IFLA_PRIORITY] = "IFLA_PRIORITY",
	[IFLA_MASTER] = "IFLA_MASTER",
	[IFLA_WIRELESS] = "IFLA_WIRELESS",
	[IFLA_PROTINFO] = "IFLA_PROTINFO",
	[IFLA_TXQLEN] = "IFLA_TXQLEN",
	[IFLA_MAP] = "IFLA_MAP",
	[IFLA_WEIGHT] = "IFLA_WEIGHT",
	[IFLA_OPERSTATE] = "IFLA_OPERSTATE",
	[IFLA_LINKMODE] = "IFLA_LINKMODE",
	[IFLA_LINKINFO] = "IFLA_LINKINFO",
	[IFLA_NET_NS_PID] = "IFLA_NET_NS_PID",
	[IFLA_IFALIAS] = "IFLA_IFALIAS",
	[IFLA_NUM_VF] = "IFLA_NUM_VF",
	[IFLA_VFINFO_LIST] = "IFLA_VFINFO_LIST",
	[IFLA_STATS64] = "IFLA_STATS64",
	[IFLA_VF_PORTS] = "IFLA_VF_PORTS",
	[IFLA_PORT_SELF] = "IFLA_PORT_SELF",
	[IFLA_AF_SPEC] = "IFLA_AF_SPEC",
	[IFLA_GROUP] = "IFLA_GROUP",
	[IFLA_NET_NS_FD] = "IFLA_NET_NS_FD",
	[IFLA_EXT_MASK] = "IFLA_EXT_MASK",
	[IFLA_PROMISCUITY] = "IFLA_PROMISCUITY",
	[IFLA_NUM_TX_QUEUES] = "IFLA_NUM_TX_QUEUES",
	[IFLA_NUM_RX_QUEUES] = "IFLA_NUM_RX_QUEUES",
	[IFLA_CARRIER] = "IFLA_CARRIER",
	[IFLA_PHYS_PORT_ID] = "IFLA_PHYS_PORT_ID",
	[IFLA_CARRIER_CHANGES] = "IFLA_CARRIER_CHANGES",
	[IFLA_PHYS_SWITCH_ID] = "IFLA_PHYS_SWITCH_ID",
	[IFLA_LINK_NETNSID] = "IFLA_LINK_NETNSID",
	[IFLA_PHYS_PORT_NAME] = "IFLA_PHYS_PORT_NAME",
	[IFLA_PROTO_DOWN] = "IFLA_PROTO_DOWN",
	[IFLA_GSO_MAX_SEGS] = "IFLA_GSO_MAX_SEGS",
	[IFLA_GSO_MAX_SIZE] = "IFLA_GSO_MAX_SIZE",
	[IFLA_PAD] = "IFLA_PAD",
	[IFLA_XDP] = "IFLA_XDP",
	[IFLA_EVENT] = "IFLA_EVENT",
	[IFLA_NEW_NETNSID] = "IFLA_NEW_NETNSID",
	[IFLA_IF_NETNSID] = "IFLA_IF_NETNSID",
	[IFLA_CARRIER_UP_COUNT] = "IFLA_CARRIER_UP_COUNT",
	[IFLA_CARRIER_DOWN_COUNT] = "IFLA_CARRIER_DOWN_COUNT",
	[IFLA_NEW_IFINDEX] = "IFLA_NEW_IFINDEX",
	[IFLA_MIN_MTU] = "IFLA_MIN_MTU",
	[IFLA_MAX_MTU] = "IFLA_MAX_MTU",
	[IFLA_PROP_LIST] = "IFLA_PROP_LIST",
	[IFLA_ALT_IFNAME] = "IFLA_ALT_IFNAME",
	[IFLA_PERM_ADDRESS] = "IFLA_PERM_ADDRESS",
	[IFLA_PROTO_DOWN_REASON] = "IFLA_PROTO_DOWN_REASON",
};

static const char *ifa_attrnames[] = {
	[IFA_UNSPEC] = "IFA_UNSPEC",
	[IFA_ADDRESS] = "IFA_ADDRESS",
	[IFA_LOCAL] = "IFA_LOCAL",
	[IFA_LABEL] = "IFA_LABEL",
	[IFA_BROADCAST] = "IFA_BROADCAST",
	[IFA_ANYCAST] = "IFA_ANYCAST",
	[IFA_CACHEINFO] = "IFA_CACHEINFO",
	[IFA_MULTICAST] = "IFA_MULTICAST",
	[IFA_FLAGS] = "IFA_FLAGS",
	[IFA_RT_PRIORITY] = "IFA_RT_PRIORITY",
	[IFA_TARGET_NETNSID] = "IFA_TARGET_NETNSID",
};

static const char *nda_attrnames[] = {
	[NDA_UNSPEC] = "NDA_UNSPEC",
	[NDA_DST] = "NDA_DST",
	[NDA_LLADDR] = "NDA_LLADDR",
	[NDA_CACHEINFO] = "NDA_CACHEINFO",
	[NDA_PROBES] = "NDA_PROBES",
	[NDA_VLAN] = "NDA_VLAN",
	[NDA_PORT] = "NDA_PORT",
	[NDA_VNI] = "NDA_VNI",
	[NDA_IFINDEX] = "NDA_IFINDEX",
	[NDA_MASTER] = "NDA_MASTER",
	[NDA_LINK_NETNSID] = "NDA_LINK_NETNSID",
	[NDA_SRC_VNI] = "NDA_SRC_VNI",
	[NDA_PROTOCOL] = "NDA_PROTOCOL",
	[NDA_NH_ID] = "NDA_NH_ID",
	[NDA_FDB_EXT_ATTRS] = "NDA_FDB_EXT_ATTRS",
};

static struct {
	size_t count;
	const char **names;
} attrnames[] = {
	[RTA_GROUP_IFLA] = { ARRAY_SIZE(ifla_attrnames), ifla_attrnames },
	[RTA_GROUP_IFA]  = { ARRAY_SIZE(ifa_attrnames), ifa_attrnames },
	[RTA_GROUP_NDA]  = { ARRAY_SIZE(nda_attrnames), nda_attrnames },
};

static const char *rtattr_name(enum attrgroup group, unsigned int type)
{
	if (group >= ARRAY_SIZE(attrnames))
		return "unknown group";
	if (type >= attrnames[group].count)
		return "unknown attr type";
	return attrnames[group].names[type];
}

static void dump_rtnlmsg_attrs(enum attrgroup group,
		struct rtattr *rta, size_t len)
{
	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		printf("attr %s (0x%x)\n", rtattr_name(group, rta->rta_type),
				rta->rta_type);
		hexdump(RTA_DATA(rta), RTA_PAYLOAD(rta), "  ");
	}
}

/* Pointer returned on match, optionally returns ret_len */
static void* get_rtnlmsg_attr(int rta_type, struct rtattr *rta, size_t len,
	size_t *ret_len)
{
	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == rta_type) {
			if (ret_len) {
				*ret_len = RTA_PAYLOAD(rta);
			}
			return RTA_DATA(rta);
		}
	}
	return NULL;
}

static bool get_rtnlmsg_attr_u32(int rta_type, struct rtattr *rta, size_t len,
				uint32_t *ret_value) {
	size_t plen;
	uint32_t *p = get_rtnlmsg_attr(rta_type, rta, len, &plen);
	if (p) {
		if (plen == sizeof(*ret_value)) {
			*ret_value = *p;
			return true;
		} else {
			warnx("Unexpected attribute length %zu for type %d",
				plen, rta_type);
		}
	}
	return false;
}

static bool get_rtnlmsg_attr_u8(int rta_type, struct rtattr *rta, size_t len,
				uint8_t *ret_value) {
	size_t plen;
	uint8_t *p = get_rtnlmsg_attr(rta_type, rta, len, &plen);
	if (p) {
		if (plen == sizeof(*ret_value)) {
			*ret_value = *p;
			return true;
		} else {
			warnx("Unexpected attribute length %zu for type %d",
				plen, rta_type);
		}
	}
	return false;
}

static int display_ifinfo(struct ctx *ctx, void *p, size_t len) {
	struct ifinfomsg *msg = p;
	size_t rta_len, nest_len;
	struct rtattr *rta, *rd_nest;

	char* name;
	uint8_t *addr;
	size_t name_len, addr_len;
	uint32_t mtu;
	uint32_t net;

	if (len < sizeof(*msg)) {
		printf("not enough data for an ifinfomsg\n");
		return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	mtu = 0;
	net = 0;
	name = get_rtnlmsg_attr(IFLA_IFNAME, rta, rta_len, &name_len);
	addr = get_rtnlmsg_attr(IFLA_ADDRESS, rta, rta_len, &addr_len);
	get_rtnlmsg_attr_u32(IFLA_MTU, rta, rta_len, &mtu);
	rd_nest = get_rtnlmsg_attr(IFLA_PROTINFO, rta, rta_len, &nest_len);
	if (rd_nest) {
		get_rtnlmsg_attr_u32(IFLA_MCTP_NET, rd_nest, nest_len, &net);
	}
	// not sure if will be NULL terminated, handle either
	name_len = strnlen(name, name_len);
	printf("dev %*s address ", name_len, name);
	print_hex_addr(addr, addr_len);
	printf(" net %d mtu %d\n", net, mtu);
	return 0;
}

static void dump_rtnlmsg_ifinfo(struct ctx *ctx, struct ifinfomsg *msg, size_t len)
{
	if (len < sizeof(*msg)) {
		printf("not enough data for an ifinfomsg\n");
		return;
	}

	printf("ifinfo:\n");
	display_ifinfo(ctx, msg, len);
	printf("  family: %d\n", msg->ifi_family);
	printf("  type:   %d\n", msg->ifi_type);
	printf("  index:  %d\n", msg->ifi_index);
	printf("  flags:  0x%08x\n", msg->ifi_flags);

	dump_rtnlmsg_attrs(RTA_GROUP_IFLA,
			(void *)(msg + 1), len - sizeof(*msg));
}

static int display_ifaddr(struct ctx *ctx, void *p, size_t len) {
	struct ifaddrmsg *msg = p;
	size_t rta_len;
	struct rtattr *rta;
	uint8_t eid;

	if (len < sizeof(*msg)) {
		printf("not enough data for an ifaddrmsg\n");
		return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	eid = 0;
	get_rtnlmsg_attr_u8(IFA_LOCAL, rta, rta_len, &eid);
	printf("eid %d dev %s\n", eid, linkmap_lookup_byindex(ctx, msg->ifa_index));
	return 0;
}

static void dump_rtnlmsg_ifaddr(struct ctx *ctx, struct ifaddrmsg *msg, size_t len)
{
	if (len < sizeof(*msg)) {
		printf("not enough data for an ifaddrmsg\n");
		return;
	}

	printf("ifaddr:\n");
	display_ifaddr(ctx, msg, len);
	printf("  family: %d\n", msg->ifa_family);
	printf("  prefixlen:   %d\n", msg->ifa_prefixlen);
	printf("  flags:  0x%08x\n", msg->ifa_flags);
	printf("  scope:  %d\n", msg->ifa_scope);
	printf("  index:  %d\n", msg->ifa_index);

	dump_rtnlmsg_attrs(RTA_GROUP_IFA,
			(void *)(msg + 1), len - sizeof(*msg));
}

static int display_neighbour(struct ctx *ctx, void *p, size_t len)
{
	struct ndmsg *msg = p;
	size_t rta_len;
	struct rtattr *rta;
	uint8_t eid;
	uint8_t *lladdr;
	size_t lladdr_len;

	if (len < sizeof(*msg)) {
		printf("not enough data for a ndmsg\n");
		return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	eid = 0;
	get_rtnlmsg_attr_u8(NDA_DST, rta, rta_len, &eid);
	lladdr = get_rtnlmsg_attr(NDA_DST, rta, rta_len, &lladdr_len);
	printf("eid %d dev %s lladdr ", eid, linkmap_lookup_byindex(ctx, msg->ndm_ifindex));
	print_hex_addr(lladdr, lladdr_len);
	printf("\n");
	return 0;
}

static void dump_rtnlmsg_neighbour(struct ctx *ctx, struct ndmsg *msg, size_t len)
{
	if (len < sizeof(*msg)) {
		printf("not enough data for a ndmsg\n");
		return;
	}

	printf("ndmsg:\n");
	display_neighbour(ctx, msg, len);
	printf("  family:  %d\n", msg->ndm_family);
	printf("  ifindex: %d\n", msg->ndm_ifindex);
	printf("  state:   0x%08x\n", msg->ndm_state);
	printf("  flags:   0x%08x\n", msg->ndm_flags);
	printf("  type:    %d\n", msg->ndm_type);

	dump_rtnlmsg_attrs(RTA_GROUP_NDA,
			(void *)(msg + 1), len - sizeof(*msg));
}

static int display_route(struct ctx *ctx, void *p, size_t len)
{
	struct rtmsg *msg = p;
	size_t rta_len, nest_len;
	struct rtattr *rta, *rd_nest;
	uint8_t dst;
	uint32_t net, ifindex, mtu;

	if (len < sizeof(*msg)) {
		printf("not enough data for a rtmsg\n");
		return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	dst = 0;
	net = 0;
	ifindex = 0;
	mtu = 0;
	get_rtnlmsg_attr_u8(RTA_DST, rta, rta_len, &dst);
	get_rtnlmsg_attr_u32(RTA_TABLE, rta, rta_len, &net);
	get_rtnlmsg_attr_u32(RTA_OIF, rta, rta_len, &ifindex);
	rd_nest = get_rtnlmsg_attr(RTA_METRICS, rta, rta_len, &nest_len);
	if (rd_nest) {
		get_rtnlmsg_attr_u32(RTAX_MTU, rd_nest, nest_len, &mtu);
	}

	printf("eid min %d max %d net %d dev %s mtu %d\n",
		dst, dst + msg->rtm_dst_len,
		net, linkmap_lookup_byindex(ctx, ifindex), mtu);
	return 0;
}

static void dump_rtnlmsg_route(struct ctx *ctx, struct rtmsg *msg, size_t len)
{
	size_t rta_len;
	struct rtattr *rta;
	if (len < sizeof(*msg)) {
		printf("not enough data for a rtmsg\n");
		return;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	printf("rtmsg:\n");
	display_route(ctx, msg, len);
	printf("  family:   %d\n", msg->rtm_family);
	printf("  dst_len:  %d\n", msg->rtm_dst_len);
	printf("  src_len:  %d\n", msg->rtm_src_len);
	printf("  tos:      %d\n", msg->rtm_tos);
	printf("  table:    %d\n", msg->rtm_table);
	printf("  protocol: %d\n", msg->rtm_protocol);
	printf("  scope:    %d\n", msg->rtm_scope);
	printf("  type:     %d\n", msg->rtm_type);
	printf("  flags:    0x%08x\n", msg->rtm_flags);
	printf("  attribute dump:\n");
	hexdump(rta, rta_len, "    ");
}

static void dump_nlmsg_hdr(struct nlmsghdr *hdr, const char *indent)
{
	printf("%slen:   %d\n", indent, hdr->nlmsg_len);
	printf("%stype:  %d\n", indent, hdr->nlmsg_type);
	printf("%sflags: %d\n", indent, hdr->nlmsg_flags);
	printf("%sseq:   %d\n", indent, hdr->nlmsg_seq);
	printf("%spid:   %d\n", indent, hdr->nlmsg_pid);
}

static void dump_rtnlmsg_error(struct nlmsgerr *err)
{
	printf("error:\n");
	printf("  err: %d %s\n", err->error, strerror(-err->error));
	printf("  msg:\n");
	dump_nlmsg_hdr(&err->msg, "    ");
}

static void dump_rtnlmsg(struct ctx *ctx, struct nlmsghdr *msg)
{
	void *payload;
	size_t len;

	printf("header:\n");
	dump_nlmsg_hdr(msg, "  ");

	len = NLMSG_PAYLOAD(msg, 0);
	payload = NLMSG_DATA(msg);

	switch (msg->nlmsg_type) {
	case RTM_NEWLINK:
		dump_rtnlmsg_ifinfo(ctx, payload, len);
		break;
	case RTM_NEWADDR:
		dump_rtnlmsg_ifaddr(ctx, payload, len);
		break;
	case RTM_NEWROUTE:
		dump_rtnlmsg_route(ctx, payload, len);
		break;
	case RTM_NEWNEIGH:
		dump_rtnlmsg_neighbour(ctx, payload, len);
		break;
	case NLMSG_ERROR:
		dump_rtnlmsg_error(payload);
		break;
	case NLMSG_NOOP:
	case NLMSG_DONE:
		break;
	default:
		printf("unknown nlmsg type\n");
		hexdump(msg, len, "    ");
	}
}

static void dump_rtnlmsgs(struct ctx *ctx, struct nlmsghdr *msg, size_t len)
{
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len))
		dump_rtnlmsg(ctx, msg);
}

// Calls pretty printing display_ function for wanted message type
void display_rtnlmsgs(struct ctx *ctx, struct nlmsghdr *msg, size_t len,
	int want_type, display_fn_t display_fn)
{
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == want_type) {
			display_fn(ctx, NLMSG_DATA(msg), NLMSG_PAYLOAD(msg, 0));
		} else switch (msg->nlmsg_type) {
			case NLMSG_NOOP:
			case NLMSG_DONE:
				break;
			case NLMSG_ERROR:
				dump_rtnlmsg_error(NLMSG_DATA(msg));
				break;
			default:
				printf("unknown nlmsg type\n");
				hexdump(msg, sizeof(msg), "    ");
		}
	}
}

/* Receive and handle a NLMSG_ERROR and return the error code */
static int handle_nlmsg_ack(struct ctx *ctx) {
	char resp[4096];
	struct nlmsghdr *msg;
	int rc;
	size_t len;

	rc = recvfrom(ctx->sd, resp, sizeof(resp), 0, NULL, NULL);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");
	len = rc;
	msg = (void*)resp;

	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (void *)(msg + 1);
			if (err->error) {
				rc = err->error;
				warnx("Error: %s", strerror(-err->error));
				// TODO: handle extended ack
				size_t ext_len = msg->nlmsg_len - sizeof(*msg) - sizeof(*err);
				if (ext_len > 0) {
					hexdump(err + 1, ext_len, "extack    ");
				}
			}
		} else {
			warnx("Unexpected message instead of status return:");
			dump_rtnlmsg(ctx, msg);
		}
	}
	return rc;
}

/*
 * Note that only rtnl_doit_func() handlers like RTM_NEWADDR
 * will automatically return a response to NLM_F_ACK, other requests
 * shouldn't have it set.
 */
static int send_nlmsg(struct ctx *ctx, struct nlmsghdr *msg)
{
	struct sockaddr_nl addr;
	int rc;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	rc = sendto(ctx->sd, msg, msg->nlmsg_len, 0,
			(struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0)
		err(EXIT_FAILURE, "sendto");

	if (rc != (int)msg->nlmsg_len)
		warnx("sendto: short send (%d, expected %d)",
				rc, msg->nlmsg_len);

	if (msg->nlmsg_flags & NLM_F_ACK) {
		return handle_nlmsg_ack(ctx);
	}
	return 0;
}

/* respp is optional for returned buffer, length is set in resp+lenp */
static int do_nlmsg(struct ctx *ctx, struct nlmsghdr *msg,
		struct nlmsghdr **respp, size_t *resp_lenp)
{
	struct nlmsghdr *respbuf;
	struct sockaddr_nl addr;
	socklen_t addrlen;
	size_t resplen;
	int rc;

	rc = send_nlmsg(ctx, msg);
	if (rc)
		return rc;

	rc = recvfrom(ctx->sd, NULL, 0, MSG_PEEK|MSG_TRUNC, NULL, 0);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom(MSG_PEEK)");

	if (!rc)
		return -1;

	resplen = rc;
	respbuf = malloc(resplen);
	addrlen = sizeof(addr);

	rc = recvfrom(ctx->sd, respbuf, resplen, MSG_TRUNC,
			(struct sockaddr *)&addr, &addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom()");

	if ((size_t)rc > resplen)
		warnx("recvfrom: extra message data? (got %d, exp %zd)",
				rc, resplen);

	if (addrlen != sizeof(addr)) {
		warn("recvfrom: weird addrlen? (%d, expecting %zd)", addrlen,
				sizeof(addr));
	}

	if (ctx->verbose) {
		printf("/---------- %zd bytes from {%d,%d}\n", resplen,
				addr.nl_family, addr.nl_pid);
		dump_rtnlmsgs(ctx, respbuf, rc);
		printf("\\----------------------------\n");
	}

	if (respp) {
		*respp = respbuf;
		*resp_lenp = rc;
	} else {
		free(respbuf);
	}

	return 0;
}

static void linkmap_add_entry(struct ctx *ctx, struct ifinfomsg *info,
		struct rtattr *ifname_rta)
{
	struct linkmap_entry *entry;
	void *tmp;
	int idx;

	idx = ctx->linkmap_count++;

	if (ctx->linkmap_count > ctx->linkmap_alloc) {
		ctx->linkmap_alloc = max(ctx->linkmap_alloc * 2, 1);
		tmp = realloc(ctx->linkmap,
				ctx->linkmap_alloc * sizeof(*ctx->linkmap));
		if (!tmp)
			err(EXIT_FAILURE, "linkmap realloc");
		ctx->linkmap = tmp;
	}

	entry = &ctx->linkmap[idx];
	strncpy(entry->ifname, RTA_DATA(ifname_rta),
			min(RTA_PAYLOAD(ifname_rta), IFNAMSIZ));
	entry->ifindex = info->ifi_index;
}

static void linkmap_dump(struct ctx *ctx)
{
	int i;

	printf("linkmap\n");
	for (i = 0; i < ctx->linkmap_count; i++) {
		struct linkmap_entry *entry = &ctx->linkmap[i];
		printf("  %d: %s\n", entry->ifindex, entry->ifname);
	}
}

static int parse_getlink_dump(struct ctx *ctx, struct nlmsghdr *nlh, int len)
{
	struct ifinfomsg *info;

	for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct rtattr *rta, *ifname_rta;
		int rlen;

		if (nlh->nlmsg_type == NLMSG_DONE)
			return 0;

		if (nlh->nlmsg_type == NLMSG_ERROR)
			return -1;

		if (NLMSG_PAYLOAD(nlh, 0) < sizeof(*info))
			return -1;

		info = NLMSG_DATA(nlh);
		if (!info->ifi_index)
			continue;

		rta = (void *)(info + 1);
		rlen = NLMSG_PAYLOAD(nlh, sizeof(*info));
		ifname_rta = NULL;

		for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
			if (rta->rta_type == IFLA_IFNAME) {
				ifname_rta = rta;
				break;
			}
		}

		if (!ifname_rta) {
			printf("no ifname?\n");
			continue;
		}

		linkmap_add_entry(ctx, info, ifname_rta);
	}
	return 1;
}

static int get_linkmap(struct ctx *ctx)
{
	struct {
		struct nlmsghdr		nh;
		struct ifinfomsg	ifmsg;
	} msg = { 0 };
	struct sockaddr_nl addr;
	socklen_t addrlen;
	size_t buflen;
	void *buf;
	int rc;

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));
	msg.nh.nlmsg_type = RTM_GETLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ifmsg.ifi_family = AF_MCTP;

	rc = send_nlmsg(ctx, &msg.nh);
	if (rc)
		return rc;

	buf = NULL;
	buflen = 0;
	addrlen = sizeof(addr);

	for (;;) {
		rc = recvfrom(ctx->sd, NULL, 0, MSG_TRUNC | MSG_PEEK,
				NULL, NULL);
		if (rc < 0) {
			warn("recvfrom(MSG_PEEK)");
			break;
		}

		if (!rc)
			break;

		if ((size_t)rc > buflen) {
			char *tmp;
			buflen = rc;
			tmp = realloc(buf, buflen);
			if (!tmp) {
				rc = -1;
				break;
			}
			buf = tmp;
		}

		rc = recvfrom(ctx->sd, buf, buflen, 0,
				(struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			warn("recvfrom()");
			break;
		}

		rc = parse_getlink_dump(ctx, buf, rc);
		if (rc <= 0)
			break;
	}

	free(buf);

	if (ctx->verbose)
		linkmap_dump(ctx);

	return rc;
}

static int linkmap_lookup_byname(struct ctx *ctx, const char *ifname)
{
	int i;

	for (i = 0; i < ctx->linkmap_count; i++) {
		struct linkmap_entry *entry = &ctx->linkmap[i];
		if (!strcmp(entry->ifname, ifname))
			return entry->ifindex;
	}

	return 0;
}

static const char* linkmap_lookup_byindex(struct ctx *ctx, int index)
{
	int i;

	for (i = 0; i < ctx->linkmap_count; i++) {
		struct linkmap_entry *entry = &ctx->linkmap[i];
		if (entry->ifindex == index) {
			return entry->ifname;
		}
	}

	return NULL;
}

static int cmd_link_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr		nh;
		struct ifinfomsg	ifmsg;
		struct rtattr		rta;
		char			ifname[16];
	} msg;
	const char *ifname = NULL;
	size_t ifnamelen = 0;
	size_t len;
	int rc;

	if (argc > 1) {
		// filter by ifname
		ifname = argv[1];
		ifnamelen = strlen(ifname);

		if (ifnamelen > sizeof(msg.ifname)) {
			warnx("interface name '%s' too long", ifname);
			return -1;
		}
	}

	memset(&msg, 0, sizeof(msg));
	if (ifname) {
		msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg)) +
					RTA_SPACE(ifnamelen);
	} else {
		msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));
	}
	msg.nh.nlmsg_type = RTM_GETLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.ifmsg.ifi_family = AF_MCTP;
	msg.ifmsg.ifi_type = 0;
	msg.ifmsg.ifi_index = 0;

	if (ifname) {
		msg.rta.rta_type = IFLA_IFNAME;
		msg.rta.rta_len = RTA_LENGTH(ifnamelen);
		strncpy(RTA_DATA(&msg.rta), ifname, ifnamelen);
	}

	rc = do_nlmsg(ctx, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWLINK, display_ifinfo);
	free(resp);
	return 0;
}

static int cmd_link(struct ctx *ctx, int argc, const char **argv)
{
	const char* subcmd;

	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s link\n", ctx->top_cmd);
		fprintf(stderr, "%s link show [ifname]\n", ctx->top_cmd);
		fprintf(stderr, "%s link set [ifname]    {unimplemented}\n", ctx->top_cmd);
		return 255;
	}

	if (argc == 1) {
		return cmd_link_show(ctx, 0, NULL);
	}

	subcmd = argv[1];
	argc--;
	argv++;

	if (!strcmp(subcmd, "show")) {
		return cmd_link_show(ctx, argc, argv);
	} else if (!strcmp(subcmd, "set")) {
		// TODO
	}

	return -1;
}

static int cmd_addr_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr		nh;
		struct ifaddrmsg	ifmsg;
		struct rtattr		rta;
		char			ifname[16];
	} msg;
	const char *ifname = NULL;
	size_t ifnamelen;
	size_t len;
	int rc;

	if (argc > 1) {
		// filter by ifname
		ifname = argv[1];
		ifnamelen = strlen(ifname);
		if (ifnamelen > sizeof(msg.ifname)) {
			warnx("interface name '%s' too long", ifname);
			return -1;
		}
	}

	get_linkmap(ctx);

	memset(&msg, 0, sizeof(msg));
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	msg.nh.nlmsg_type = RTM_GETADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.ifmsg.ifa_index = 1; // TODO: check this, could be 0?
	msg.ifmsg.ifa_family = AF_MCTP;

	if (ifname) {
		msg.rta.rta_type = IFA_LABEL;
		msg.rta.rta_len = RTA_LENGTH(ifnamelen);
		strncpy(RTA_DATA(&msg.rta), ifname, ifnamelen);
	}

	rc = do_nlmsg(ctx, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWADDR, display_ifaddr);
	free(resp);
	return 0;
}

static int cmd_addr_add(struct ctx *ctx, int argc, const char **argv)
{
	struct {
		struct nlmsghdr		nh;
		struct ifaddrmsg	ifmsg;
		struct rtattr		rta;
		uint8_t			data[4];
	} msg;
	const char *eidstr, *linkstr;
	unsigned long tmp;
	uint8_t eid;
	int ifindex;
	char *endp;

	if (argc != 4) {
		warnx("add: invalid arguments");
		return -1;
	}

	if (strcmp(argv[2], "dev")) {
		warnx("invalid dev spec");
		return -1;
	}

	eidstr = argv[1];
	linkstr = argv[3];

	get_linkmap(ctx);

	ifindex = linkmap_lookup_byname(ctx, linkstr);
	if (!ifindex) {
		warnx("invalid device %s", linkstr);
		return -1;
	}

	tmp = strtoul(eidstr, &endp, 0);
	if (endp == eidstr || tmp > 0xff) {
		warnx("invalid address %s", eidstr);
		return -1;
	}
	eid = tmp & 0xff;

	msg.nh.nlmsg_type = RTM_NEWADDR;
	// request an error status since there's no other reply
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	msg.ifmsg.ifa_index = ifindex;
	msg.ifmsg.ifa_family = AF_MCTP;

	msg.rta.rta_type = IFA_LOCAL;
	msg.rta.rta_len = RTA_LENGTH(sizeof(eid));
	memcpy(RTA_DATA(&msg.rta), &eid, sizeof(eid));

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg)) +
			RTA_SPACE(sizeof(eid));

	send_nlmsg(ctx, &msg.nh);

	return 0;
}

static int cmd_addr(struct ctx *ctx, int argc, const char **argv)
{
	const char* subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s address\n", ctx->top_cmd);
		fprintf(stderr, "%s address show [IFNAME]\n", ctx->top_cmd);
		fprintf(stderr, "%s address add <eid> dev <IFNAME>\n", ctx->top_cmd);
		fprintf(stderr, "%s address remove <eid> dev <IFNAME>  {unimplemented}\n", ctx->top_cmd);
		return 255;
	}

	if (argc == 1)
		return cmd_addr_show(ctx, 0, NULL);

	subcmd = argv[1];
	argv++;
	argc--;

	if (!strcmp(subcmd, "show"))
		return cmd_addr_show(ctx, argc, argv);
	else if (!strcmp(subcmd, "add"))
		return cmd_addr_add(ctx, argc, argv);

	warnx("unknown address command '%s'", subcmd);
	return -1;
}

static int cmd_route_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr		nh;
		struct rtmsg	 rtmsg;
		// struct rtattr		rta;
	} msg;
	size_t len;
	int rc;

	get_linkmap(ctx);

	memset(&msg, 0, sizeof(msg));
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.rtmsg));

	msg.nh.nlmsg_type = RTM_GETROUTE;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.rtmsg.rtm_family = AF_MCTP;

	rc = do_nlmsg(ctx, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWROUTE, display_route);

	free(resp);
	return 0;
}

// static int cmd_route_add(struct ctx *ctx, int argc, const char **argv)
// {
// 	struct {
// 		struct nlmsghdr		nh;
// 		struct rtmsg	 rtmsg;
// 		// struct rtattr		rta;
// 	} msg;

// 	memset(&msg, 0, sizeof(msg));
// 	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.rtmsg));

// 	msg.nh.nlmsg_type = RTM_GETROUTE;
// 	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

// 	msg.rtmsg.rtm_family = AF_MCTP;

// 	return do_nlmsg(ctx, &msg.nh);
// }

static int cmd_route(struct ctx *ctx, int argc, const char **argv)
{
	const char* subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s route\n", ctx->top_cmd);
		fprintf(stderr, "%s route show [net <network>]\n", ctx->top_cmd);
		fprintf(stderr, "%s route add <eid> via <dev>\n", ctx->top_cmd);
		fprintf(stderr, "%s route del  {unimplemented}\n", ctx->top_cmd);
		return 255;
	}

	if (argc == 1)
		return cmd_route_show(ctx, 0, NULL);

	subcmd = argv[1];
	argv++;
	argc--;

	if (!strcmp(subcmd, "show"))
		return cmd_route_show(ctx, argc, argv);
	// else if (!strcmp(subcmd, "add"))
	// 	return cmd_route_add(ctx, argc, argv);

	warnx("unknown route command '%s'", subcmd);
	return -1;
}

static int cmd_neigh_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr		nh;
		struct ndmsg		ndmsg;
	} msg = {0};
	const char* linkstr = NULL;
	int ifindex = 0;
	size_t len;
	int rc;

	if (!(argc <= 1 || argc == 3)) {
		warnx("show: invalid arguments");
		return -1;
	}
	if (argc == 3) {
		if (strcmp(argv[1], "dev")) {
			warnx("show: invalid arguments");
			return -1;
		}
		linkstr = argv[2];
	}

	get_linkmap(ctx);

	if (linkstr) {
		ifindex = linkmap_lookup_byname(ctx, linkstr);
		if (!ifindex) {
			warnx("invalid device %s", linkstr);
			return -1;
		}
	}

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg));
	msg.nh.nlmsg_type = RTM_GETNEIGH;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ndmsg.ndm_family = AF_MCTP;
	msg.ndmsg.ndm_ifindex = ifindex;

	rc = do_nlmsg(ctx, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWNEIGH, display_neighbour);
	free(resp);
	return 0;
}


static int cmd_neigh_add(struct ctx *ctx, int argc, const char **argv)
{
	struct {
		struct nlmsghdr		nh;
		struct ndmsg		ndmsg;
		uint8_t			rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
	} msg;
	struct rtattr *rta;
	const char *linkstr, *eidstr, *lladdrstr;
	int rc;
	unsigned long tmp;
	uint8_t eid;
	char* endp;
	int ifindex;
	char llbuf[MAX_ADDR_LEN];
	size_t llbuf_len, rta_len;

	rc = 0;
	if (argc != 6) {
		rc = -EINVAL;
	} else {
		if (strcmp(argv[2], "dev")) {
			rc = -EINVAL;
		}
		if (strcmp(argv[4], "lladdr")) {
			rc = -EINVAL;
		}
	}
	if (rc) {
		warnx("add: invalid arguments");
		return -1;
	}

	eidstr = argv[1];
	linkstr = argv[3];
	lladdrstr = argv[5];

	get_linkmap(ctx);

	ifindex = linkmap_lookup_byname(ctx, linkstr);
	if (!ifindex) {
		warnx("invalid device %s", linkstr);
		return -1;
	}

	tmp = strtoul(eidstr, &endp, 0);
	if (endp == eidstr || tmp > 0xff) {
		warnx("invalid address %s", eidstr);
		return -1;
	}
	eid = tmp & 0xff;

	llbuf_len = sizeof(llbuf);
	rc = parse_hex_addr(lladdrstr, llbuf, &llbuf_len);
	if (rc) {
		warnx("invalid lladdr %s", lladdrstr);
		return rc;
	}

	msg.nh.nlmsg_type = RTM_NEWNEIGH;
	// request an error status since there's no other reply
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	msg.ndmsg.ndm_ifindex = ifindex;
	msg.ndmsg.ndm_family = AF_MCTP;

	rta_len = sizeof(msg.rta_buff);
	rta = (void*)msg.rta_buff;
	rta->rta_type = NDA_DST;
	rta->rta_len = RTA_LENGTH(sizeof(eid));
	memcpy(RTA_DATA(rta), &eid, sizeof(eid));
	rta = RTA_NEXT(rta, rta_len);
	rta->rta_type = NDA_LLADDR;
	rta->rta_len = RTA_LENGTH(llbuf_len);
	memcpy(RTA_DATA(rta), llbuf, llbuf_len);

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg)) +
			RTA_SPACE(sizeof(eid)) + RTA_SPACE(llbuf_len);

	rc = send_nlmsg(ctx, &msg.nh);

	return rc;
}

static int cmd_neigh(struct ctx *ctx, int argc, const char **argv) {
	const char* subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s neigh\n", ctx->top_cmd);
		fprintf(stderr, "%s neigh show [dev <network>]\n", ctx->top_cmd);
		fprintf(stderr, "%s neigh add <eid> dev <device> lladdr <physaddr>\n", ctx->top_cmd);
		fprintf(stderr, "%s neigh del  {unimplemented}\n", ctx->top_cmd);
		return 255;
	}

	if (argc == 1)
		return cmd_neigh_show(ctx, 0, NULL);

	subcmd = argv[1];
	argv++;
	argc--;

	if (!strcmp(subcmd, "show"))
		return cmd_neigh_show(ctx, argc, argv);
	else if (!strcmp(subcmd, "add"))
	 	return cmd_neigh_add(ctx, argc, argv);

	warnx("unknown route command '%s'", subcmd);
	return -1;
}

static int cmd_testhex(struct ctx *ctx, int argc, const char **argv) {
	if (argc < 2 || !strcmp(argv[1], "help")) {
		fprintf(stderr, "testhex aa:bb:12:23:...   limited to 5 output len\n");
		return 255;
	}

	char buf[5];
	size_t lenbuf = sizeof(buf);
	int rc = parse_hex_addr(argv[1], buf, &lenbuf);
	if (rc) {
		warnx("Bad hex");
	} else {
		hexdump(buf, lenbuf, "output    ");
	}
	return 0;
}


static int cmd_help(struct ctx * ctx, int argc, const char** argv);

struct command {
	const char *name;
	int (*fn)(struct ctx *, int, const char **);
	bool hidden;
} commands[] = {
	{ "link", cmd_link, 0 },
	{ "address", cmd_addr, 0 },
	{ "route", cmd_route, 0 },
	{ "neighbour", cmd_neigh, 0 },
	{ "testhex", cmd_testhex, 1 },
	{ "help", cmd_help, 0 },
};

static int cmd_help(struct ctx * ctx, int argc, const char** argv)
{
	struct command *cm;
	size_t i;
	for (i = 0, cm = commands; i < ARRAY_SIZE(commands); i++, cm++) {
		if (!cm->hidden && cm->fn != cmd_help) {
			const char * help_args[] = { cm->name, "help" };
			cm->fn(ctx, 2, help_args);
			fprintf(stderr, "\n");
		}
	}
	// TODO: pass 255 out as a program exit code
	return 255;
}

static void print_usage(const char* top_cmd) {
	fprintf(stderr, "usage: %s <command> [args]\n", top_cmd);
	fprintf(stderr, "Commands: ");
	for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!commands[i].hidden) {
			fprintf(stderr, "%s%s", (i>0 ? ", " : ""), commands[i].name);
		}
	}
	fprintf(stderr, "\n");
}

struct option options[] = {
	{ .name = "help", .has_arg = no_argument, .val = 'h' },
	{ .name = "verbose", .has_arg = no_argument, .val = 'v' },
	{ 0 },
};

int main(int argc, char **argv)
{
	struct ctx _ctx, *ctx = &_ctx;
	struct sockaddr_nl addr;
	const char *cmdname = NULL;
	struct command *cmd = NULL;
	unsigned int i;
	int rc, c, opt;

	ctx->linkmap = NULL;
	ctx->linkmap_alloc = 0;
	ctx->linkmap_count = 0;
	ctx->top_cmd = "mctp";
	ctx->verbose = false;

	/* parse initial option arguments, until the subcommand */
	for (;;) {
		c = getopt_long(argc, argv, "+hv", options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			ctx->verbose = true;
			break;
		case 'h':
			cmd_help(ctx, 0, NULL);
			return 255;
		default:
			print_usage(ctx->top_cmd);
			return 255;
		}
	}

	/* consume option arguments */
	argc -= optind - 1;
	argv += optind - 1;

	if (argc < 2 || !strcmp(argv[1], "") ) {
		print_usage(ctx->top_cmd);
		return 255;
	}

	cmdname = argv[1];

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strncmp(cmdname, commands[i].name, strlen(cmdname))) {
			cmd = &commands[i];
			break;
		}
	}

	if (!cmd)
		errx(EXIT_FAILURE, "no such command '%s'", cmdname);

	rc = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rc < 0)
		err(EXIT_FAILURE, "socket(AF_NETLINK)");

	ctx->sd = rc;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	rc = bind(ctx->sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		err(EXIT_FAILURE, "bind(AF_NETLINK)");

	opt = 1;
	rc = setsockopt(ctx->sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
			&opt, sizeof(opt));
	if (rc)
		err(EXIT_FAILURE, "setsockopt(NETLINK_F_STRICT_CHK)");

	opt = 1;
	rc = setsockopt(ctx->sd, SOL_NETLINK, NETLINK_EXT_ACK,
			&opt, sizeof(opt));
	if (rc)
		err(EXIT_FAILURE, "setsockopt(NETLINK_EXT_ACK)");

	argc--;
	argv++;

	rc = cmd->fn(ctx, argc, (const char**)argv);

	free(ctx->linkmap);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}


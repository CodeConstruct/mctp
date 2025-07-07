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
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>

#include "mctp.h"
#include "mctp-util.h"
#include "mctp-netlink.h"
#include "mctp-ops.h"

struct ctx {
	mctp_nl *nl;
	bool verbose;
	const char *top_cmd; // main() argv[0]
};

typedef int (*display_fn_t)(struct ctx *ctx, void *msg, size_t len);

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
	[RTA_GROUP_IFA] = { ARRAY_SIZE(ifa_attrnames), ifa_attrnames },
	[RTA_GROUP_NDA] = { ARRAY_SIZE(nda_attrnames), nda_attrnames },
};

static const char *rtattr_name(enum attrgroup group, unsigned int type)
{
	if (group >= ARRAY_SIZE(attrnames))
		return "unknown group";
	if (type >= attrnames[group].count)
		return "unknown attr type";
	return attrnames[group].names[type];
}

static void dump_rtnlmsg_attrs(enum attrgroup group, struct rtattr *rta,
			       size_t len)
{
	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		printf("attr %s (0x%x)\n", rtattr_name(group, rta->rta_type),
		       rta->rta_type);
		mctp_hexdump(RTA_DATA(rta), RTA_PAYLOAD(rta), "  ");
	}
}

static int display_ifinfo(struct ctx *ctx, void *p, size_t len)
{
	struct ifinfomsg *msg = p;
	size_t rta_len, nest_len, mctp_len;
	struct rtattr *rta, *rt_nest, *rt_mctp;
	char *name;
	const char *updown;
	uint8_t *addr;
	size_t name_len, addr_len;
	uint32_t mtu = 0;
	uint32_t net = 0;

	if (len < sizeof(*msg)) {
		printf("not enough data for an ifinfomsg\n");
		return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	name = mctp_get_rtnlmsg_attr(IFLA_IFNAME, rta, rta_len, &name_len);
	if (!name) {
		warnx("Missing interface name");
		name = "???";
		name_len = strlen(name);
	}

	addr = mctp_get_rtnlmsg_attr(IFLA_ADDRESS, rta, rta_len, &addr_len);
	mctp_get_rtnlmsg_attr_u32(IFLA_MTU, rta, rta_len, &mtu);

	// Nested IFLA_MCTP_NET
	rt_mctp = NULL;
	rt_nest = mctp_get_rtnlmsg_attr(IFLA_AF_SPEC, rta, rta_len, &nest_len);
	if (rt_nest) {
		rt_mctp = mctp_get_rtnlmsg_attr(AF_MCTP, rt_nest, nest_len,
						&mctp_len);
	}
	if (!rt_mctp) {
		// Ignore other interfaces
		return 0;
	}
	if (!mctp_get_rtnlmsg_attr_u32(IFLA_MCTP_NET, rt_mctp, mctp_len,
				       &net)) {
		warnx("No network attribute from %*s", (int)name_len, name);
	}

	updown = msg->ifi_flags & IFF_UP ? "up" : "down";
	// not sure if will be NULL terminated, handle either
	name_len = strnlen(name, name_len);
	printf("dev %*s index %d address ", (int)name_len, name,
	       msg->ifi_index);
	if (addr_len == 1) {
		// make it clear that it is hex not decimal
		printf("0x");
	}
	if (addr && addr_len)
		print_hex_addr(addr, addr_len);
	else
		printf("none");
	printf(" net %d mtu %d %s\n", net, mtu, updown);
	return 0;
}

static void dump_rtnlmsg_ifinfo(struct ctx *ctx, struct ifinfomsg *msg,
				size_t len)
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

	dump_rtnlmsg_attrs(RTA_GROUP_IFLA, (void *)(msg + 1),
			   len - sizeof(*msg));
}

static int display_ifaddr(struct ctx *ctx, void *p, size_t len)
{
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
	mctp_get_rtnlmsg_attr_u8(IFA_LOCAL, rta, rta_len, &eid);
	printf("eid %d net %u dev %s\n", eid,
	       mctp_nl_net_byindex(ctx->nl, msg->ifa_index),
	       mctp_nl_if_byindex(ctx->nl, msg->ifa_index));

	return 0;
}

static void dump_rtnlmsg_ifaddr(struct ctx *ctx, struct ifaddrmsg *msg,
				size_t len)
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

	dump_rtnlmsg_attrs(RTA_GROUP_IFA, (void *)(msg + 1),
			   len - sizeof(*msg));
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
	mctp_get_rtnlmsg_attr_u8(NDA_DST, rta, rta_len, &eid);
	lladdr = mctp_get_rtnlmsg_attr(NDA_LLADDR, rta, rta_len, &lladdr_len);
	printf("eid %d net %u dev %s lladdr ", eid,
	       mctp_nl_net_byindex(ctx->nl, msg->ndm_ifindex),
	       mctp_nl_if_byindex(ctx->nl, msg->ndm_ifindex));
	if (lladdr_len == 1) {
		printf("0x");
	}
	if (lladdr && lladdr_len)
		print_hex_addr(lladdr, lladdr_len);
	else
		printf("none");
	printf("\n");
	return 0;
}

static void dump_rtnlmsg_neighbour(struct ctx *ctx, struct ndmsg *msg,
				   size_t len)
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

	dump_rtnlmsg_attrs(RTA_GROUP_NDA, (void *)(msg + 1),
			   len - sizeof(*msg));
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
	mctp_get_rtnlmsg_attr_u8(RTA_DST, rta, rta_len, &dst);
	mctp_get_rtnlmsg_attr_u32(RTA_OIF, rta, rta_len, &ifindex);
	rd_nest = mctp_get_rtnlmsg_attr(RTA_METRICS, rta, rta_len, &nest_len);
	if (rd_nest) {
		mctp_get_rtnlmsg_attr_u32(RTAX_MTU, rd_nest, nest_len, &mtu);
	}
	net = mctp_nl_net_byindex(ctx->nl, ifindex);

	printf("eid min %d max %d net %d dev %s mtu %d\n", dst,
	       dst + msg->rtm_dst_len, net,
	       mctp_nl_if_byindex(ctx->nl, ifindex), mtu);
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
	mctp_hexdump(rta, rta_len, "    ");
}

static void dump_nlmsg_hdr(struct nlmsghdr *hdr, const char *indent)
{
	printf("%slen:   %d\n", indent, hdr->nlmsg_len);
	printf("%stype:  %d\n", indent, hdr->nlmsg_type);
	printf("%sflags: %d\n", indent, hdr->nlmsg_flags);
	printf("%sseq:   %d\n", indent, hdr->nlmsg_seq);
	printf("%spid:   %d\n", indent, hdr->nlmsg_pid);
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
		mctp_dump_nlmsg_error(ctx->nl, payload, len);
		break;
	case NLMSG_NOOP:
	case NLMSG_DONE:
		break;
	default:
		printf("unknown nlmsg type\n");
		mctp_hexdump(msg, len, "    ");
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
	if (ctx->verbose) {
		printf("/---------- %zd bytes total from kernel\n", len);
		dump_rtnlmsgs(ctx, msg, len);
		printf("\\----------------------------\n");
	}

	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == want_type) {
			display_fn(ctx, NLMSG_DATA(msg), NLMSG_PAYLOAD(msg, 0));
		} else
			switch (msg->nlmsg_type) {
			case NLMSG_NOOP:
			case NLMSG_DONE:
				break;
			case NLMSG_ERROR:
				mctp_display_nlmsg_error(ctx->nl,
							 NLMSG_DATA(msg),
							 NLMSG_PAYLOAD(msg, 0));
				break;
			default:
				printf("unknown nlmsg type\n");
				mctp_hexdump(msg, sizeof(msg), "    ");
			}
	}
}

static int cmd_link_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifmsg;
	} msg = { 0 };
	const char *linkstr = NULL;
	int ifindex;
	size_t len;
	int rc;

	if (argc > 2)
		errx(EXIT_FAILURE, "Bad arguments to 'link show'");

	if (argc == 2) {
		// check ifname exists
		linkstr = argv[1];
		ifindex = mctp_nl_ifindex_byname(ctx->nl, linkstr);
		if (!ifindex) {
			warnx("invalid device %s", linkstr);
			return -1;
		}
	}

	msg.nh.nlmsg_type = RTM_GETLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	if (linkstr) {
		msg.ifmsg.ifi_index = ifindex;
	} else {
		// NLM_F_DUMP prevents filtering on ifindex
		msg.nh.nlmsg_flags |= NLM_F_DUMP;
	}

	rc = mctp_nl_query(ctx->nl, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWLINK, display_ifinfo);
	free(resp);
	return 0;
}

static int do_link_set(struct ctx *ctx, int ifindex, bool have_updown, bool up,
		       uint32_t mtu, bool have_net, uint32_t net)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifmsg;
		/* Space for all attributes */
		uint8_t rta_buff[200];
	} msg = { 0 };
	struct rtattr *rta;
	size_t rta_len;

	msg.nh.nlmsg_type = RTM_NEWLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ifmsg.ifi_index = ifindex;

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));
	rta_len = sizeof(msg.rta_buff);
	rta = (void *)msg.rta_buff;

	if (have_updown) {
		msg.ifmsg.ifi_change |= IFF_UP;
		if (up)
			msg.ifmsg.ifi_flags |= IFF_UP;
	}

	if (mtu)
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, IFLA_MTU, &mtu, sizeof(mtu));

	if (have_net) {
		/* Nested
		IFLA_AF_SPEC
			AF_MCTP
				IFLA_MCTP_NET
				... future device properties
		*/
		struct rtattr *rta1, *rta2;
		size_t rta_len1, rta_len2, space1, space2;
		uint8_t buff1[100], buff2[100];

		rta2 = (void *)buff2;
		rta_len2 = sizeof(buff2);
		space2 = 0;
		if (have_net)
			space2 += mctp_put_rtnlmsg_attr(&rta2, &rta_len2,
							IFLA_MCTP_NET, &net,
							sizeof(net));
		rta1 = (void *)buff1;
		rta_len1 = sizeof(buff1);
		space1 = mctp_put_rtnlmsg_attr(&rta1, &rta_len1,
					       AF_MCTP | NLA_F_NESTED, buff2,
					       space2);
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, IFLA_AF_SPEC | NLA_F_NESTED, buff1,
			space1);
	}

	return mctp_nl_send(ctx->nl, &msg.nh);
}

static int cmd_link_set(struct ctx *ctx, int argc, const char **argv)
{
	bool have_updown = false, up = false, have_net = false;
	int i;
	int ifindex;
	uint32_t mtu = 0, net = 0;
	const char *curr, *linkstr, *mtustr = NULL, *netstr = NULL;
	const char **next = NULL;

	if (argc < 3)
		errx(EXIT_FAILURE, "Bad arguments to 'link set'");

	linkstr = argv[1];
	ifindex = mctp_nl_ifindex_byname(ctx->nl, linkstr);
	if (!ifindex) {
		warnx("invalid device %s", linkstr);
		return -1;
	}

	for (i = 2; i < argc; i++) {
		curr = argv[i];
		if (next) {
			*next = curr;
			next = NULL;
			continue;
		}

		if (!strcmp(curr, "up")) {
			have_updown = true;
			up = true;
		} else if (!strcmp(curr, "down")) {
			have_updown = true;
			up = false;
		} else if (!strcmp(curr, "mtu")) {
			next = &mtustr;
		} else if (!strcmp(curr, "network") || !strcmp(curr, "net")) {
			have_net = true;
			next = &netstr;
		} else {
			warnx("Unknown link set command '%s'", curr);
			return -1;
		}
	}

	if (next) {
		warnx("Bad link set arguments");
		return -1;
	}

	if (mtustr) {
		if (parse_uint32(mtustr, &mtu) < 0 || mtu == 0) {
			warnx("invalid mtu %s", mtustr);
			return -1;
		}
	}

	if (netstr) {
		if (parse_uint32(netstr, &net) < 0 || net == 0) {
			warnx("invalid net %s", netstr);
			return -1;
		}
	}

	return do_link_set(ctx, ifindex, have_updown, up, mtu, have_net, net);
}

static int cmd_link_serial(struct ctx *ctx, int argc, const char **argv)
{
	const char *tty;
	int fd, rc, i;

	if (argc != 2) {
		fprintf(stderr, "%s link serial: no device specified\n",
			ctx->top_cmd);
		return 255;
	}

	tty = argv[1];

	fd = open(tty, O_RDWR);
	if (fd < 0)
		err(EXIT_FAILURE, "Can't open tty %s", tty);

	i = N_MCTP;

	rc = ioctl(fd, TIOCSETD, &i);
	if (rc)
		err(EXIT_FAILURE, "Can't set tty line discipline");

	pause();

	return 0;
}

static int cmd_link(struct ctx *ctx, int argc, const char **argv)
{
	const char *subcmd;

	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s link\n", ctx->top_cmd);
		fprintf(stderr, "%s link show [ifname]\n", ctx->top_cmd);
		fprintf(stderr,
			"%s link set <ifname> [up|down] [mtu <mtu>] [network <net>] [bus-owner <physaddr>]\n",
			ctx->top_cmd);
		fprintf(stderr, "%s link serial <device>\n", ctx->top_cmd);
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
		return cmd_link_set(ctx, argc, argv);
	} else if (!strcmp(subcmd, "serial")) {
		return cmd_link_serial(ctx, argc, argv);
	} else {
		warnx("Unknown link command '%s'", subcmd);
	}

	return -1;
}

static int cmd_addr_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifmsg;
		struct rtattr rta;
		char ifname[16];
	} msg = { 0 };
	const char *ifname = NULL;
	int ifindex = 0;
	size_t len;
	int rc;

	if (argc > 1) {
		ifname = argv[1];
		ifindex = mctp_nl_ifindex_byname(ctx->nl, ifname);
		if (ifindex == 0) {
			warnx("Unknown interface '%s'", ifname);
			return -1;
		}
	}

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	msg.nh.nlmsg_type = RTM_GETADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ifmsg.ifa_family = AF_MCTP;
	msg.ifmsg.ifa_index = ifindex;

	rc = mctp_nl_query(ctx->nl, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWADDR, display_ifaddr);
	free(resp);
	return 0;
}

// cmdname is for error messages.
// rtm_command is RTM_NEWADDR or RTM_DELADDR
static int cmd_addr_addremove(struct ctx *ctx, const char *cmdname,
			      int rtm_command, int argc, const char **argv)
{
	const char *eidstr, *linkstr;
	uint32_t tmp;
	uint8_t eid;
	int ifindex;

	if (argc != 4) {
		warnx("%s: invalid command line arguments", cmdname);
		return -1;
	}

	if (strcmp(argv[2], "dev")) {
		warnx("invalid dev spec");
		return -1;
	}

	mctp_ops_init();

	eidstr = argv[1];
	linkstr = argv[3];

	ifindex = mctp_nl_ifindex_byname(ctx->nl, linkstr);
	if (!ifindex) {
		warnx("invalid device %s", linkstr);
		return -1;
	}

	if (parse_uint32(eidstr, &tmp) < 0 || tmp > 0xff) {
		warnx("invalid address %s", eidstr);
		return -1;
	}
	eid = tmp & 0xff;

	return mctp_nl_addr(ctx->nl, eid, ifindex, rtm_command);
}

static int cmd_addr_add(struct ctx *ctx, int argc, const char **argv)
{
	return cmd_addr_addremove(ctx, "add", RTM_NEWADDR, argc, argv);
}

static int cmd_addr_remove(struct ctx *ctx, int argc, const char **argv)
{
	return cmd_addr_addremove(ctx, "del", RTM_DELADDR, argc, argv);
}

static int cmd_addr(struct ctx *ctx, int argc, const char **argv)
{
	const char *subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s address\n", ctx->top_cmd);
		fprintf(stderr, "%s address show [IFNAME]\n", ctx->top_cmd);
		fprintf(stderr, "%s address add <eid> dev <IFNAME>\n",
			ctx->top_cmd);
		fprintf(stderr, "%s address del <eid> dev <IFNAME>\n",
			ctx->top_cmd);
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
	else if (!strcmp(subcmd, "del"))
		return cmd_addr_remove(ctx, argc, argv);

	warnx("unknown address command '%s'", subcmd);
	return -1;
}

static int cmd_route_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct rtmsg rtmsg;
		// struct rtattr		rta;
	} msg = { 0 };
	size_t len;
	int rc;

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.rtmsg));

	msg.nh.nlmsg_type = RTM_GETROUTE;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.rtmsg.rtm_family = AF_MCTP;

	rc = mctp_nl_query(ctx->nl, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWROUTE, display_route);
	free(resp);
	return 0;
}

static int cmd_route_add(struct ctx *ctx, int argc, const char **argv)
{
	const char *eidstr = NULL, *linkstr = NULL, *mtustr = NULL;
	uint32_t mtu = 0, eid = 0;
	int ifindex = 0;
	int rc = 0;

	if (!(argc == 4 || argc == 6)) {
		rc = -EINVAL;
	} else {
		if (strcmp(argv[2], "via")) {
			rc = -EINVAL;
		} else {
			eidstr = argv[1];
			linkstr = argv[3];
		}
	}
	if (argc == 6) {
		if (strcmp(argv[4], "mtu")) {
			rc = -EINVAL;
		} else {
			mtustr = argv[5];
		}
	}

	if (mtustr) {
		if (parse_uint32(mtustr, &mtu) < 0) {
			rc = -EINVAL;
		}
	}
	if (eidstr && parse_uint32(eidstr, &eid) < 0) {
		rc = -EINVAL;
	}
	if (eid > 0xff) {
		warnx("Bad eid");
		rc = -EINVAL;
	}
	ifindex = mctp_nl_ifindex_byname(ctx->nl, linkstr);
	if (!ifindex) {
		warnx("add: invalid device %s", linkstr);
		rc = -EINVAL;
	}
	if (rc) {
		warnx("add: invalid command line arguments");
		return -1;
	}

	return mctp_nl_route_add(ctx->nl, eid, ifindex, mtu);
}

static int cmd_route_del(struct ctx *ctx, int argc, const char **argv)
{
	const char *eidstr = NULL;
	uint32_t tmp = 0;
	int ifindex = 0;
	uint8_t eid;
	int rc = 0;

	if (argc != 4) {
		rc = -EINVAL;
	} else {
		if (strcmp(argv[2], "via")) {
			rc = -EINVAL;
		}
		eidstr = argv[1];
	}
	if (eidstr && parse_uint32(eidstr, &tmp) < 0) {
		rc = -EINVAL;
	}
	if (tmp > 0xff) {
		warnx("Bad eid");
		rc = -EINVAL;
	}
	ifindex = mctp_nl_ifindex_byname(ctx->nl, argv[3]);
	if (!ifindex) {
		warnx("del: invalid device %s", argv[3]);
		rc = -EINVAL;
	}
	if (rc) {
		warnx("del: invalid command line arguments");
		return -1;
	}
	eid = tmp & 0xff;

	return mctp_nl_route_del(ctx->nl, eid, ifindex);
}

static int cmd_route(struct ctx *ctx, int argc, const char **argv)
{
	const char *subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s route\n", ctx->top_cmd);
		fprintf(stderr, "%s route show [net <network>]\n",
			ctx->top_cmd);
		fprintf(stderr, "%s route add <eid> via <dev> [mtu <mtu>]\n",
			ctx->top_cmd);
		fprintf(stderr, "%s route del <eid> via <dev>\n", ctx->top_cmd);
		return 255;
	}

	if (argc == 1)
		return cmd_route_show(ctx, 0, NULL);

	subcmd = argv[1];
	argv++;
	argc--;

	if (!strcmp(subcmd, "show"))
		return cmd_route_show(ctx, argc, argv);
	else if (!strcmp(subcmd, "add"))
		return cmd_route_add(ctx, argc, argv);
	else if (!strcmp(subcmd, "del"))
		return cmd_route_del(ctx, argc, argv);

	warnx("unknown route command '%s'", subcmd);
	return -1;
}

static int cmd_neigh_show(struct ctx *ctx, int argc, const char **argv)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndmsg;
	} msg = { 0 };
	const char *linkstr = NULL;
	int ifindex = 0;
	size_t len;
	int rc;

	if (!(argc <= 1 || argc == 3)) {
		warnx("show: invalid command line arguments");
		return -1;
	}
	if (argc == 3) {
		if (strcmp(argv[1], "dev")) {
			warnx("show: invalid command line arguments");
			return -1;
		}
		linkstr = argv[2];
	}

	if (linkstr) {
		ifindex = mctp_nl_ifindex_byname(ctx->nl, linkstr);
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

	rc = mctp_nl_query(ctx->nl, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	display_rtnlmsgs(ctx, resp, len, RTM_NEWNEIGH, display_neighbour);
	free(resp);
	return 0;
}

struct mctp_neighalter_msg {
	struct nlmsghdr nh;
	struct ndmsg ndmsg;
	uint8_t rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
};

static int fill_neighalter_args(struct ctx *ctx,
				struct mctp_neighalter_msg *msg,
				struct rtattr **prta, size_t *prta_len,
				const char *eidstr, const char *linkstr)
{
	struct rtattr *rta;
	uint32_t tmp;
	uint8_t eid;
	int ifindex;
	size_t rta_len;

	ifindex = mctp_nl_ifindex_byname(ctx->nl, linkstr);
	if (!ifindex) {
		warnx("invalid device %s", linkstr);
		return -1;
	}

	if (parse_uint32(eidstr, &tmp) < 0 || tmp > 0xff) {
		warnx("invalid address %s", eidstr);
		return -1;
	}
	eid = tmp & 0xff;

	memset(msg, 0x0, sizeof(*msg));
	msg->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg->ndmsg.ndm_ifindex = ifindex;
	msg->ndmsg.ndm_family = AF_MCTP;

	msg->nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg->ndmsg));
	rta_len = sizeof(msg->rta_buff);
	rta = (void *)msg->rta_buff;

	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_DST,
						   &eid, sizeof(eid));

	if (prta)
		*prta = rta;
	if (prta_len)
		*prta_len = rta_len;
	return 0;
}

static int cmd_neigh_add(struct ctx *ctx, int argc, const char **argv)
{
	struct mctp_neighalter_msg msg;
	struct rtattr *rta;
	const char *linkstr, *eidstr, *lladdrstr;
	int rc;
	uint8_t llbuf[MAX_ADDR_LEN];
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
		warnx("add: invalid command line arguments");
		return -1;
	}

	eidstr = argv[1];
	linkstr = argv[3];
	lladdrstr = argv[5];

	llbuf_len = sizeof(llbuf);
	rc = parse_hex_addr(lladdrstr, llbuf, &llbuf_len);
	if (rc) {
		warnx("invalid lladdr %s", lladdrstr);
		return rc;
	}

	rc = fill_neighalter_args(ctx, &msg, &rta, &rta_len, eidstr, linkstr);
	if (rc) {
		return -1;
	}

	msg.nh.nlmsg_type = RTM_NEWNEIGH;
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_LLADDR,
						  llbuf, llbuf_len);
	return mctp_nl_send(ctx->nl, &msg.nh);
}

static int cmd_neigh_del(struct ctx *ctx, int argc, const char **argv)
{
	struct mctp_neighalter_msg msg;
	const char *linkstr, *eidstr;
	int rc;

	rc = 0;
	if (argc != 4) {
		rc = -EINVAL;
	} else {
		if (strcmp(argv[2], "dev")) {
			rc = -EINVAL;
		}
	}
	if (rc) {
		warnx("del: invalid command line arguments");
		return -1;
	}

	eidstr = argv[1];
	linkstr = argv[3];

	rc = fill_neighalter_args(ctx, &msg, NULL, NULL, eidstr, linkstr);
	if (rc) {
		return -1;
	}

	msg.nh.nlmsg_type = RTM_DELNEIGH;
	return mctp_nl_send(ctx->nl, &msg.nh);
}

static int cmd_neigh(struct ctx *ctx, int argc, const char **argv)
{
	const char *subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s neigh\n", ctx->top_cmd);
		fprintf(stderr, "%s neigh show [dev <network>]\n",
			ctx->top_cmd);
		fprintf(stderr,
			"%s neigh add <eid> dev <device> lladdr <physaddr>\n",
			ctx->top_cmd);
		fprintf(stderr,
			"        <physaddr> syntax is for example \"1d\" or \"aa:bb:cc:11:22:33\"\n");
		fprintf(stderr, "%s neigh del <eid> dev <device>\n",
			ctx->top_cmd);
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
	else if (!strcmp(subcmd, "del"))
		return cmd_neigh_del(ctx, argc, argv);

	warnx("unknown route command '%s'", subcmd);
	return -1;
}

static int cmd_monitor(struct ctx *ctx, int argc, const char **argv)
{
	int rc, sd;

	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s monitor\n", ctx->top_cmd);
		return 255;
	}

	rc = mctp_nl_monitor(ctx->nl, true);
	if (rc < 0) {
		warnx("Failed monitor: %s", strerror(-rc));
		return -1;
	} else {
		sd = rc;
	}

	while (1) {
		struct nlmsghdr *resp;
		size_t resp_len;

		rc = mctp_nl_recv_all(ctx->nl, sd, &resp, &resp_len);
		if (rc < 0) {
			warnx("error recv: %s", strerror(-rc));
			continue;
		}
		dump_rtnlmsgs(ctx, resp, resp_len);
		free(resp);
	}
	return 0;
}

static int cmd_help(struct ctx *ctx, int argc, const char **argv);

struct command {
	const char *name;
	int (*fn)(struct ctx *, int, const char **);
	bool hidden;
} commands[] = {
	// clang-format off
	{ "link", cmd_link, 0 },
	{ "address", cmd_addr, 0 },
	{ "route", cmd_route, 0 },
	{ "neighbour", cmd_neigh, 0 },
	{ "monitor", cmd_monitor, 0 },
	{ "help", cmd_help, 0 },
	// clang-format on
};

static int cmd_help(struct ctx *ctx, int argc, const char **argv)
{
	struct command *cm;
	size_t i;
	for (i = 0, cm = commands; i < ARRAY_SIZE(commands); i++, cm++) {
		if (!cm->hidden && cm->fn != cmd_help) {
			const char *help_args[] = { cm->name, "help" };
			cm->fn(ctx, 2, help_args);
			fprintf(stderr, "\n");
		}
	}
	// TODO: pass 255 out as a program exit code
	return 255;
}

static void print_usage(const char *top_cmd)
{
	fprintf(stderr, "usage: %s <command> [args]\n", top_cmd);
	fprintf(stderr, "Commands: ");
	for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!commands[i].hidden) {
			fprintf(stderr, "%s%s", (i > 0 ? ", " : ""),
				commands[i].name);
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
	struct ctx _ctx = { 0 }, *ctx = &_ctx;
	const char *cmdname = NULL;
	struct command *cmd = NULL;
	unsigned int i;
	int rc, c;

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

	if (argc < 2 || !strcmp(argv[1], "")) {
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

	mctp_ops_init();
	ctx->nl = mctp_nl_new(ctx->verbose);
	if (!ctx->nl)
		errx(EXIT_FAILURE, "Error creating netlink object");
	if (ctx->verbose)
		mctp_nl_linkmap_dump(ctx->nl);

	argc--;
	argv++;

	rc = cmd->fn(ctx, argc, (const char **)argv);

	mctp_nl_close(ctx->nl);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

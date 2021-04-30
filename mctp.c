
#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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
	struct linkmap_entry	*linkmap;
	int			linkmap_count;
	int			linkmap_alloc;
	const char* top_cmd; // main() argv[0]
};

static void hexdump(const char *buf, int len, const char *indent)
{
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

enum attrgroup {
	RTA_GROUP_IFLA,
	RTA_GROUP_IFA,
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

static struct {
	size_t count;
	const char **names;
} attrnames[] = {
	[RTA_GROUP_IFLA] = { ARRAY_SIZE(ifla_attrnames), ifla_attrnames },
	[RTA_GROUP_IFA]  = { ARRAY_SIZE(ifa_attrnames), ifa_attrnames },
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

static void dump_rtnlmsg_ifinfo(struct ifinfomsg *msg, size_t len)
{
	if (len < sizeof(*msg)) {
		printf("not enough data for an ifinfomsg\n");
		return;
	}

	printf("ifinfo:\n");
	printf("  family: %d\n", msg->ifi_family);
	printf("  type:   %d\n", msg->ifi_type);
	printf("  index:  %d\n", msg->ifi_index);
	printf("  flags:  0x%08x\n", msg->ifi_flags);

	dump_rtnlmsg_attrs(RTA_GROUP_IFLA,
			(void *)(msg + 1), len - sizeof(*msg));
}

static void dump_rtnlmsg_ifaddr(struct ifaddrmsg *msg, size_t len)
{
	if (len < sizeof(*msg)) {
		printf("not enough data for an ifaddrmsg\n");
		return;
	}

	printf("ifaddr:\n");
	printf("  family: %d\n", msg->ifa_family);
	printf("  prefixlen:   %d\n", msg->ifa_prefixlen);
	printf("  flags:  0x%08x\n", msg->ifa_flags);
	printf("  scope:  %d\n", msg->ifa_scope);
	printf("  index:  %d\n", msg->ifa_index);

	dump_rtnlmsg_attrs(RTA_GROUP_IFA,
			(void *)(msg + 1), len - sizeof(*msg));
}

static void dump_rtnlmsg_route(struct rtmsg *msg, size_t len)
{
	if (len < sizeof(*msg)) {
		printf("not enough data for a rtmsg\n");
		return;
	}

	printf("rtmsg:\n");
	printf("  family:   %d\n", msg->rtm_family);
	printf("  dst_len:  %d\n", msg->rtm_dst_len);
	printf("  src_len:  %d\n", msg->rtm_src_len);
	printf("  tos:      %d\n", msg->rtm_tos);
	printf("  table:    %d\n", msg->rtm_table);
	printf("  protocol: %d\n", msg->rtm_protocol);
	printf("  scope:    %d\n", msg->rtm_scope);
	printf("  type:     %d\n", msg->rtm_type);
	printf("  flags:    0x%08x\n", msg->rtm_flags);

	printf("  Attribute dump:\n");
	hexdump((void *)(msg + 1), len - sizeof(*msg), "    ");

}


static void dump_nlmsg_hdr(struct nlmsghdr *hdr, const char *indent)
{
	printf("%slen:   %d\n", indent, hdr->nlmsg_len);
	printf("%stype:  %d\n", indent, hdr->nlmsg_type);
	printf("%sflags: %d\n", indent, hdr->nlmsg_flags);
	printf("%sseq:   %d\n", indent, hdr->nlmsg_seq);
	printf("%spid:   %d\n", indent, hdr->nlmsg_pid);
}


static void dump_rtnlmsg(struct nlmsghdr *msg)
{
	void *payload;
	size_t len;

	printf("header:\n");
	dump_nlmsg_hdr(msg, "  ");

	if (msg->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (void *)(msg + 1);
		printf("error:\n");
		printf("  err: %d %s\n", err->error, strerror(-err->error));
		printf("  msg:\n");
		dump_nlmsg_hdr(&err->msg, "    ");
		return;
	}

	len = NLMSG_PAYLOAD(msg, 0);
	payload = NLMSG_DATA(msg);

	switch (msg->nlmsg_type) {
	case RTM_NEWLINK:
		dump_rtnlmsg_ifinfo(payload, len);
		break;
	case RTM_NEWADDR:
		dump_rtnlmsg_ifaddr(payload, len);
		break;
	case RTM_NEWROUTE:
		dump_rtnlmsg_route(payload, len);
		break;
	case NLMSG_NOOP:
	case NLMSG_ERROR:
	case NLMSG_DONE:
		break;
	default:
		printf("unknown nlmsg type\n");
		hexdump((void *)msg, len, "    ");
	}
}

static void dump_rtnlmsgs(struct nlmsghdr *msg, size_t len)
{
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len))
		dump_rtnlmsg(msg);
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
					hexdump((void *)(err + 1), ext_len, "extack    ");
				}
			}
		} else {
			warnx("Unexpected message instead of status return:");
			dump_rtnlmsg(msg);
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

static int do_nlmsg(struct ctx *ctx, struct nlmsghdr *msg)
{
	struct sockaddr_nl addr;
	socklen_t addrlen;
	char resp[4096];
	int rc;

	rc = send_nlmsg(ctx, msg);
	if (rc)
		return rc;

	addrlen = sizeof(addr);
	rc = recvfrom(ctx->sd, resp, sizeof(resp), 0,
			(struct sockaddr *)&addr, &addrlen);

	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");

	if (addrlen != sizeof(addr)) {
		warn("recvfrom: weird addrlen? (%d, expecting %zd)", addrlen,
				sizeof(addr));
	}

	printf("%d bytes from {%d,%d}\n", rc, addr.nl_family, addr.nl_pid);

	dump_rtnlmsgs((struct nlmsghdr *)resp, rc);

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
	linkmap_dump(ctx);
	return rc;
}

static int linkmap_lookup_name(struct ctx *ctx, const char *ifname)
{
	int i;

	for (i = 0; i < ctx->linkmap_count; i++) {
		struct linkmap_entry *entry = &ctx->linkmap[i];
		if (!strcmp(entry->ifname, ifname))
			return entry->ifindex;
	}

	return 0;
}

static int cmd_link_show(struct ctx *ctx, int argc, const char **argv) 
{
	struct {
		struct nlmsghdr		nh;
		struct ifinfomsg	ifmsg;
		struct rtattr		rta;
		char			ifname[16];
	} msg;
	const char *ifname = NULL;
	size_t ifnamelen = 0;

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
		msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg) +
					RTA_LENGTH(ifnamelen));
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

	do_nlmsg(ctx, &msg.nh);
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
	struct {
		struct nlmsghdr		nh;
		struct ifaddrmsg	ifmsg;
		struct rtattr		rta;
		char			ifname[16];
	} msg;
	const char *ifname = NULL;
	size_t ifnamelen;

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
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	msg.nh.nlmsg_type = RTM_GETADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.ifmsg.ifa_index = 1;
	msg.ifmsg.ifa_family = AF_MCTP;

	if (ifname) {
		msg.rta.rta_type = IFA_LABEL;
		msg.rta.rta_len = RTA_LENGTH(ifnamelen);
		strncpy(RTA_DATA(&msg.rta), ifname, ifnamelen);
	}

	do_nlmsg(ctx, &msg.nh);

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

	ifindex = linkmap_lookup_name(ctx, linkstr);
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

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg) +
			RTA_SPACE(sizeof(eid)));

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
	struct {
		struct nlmsghdr		nh;
		struct rtmsg	 rtmsg;
		// struct rtattr		rta;
	} msg;

	memset(&msg, 0, sizeof(msg));
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.rtmsg));

	msg.nh.nlmsg_type = RTM_GETROUTE;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.rtmsg.rtm_family = AF_MCTP;

	do_nlmsg(ctx, &msg.nh);

	return 0;

}

static int cmd_route(struct ctx *ctx, int argc, const char **argv)
{
	const char* subcmd;
	if (argc == 2 && !strcmp(argv[1], "help")) {
		fprintf(stderr, "%s route\n", ctx->top_cmd);
		fprintf(stderr, "%s route show [net <network>]\n", ctx->top_cmd);
		fprintf(stderr, "%s route add  {unimplemented}\n", ctx->top_cmd);
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

static int cmd_help(struct ctx * ctx, int argc, const char** argv);

struct command {
	const char *name;
	int (*fn)(struct ctx *, int, const char **);
} commands[] = {
	{ "link", cmd_link },
	{ "address", cmd_addr },
	{ "route", cmd_route },
	{ "help", cmd_help },
};

static int cmd_help(struct ctx * ctx, int argc, const char** argv) 
{
	for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		if (commands[i].fn != cmd_help) {
			const char * help_args[] = { commands[i].name, "help" };
			commands[i].fn(ctx, 2, help_args);
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
		fprintf(stderr, "%s%s", (i>0 ? ", " : ""), commands[i].name);
	}
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct ctx _ctx, *ctx = &_ctx;
	struct sockaddr_nl addr;
	const char *cmdname = NULL;
	struct command *cmd = NULL;
	unsigned int i;
	int rc, opt;

	ctx->linkmap = NULL;
	ctx->linkmap_alloc = 0;
	ctx->linkmap_count = 0;
	ctx->top_cmd = "mctp";

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


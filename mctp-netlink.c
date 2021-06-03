#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <err.h>

#include <sys/socket.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>

#include "mctp-netlink.h"
#include "mctp.h"
#include "mctp-util.h"

struct linkmap_entry {
	int ifindex;
	char    ifname[IFNAMSIZ+1];
	int net;
};

struct mctp_nl {
	int         sd;
	struct linkmap_entry    *linkmap;
	int         linkmap_count;
	int         linkmap_alloc;
	bool        verbose;
};

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static int fill_linkmap(mctp_nl *nl);
static int linkmap_add_entry(mctp_nl *nl, struct ifinfomsg *info,
		const char *ifname, size_t ifname_len, int net);

mctp_nl * mctp_nl_new(bool verbose)
{
	struct sockaddr_nl addr;
	int opt, rc;
	mctp_nl *nl;

	nl = calloc(1, sizeof(*nl));
	if (!nl) {
		warn("calloc failed");
		return NULL;
	}

	nl->sd = -1;
	nl->verbose = verbose;
	rc = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rc < 0)
		goto err;

	nl->sd = rc;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	rc = bind(nl->sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		goto err;

	opt = 1;
	rc = setsockopt(nl->sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
			&opt, sizeof(opt));
	if (rc)
		goto err;

	opt = 1;
	rc = setsockopt(nl->sd, SOL_NETLINK, NETLINK_EXT_ACK,
			&opt, sizeof(opt));
	if (rc)
		goto err;

	rc = fill_linkmap(nl);
	if (rc)
		goto err;

	return nl;
err:
	mctp_nl_close(nl);
	return NULL;
}

int mctp_nl_close(mctp_nl *nl)
{
	int rc;

	free(nl->linkmap);
	rc = close(nl->sd);
	if (rc)
		return rc;
	nl->sd = -1;
	return 0;
}

/* Pointer returned on match, optionally returns ret_len */
void* mctp_get_rtnlmsg_attr(int rta_type, struct rtattr *rta, size_t len,
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
	if (ret_len) {
		*ret_len = 0;
	}
	return NULL;
}

bool mctp_get_rtnlmsg_attr_u32(int rta_type, struct rtattr *rta, size_t len,
				uint32_t *ret_value) {
	size_t plen;
	uint32_t *p = mctp_get_rtnlmsg_attr(rta_type, rta, len, &plen);
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

bool mctp_get_rtnlmsg_attr_u8(int rta_type, struct rtattr *rta, size_t len,
				uint8_t *ret_value) {
	size_t plen;
	uint8_t *p = mctp_get_rtnlmsg_attr(rta_type, rta, len, &plen);
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

/* Returns the space used */
size_t mctp_put_rtnlmsg_attr(struct rtattr **prta, size_t *rta_len,
	unsigned short type, const void* value, size_t val_len)
{
	struct rtattr *rta = *prta;
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(val_len);
	memcpy(RTA_DATA(rta), value, val_len);
	*prta = RTA_NEXT(*prta, *rta_len);
	return RTA_SPACE(val_len);
}


static void dump_nlmsg_hdr(struct nlmsghdr *hdr, const char *indent)
{
	printf("%slen:   %d\n", indent, hdr->nlmsg_len);
	printf("%stype:  %d\n", indent, hdr->nlmsg_type);
	printf("%sflags: %d\n", indent, hdr->nlmsg_flags);
	printf("%sseq:   %d\n", indent, hdr->nlmsg_seq);
	printf("%spid:   %d\n", indent, hdr->nlmsg_pid);
}

void mctp_display_nlmsg_error(struct nlmsgerr *errmsg, size_t errlen)
{
	size_t rta_len, errstrlen;
	struct rtattr *rta;
	char* errstr;

	if (errlen < sizeof(*errmsg)) {
		printf("short error message (%zu bytes)\n", errlen);
		return;
	}
	// skip the whole errmsg->msg and following payload
	rta = (void *)errmsg + offsetof(struct nlmsgerr, msg) + errmsg->msg.nlmsg_len;
	rta_len = (void*)errmsg + errlen - (void*)rta;

	printf("Error from kernel: %s (%d)\n", strerror(-errmsg->error), errmsg->error);
	errstr = mctp_get_rtnlmsg_attr(NLMSGERR_ATTR_MSG, rta, rta_len, &errstrlen);
	if (errstr) {
		errstrlen = strnlen(errstr, errstrlen);
		printf("  %*s\n", (int)errstrlen, errstr);
	}
}

void mctp_dump_nlmsg_error(struct nlmsgerr *errmsg, size_t errlen)
{
	printf("error:\n");
	mctp_display_nlmsg_error(errmsg, errlen);
	printf("  error packet dump:\n");
	mctp_hexdump(errmsg, errlen, "    ");
	printf("  error in reply to message:\n");
	dump_nlmsg_hdr(&errmsg->msg, "    ");
}

/* Receive and handle a NLMSG_ERROR and return the error code */
static int handle_nlmsg_ack(mctp_nl *nl)
{
	char resp[4096];
	struct nlmsghdr *msg;
	int rc;
	size_t len;

	rc = recvfrom(nl->sd, resp, sizeof(resp), 0, NULL, NULL);
	if (rc < 0)
		return rc;
	len = rc;
	msg = (void*)resp;

	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *errmsg = NLMSG_DATA(msg);
			size_t errlen = NLMSG_PAYLOAD(msg, 0);
			if (errmsg->error) {
				if (nl->verbose)
					mctp_dump_nlmsg_error(errmsg, errlen);
				else
					mctp_display_nlmsg_error(errmsg, errlen);
				rc = errmsg->error;
			}
		} else {
			warnx("Unexpected message instead of status return:");
			// TODO
			// dump_rtnlmsg(nl, msg);
		}
	}
	return rc;
}

/*
 * Note that only rtnl_doit_func() handlers like RTM_NEWADDR
 * will automatically return a response to NLM_F_ACK, other requests
 * shouldn't have it set.
 */
int mctp_nl_send(mctp_nl *nl, struct nlmsghdr *msg)
{
	struct sockaddr_nl addr;
	int rc;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	rc = sendto(nl->sd, msg, msg->nlmsg_len, 0,
			(struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0)
		return rc;

	if (rc != (int)msg->nlmsg_len)
		warnx("sendto: short send (%d, expected %d)",
				rc, msg->nlmsg_len);

	if (msg->nlmsg_flags & NLM_F_ACK) {
		return handle_nlmsg_ack(nl);
	}
	return 0;
}

/* Returns if the last message is NLMSG_DONE, or isn't multipart */
static bool nlmsgs_are_done(struct nlmsghdr *msg, size_t len)
{
	bool done = false;
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (done)
			warnx("received message after NLMSG_DONE");
		done = (msg->nlmsg_type == NLMSG_DONE)
			|| !(msg->nlmsg_flags & NLM_F_MULTI);
	}
	return done;
}

/* respp is optional for returned buffer, length is set in resp+lenp */
int mctp_nl_query(mctp_nl *nl, struct nlmsghdr *msg,
		struct nlmsghdr **respp, size_t *resp_lenp)
{
	void *respbuf;
	struct nlmsghdr *resp;
	struct sockaddr_nl addr;
	socklen_t addrlen;
	size_t newlen, readlen, pos;
	bool done;
	int rc;

	rc = mctp_nl_send(nl, msg);
	if (rc)
		return rc;

	pos = 0;
	respbuf = NULL;
	done = false;

	// read all the responses into a single buffer
	while (!done) {
		rc = recvfrom(nl->sd, NULL, 0, MSG_PEEK|MSG_TRUNC, NULL, 0);
		if (rc < 0)
			err(EXIT_FAILURE, "recvfrom(MSG_PEEK)");

		if (rc == 0) {
			if (pos == 0) {
				warnx("No response to message");
				return -1;
			} else {
				// No more datagrams
				break;
			}
		}

		readlen = rc;
		newlen = pos + readlen;
		respbuf = realloc(respbuf, newlen);
		if (!respbuf)
			err(EXIT_FAILURE, "allocation of %zu failed", newlen);
		resp = respbuf + pos;

		addrlen = sizeof(addr);
		rc = recvfrom(nl->sd, resp, readlen, MSG_TRUNC,
				(struct sockaddr *)&addr, &addrlen);
		if (rc < 0)
			err(EXIT_FAILURE, "recvfrom()");

		if ((size_t)rc > readlen)
			warnx("recvfrom: extra message data? (got %d, exp %zd)",
					rc, readlen);

		if (addrlen != sizeof(addr)) {
			warn("recvfrom: weird addrlen? (%d, expecting %zd)", addrlen,
					sizeof(addr));
		}

		done = nlmsgs_are_done(resp, rc);
		pos = min(newlen, pos+rc);
	}

	if (respp) {
		*respp = respbuf;
		*resp_lenp = pos;
	} else {
		free(respbuf);
	}

	return 0;
}

static int parse_getlink_dump(mctp_nl *nl, struct nlmsghdr *nlh, int len)
{
	struct ifinfomsg *info;

	for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct rtattr *rta, *rt_nest, *rt_mctp;
		char *ifname;
		size_t ifname_len, rlen, nlen, mlen;
		uint32_t net;

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

		rt_mctp = false;
		rt_nest = mctp_get_rtnlmsg_attr(IFLA_AF_SPEC, rta, rlen, &nlen);
		if (rt_nest) {
			rt_mctp = mctp_get_rtnlmsg_attr(AF_MCTP, rt_nest, nlen, &mlen);
		}
		if (!rt_mctp) {
			/* Skip non-MCTP interfaces */
			continue;
		}
		if (!mctp_get_rtnlmsg_attr_u32(IFLA_MCTP_NET, rt_mctp, mlen, &net)) {
			warnx("Missing IFLA_MCTP_NET");
			continue;
		}

		ifname = mctp_get_rtnlmsg_attr(IFLA_IFNAME, rta, rlen, &ifname_len);
		if (!ifname) {
			warnx("no ifname?");
			continue;
		}
		ifname_len = strnlen(ifname, ifname_len);
		linkmap_add_entry(nl, info, ifname, ifname_len, net);
	}
	// Not done.
	return 1;
}

static int fill_linkmap(mctp_nl *nl)
{
	struct {
		struct nlmsghdr     nh;
		struct ifinfomsg    ifmsg;
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

	rc = mctp_nl_send(nl, &msg.nh);
	if (rc)
		return rc;

	buf = NULL;
	buflen = 0;
	addrlen = sizeof(addr);

	for (;;) {
		rc = recvfrom(nl->sd, NULL, 0, MSG_TRUNC | MSG_PEEK,
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

		rc = recvfrom(nl->sd, buf, buflen, 0,
				(struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			warn("recvfrom()");
			break;
		}

		rc = parse_getlink_dump(nl, buf, rc);
		if (rc <= 0)
			break;
	}

	free(buf);
	return rc;
}

void mctp_nl_linkmap_dump(const mctp_nl *nl)
{
	int i;

	printf("linkmap\n");
	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		printf("  %d: %s, net %d\n", entry->ifindex, entry->ifname,
			entry->net);
	}
}

int mctp_nl_ifindex_byname(const mctp_nl *nl, const char *ifname)
{
	int i;

	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		if (!strcmp(entry->ifname, ifname))
			return entry->ifindex;
	}

	return 0;
}

const char* mctp_nl_if_byindex(const mctp_nl *nl, int index)
{
	int i;

	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		if (entry->ifindex == index) {
			return entry->ifname;
		}
	}

	return NULL;
}

int mctp_nl_net_byindex(const mctp_nl *nl, int index)
{
	int i;

	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		if (entry->ifindex == index) {
			return entry->net;
		}
	}

	return 0;
}

static int linkmap_add_entry(mctp_nl *nl, struct ifinfomsg *info,
		const char *ifname, size_t ifname_len, int net)
{
	struct linkmap_entry *entry;
	size_t newsz;
	void *tmp;
	int idx;

	if (ifname_len > IFNAMSIZ) {
		warnx("linkmap, too long ifname '%*s'", (int)ifname_len, ifname);
		return -1;
	}

	idx = nl->linkmap_count++;

	if (nl->linkmap_count > nl->linkmap_alloc) {
		newsz = max(nl->linkmap_alloc * 2, 1);
		tmp = reallocarray(nl->linkmap, newsz, sizeof(*nl->linkmap));
		if (!tmp) {
			warnx("Error allocating linkmap memory");
			return -1;
		}
		nl->linkmap_alloc = newsz;
		nl->linkmap = tmp;
	}

	entry = &nl->linkmap[idx];
	snprintf(entry->ifname, IFNAMSIZ, "%*s", (int)ifname_len, ifname);
	entry->ifindex = info->ifi_index;
	entry->net = net;
	return 0;
}

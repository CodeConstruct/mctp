#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>

#include <sys/socket.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>

#include "mctp-netlink.h"
#include "mctp.h"
#include "mctp-util.h"
#include "mctp-ops.h"

struct linkmap_entry {
	int	ifindex;
	char	ifname[IFNAMSIZ+1];
	uint8_t	ifaddr[MAX_ADDR_LEN];
	size_t	ifaddr_len;
	int	net;
	bool 	up;

	mctp_eid_t *local_eids;
	size_t num_local;

	void	*userdata;
};

struct mctp_nl {
	// socket for queries
	int	sd;
	// socket for monitor
	int	sd_monitor;

	struct linkmap_entry *linkmap;
	size_t	linkmap_count;
	size_t	linkmap_alloc;
	bool	verbose;

	// allows callers to silence printf of EEXIST returns.
	// TODO: this is a workaround, if more are required we should
	// rework how error messages are returned to callers.
	bool quiet_eexist;
};

static int fill_local_addrs(mctp_nl *nl);
static int fill_linkmap(mctp_nl *nl);
static void sort_linkmap(mctp_nl *nl);
static int linkmap_add_entry(mctp_nl *nl, struct ifinfomsg *info,
			     const char *ifname, size_t ifname_len,
			     uint8_t *ifaddr, size_t ifaddr_len, int net,
			     bool up);
static struct linkmap_entry *entry_byindex(const mctp_nl *nl,
	int index);

static int open_nl_socket(void)
{
	struct sockaddr_nl addr;
	int opt, rc, sd = -1;

	rc = mctp_ops.nl.socket();
	if (rc < 0)
		goto err;
	sd = rc;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	rc = mctp_ops.nl.bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		goto err;

	opt = 1;
	rc = mctp_ops.nl.setsockopt(sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
				    &opt, sizeof(opt));
	if (rc) {
		rc = -errno;
		goto err;
	}

	opt = 1;
	rc = mctp_ops.nl.setsockopt(sd, SOL_NETLINK, NETLINK_EXT_ACK, &opt,
				    sizeof(opt));
	if (rc)
	{
		rc = -errno;
		goto err;
	}
	return sd;
err:
	if (sd >= 0) {
		close(sd);
	}
	return rc;
}

mctp_nl * mctp_nl_new(bool verbose)
{
	int rc;
	mctp_nl *nl;

	nl = calloc(1, sizeof(*nl));
	if (!nl) {
		warn("calloc failed");
		return NULL;
	}

	nl->sd = -1;
	nl->sd_monitor = -1;
	nl->verbose = verbose;
	nl->quiet_eexist = false;

	nl->sd = open_nl_socket();
	if (nl->sd < 0)
		goto err;

	rc = fill_linkmap(nl);
	if (rc)
		goto err;

	return nl;
err:
	mctp_nl_close(nl);
	return NULL;
}

/* Avoids printing warnings for EEXIST */
void mctp_nl_warn_eexist(mctp_nl *nl, bool warn) {
	nl->quiet_eexist = !warn;
}

static void free_linkmap(struct linkmap_entry *linkmap, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		free(linkmap[i].local_eids);
	}
	free(linkmap);
}

void mctp_nl_close(mctp_nl *nl)
{
	free_linkmap(nl->linkmap, nl->linkmap_count);
	mctp_ops.nl.close(nl->sd);
	mctp_ops.nl.close(nl->sd_monitor);
	free(nl);
}

int mctp_nl_monitor(mctp_nl *nl, bool enable)
{
	int rc;
	int opt;

	if (enable) {
		/* Already open */
		if (nl->sd_monitor >= 0)
			return nl->sd_monitor;

		nl->sd_monitor = open_nl_socket();
		if (nl->sd_monitor < 0)
			return nl->sd_monitor;

		opt = RTNLGRP_LINK;
		rc = mctp_ops.nl.setsockopt(nl->sd_monitor, SOL_NETLINK,
					    NETLINK_ADD_MEMBERSHIP,
					    &opt, sizeof(opt));
		if (rc < 0) {
			rc = -errno;
			goto err;
		}

		opt = RTNLGRP_MCTP_IFADDR;
		rc = mctp_ops.nl.setsockopt(nl->sd_monitor, SOL_NETLINK,
					    NETLINK_ADD_MEMBERSHIP,
					    &opt, sizeof(opt));
		if (rc < 0) {
			rc = -errno;
			if (errno == EINVAL) {
				warnx("Kernel doesn't support netlink monitor for MCTP addresses");
			}
			goto err;
		}

	} else {
		close(nl->sd_monitor);
		nl->sd_monitor = -1;
	}

	return nl->sd_monitor;

err:
	close(nl->sd_monitor);
	nl->sd_monitor = -1;
	return rc;
}

mctp_nl_change *push_change(mctp_nl_change **changes, size_t *psize) {
	size_t siz = *psize;
	siz++;
	*changes = realloc(*changes, siz * sizeof(**changes));
	*psize = siz;
	return &(*changes)[siz-1];
}

static void fill_eid_changes(const struct linkmap_entry *oe,
	const mctp_eid_t *old_eids, size_t num_old,
	const mctp_eid_t *new_eids, size_t num_new,
	mctp_nl_change **changes, size_t *psize) {

	// Iterate and match old/new eid lists
	for (size_t o = 0, n = 0; o < num_old || n < num_new; ) {
		mctp_nl_change *ch = NULL;

		// "beyond end of list" value
		int vo = 1000, vn = 1000;
		if (o < num_old)
			vo = old_eids[o];
		if (n < num_new)
			vn = new_eids[n];

		if (vo == vn) {
			// Same eid
			o++;
			n++;
		} else if (vn < vo) {
			// Added eid
			ch = push_change(changes, psize);
			ch->op = MCTP_NL_ADD_EID;
			ch->ifindex = oe->ifindex;
			ch->eid = vn;
			n++;
		} else if (vo < vn) {
			// Removed eid
			ch = push_change(changes, psize);
			ch->op = MCTP_NL_DEL_EID;
			ch->ifindex = oe->ifindex;
			ch->old_net = oe->net;
			ch->eid = vo;
			o++;
		}
	}
}

static void fill_link_changes(const struct linkmap_entry *old, size_t old_count,
	struct linkmap_entry *new, size_t new_count,
	mctp_nl_change **changes, size_t *num_changes) {

	size_t siz = 0;

	// iterate and match old/new interface lists
	for (size_t o = 0, n = 0; o < old_count || n < new_count; ) {
		const struct linkmap_entry *oe = &old[o];
		struct linkmap_entry *ne = &new[n];
		mctp_nl_change *ch = NULL;

		if (o >= old_count)
			oe = NULL;
		if (n >= new_count)
			ne = NULL;
		assert(oe || ne);

		if (oe && ne && oe->ifindex == ne->ifindex) {
			// Same link.
			ne->userdata = oe->userdata;
			if (oe->net == ne->net) {
				// Same net. Check for eid changes.
				fill_eid_changes(oe,
					oe->local_eids, oe->num_local,
					ne->local_eids, ne->num_local,
					changes, &siz);
			} else {
				// Net changed
				// First remove all old local EIDs. They can be re-added
				// in response to the later CHANGE_NET
				fill_eid_changes(oe,
					oe->local_eids, oe->num_local,
					NULL, 0,
					changes, &siz);

				ch = push_change(changes, &siz);
				ch->op = MCTP_NL_CHANGE_NET;
				ch->ifindex = ne->ifindex;
				ch->old_net = oe->net;
				ch->link_userdata = oe->userdata;
			}

			if (oe->up != ne->up) {
				ch = push_change(changes, &siz);
				ch->op = MCTP_NL_CHANGE_UP;
				ch->ifindex = ne->ifindex;
				ch->old_up = oe->up;
				ch->link_userdata = oe->userdata;
			}
			o++;
			n++;
		} else if (!oe || (ne && ne->ifindex < oe->ifindex)) {
			// Added link
			ch = push_change(changes, &siz);
			ch->op = MCTP_NL_ADD_LINK;
			ch->ifindex = ne->ifindex;
			n++;
		} else if (!ne || (oe && oe->ifindex < ne->ifindex)) {
			// Deleted link

			// Record each EID deletion as a change, since the old
			// EID list is deleted before this change list is returned
			fill_eid_changes(oe, oe->local_eids, oe->num_local,
				NULL, 0,
				changes, &siz);
			// Delete the link itself
			ch = push_change(changes, &siz);
			ch->op = MCTP_NL_DEL_LINK;
			ch->ifindex = oe->ifindex;
			ch->old_net = oe->net;
			ch->link_userdata = oe->userdata;
			o++;
		}
	}
	*num_changes = siz;
}

void mctp_nl_changes_dump(mctp_nl *nl, mctp_nl_change *changes, size_t num_changes) {
	const char* ops[MCTP_NL_OP_COUNT] = {
		"ADD_LINK", "DEL_LINK", "CHANGE_NET", "CHANGE_UP",
		"ADD_EID", "DEL_EID",
	};

	printf("%zu changes:\n", num_changes);
	for (size_t i = 0; i < num_changes; i++) {
		mctp_nl_change *ch = &changes[i];
		const char* ifname = mctp_nl_if_byindex(nl, ch->ifindex);
		if (!ifname)
			ifname = "deleted";
		printf("%3zd %-12s ifindex %3d (%-20s) eid %3d old_net %4d old_up %d\n",
			i, ops[ch->op], ch->ifindex, ifname, ch->eid,
			ch->old_net, ch->old_up);
	}

}

int mctp_nl_handle_monitor(mctp_nl *nl, mctp_nl_change **changes, size_t *num_changes)
{
	int rc;
	struct linkmap_entry *old_linkmap;
	size_t old_count;
	size_t old_alloc;

	*changes = NULL;
	*num_changes = 0;

	if (nl->sd_monitor < 0) {
		warnx("%s without mctp_nl_monitor", __func__);
		return -EBADF;
	}

	// Drain the socket
	while (recv(nl->sd_monitor, NULL, 0, MSG_TRUNC|MSG_DONTWAIT) > 0) {}

	old_linkmap = nl->linkmap;
	old_count = nl->linkmap_count;
	old_alloc = nl->linkmap_alloc;

	nl->linkmap = NULL;
	nl->linkmap_count = nl->linkmap_alloc = 0;

	rc = fill_linkmap(nl);
	if (rc)
		goto err;

	fill_link_changes(old_linkmap, old_count,
		nl->linkmap, nl->linkmap_count,
		changes, num_changes);

	free_linkmap(old_linkmap, old_count);
	return 0;

err:
	// restore original
	free_linkmap(nl->linkmap, nl->linkmap_count);
	nl->linkmap = old_linkmap;
	nl->linkmap_count = old_count;
	nl->linkmap_alloc = old_alloc;

	return rc;
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

void mctp_display_nlmsg_error(const mctp_nl *nl, struct nlmsgerr *errmsg, size_t errlen)
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

	if (!(nl->quiet_eexist && errmsg->error == -EEXIST))
		printf("Error from kernel: %s (%d)\n", strerror(-errmsg->error), errmsg->error);
	errstr = mctp_get_rtnlmsg_attr(NLMSGERR_ATTR_MSG, rta, rta_len, &errstrlen);
	if (errstr) {
		errstrlen = strnlen(errstr, errstrlen);
		printf("  %*s\n", (int)errstrlen, errstr);
	}
}

void mctp_dump_nlmsg_error(const mctp_nl *nl, struct nlmsgerr *errmsg, size_t errlen)
{
	printf("error:\n");
	mctp_display_nlmsg_error(nl, errmsg, errlen);
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

	rc = mctp_ops.nl.recvfrom(nl->sd, resp, sizeof(resp), 0, NULL, NULL);
	if (rc < 0)
		return rc;
	len = rc;
	msg = (void*)resp;

	rc = 0;
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *errmsg = NLMSG_DATA(msg);
			size_t errlen = NLMSG_PAYLOAD(msg, 0);
			if (errmsg->error) {
				if (nl->verbose)
					mctp_dump_nlmsg_error(nl, errmsg, errlen);
				else
					mctp_display_nlmsg_error(nl, errmsg, errlen);
				rc = errmsg->error;
			}
		} else {
			warnx("Received unexpected message type %d instead of status",
				msg->nlmsg_type);
			if (nl->verbose) {
				mctp_hexdump(msg, msg->nlmsg_len, "    ");
			}
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

	rc = mctp_ops.nl.sendto(nl->sd, msg, msg->nlmsg_len, 0,
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
int mctp_nl_recv_all(mctp_nl *nl, int sd,
	struct nlmsghdr **respp, size_t *resp_lenp)
{
	void *respbuf = NULL;
	struct nlmsghdr *resp = NULL;
	struct sockaddr_nl addr;
	socklen_t addrlen;
	size_t newlen, readlen, pos;
	bool done;
	int rc;

	if (respp) {
		*respp = NULL;
		*resp_lenp = 0;
	}

	pos = 0;
	done = false;

	// read all the responses into a single buffer
	while (!done) {
		rc = mctp_ops.nl.recvfrom(sd, NULL, 0, MSG_PEEK|MSG_TRUNC,
					  NULL, 0);
		if (rc < 0) {
			warnx("recvfrom(MSG_PEEK)");
			rc = -errno;
			goto out;
		}

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
		{
			warnx("allocation of %zu failed", newlen);
			rc = -ENOMEM;
			goto out;
		}
		resp = respbuf + pos;

		addrlen = sizeof(addr);
		rc = mctp_ops.nl.recvfrom(sd, resp, readlen, MSG_TRUNC,
					  (struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			warnx("recvfrom(MSG_PEEK)");
			rc = -errno;
			goto out;
		}

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

	rc = 0;
out:
	if (rc == 0 && respp) {
		*respp = respbuf;
		*resp_lenp = pos;
	} else {
		free(respbuf);
	}

	return rc;
}

/* respp is optional for returned buffer, length is set in resp+lenp */
int mctp_nl_query(mctp_nl *nl, struct nlmsghdr *msg,
		struct nlmsghdr **respp, size_t *resp_lenp)
{
	int rc;

	if (respp) {
		*respp = NULL;
		*resp_lenp = 0;
	}

	rc = mctp_nl_send(nl, msg);
	if (rc)
		return rc;

	return mctp_nl_recv_all(nl, nl->sd, respp, resp_lenp);
}

static int parse_getlink_dump(mctp_nl *nl, struct nlmsghdr *nlh, uint32_t len)
{
	struct ifinfomsg *info;

	for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct rtattr *rta, *rt_nest, *rt_mctp;
		uint8_t *ifaddr;
		char *ifname;
		size_t ifname_len, ifaddr_len, rlen, nlen, mlen;
		uint32_t net;
		bool up;

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

		/* TODO: media type */

		ifname = mctp_get_rtnlmsg_attr(IFLA_IFNAME, rta, rlen, &ifname_len);
		if (!ifname) {
			warnx("no ifname?");
			continue;
		}
		ifname_len = strnlen(ifname, ifname_len);

		ifaddr = mctp_get_rtnlmsg_attr(IFLA_ADDRESS, rta, rlen,
					       &ifaddr_len);

		up = info->ifi_flags & IFF_UP;
		linkmap_add_entry(nl, info, ifname, ifname_len, ifaddr,
				  ifaddr_len, net, up);
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
		rc = mctp_ops.nl.recvfrom(nl->sd, NULL, 0, MSG_TRUNC | MSG_PEEK,
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

		rc = mctp_ops.nl.recvfrom(nl->sd, buf, buflen, 0,
					  (struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			warn("recvfrom()");
			break;
		}

		rc = parse_getlink_dump(nl, buf, rc);
		if (rc <= 0)
			break;
	}

	if (rc == 0)
		rc = fill_local_addrs(nl);

	sort_linkmap(nl);

	free(buf);
	return rc;
}

static int fill_local_addrs(mctp_nl *nl)
{
	int rc;
	struct nlmsghdr *resp = NULL, *rp = NULL;
	size_t len;
	struct {
		struct nlmsghdr		nh;
		struct ifaddrmsg	ifmsg;
		struct rtattr		rta;
		char			ifname[16];
	} msg = {0};

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	msg.nh.nlmsg_type = RTM_GETADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ifmsg.ifa_family = AF_MCTP;

	rc = mctp_nl_query(nl, &msg.nh, &resp, &len);
	if (rc)
		return rc;

	rp = resp;
	for (; NLMSG_OK(rp, len); rp = NLMSG_NEXT(rp, len)) {
		struct ifaddrmsg *ifa = NULL;
		size_t rta_len, ifalen;
		struct rtattr *rta = NULL;
		void* tmp;
		struct linkmap_entry* entry = NULL;
		mctp_eid_t eid;

		if (rp->nlmsg_type != RTM_NEWADDR)
			continue;
		ifa = NLMSG_DATA(rp);
		ifalen = NLMSG_PAYLOAD(rp, 0);
		if (ifalen < sizeof(*ifa)) {
			warnx("kernel returned short ifaddrmsg");
			continue;
		}
		if (ifa->ifa_family != AF_MCTP)
			continue;
		rta = (void *)(ifa + 1);
		rta_len = ifalen - sizeof(*ifa);
		if (!mctp_get_rtnlmsg_attr_u8(IFA_LOCAL, rta, rta_len, &eid))
			continue;

		entry = entry_byindex(nl, ifa->ifa_index);
		if (!entry) {
			warnx("kernel returned address for unknown if");
			continue;
		}
		tmp = realloc(entry->local_eids,
			(entry->num_local+1) * sizeof(*entry->local_eids));
		if (!tmp)
			continue;
		entry->local_eids = tmp;
		entry->local_eids[entry->num_local] = eid;
		entry->num_local++;
	}

	free(resp);
	return rc;
}

static int cmp_eid(const void* a, const void* b)
{
	const mctp_eid_t *ea = a, *eb = b;
	return (int)(*ea) - (int)(*eb);
}

static int cmp_ifindex(const void* a, const void* b)
{
	const struct linkmap_entry *ea = a, *eb = b;
	return ea->ifindex - eb->ifindex;
}

static void sort_linkmap(mctp_nl *nl)
{
	size_t i;

	qsort(nl->linkmap, nl->linkmap_count, sizeof(*nl->linkmap), cmp_ifindex);

	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		qsort(entry->local_eids, entry->num_local,
			sizeof(mctp_eid_t), cmp_eid);
	}
}

void mctp_nl_linkmap_dump(const mctp_nl *nl)
{
	size_t i, j;

	printf("linkmap\n");
	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		const char* updown = entry->up ? "up" : "DOWN";
		printf("  %2d: %s, net %d %s local addrs [",
			entry->ifindex, entry->ifname,
			entry->net, updown);
		for (j = 0; j < entry->num_local; j++) {
			if (j != 0)
				printf(", ");
			printf("%d", entry->local_eids[j]);
		}
		printf("]\n");
	}
}

int mctp_nl_ifindex_byname(const mctp_nl *nl, const char *ifname)
{
	size_t i;

	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		if (!strcmp(entry->ifname, ifname))
			return entry->ifindex;
	}

	return 0;
}

const char* mctp_nl_if_byindex(const mctp_nl *nl, int index)
{
	struct linkmap_entry *entry = entry_byindex(nl, index);
	if (entry)
		return entry->ifname;
	return NULL;
}

uint8_t *mctp_nl_ifaddr_byindex(const mctp_nl *nl, int index, size_t *ret_len)
{
	struct linkmap_entry *entry = entry_byindex(nl, index);
	if (entry) {
		*ret_len = entry->ifaddr_len;
		return entry->ifaddr;
	}
	return NULL;
}

int mctp_nl_net_byindex(const mctp_nl *nl, int index)
{
	struct linkmap_entry *entry = entry_byindex(nl, index);
	if (entry)
		return entry->net;
	return 0;
}

int mctp_nl_set_link_userdata(mctp_nl *nl, int ifindex, void *userdata)
{
	struct linkmap_entry *entry = entry_byindex(nl, ifindex);
	if (!entry)
		return -1;

	entry->userdata = userdata;
	return 0;
}

void *mctp_nl_get_link_userdata(const mctp_nl *nl, int ifindex)
{
	struct linkmap_entry *entry = entry_byindex(nl, ifindex);

	return entry ? entry->userdata : NULL;
}

void *mctp_nl_get_link_userdata_byname(const mctp_nl *nl, const char *ifname)
{
       size_t i;

       for (i = 0; i < nl->linkmap_count; i++) {
               struct linkmap_entry *entry = &nl->linkmap[i];
               if (!strcmp(entry->ifname, ifname))
                       return entry->userdata;
       }

       return NULL;
}

bool mctp_nl_up_byindex(const mctp_nl *nl, int index)
{
	struct linkmap_entry *entry = entry_byindex(nl, index);
	if (entry)
		return entry->up;
	return false;
}

mctp_eid_t *mctp_nl_addrs_byindex(const mctp_nl *nl, int index,
	size_t *ret_num)
{
	struct linkmap_entry *entry = entry_byindex(nl, index);
	mctp_eid_t *ret;

	*ret_num = 0;
	if (!entry)
		return NULL;
	ret = malloc(entry->num_local);
	if (!ret)
		return NULL;
	memcpy(ret, entry->local_eids, entry->num_local);
	*ret_num = entry->num_local;
	return ret;
}

static struct linkmap_entry *entry_byindex(const mctp_nl *nl,
	int index)
{
	size_t i;

	for (i = 0; i < nl->linkmap_count; i++) {
		struct linkmap_entry *entry = &nl->linkmap[i];
		if (entry->ifindex == index) {
			return entry;
		}
	}
	return NULL;
}

int *mctp_nl_net_list(const mctp_nl *nl, size_t *ret_num_nets)
{
	size_t i, j;
	int *nets = NULL;

	*ret_num_nets = 0;
	// allocation may be oversized, that's OK
	nets = malloc(sizeof(int) * nl->linkmap_count);
	if (!nets) {
		warnx("Allocation failed");
		return NULL;
	}
	for (j = 0; j < nl->linkmap_count; j++) {
		nets[j] = -1;
	}

	for (i = 0; i < nl->linkmap_count; i++) {
		for (j = 0; j < nl->linkmap_count; j++) {
			if (nets[j] == nl->linkmap[i].net) {
				// Already added
				break;
			}
			if (nets[j] == -1) {
				// End of the list, add it
				nets[j] = nl->linkmap[i].net;
				(*ret_num_nets)++;
				break;
			}
		}
	}
	return nets;
}

int *mctp_nl_if_list(const mctp_nl *nl, size_t *ret_num_ifs)
{
	size_t i;
	int *ifs;

	*ret_num_ifs = 0;
	ifs = malloc(sizeof(int) * nl->linkmap_count);
	if (!ifs)
		return NULL;
	for (i = 0; i < nl->linkmap_count; i++) {
		ifs[i] = nl->linkmap[i].ifindex;
	}
	*ret_num_ifs = nl->linkmap_count;
	return ifs;
}

static int linkmap_add_entry(mctp_nl *nl, struct ifinfomsg *info,
			     const char *ifname, size_t ifname_len,
			     uint8_t *ifaddr, size_t ifaddr_len, int net,
			     bool up)
{
	struct linkmap_entry *entry;
	size_t newsz;
	void *tmp;
	int idx;

	if (ifname_len > IFNAMSIZ) {
		warnx("linkmap, too long ifname '%*s'", (int)ifname_len, ifname);
		return -1;
	}

	if (ifaddr_len > MAX_ADDR_LEN) {
		warnx("linkmap, too long ifaddr (%zu bytes long, expected max %d bytes)",
		      ifaddr_len, MAX_ADDR_LEN);
		return -1;
	}

	if (net <= 0) {
		warnx("Bad network ID %d for %*s", net, (int)ifname_len, ifname);
		return -1;
	}

	idx = nl->linkmap_count++;

	if (nl->linkmap_count > nl->linkmap_alloc) {
		newsz = max(nl->linkmap_alloc * 2, 1);
		tmp = realloc(nl->linkmap, newsz * sizeof(*nl->linkmap));
		if (!tmp) {
			warnx("Error allocating linkmap memory");
			return -1;
		}
		nl->linkmap_alloc = newsz;
		nl->linkmap = tmp;
	}

	entry = &nl->linkmap[idx];
	memset(entry, 0, sizeof(*entry));
	snprintf(entry->ifname, IFNAMSIZ, "%*s", (int)ifname_len, ifname);
	memcpy(entry->ifaddr, ifaddr, ifaddr_len);
	entry->ifaddr_len = ifaddr_len;
	entry->ifindex = info->ifi_index;
	entry->net = net;
	entry->up = up;
	return 0;
}

/* Common parts of RTM_NEWROUTE and RTM_DELROUTE */
struct mctp_rtalter_msg {
	struct nlmsghdr		nh;
	struct rtmsg		rtmsg;
	uint8_t			rta_buff[
				RTA_SPACE(sizeof(mctp_eid_t)) + // eid
				RTA_SPACE(sizeof(int)) + // ifindex
				100 // space for MTU, nexthop etc
				];
};
static int fill_rtalter_args(struct mctp_nl *nl, struct mctp_rtalter_msg *msg,
	struct rtattr **prta, size_t *prta_len,
	mctp_eid_t eid, const char* linkstr)
{
	int ifindex;
	struct rtattr *rta;
	size_t rta_len;

	ifindex = mctp_nl_ifindex_byname(nl, linkstr);
	if (!ifindex) {
		warnx("invalid device %s", linkstr);
		return -1;
	}

	memset(msg, 0x0, sizeof(*msg));
	msg->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	msg->rtmsg.rtm_family = AF_MCTP;
	msg->rtmsg.rtm_type = RTN_UNICAST;
	// TODO add eid range handling
	msg->rtmsg.rtm_dst_len = 0;
	msg->rtmsg.rtm_type = RTN_UNICAST;

	msg->nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg->rtmsg));
	rta_len = sizeof(msg->rta_buff);
	rta = (void*)msg->rta_buff;

	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
		RTA_DST, &eid, sizeof(eid));
	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
		RTA_OIF, &ifindex, sizeof(ifindex));

	if (prta)
		*prta = rta;
	if (prta_len)
		*prta_len = rta_len;

	return 0;
}

int mctp_nl_route_add(struct mctp_nl *nl, uint8_t eid, const char* ifname,
		uint32_t mtu) {
	struct mctp_rtalter_msg msg;
	struct rtattr *rta;
	size_t rta_len;
	int rc;

	rc = fill_rtalter_args(nl, &msg, &rta, &rta_len, eid, ifname);
	if (rc) {
		return -1;
	}
	msg.nh.nlmsg_type = RTM_NEWROUTE;

	if (mtu != 0) {
		/* Nested
		RTA_METRICS
			RTAX_MTU
		*/
		struct rtattr *rta1;
		size_t rta_len1, space1;
		uint8_t buff1[100];

		rta1 = (void*)buff1;
		rta_len1 = sizeof(buff1);
		space1 = 0;
		space1 += mctp_put_rtnlmsg_attr(&rta1, &rta_len1,
			RTAX_MTU, &mtu, sizeof(mtu));
		// TODO add metric
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
			RTA_METRICS|NLA_F_NESTED, buff1, space1);
	}

	return mctp_nl_send(nl, &msg.nh);

}

int mctp_nl_route_del(struct mctp_nl *nl, uint8_t eid, const char* ifname)
{
	struct mctp_rtalter_msg msg;
	int rc;

	rc = fill_rtalter_args(nl, &msg, NULL, NULL, eid, ifname);
	if (rc) {
		return rc;
	}
	msg.nh.nlmsg_type = RTM_DELROUTE;

	return mctp_nl_send(nl, &msg.nh);
}


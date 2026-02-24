/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-ops: Abstraction for socket operations for mctp & mctpd.
 *
 * Copyright (c) 2023 Code Construct
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <err.h>

#include "mctp.h"
#include "mctp-ops.h"

static int mctp_op_mctp_socket(void)
{
	return socket(AF_MCTP, SOCK_DGRAM, 0);
}

static int mctp_op_netlink_socket(void)
{
	return socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
}

static int mctp_op_bind(int sd, struct sockaddr *addr, socklen_t addrlen)
{
	return bind(sd, addr, addrlen);
}

static int mctp_op_setsockopt(int sd, int level, int optname, void *optval,
			      socklen_t optlen)
{
	return setsockopt(sd, level, optname, optval, optlen);
}

static ssize_t mctp_op_sendto(int sd, const void *buf, size_t len, int flags,
			      const struct sockaddr *dest, socklen_t addrlen)
{
	return sendto(sd, buf, len, flags, dest, addrlen);
}

static ssize_t mctp_op_recvfrom(int sd, void *buf, size_t len, int flags,
				struct sockaddr *src, socklen_t *addrlen)
{
	return recvfrom(sd, buf, len, flags, src, addrlen);
}

static int mctp_op_close(int sd)
{
	return close(sd);
}

static int mctp_op_link_sysfs_path(const char *ifname, char **path)
{
	char *dev_class_path = NULL, *dev_path = NULL;
	int rc = 1;

	rc = asprintf(&dev_class_path, "/sys/class/net/%s/device", ifname);
	if (rc < 0)
		return -1;

	dev_path = realpath(dev_class_path, NULL);
	if (!dev_path) {
		warnx("no path data for interface %s", ifname);
		goto out;
	}

	if (!strncmp(dev_path, "/sys", strlen("/sys"))) {
		warnx("malformed interface path for %s", ifname);
		goto out;
	}

	*path = strdup(dev_path + 4);
	rc = 0;

out:
	free(dev_path);
	free(dev_class_path);
	return rc;
	return -1;
}

static void mctp_bug_warn(const char *fmt, va_list args)
{
	vwarnx(fmt, args);
}

const struct mctp_ops mctp_ops = {
	.mctp = {
		.socket = mctp_op_mctp_socket,
		.setsockopt = mctp_op_setsockopt,
		.bind = mctp_op_bind,
		.sendto = mctp_op_sendto,
		.recvfrom = mctp_op_recvfrom,
		.close = mctp_op_close,
	},
	.nl = {
		.socket = mctp_op_netlink_socket,
		.setsockopt = mctp_op_setsockopt,
		.bind = mctp_op_bind,
		.sendto = mctp_op_sendto,
		.recvfrom = mctp_op_recvfrom,
		.close = mctp_op_close,
	},
#if OPS_SD_EVENT
	.sd_event = {
		.add_time_relative = sd_event_add_time_relative,
		.source_set_time_relative = sd_event_source_set_time_relative,
	},
#endif
	.bug_warn = mctp_bug_warn,
	.link_sysfs_path = mctp_op_link_sysfs_path,
};

void mctp_ops_init(void)
{
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-ops: Abstraction for socket operations for mctp & mctpd.
 *
 * Copyright (c) 2023 Code Construct
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <linux/netlink.h>

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

struct mctp_ops mctp_ops = {
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
};

void mctp_ops_init(void) { }

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-ops-test: Test implementations for mctp socket ops
 *
 * Copyright (c) 2023 Code Construct
 */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <linux/netlink.h>

#include "mctp-ops.h"
#include "test-proto.h"

static int control_sd;

static int mctp_op_socket(int type)
{
	union {
		struct cmsghdr hdr;
		unsigned char buf[CMSG_SPACE(sizeof(int))];
	} msg;
	struct cmsghdr *cmsg;
	struct control_msg_req req;
	struct control_msg_rsp rsp;
	struct msghdr hdr = { 0 };
	struct iovec iov;
	int rc, var, sd;

	if (type == AF_MCTP)
		req.type = CONTROL_OP_SOCKET_MCTP;
	else if (type == AF_NETLINK)
		req.type = CONTROL_OP_SOCKET_NL;
	else
		errx(EXIT_FAILURE, "invalid socket type?");

	rc = send(control_sd, &req, sizeof(req), 0);
	if (rc < 0)
		err(EXIT_FAILURE, "control send error");

	iov.iov_base = &rsp;
	iov.iov_len = sizeof(rsp);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = &msg;
	hdr.msg_controllen = sizeof(msg);
	rc = recvmsg(control_sd, &hdr, 0);

	cmsg = CMSG_FIRSTHDR(&hdr);
	if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
	    cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		errx(EXIT_FAILURE, "invalid control response");
	}

	memcpy(&sd, CMSG_DATA(cmsg), sizeof(int));
	var = 0;
	ioctl(sd, FIONBIO, &var);

	return sd;
}

static int mctp_op_mctp_socket(void)
{
	return mctp_op_socket(AF_MCTP);
}

static int mctp_op_netlink_socket(void)
{
	return mctp_op_socket(AF_NETLINK);
}

static int mctp_op_bind(int sd, struct sockaddr *addr, socklen_t addrlen)
{
	struct msghdr msg = { 0 };
	struct sock_msg sock_msg = { 0 };
	struct iovec iov;
	ssize_t rc;

	sock_msg.type = SOCK_BIND;
	sock_msg.bind.addrlen = addrlen;
	memcpy(&sock_msg.bind.addr.buf, addr, addrlen);

	iov.iov_base = &sock_msg;
	iov.iov_len = sizeof(sock_msg);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = sendmsg(sd, &msg, 0);
	if (rc < 0)
		return rc;

	if (rc < (int)sizeof(sock_msg)) {
		errno = EPROTO;
		return -1;
	}

	return 0;
}

static int mctp_op_setsockopt(int sd, int level, int optname, void *optval,
			      socklen_t optlen)
{
	struct msghdr msg = { 0 };
	struct sock_msg sock_msg = { 0 };
	struct iovec iov[2];
	ssize_t rc;

	sock_msg.type = SOCK_SETSOCKOPT;
	sock_msg.setsockopt.level = level;
	sock_msg.setsockopt.optname = optname;

	iov[0].iov_base = &sock_msg;
	iov[0].iov_len = sizeof(sock_msg);
	iov[1].iov_base = optval;
	iov[1].iov_len = optlen;

	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	rc = sendmsg(sd, &msg, 0);
	if (rc < 0)
		return rc;

	if (rc < (int)sizeof(sock_msg)) {
		errno = EPROTO;
		return -1;
	}

	/* todo: return code */
	return 0;
}

static ssize_t mctp_op_sendto(int sd, const void *buf, size_t len, int flags,
			      const struct sockaddr *dest, socklen_t addrlen)
{
	struct msghdr msg = { 0 };
	struct sock_msg sock_msg = { 0 };
	struct iovec iov[2];
	ssize_t rc;

	sock_msg.type = SOCK_SEND;
	sock_msg.send.addrlen = addrlen;
	memcpy(&sock_msg.send.addr.buf, dest, addrlen);

	iov[0].iov_base = &sock_msg;
	iov[0].iov_len = sizeof(sock_msg);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = len;

	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	rc = sendmsg(sd, &msg, 0);
	if (rc < 0)
		return rc;

	if (rc < (int)sizeof(sock_msg)) {
		errno = EPROTO;
		return -1;
	}

	return rc - sizeof(sock_msg);
}

static ssize_t mctp_op_recvfrom(int sd, void *buf, size_t len, int flags,
				struct sockaddr *src, socklen_t *addrlenp)
{
	struct msghdr msg = { 0 };
	struct sock_msg sock_msg = { 0 };
	struct iovec iov[2];
	ssize_t rc;

	iov[0].iov_base = &sock_msg;
	iov[0].iov_len = sizeof(sock_msg);
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = len;

	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	rc = recvmsg(sd, &msg, flags);
	if (rc <= 0)
		return rc;

	if (rc < (ssize_t)sizeof(sock_msg))
		errx(EXIT_FAILURE, "ops protocol error");

	if (sock_msg.type != SOCK_RECV)
		errx(EXIT_FAILURE, "Unexpected message type %d?",
		     sock_msg.type);

	if (src)
		memcpy(src, &sock_msg.recv.addr.buf, sock_msg.recv.addrlen);
	if (addrlenp)
		*addrlenp = sock_msg.recv.addrlen;

	return rc - sizeof(sock_msg);
}

static int mctp_op_close(int sd)
{
	return close(sd);
}

static void mctp_bug_warn(const char *fmt, va_list args)
{
	vwarnx(fmt, args);
	warnx("Aborting on bug in tests");
	abort();
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
	.bug_warn = mctp_bug_warn,
};

void mctp_ops_init(void)
{
	struct control_msg_req req;
	struct control_msg_rsp rsp;
	const char *sockstr;
	ssize_t len;
	int var, sd;

	sockstr = getenv("MCTP_TEST_SOCK");
	if (!sockstr || !strlen(sockstr))
		errx(EXIT_FAILURE, "No MCTP_TEST_SOCK fd provided");

	sd = atoi(sockstr);
	var = 0;
	ioctl(sd, FIONBIO, &var);

	req.type = CONTROL_OP_INIT;
	len = send(sd, &req, sizeof(req), 0);
	if (len != sizeof(req))
		err(EXIT_FAILURE, "control init failed");

	len = recv(sd, &rsp, sizeof(rsp), 0);
	control_sd = sd;
}

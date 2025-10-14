/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-ops-test: Test implementations for mctp socket ops
 *
 * Copyright (c) 2023 Code Construct
 */

#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <systemd/sd-event.h>
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

	if (type == CONTROL_OP_SOCKET_MCTP)
		req.type = CONTROL_OP_SOCKET_MCTP;
	else if (type == CONTROL_OP_SOCKET_NL)
		req.type = CONTROL_OP_SOCKET_NL;
	else if (type == CONTROL_OP_TIMER)
		req.type = CONTROL_OP_TIMER;
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
	return mctp_op_socket(CONTROL_OP_SOCKET_MCTP);
}

static int mctp_op_netlink_socket(void)
{
	return mctp_op_socket(CONTROL_OP_SOCKET_NL);
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

struct wrapped_time_userdata {
	sd_event_time_handler_t callback;
	void *userdata;
};

int wrapped_time_callback(sd_event_source *source, int fd, uint revents,
			  void *userdata)
{
	struct wrapped_time_userdata *wrapud = userdata;
	uint64_t usec;
	ssize_t rc;

	rc = read(fd, &usec, sizeof(usec));
	if (rc != 8)
		errx(EXIT_FAILURE, "ops protocol error");

	rc = wrapud->callback(source, usec, wrapud->userdata);
	warnx("%ld", rc);

	return 0;
}

void wrapped_time_destroy(void *wrapud)
{
	free(wrapud);
}

static int mctp_op_sd_event_add_time_relative(
	sd_event *e, sd_event_source **ret, clockid_t clock, uint64_t usec,
	uint64_t accuracy, sd_event_time_handler_t callback, void *userdata)
{
	struct wrapped_time_userdata *wrapud = NULL;
	sd_event_source *source = NULL;
	int sd = -1;
	int rc = 0;

	sd = mctp_op_socket(CONTROL_OP_TIMER);
	if (sd < 0)
		return -errno;

	rc = write(sd, &usec, sizeof(usec));
	if (rc != 8)
		errx(EXIT_FAILURE, "ops protocol error");

	wrapud = malloc(sizeof(*wrapud));
	if (!wrapud) {
		rc = -ENOMEM;
		goto fail;
	}

	wrapud->callback = callback;
	wrapud->userdata = userdata;

	rc = sd_event_add_io(e, &source, sd, EPOLLIN, wrapped_time_callback,
			     wrapud);
	if (rc < 0)
		goto fail;

	rc = sd_event_source_set_destroy_callback(source, wrapped_time_destroy);
	if (rc < 0)
		goto fail;

	wrapud = NULL;

	rc = sd_event_source_set_io_fd_own(source, 1);
	if (rc < 0)
		goto fail;

	sd = -1;

	rc = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
	if (rc < 0)
		goto fail;

	if (!ret) {
		rc = sd_event_source_set_floating(source, 1);
		if (rc < 0)
			goto fail;

		sd_event_source_unref(source);
	} else {
		*ret = source;
	}

	return 0;

fail:
	if (sd > 0)
		close(sd);
	free(wrapud);
	sd_event_source_disable_unref(*ret);
	return rc;
}

static int mctp_op_sd_event_source_set_time_relative(sd_event_source *s,
						     uint64_t usec)
{
	int sd = sd_event_source_get_io_fd(s);
	ssize_t rc;

	rc = write(sd, &usec, sizeof(usec));
	if (rc != 8)
		errx(EXIT_FAILURE, "ops protocol error");

	return 0;
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
	.sd_event = {
	    .add_time_relative = mctp_op_sd_event_add_time_relative,
		.source_set_time_relative = mctp_op_sd_event_source_set_time_relative,
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

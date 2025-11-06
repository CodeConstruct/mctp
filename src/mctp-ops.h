
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctpd: bus owner for MCTP using Linux kernel
 *
 * Copyright (c) 2023 Code Construct
 */
#pragma once

#include <sys/socket.h>
#include <stdarg.h>
#if OPS_SD_EVENT
#include <systemd/sd-event.h>
#endif

#define _GNU_SOURCE

struct socket_ops {
	int (*socket)(void);
	int (*setsockopt)(int sd, int level, int optname, void *optval,
			  socklen_t optlen);
	int (*bind)(int sd, struct sockaddr *addr, socklen_t addrlen);
	ssize_t (*sendto)(int sd, const void *buf, size_t len, int flags,
			  const struct sockaddr *dest, socklen_t addrlen);
	ssize_t (*recvfrom)(int sd, void *buf, size_t len, int flags,
			    struct sockaddr *src, socklen_t *addrlen);
	int (*close)(int sd);
};

#if OPS_SD_EVENT
struct sd_event_ops {
	typeof(sd_event_add_time_relative) *add_time_relative;
	typeof(sd_event_source_set_time_relative) *source_set_time_relative;
};
#endif

struct mctp_ops {
	struct socket_ops mctp;
	struct socket_ops nl;
#if OPS_SD_EVENT
	struct sd_event_ops sd_event;
#endif
	void (*bug_warn)(const char *fmt, va_list args);
};

extern const struct mctp_ops mctp_ops;

void mctp_ops_init(void);

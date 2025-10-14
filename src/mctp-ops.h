
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctpd: bus owner for MCTP using Linux kernel
 *
 * Copyright (c) 2023 Code Construct
 */
#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <systemd/sd-event.h>

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

struct sd_event_ops {
	int (*add_time_relative)(sd_event *e, sd_event_source **ret,
				 clockid_t clock, uint64_t usec,
				 uint64_t accuracy,
				 sd_event_time_handler_t callback,
				 void *userdata);
	int (*source_set_time_relative)(sd_event_source *s, uint64_t usec);
};

struct mctp_ops {
	struct socket_ops mctp;
	struct socket_ops nl;
	struct sd_event_ops sd_event;
	void (*bug_warn)(const char *fmt, va_list args);
};

extern const struct mctp_ops mctp_ops;

void mctp_ops_init(void);

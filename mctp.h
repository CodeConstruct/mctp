/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp: userspace utility for managing the kernel MCTP stack.
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#ifndef _MCTP_H
#define _MCTP_H

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

#include <stdint.h>

typedef uint8_t			mctp_eid_t;

struct _mctp_addr {
	mctp_eid_t		s_addr;
};

struct _sockaddr_mctp {
	unsigned short int	smctp_family;
	int			smctp_network;
	struct _mctp_addr	smctp_addr;
	uint8_t			smctp_type;
	uint8_t			smctp_tag;
};

#define MCTP_NET_ANY 0
#define MCTP_ADDR_ANY 0xff
#define MCTP_TAG_OWNER 0x08


/* From if_link.h */
enum {
	IFLA_MCTP_UNSPEC,
	IFLA_MCTP_NET,
	IFLA_MCTP_BUSOWNER,
	__IFLA_MCTP_MAX,
};

enum {
	RTA_MCTP_NET,
	__RTA_MCT_MAX,
};

#define IFLA_MCTP_MAX (__IFLA_MCTP_MAX - 1)


#endif /* _MCTP_H */

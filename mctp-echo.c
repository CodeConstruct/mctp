/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-echo: MCTP echo server, for testing.
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/socket.h>
#include "mctp.h"

int main(void)
{
	struct _sockaddr_mctp addr;
	socklen_t addrlen;
	int rc, sd;
	char c;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = 1;
	addr.smctp_tag = MCTP_TAG_OWNER;

	c = 1;

	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		err(EXIT_FAILURE, "bind");

	for (;;) {
		addrlen = sizeof(addr);
		rc = recvfrom(sd, &c, sizeof(c), 0,
				(struct sockaddr *)&addr, &addrlen);
		if (rc < 0)
			err(EXIT_FAILURE, "recvfrom");

		if (addrlen != sizeof(addr))
			errx(EXIT_FAILURE,
				"unknown address length %d, exp %zd",
				addrlen, sizeof(addr));

		printf("echo: message from (net %d, eid %d), tag %d, type %d: 0x%02x, responding\n",
				addr.smctp_network, addr.smctp_addr.s_addr,
				addr.smctp_tag,
				addr.smctp_type,
				c);

		rc = sendto(sd, &c, sizeof(c), 0,
				(struct sockaddr *)&addr, sizeof(addr));

		if (rc != sizeof(c))
			err(EXIT_FAILURE, "sendto");
	}

	return EXIT_SUCCESS;
}

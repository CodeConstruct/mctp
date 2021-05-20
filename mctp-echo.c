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
	unsigned char *buf;
	socklen_t addrlen;
	size_t buflen;
	ssize_t len;
	int rc, sd;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = 1;
	addr.smctp_tag = MCTP_TAG_OWNER;

	buflen = 0;
	buf = NULL;

	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		err(EXIT_FAILURE, "bind");

	for (;;) {
		len = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
		if (len < 0)
			err(EXIT_FAILURE, "recvfrom(MSG_PEEK)");

		if ((size_t)len > buflen) {
			buflen = len;
			buf = realloc(buf, buflen);
			if (!buf)
				err(EXIT_FAILURE, "realloc(%zd)", buflen);
		}

		addrlen = sizeof(addr);
		len = recvfrom(sd, buf, buflen, 0,
				(struct sockaddr *)&addr, &addrlen);
		if (len < 0)
			err(EXIT_FAILURE, "recvfrom");

		if (addrlen != sizeof(addr))
			errx(EXIT_FAILURE,
				"unknown address length %d, exp %zd",
				addrlen, sizeof(addr));

		printf("echo: message from (net %d, eid %d), tag %d, type %d: 0x%02x ..., responding\n",
				addr.smctp_network, addr.smctp_addr.s_addr,
				addr.smctp_tag,
				addr.smctp_type,
				buf[0]);

		rc = sendto(sd, buf, len, 0,
				(struct sockaddr *)&addr, sizeof(addr));

		if (rc != (int)len)
			err(EXIT_FAILURE, "sendto");
	}

	return EXIT_SUCCESS;
}

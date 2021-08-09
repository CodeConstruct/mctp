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
	struct sockaddr_mctp addr;
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
		if (len < 0) {
			warn("recvfrom(MSG_PEEK)");
			continue;
		}

		if ((size_t)len > buflen) {
			buflen = len;
			buf = realloc(buf, buflen);
			if (!buf)
				err(EXIT_FAILURE, "realloc(%zd)", buflen);
		}

		addrlen = sizeof(addr);
		len = recvfrom(sd, buf, buflen, 0,
				(struct sockaddr *)&addr, &addrlen);
		if (len < 0) {
			warn("recvfrom");
			continue;
		}

		if (addrlen != sizeof(addr)) {
			warnx("unknown address length %d, exp %zd",
				addrlen, sizeof(addr));
			continue;
		}

		printf("echo: message from (net %d, eid %d), tag %d, type %d: len %zd, 0x%02x ..., responding\n",
				addr.smctp_network, addr.smctp_addr.s_addr,
				addr.smctp_tag,
				addr.smctp_type,
				len, buf[0]);

		addr.smctp_tag &= ~MCTP_TAG_OWNER;

		rc = sendto(sd, buf, len, 0,
				(struct sockaddr *)&addr, sizeof(addr));

		if (rc != (int)len) {
			warn("sendto");
			continue;
		}
	}

	return EXIT_SUCCESS;
}

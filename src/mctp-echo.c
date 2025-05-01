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
#include <string.h>
#include <sys/socket.h>
#include "mctp.h"

// Code Construct allocation
static const uint8_t VENDOR_TYPE_ECHO[3] = { 0xcc, 0xde, 0xf0 };
static const uint8_t MCTP_TYPE_VENDOR_PCIE = 0x7e;

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

	memset(&addr, 0, sizeof(addr));
	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = MCTP_TYPE_VENDOR_PCIE;
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

		if (len < (ssize_t)sizeof(VENDOR_TYPE_ECHO)) {
			warnx("echo: short message from (net %d, eid %d), tag %d, type 0x%x: len %zd.\n",
				addr.smctp_network, addr.smctp_addr.s_addr,
				addr.smctp_tag,
				addr.smctp_type,
				len);
			continue;
		}

		if (memcmp(buf, VENDOR_TYPE_ECHO, sizeof(VENDOR_TYPE_ECHO)) != 0) {
			warnx("echo: unexpected vendor ID from (net %d, eid %d), tag %d, type 0x%x, len %zd.\n",
				addr.smctp_network, addr.smctp_addr.s_addr,
				addr.smctp_tag,
				addr.smctp_type,
				len);
			continue;
		}

		printf("echo: message from (net %d, eid %d), tag %d, type 0x%x: len %zd, responding\n",
				addr.smctp_network, addr.smctp_addr.s_addr,
				addr.smctp_tag,
				addr.smctp_type,
				len);

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

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-req: MCTP echo requester
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <sys/socket.h>

#include "mctp.h"
#include "mctp-util.h"

static const int DEFAULT_NET = 1;
static const mctp_eid_t DEFAULT_EID = 8;
static const size_t DEFAULT_LEN = 1;

/* lladdrlen != -1 to ignore ifindex/lladdr */
static int mctp_req(unsigned int net, mctp_eid_t eid,
	unsigned int ifindex, uint8_t *lladdr, int lladdrlen,
	size_t len)
{
	struct _sockaddr_mctp_ext addr;
	socklen_t addrlen;
	unsigned char *buf;
	int rc, sd;
	size_t i;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0x0, sizeof(addr));
	addrlen = sizeof(struct _sockaddr_mctp);
	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = net;
	addr.smctp_base.smctp_addr.s_addr = eid;
	addr.smctp_base.smctp_type = 1;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;
	printf("req:  sending to (net %d, eid %d), type %d\n",
		net, eid, addr.smctp_base.smctp_type);

	buf = malloc(len);
	if (!buf)
		err(EXIT_FAILURE, "malloc");
	for (i = 0; i < len; i++)
		buf[i] = i & 0xff;

	/* extended addressing */
	if (lladdrlen != -1) {
		addrlen = sizeof(struct _sockaddr_mctp_ext);
		addr.smctp_halen = lladdrlen;
		memcpy(addr.smctp_haddr, lladdr, lladdrlen);
		addr.smctp_ifindex = ifindex;
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
			addr.smctp_ifindex,
			addr.smctp_haddr[0], addr.smctp_halen);
	}

	/* send data */
	rc = sendto(sd, buf, len, 0,
			(struct sockaddr *)&addr, addrlen);
	if (rc != (int)len)
		err(EXIT_FAILURE, "sendto(%zd)", len);

	/* receive response */
	addrlen = sizeof(addr);
	rc = recvfrom(sd, buf, len, MSG_TRUNC,
			(struct sockaddr *)&addr, &addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");
	else if ((size_t)rc != len)
		errx(EXIT_FAILURE, "unexpected length: got %d, exp %zd",
				rc, len);

	if (!(addrlen == sizeof(struct _sockaddr_mctp_ext) ||
		addrlen == sizeof(struct _sockaddr_mctp)))
		errx(EXIT_FAILURE, "unknown recv address length %d, exp %zu or %zu)",
				addrlen, sizeof(struct _sockaddr_mctp_ext),
				sizeof(struct _sockaddr_mctp));


	printf("req:  message from (net %d, eid %d) type %d: 0x%02x..\n",
			addr.smctp_base.smctp_network, addr.smctp_base.smctp_addr.s_addr,
			addr.smctp_base.smctp_type,
			buf[0]);
	if (addrlen == sizeof(struct _sockaddr_mctp_ext)) {
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
			addr.smctp_ifindex,
			addr.smctp_haddr[0], addr.smctp_halen);
	}

	for (i = 0; i < len; i++) {
		if (buf[i] != (i & 0xff))
			errx(EXIT_FAILURE,
				"payload mismatch at byte 0x%zx; "
					"sent 0x%02x, received 0x%02x",
				i, (unsigned char)(i & 0xff), buf[i]);
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "mctp-req [eid <eid>] [net <net>] [if <ifindex> lladdr <hwaddr>] [len <len>]\n");
	fprintf(stderr, "default eid %d net %d len %zd\n",
			DEFAULT_EID, DEFAULT_NET, DEFAULT_LEN);
}

int main(int argc, char ** argv)
{
	unsigned int net = DEFAULT_NET;
	mctp_eid_t eid = DEFAULT_EID;
	size_t len = DEFAULT_LEN, sz;
	char *endp, *optname, *optval;
	unsigned int tmp, ifindex;
	int lladdrlen = -1;
	uint8_t lladdr[MAX_ADDR_LEN];
	bool valid_parse;
	int i;

	if (!(argc % 2)) {
		warnx("extra argument %s", argv[argc-1]);
		usage();
		return 255;
	}

	for (i = 1; i < argc; i += 2) {
		optname = argv[i];
		optval = argv[i+1];

		tmp = strtoul(optval, &endp, 0);
		valid_parse = (endp != optval);

		if (!strcmp(optname, "eid")) {
			if (tmp > 0xff)
				errx(EXIT_FAILURE, "Bad eid");
			eid = tmp;
		} else if (!strcmp(optname, "net")) {
			if (tmp > 0xff)
				errx(EXIT_FAILURE, "Bad net");
			net = tmp;
		} else if (!strcmp(optname, "ifindex")) {
			ifindex = tmp;
		} else if (!strcmp(optname, "len")) {
			if (tmp > 64 * 1024)
				errx(EXIT_FAILURE, "Bad len");
			len = tmp;
		} else if (!strcmp(optname, "lladdr")) {
			sz = sizeof(lladdr);
			if (parse_hex_addr(optval, lladdr, &sz)) {
				errx(EXIT_FAILURE, "Bad lladdr");
			}
			lladdrlen = sz;
			valid_parse = true;
		} else
			errx(EXIT_FAILURE, "Unknown argument %s", optname);

		// Handle bad integer etc.
		if (!valid_parse) {
			errx(EXIT_FAILURE, "invalid %s value %s",
					optname, optval);
		}
	}

	return mctp_req(net, eid, ifindex, lladdr, lladdrlen, len);
}

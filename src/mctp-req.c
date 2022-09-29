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
	uint8_t type, uint8_t *data, size_t len)
{
	struct sockaddr_mctp_ext addr;
	unsigned char *buf, *rxbuf;
	socklen_t addrlen;
	int rc, sd, val;
	size_t i;
	ssize_t ret;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0x0, sizeof(addr));
	addrlen = sizeof(struct sockaddr_mctp);
	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = net;
	addr.smctp_base.smctp_addr.s_addr = eid;
	addr.smctp_base.smctp_type = type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;
	printf("req:  sending to (net %d, eid %d), type %d, len %zu\n",
		net, eid, addr.smctp_base.smctp_type, len);

	rxbuf = malloc(len);
	if (!rxbuf)
		err(EXIT_FAILURE, "malloc");
	if (data) {
		buf = data;
	} else {
		buf = rxbuf;
		for (i = 0; i < len; i++)
			buf[i] = i & 0xff;
	}

	/* extended addressing */
	if (lladdrlen != -1) {
		addrlen = sizeof(struct sockaddr_mctp_ext);
		addr.smctp_halen = lladdrlen;
		memcpy(addr.smctp_haddr, lladdr, lladdrlen);
		addr.smctp_ifindex = ifindex;
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
			addr.smctp_ifindex,
			addr.smctp_haddr[0], addr.smctp_halen);
		val = 1;
		rc = setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val, sizeof(val));
		if (rc < 0)
			errx(EXIT_FAILURE,
				"Kernel does not support MCTP extended addressing");
	}


	/* send data */
	rc = sendto(sd, buf, len, 0,
			(struct sockaddr *)&addr, addrlen);
	if (rc != (int)len)
		err(EXIT_FAILURE, "sendto(%zd)", len);

	ret = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
	if (ret < 0)
		err(EXIT_FAILURE, "recvfrom");
	len = (size_t)ret;

	rxbuf = realloc(rxbuf, len);
	if (!rxbuf)
		err(EXIT_FAILURE, "realloc");

	/* receive response */
	addrlen = sizeof(addr);
	rc = recvfrom(sd, rxbuf, len, MSG_TRUNC,
			(struct sockaddr *)&addr, &addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");

	if (!(addrlen == sizeof(struct sockaddr_mctp_ext) ||
		addrlen == sizeof(struct sockaddr_mctp)))
		errx(EXIT_FAILURE, "unknown recv address length %d, exp %zu or %zu)",
				addrlen, sizeof(struct sockaddr_mctp_ext),
				sizeof(struct sockaddr_mctp));


	printf("req:  message from (net %d, eid %d) type %d len %zd\n",
			addr.smctp_base.smctp_network, addr.smctp_base.smctp_addr.s_addr,
			addr.smctp_base.smctp_type, len);
	if (addrlen == sizeof(struct sockaddr_mctp_ext)) {
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
			addr.smctp_ifindex,
			addr.smctp_haddr[0], addr.smctp_halen);
	}

	printf("data:\n");
	for (i = 0; i < len; i++)
		printf("0x%02x ", rxbuf[i]);
	printf("\n");
	return 0;
}

static void usage(void)
{
	fprintf(stderr, "mctp-req [eid <eid>] [net <net>]"
		"[ifindex <ifindex> lladdr <hwaddr>] [type <type>] [len <len>]"
		"[data <data>]\n");
	fprintf(stderr, "default eid %d net %d len %zd\n",
			DEFAULT_EID, DEFAULT_NET, DEFAULT_LEN);
	fprintf(stderr, "The data is in hex format separated by colon, e.g."
			"00:01:0f");
}

int main(int argc, char ** argv)
{
	uint8_t *data, lladdr[MAX_ADDR_LEN];
	int lladdrlen = -1, datalen = -1;
	unsigned int net = DEFAULT_NET;
	mctp_eid_t eid = DEFAULT_EID;
	size_t len = DEFAULT_LEN, sz;
	uint8_t type = 1;
	char *endp, *optname, *optval;
	unsigned int tmp, ifindex;
	bool valid_parse;
	int i;

	if (!(argc % 2)) {
		warnx("extra argument %s", argv[argc-1]);
		usage();
		return 255;
	}

	data = NULL;

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
		} else if (!strcmp(optname, "type")) {
			if (tmp > 0xff)
				errx(EXIT_FAILURE, "Bad type");
			type = tmp;
		} else if (!strcmp(optname, "data")) {
			sz = (strlen(optval) + 2) / 3;
			data = malloc(sz);
			if (!data)
				err(EXIT_FAILURE, "malloc");
			if (parse_hex_addr(optval, data, &sz)) {
				errx(EXIT_FAILURE, "Bad data");
			}
			datalen = sz;
			valid_parse = true;
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

	if (data)
		len = datalen;

	return mctp_req(net, eid, ifindex, lladdr, lladdrlen, type, data, len);
}

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
#include <string.h>
#include <err.h>
#include <sys/socket.h>

#include "mctp.h"

static const int DEFAULT_NET = 1;
static const mctp_eid_t DEFAULT_EID = 8;

static int mctp_req(unsigned int net, mctp_eid_t eid)
{
	struct _sockaddr_mctp addr;
	socklen_t addrlen;
	int rc, sd;
	char c, r;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = net;
	addr.smctp_addr.s_addr = eid;
	addr.smctp_type = 1;
	addr.smctp_tag = MCTP_TAG_OWNER;

	printf("req:  sending to (net %d, eid %d), type %d\n",
		net, eid, addr.smctp_type);

	c = 0xaa;

	/* send data */
	rc = sendto(sd, &c, sizeof(c), 0,
			(struct sockaddr *)&addr, sizeof(addr));
	if (rc != sizeof(c))
		err(EXIT_FAILURE, "sendto");

	/* receive response */
	addrlen = sizeof(addr);
	rc = recvfrom(sd, &r, sizeof(r), MSG_TRUNC,
			(struct sockaddr *)&addr, &addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");
	else if (rc != sizeof(c))
		errx(EXIT_FAILURE, "unexpected length: got %d, exp %zd",
				rc, sizeof(c));

	if (addrlen != sizeof(addr))
		errx(EXIT_FAILURE, "unknown recv address length %d, exp %zd)",
				addrlen, sizeof(addr));

	printf("req:  message from (net %d, eid %d) type %d: 0x%02x\n",
			addr.smctp_network, addr.smctp_addr.s_addr,
			addr.smctp_type,
			r);

	if (c != r)
		errx(EXIT_FAILURE,
				"payload mismatch; sent 0x%x, received 0x%x",
				c, r);

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "mctp-req [<eid> net <net>]\n");
	fprintf(stderr, "default eid %d net %d\n", DEFAULT_EID, DEFAULT_NET);
}

int main(int argc, char ** argv)
{
	unsigned int net = DEFAULT_NET;
	mctp_eid_t eid = DEFAULT_EID;
	char *endp, *eidstr, *netstr;
	unsigned int tmp;

	if (argc == 1) {
		// use defaults
	} else if (argc == 4 && !(strcmp(argv[2], "net"))) {

		eidstr = argv[1];
		netstr = argv[3];

		tmp = strtoul(eidstr, &endp, 0);
		if (endp == eidstr || tmp > 0xff) {
			errx(EXIT_FAILURE, "Bad eid");
		}
		eid = tmp;

		net = strtoul(netstr, &endp, 0);
		if (endp == netstr) {
			errx(EXIT_FAILURE, "Bad net");
		}
	} else {
		usage();
		return 255;
	}

	return mctp_req(net, eid);
}

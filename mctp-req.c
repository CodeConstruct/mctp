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
#include "mctp-util.h"

static const int DEFAULT_NET = 1;
static const mctp_eid_t DEFAULT_EID = 8;

/* lladdrlen != -1 to ignore ifindex/lladdr */
static int mctp_req(unsigned int net, mctp_eid_t eid,
	unsigned int ifindex, uint8_t *lladdr, int lladdrlen,
	size_t reqlen, uint8_t *req)
{
	struct _sockaddr_mctp_ext addr;
	socklen_t addrlen;
	int rc, sd;
	uint8_t recv[300];

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0x0, sizeof(addr));
	addrlen = sizeof(struct _sockaddr_mctp);
	addr.smctp_family = AF_MCTP;
	addr.smctp_network = net;
	addr.smctp_addr.s_addr = eid;
	addr.smctp_type = 1;
	if (reqlen > 1) {
		addr.smctp_type = req[0];
		reqlen--;
		req++;
	}
	addr.smctp_tag = MCTP_TAG_OWNER;
	printf("req:  sending to (net %d, eid %d), type %d\n",
		net, eid, addr.smctp_type);

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
	rc = sendto(sd, req, reqlen, 0,
			(struct sockaddr *)&addr, addrlen);
	if (rc != (int)reqlen)
		err(EXIT_FAILURE, "sendto");

	/* receive response */
	addrlen = sizeof(addr);
	rc = recvfrom(sd, recv, sizeof(recv), MSG_TRUNC,
			(struct sockaddr *)&addr, &addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");
	else if (rc > (int)sizeof(recv))
		errx(EXIT_FAILURE, "unexpected length: got %d, exp %zd",
				rc, sizeof(recv));

	if (!(addrlen == sizeof(struct _sockaddr_mctp_ext)) ||
		(addrlen == sizeof(struct _sockaddr_mctp)))
		errx(EXIT_FAILURE, "unknown recv address length %d, exp %zd)",
				addrlen, sizeof(addr));

	printf("req:  message from (net %d, eid %d) type %d: hex dump:\n",
			addr.smctp_network, addr.smctp_addr.s_addr,
			addr.smctp_type);
	if (addrlen == sizeof(struct _sockaddr_mctp_ext)) {
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
			addr.smctp_ifindex,
			addr.smctp_haddr[0], addr.smctp_halen);
	}
	hexdump(recv, rc, "      ");

	// if (c != r)
	// 	errx(EXIT_FAILURE,
	// 			"payload mismatch; sent 0x%x, received 0x%x",
	// 			c, r);

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "mctp-req [<eid> net <net>] [if <ifindex> lladdr <hwaddr>] [colon-sep-hex-send-data]\n");
	fprintf(stderr, "default eid %d net %d\n", DEFAULT_EID, DEFAULT_NET);
	fprintf(stderr, "  When hex data is provided >1 byte, the first byte is the type\n");
}

int main(int argc, char ** argv)
{
	unsigned int net = DEFAULT_NET;
	mctp_eid_t eid = DEFAULT_EID;
	char *endp, *eidstr, *netstr, *ifstr, *lladdrstr;
	unsigned int tmp, ifindex;
	int lladdrlen = -1;
	uint8_t send_buf[300], lladdr[MAX_ADDR_LEN];
	size_t send_len, sz;

	// default
	send_buf[0] = 0xaa;
	send_len = 1;

	if (argc == 1) {
		// use defaults
	} else {
		if (argc < 4) {
			usage();
			errx(EXIT_FAILURE, "Short argument list");
		}

		if ((strcmp(argv[2], "net"))) {
			usage();
			errx(EXIT_FAILURE, "Bad '<eid> net <net>' part");
		}
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

		if (argc >= 8) {
			if ((strcmp(argv[4], "if") || strcmp(argv[6], "lladdr"))) {
				usage();
				errx(EXIT_FAILURE, "Bad 'if <ifindex> lladdr <lladdr>' part");
			}
			ifstr = argv[5];
			lladdrstr = argv[7];

			tmp = strtoul(ifstr, &endp, 0);
			if (endp == ifstr) {
				errx(EXIT_FAILURE, "Bad ifindex");
			}
			ifindex = tmp;

			sz = sizeof(lladdr);
			if (parse_hex_addr(lladdrstr, lladdr, &sz)) {
				errx(EXIT_FAILURE, "Bad lladdr");
			}
			lladdrlen = sz;
		}

		if (argc == 5 || argc == 9) {
			send_len = sizeof(send_buf);
			if (parse_hex_addr(argv[argc-1], send_buf, &send_len)) {
				errx(EXIT_FAILURE, "Bad send data");
			}
		}
	}

	return mctp_req(net, eid, ifindex, lladdr, lladdrlen,
		send_len, send_buf);
}

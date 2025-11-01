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
#include <poll.h>

#include "mctp.h"
#include "mctp-util.h"

static const int DEFAULT_NET = 1;
static const mctp_eid_t DEFAULT_EID = 8;
static const size_t DEFAULT_LEN = 1;

// Code Construct allocation
static const uint8_t VENDOR_TYPE_ECHO[3] = { 0xcc, 0xde, 0xf0 };
static const uint8_t MCTP_TYPE_VENDOR_PCIE = 0x7e;

/* lladdrlen != -1 to ignore ifindex/lladdr */
static int mctp_req(unsigned int net, mctp_eid_t eid, unsigned int ifindex,
		    uint8_t *lladdr, int lladdrlen, uint8_t *data, size_t len,
		    int8_t type, unsigned int timeout)
{
	struct sockaddr_mctp_ext addr;
	unsigned char *buf;
	socklen_t addrlen;
	int rc, sd, val;
	size_t i, buf_len;

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
	printf("req:  sending to (net %d, eid %d), type 0x%02x, len %zu\n", net,
	       eid, type, len);

	/* extended addressing */
	if (lladdrlen != -1) {
		addrlen = sizeof(struct sockaddr_mctp_ext);
		addr.smctp_halen = lladdrlen;
		memcpy(addr.smctp_haddr, lladdr, lladdrlen);
		addr.smctp_ifindex = ifindex;
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
		       addr.smctp_ifindex, addr.smctp_haddr[0],
		       addr.smctp_halen);
		val = 1;
		rc = setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				sizeof(val));
		if (rc < 0)
			errx(EXIT_FAILURE,
			     "Kernel does not support MCTP extended addressing");
	}

	/* send data */
	rc = sendto(sd, data, len, 0, (struct sockaddr *)&addr, addrlen);
	if (rc != (int)len)
		err(EXIT_FAILURE, "sendto(%zd)", len);

	struct pollfd pfd = { .fd = sd, .events = POLLIN };
	rc = poll(&pfd, 1, timeout);
	if (rc < 0) {
		err(EXIT_FAILURE, "poll");
	} else if (rc < 0) {
		err(EXIT_FAILURE, "timeout");
	}

	rc = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");
	buf_len = (size_t)rc;

	buf = malloc(buf_len);
	if (!buf)
		err(EXIT_FAILURE, "malloc");

	/* receive response */
	addrlen = sizeof(addr);
	rc = recvfrom(sd, buf, buf_len, MSG_TRUNC, (struct sockaddr *)&addr,
		      &addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "recvfrom");
	else if ((size_t)rc != buf_len)
		errx(EXIT_FAILURE, "unexpected length: got %d, exp %zd", rc,
		     buf_len);

	if (!(addrlen == sizeof(struct sockaddr_mctp_ext) ||
	      addrlen == sizeof(struct sockaddr_mctp)))
		errx(EXIT_FAILURE,
		     "unknown recv address length %d, exp %zu or %zu)", addrlen,
		     sizeof(struct sockaddr_mctp_ext),
		     sizeof(struct sockaddr_mctp));

	printf("rsp:  message from (net %d, eid %d) type 0x%02x len %zd\n",
	       addr.smctp_base.smctp_network, addr.smctp_base.smctp_addr.s_addr,
	       addr.smctp_base.smctp_type, buf_len);
	if (addrlen == sizeof(struct sockaddr_mctp_ext)) {
		printf("      ext ifindex %d ha[0]=0x%02x len %hhu\n",
		       addr.smctp_ifindex, addr.smctp_haddr[0],
		       addr.smctp_halen);
	}

	printf("data:");
	for (i = 0; i < buf_len; i++) {
		if (i % 16 == 0)
			printf("\n%04lX\t", i);
		printf("0x%02x ", buf[i]);
	}
	printf("\n");

	if (type == MCTP_TYPE_VENDOR_PCIE &&
	    !memcmp(data, VENDOR_TYPE_ECHO, sizeof(VENDOR_TYPE_ECHO))) {
		if (buf_len >= sizeof(VENDOR_TYPE_ECHO) &&
		    memcmp(buf, VENDOR_TYPE_ECHO, sizeof(VENDOR_TYPE_ECHO))) {
			errx(EXIT_FAILURE, "unexpected vendor ID");
		}

		if (len != buf_len) {
			errx(EXIT_FAILURE,
			     "unmatched payload length, "
			     "sent %zd bytes, but received %zd bytes",
			     len - sizeof(VENDOR_TYPE_ECHO),
			     buf_len - sizeof(VENDOR_TYPE_ECHO));
		}

		for (i = sizeof(VENDOR_TYPE_ECHO); i < len; i++) {
			if (buf[i] != data[i])
				errx(EXIT_FAILURE,
				     "payload mismatch at byte 0x%zx; "
				     "sent 0x%02x, but received 0x%02x",
				     i - sizeof(VENDOR_TYPE_ECHO), data[i],
				     buf[i]);
		}
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"mctp-req [eid <eid>] [net <net>] [ifindex <ifindex> lladdr <hwaddr>]"
		" [timeout <ms>] [type <type>] [len <len>] [data <data>]\n");
	fprintf(stderr, "default eid %d net %d len %zd\n", DEFAULT_EID,
		DEFAULT_NET, DEFAULT_LEN);
	fprintf(stderr,
		"default to send <data> as payload of code construct echo command if"
		" type is not specified");
	fprintf(stderr, "<data> is colon separated hex bytes, e.g. cc:de:f0");
}

int main(int argc, char **argv)
{
	uint8_t *data, *buf, lladdr[MAX_ADDR_LEN];
	int lladdrlen = -1, datalen = -1;
	unsigned int net = DEFAULT_NET;
	mctp_eid_t eid = DEFAULT_EID;
	size_t len = DEFAULT_LEN, sz;
	char *endp, *optname, *optval;
	unsigned int tmp, ifindex;
	uint8_t type = MCTP_TYPE_VENDOR_PCIE;
	unsigned int timeout = 1000;
	bool valid_parse;
	bool echo_req = true;
	int i;

	if (!(argc % 2)) {
		warnx("extra argument %s", argv[argc - 1]);
		usage();
		return 255;
	}

	data = NULL;
	ifindex = 0;

	for (i = 1; i < argc; i += 2) {
		optname = argv[i];
		optval = argv[i + 1];

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
		} else if (!strcmp(optname, "timeout")) {
			timeout = tmp;
		} else if (!strcmp(optname, "len")) {
			if (tmp > 64 * 1024)
				errx(EXIT_FAILURE, "Bad len");
			len = tmp;
		} else if (!strcmp(optname, "type")) {
			if (tmp > 0xff)
				errx(EXIT_FAILURE, "Bad type");
			type = tmp;
			echo_req = false;
		} else if (!strcmp(optname, "data")) {
			sz = (strlen(optval) + 2) / 3;
			data = malloc(sz + sizeof(VENDOR_TYPE_ECHO));
			if (!data)
				err(EXIT_FAILURE, "malloc");
			if (parse_hex_addr(optval,
					   data + sizeof(VENDOR_TYPE_ECHO),
					   &sz)) {
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
			errx(EXIT_FAILURE, "invalid %s value %s", optname,
			     optval);
		}
	}

	if (data) {
		len = datalen;
	} else {
		data = malloc(len + sizeof(VENDOR_TYPE_ECHO));
		if (!data)
			err(EXIT_FAILURE, "malloc");
		buf = data + sizeof(VENDOR_TYPE_ECHO);
		for (i = 0; i < len; i++)
			*buf++ = i & 0xff;
	}

	if (echo_req) {
		memcpy(data, VENDOR_TYPE_ECHO, sizeof(VENDOR_TYPE_ECHO));
		buf = data;
		len += sizeof(VENDOR_TYPE_ECHO);
	} else {
		buf = data + sizeof(VENDOR_TYPE_ECHO);
	}

	return mctp_req(net, eid, ifindex, lladdr, lladdrlen, buf, len, type,
			timeout);
}

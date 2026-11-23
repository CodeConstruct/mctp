/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-client: a raw mctp client for the mctp kernel interface
 *
 * Copyright (c) 2025 Nvidia
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <sys/socket.h>
#include <errno.h>
#include <limits.h>

#include "mctp.h"
#include "mctp-netlink.h"
#include "mctp-util.h"

struct data_t {
	uint8_t *data;
	size_t len;
};

struct physical_address {
	int ifindex;
	uint8_t lladdr[MAX_ADDR_LEN];
	size_t lladdrlen;
};

/* Types and values taken from DSP0239 */
static struct type_lookup_t {
	const char *name;
	uint8_t type;
	const char *description;
} type_lookup[] = {
	{
		.name = "control",
		.type = 0,
		.description = "control mctp messages per DSP0236",
	},
	{
		.name = "pldm",
		.type = 1,
		.description = "platform level data model per DSP0241",
	},
	{
		.name = "nc-si",
		.type = 2,
		.description = "NC-SI traffic over MCTP per DSP0261",
	},
	{
		.name = "ethernet",
		.type = 3,
		.description = "Ethernet traffic over MCTP per DSP0261",
	},
	{
		.name = "nvme",
		.type = 4,
		.description = "nvme over mctp per DSP0235",
	},
	{
		.name = "spdm",
		.type = 5,
		.description = "spdm over mctp per DSP0275",
	},
	{
		.name = "secured",
		.type = 6,
		.description =
			"secured messages using spdm over mctp per DSP0276",
	},
	{
		.name = "cxl-cci",
		.type = 8,
		.description =
			"CXL type 3 device component command interface over mctp per DSP0281",
	},
	{
		.name = "pcie-mi",
		.type = 9,
		.description =
			"PCIe management interface over mctp per DSP0291",
	},
	{
		.name = "pci",
		.type = 0x7e,
		.description = "vdm using a pci based vendor id per DSP0236",
	},
	{
		.name = "iana",
		.type = 0x7f,
		.description = "vdm using an iana based vendor id per DSP0236",
	},
};

static int do_type_lookup(char *type_str)
{
	size_t ctr;

	for (ctr = 0; ctr < ARRAY_SIZE(type_lookup); ++ctr) {
		if (!strcmp(type_str, type_lookup[ctr].name))
			return type_lookup[ctr].type;
	}

	return -ENOENT;
};

static int do_send_recv(unsigned int net, mctp_eid_t eid, uint8_t type,
			const struct physical_address *physical,
			struct data_t *data)
{
	struct sockaddr_mctp_ext addr;
	ssize_t rc, recvlen, ctr;
	uint8_t *recv_buffer;
	socklen_t addrlen;
	int sd;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	memset(&addr, 0, sizeof(addr));
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;
	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = net;
	addr.smctp_base.smctp_type = type;
	addr.smctp_base.smctp_addr.s_addr = eid;
	addrlen = sizeof(struct sockaddr_mctp);

	if (physical) {
		int val = 1;

		if (setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
			       sizeof(val)))
			err(EXIT_FAILURE, "setsockopt(MCTP_OPT_ADDR_EXT)");
		addr.smctp_ifindex = physical->ifindex;
		addr.smctp_halen = physical->lladdrlen;
		memcpy(addr.smctp_haddr, physical->lladdr, physical->lladdrlen);
		addrlen = sizeof(addr);
	}

	rc = sendto(sd, data->data, data->len, 0, (struct sockaddr *)&addr,
		    addrlen);
	if (rc < 0)
		err(EXIT_FAILURE, "sendto(%zd) failed", data->len);
	if (rc != (ssize_t)data->len)
		err(EXIT_FAILURE, "sendto(%zd) partial send (%zd)", data->len,
		    rc);

	recvlen = recvfrom(sd, NULL, 0, MSG_TRUNC | MSG_PEEK, NULL, NULL);
	if (recvlen < 0)
		err(EXIT_FAILURE, "receive failed %zd", recvlen);

	recv_buffer = malloc(recvlen);
	if (!recv_buffer)
		errx(EXIT_FAILURE, "malloc failed for recv");

	rc = recvfrom(sd, recv_buffer, recvlen, MSG_TRUNC, NULL, NULL);

	if (rc < 0)
		err(EXIT_FAILURE, "receive failed %zd", recvlen);

	if (recvlen != rc)
		errx(EXIT_FAILURE, "invalid bytes received: %zd, expected %zd",
		     rc, recvlen);

	for (ctr = 0; ctr < rc; ++ctr) {
		printf("%02X", recv_buffer[ctr]);
		if (ctr != (rc - 1))
			printf(" ");
	}

	printf("\n");

	return 0;
}

static void print_usage()
{
	size_t ctr;

	printf("usage:\n\tmctp-client [net <net>] [eid <eid>] [iface <iface> [lladdr <lladdr>]] type <type> data <data>\n");
	printf("at least one of eid or iface is required. iface selects physical addressing.\n");
	printf("net defaults to MCTP_NET_ANY, eid defaults to 0 with iface.\n");
	printf("data is space delimited hexadecimal and must be the last parameter.\n");
	printf("possible types:\n");
	for (ctr = 0; ctr < ARRAY_SIZE(type_lookup); ++ctr) {
		printf("\t%s: %s\n", type_lookup[ctr].name,
		       type_lookup[ctr].description);
	}
	printf("return data is always output as space delimited hexadecimal\n");
}

static struct data_t create_data(char **data_start, size_t count)
{
	unsigned long int tmp;
	struct data_t data;
	char *endp;
	size_t ctr;

	data.data = malloc(count);
	if (!data.data)
		errx(EXIT_FAILURE, "failed to malloc for data");

	if (!count)
		errx(EXIT_FAILURE, "no data to send");

	data.len = count;

	for (ctr = 0; ctr < count; ++ctr) {
		tmp = strtoul(data_start[ctr], &endp, 16);
		if (endp == data_start[ctr])
			errx(EXIT_FAILURE, "data must be the last parameter");
		if (tmp == ULONG_MAX)
			errx(EXIT_FAILURE, "failed to parse: %s",
			     data_start[ctr]);
		if (tmp > 0xff)
			errx(EXIT_FAILURE, "data parsed is invalid: %s",
			     data_start[ctr]);
		data.data[ctr] = tmp;
	}

	return data;
}

static int find_data(int argc, char **argv)
{
	int ctr;

	for (ctr = argc - 1; ctr > 0; --ctr) {
		if (!strcmp(argv[ctr], "data"))
			return ctr;
	}

	return -ENOENT;
}

static void check_lladdr_len(const mctp_nl *nl, const char *iface,
			     const struct physical_address *physical)
{
	size_t hwaddr_len;

	if (mctp_nl_hwaddr_len_byindex(nl, physical->ifindex, &hwaddr_len))
		errx(EXIT_FAILURE, "failed to query lladdr length for %s",
		     iface);

	if (physical->lladdrlen != hwaddr_len)
		errx(EXIT_FAILURE,
		     "invalid lladdr length for %s: expected %zu bytes, got %zu",
		     iface, hwaddr_len, physical->lladdrlen);
}

static void resolve_physical_address(const char *iface,
				     struct physical_address *physical)
{
	mctp_nl *nl;

	nl = mctp_nl_new(false);
	if (!nl)
		errx(EXIT_FAILURE, "failed to query MCTP interfaces");

	physical->ifindex = mctp_nl_ifindex_byname(nl, iface);
	if (!physical->ifindex)
		errx(EXIT_FAILURE, "invalid interface: %s", iface);

	check_lladdr_len(nl, iface, physical);

	mctp_nl_close(nl);
}

int main(int argc, char **argv)
{
	struct physical_address physical = { 0 };
	bool valid_eid, valid_type, valid_lladdr;
	unsigned int net = MCTP_NET_ANY;
	const char *iface = NULL;
	struct data_t send_data;
	int type, ctr, data_idx;
	mctp_eid_t eid = 0;

	data_idx = find_data(argc, argv);
	if (data_idx < 0) {
		printf("unable to find data to send\n");
		print_usage();
		return EXIT_FAILURE;
	}

	send_data = create_data(argv + data_idx + 1, argc - data_idx - 1);

	/*
	 * a little hacky, start by parsing the data since it needs to be last
	 * then parse the rest of the params
	 */
	argc = data_idx;
	valid_eid = false;
	valid_type = false;
	valid_lladdr = false;

	for (ctr = 1; ctr < argc; ctr += 2) {
		char *tag, *val;
		int rc;

		tag = argv[ctr];
		val = argv[ctr + 1];

		if (!strcmp(tag, "eid")) {
			rc = parse_eid(val, &eid);
			if (rc)
				errx(EXIT_FAILURE, "invalid eid: %s", val);
			valid_eid = true;
		} else if (!strcmp(tag, "net")) {
			rc = parse_uint32(val, &net);
			if (rc)
				errx(EXIT_FAILURE, "invalid net: %s", val);
		} else if (!strcmp(tag, "type")) {
			type = do_type_lookup(val);
			if (type < 0 || type > 0xff)
				errx(EXIT_FAILURE, "invalid type: %s", val);
			valid_type = true;
		} else if (!strcmp(tag, "iface")) {
			iface = val;
		} else if (!strcmp(tag, "lladdr")) {
			physical.lladdrlen = sizeof(physical.lladdr);
			if (parse_hex_addr(val, physical.lladdr,
					   &physical.lladdrlen))
				errx(EXIT_FAILURE, "invalid lladdr: %s", val);
			valid_lladdr = true;
		} else
			errx(EXIT_FAILURE, "invalid argument: %s", tag);
	}

	if (!valid_type || (!valid_eid && !iface) || (valid_lladdr && !iface)) {
		print_usage();
		return EXIT_FAILURE;
	}

	if (iface)
		resolve_physical_address(iface, &physical);

	return do_send_recv(net, eid, type, iface ? &physical : NULL,
			    &send_data);
}

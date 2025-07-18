#define _XOPEN_SOURCE 700
#include <time.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <assert.h>
#include <sys/random.h>

#include "mctp.h"

// Code Construct allocation
static const uint8_t VENDOR_TYPE_BENCH[3] = { 0xcc, 0xde, 0xf1 };
static const uint8_t MCTP_TYPE_VENDOR_PCIE = 0x7e;

struct mctp_bench_send_args {
	mctp_eid_t eid;
	size_t len;
	int net;
};

struct mctp_bench_recv_args {
	mctp_eid_t eid;
	int net;

	unsigned int payload_size;
	uint64_t message_count;
};

// Packet fields are little endian.

struct msg_header {
	uint8_t vendor_prefix[sizeof(VENDOR_TYPE_BENCH)];
	uint16_t magic;
	uint32_t seq_no;
} __attribute__((packed));

struct command_msg {
	uint8_t vendor_prefix[sizeof(VENDOR_TYPE_BENCH)];
	uint16_t magic;
	// Initial portion the same structure as msg_header,
	// with different magic value.

	uint8_t version;
	uint8_t command;
	uint32_t iid;

	uint8_t body[];
} __attribute__((packed));

struct mctp_stats {
	size_t total_received_len, curr_packet_len;
	uint32_t prev_seq_no;
	float elapsed_time;
	unsigned long msgs_dropped, msg_count, invalid_payloads;
};

struct recv_ctx {
	struct mctp_stats stats;
	struct timespec start_time, current_time;
	unsigned char *buf;
	bool started_recv_flag;
	int sd;
};

struct command_response {
	// A command_response value
	uint8_t status;
} __attribute__((packed));

struct command_request_bench {
	uint32_t flags;
	uint16_t payload_size;
	uint64_t message_count;
} __attribute__((packed));

static const size_t MSG_HEADER_LEN = sizeof(struct msg_header);
static const size_t MAX_LEN = 64 * 1024 - 1;
static const uint32_t SEQ_START = UINT32_MAX - 5;
static const uint16_t MAGIC_VAL = 0xbeca;
static const int DEFAULT_NET = MCTP_NET_ANY;
static const int DEFAULT_SECONDS_INTERVAL = 2;

static const uint16_t COMMAND_MAGIC = 0x22dd;
static const uint8_t COMMAND_VERSION = 1;

enum command {
	COMMAND_RESPONSE = 0x00,
	COMMAND_REQUEST_BENCH = 0x01,
};

enum command_status {
	RESPONSE_SUCCESS = 0x00,
	RESPONSE_OTHER_FAILURE = 0x01,
	RESPONSE_UNKNOWN_COMMAND = 0x02,
	RESPONSE_BAD_ARGUMENT = 0x03,
};

static int request_recv(const struct mctp_bench_recv_args *recv_args);
static int command(mctp_eid_t eid, int net, enum command command,
		   const void *body, size_t body_len);

static float get_throughput(float total_len, float elapsed_time)
{
	return total_len / (elapsed_time * 1024);
}

static void print_stats(struct recv_ctx *recv_ctx)
{
	float throughput = get_throughput(recv_ctx->stats.total_received_len,
					  recv_ctx->stats.elapsed_time);
	printf("Throughput: %.2f kB/s | Received: %lu msgs | "
	       "Dropped: %lu msgs | "
	       "Invalid: %lu msgs\n",
	       throughput, recv_ctx->stats.msg_count,
	       recv_ctx->stats.msgs_dropped, recv_ctx->stats.invalid_payloads);
}

static float get_elapsed_time(struct recv_ctx *recv_ctx)
{
	return (recv_ctx->current_time.tv_sec - recv_ctx->start_time.tv_sec) +
	       (recv_ctx->current_time.tv_nsec - recv_ctx->start_time.tv_nsec) /
		       1.0e9;
}

static int get_timeout(struct recv_ctx *recv_ctx)
{
	int time_to_print_sec =
		(DEFAULT_SECONDS_INTERVAL) -
		(recv_ctx->current_time.tv_sec - recv_ctx->start_time.tv_sec);
	return (time_to_print_sec > 0) ? time_to_print_sec * 1000 : 0;
}

static bool valid_payload(unsigned char *buf, size_t buflen)
{
	for (size_t i = MSG_HEADER_LEN; i < buflen; i++) {
		if (buf[i] != (i & 0xff))
			return false;
	}
	return true;
}

static uint32_t get_packets_dropped(uint32_t curr, uint32_t prev)
{
	if (prev < curr) {
		return curr - prev - 1;
	} else if (curr == prev) {
		return 0;
	}
	return UINT32_MAX - prev + curr;
}

static int validate_vendor_prefix(const void *buf, size_t buf_len)
{
	if (buf_len < sizeof(VENDOR_TYPE_BENCH)) {
		warn("recv: short vendor prefix, got:%zd bytes", buf_len);
		return -1;
	}

	const struct msg_header *hdr = (const struct msg_header *)buf;
	if (memcmp(hdr->vendor_prefix, VENDOR_TYPE_BENCH,
		   sizeof(VENDOR_TYPE_BENCH)) != 0) {
		warnx("recv: unexpected vendor prefix %02x %02x %02x",
		      hdr->vendor_prefix[0], hdr->vendor_prefix[1],
		      hdr->vendor_prefix[2]);
		return -1;
	}
	return 0;
}

static int handle_incoming_msg(struct recv_ctx *recv_ctx)
{
	const struct msg_header *hdr;

	ssize_t len = recv(recv_ctx->sd, recv_ctx->buf, MAX_LEN, MSG_TRUNC);
	if (len < 0) {
		warn("recv: recvfrom");
		return -1;
	}

	recv_ctx->stats.curr_packet_len = len;
	if (recv_ctx->stats.curr_packet_len > MAX_LEN) {
		warn("recv: expected max len:%zd bytes, got:%zd bytes", MAX_LEN,
		     recv_ctx->stats.curr_packet_len);
		return -1;
	}

	if (validate_vendor_prefix(recv_ctx->buf,
				   recv_ctx->stats.curr_packet_len) != 0) {
		return -1;
	}

	hdr = (const struct msg_header *)recv_ctx->buf;
	if (recv_ctx->stats.curr_packet_len < sizeof(*hdr)) {
		warn("recv: short message, got:%zd bytes",
		     recv_ctx->stats.curr_packet_len);
		return -1;
	}

	if (hdr->magic != MAGIC_VAL) {
		warnx("recv: expected magic:\"%x\", got:\"%x\"\n", MAGIC_VAL,
		      hdr->magic);
		return -1;
	}

	recv_ctx->stats.total_received_len += recv_ctx->stats.curr_packet_len;
	recv_ctx->stats.msg_count++;

	if (!valid_payload(recv_ctx->buf, recv_ctx->stats.curr_packet_len))
		recv_ctx->stats.invalid_payloads++;

	if (!recv_ctx->started_recv_flag) {
		printf("recv: first msg received\n");
		recv_ctx->started_recv_flag = true;
		clock_gettime(CLOCK_MONOTONIC, &recv_ctx->start_time);
		recv_ctx->stats.prev_seq_no = hdr->seq_no;
		recv_ctx->stats.msgs_dropped +=
			get_packets_dropped(hdr->seq_no, SEQ_START);
		return -1;
	}

	recv_ctx->stats.msgs_dropped +=
		get_packets_dropped(hdr->seq_no, recv_ctx->stats.prev_seq_no);

	recv_ctx->stats.prev_seq_no = hdr->seq_no;
	return 0;
}

static int mctp_bench_recv(const struct mctp_bench_recv_args *recv_args)
{
	struct recv_ctx recv_ctx = { 0 };
	struct sockaddr_mctp addr = { 0 };
	int rc;

	// Construct a listening socket prior to sending any receive request.
	// Otherwise the peer might respond before we're ready, and we'll miss
	// the first few messages.
	recv_ctx.sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (recv_ctx.sd < 0)
		err(EXIT_FAILURE, "recv: socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = MCTP_TYPE_VENDOR_PCIE;
	addr.smctp_tag = MCTP_TAG_OWNER;

	recv_ctx.buf = malloc(MAX_LEN);
	if (!recv_ctx.buf) {
		err(EXIT_FAILURE, "recv: malloc failed");
	}

	rc = bind(recv_ctx.sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		close(recv_ctx.sd);
		err(EXIT_FAILURE, "recv: bind failed");
	}

	recv_ctx.started_recv_flag = false;

	if (request_recv(recv_args) != 0) {
		errx(EXIT_FAILURE, "Request failed");
	}

	printf("recv: waiting for first msg\n");
	while (1) {
		int timeout;
		struct pollfd pollfd;
		pollfd.fd = recv_ctx.sd;
		pollfd.events = POLLIN;

		if (recv_ctx.started_recv_flag) {
			clock_gettime(CLOCK_MONOTONIC, &recv_ctx.current_time);
			timeout = get_timeout(&recv_ctx);
		} else
			timeout = -1;

		rc = poll(&pollfd, 1, timeout);
		if (rc < 0) {
			warn("recv: poll failed");
			break;
		}

		if (rc == 1 && pollfd.revents & POLLIN) {
			rc = handle_incoming_msg(&recv_ctx);
			if (rc)
				continue;
		}

		clock_gettime(CLOCK_MONOTONIC, &recv_ctx.current_time);

		recv_ctx.stats.elapsed_time = get_elapsed_time(&recv_ctx);
		if (recv_ctx.stats.elapsed_time >= DEFAULT_SECONDS_INTERVAL) {
			print_stats(&recv_ctx);
			recv_ctx.stats.total_received_len = 0;
			recv_ctx.stats.msg_count = 0l;
			recv_ctx.stats.msgs_dropped = 0l;
			recv_ctx.stats.invalid_payloads = 0l;
			clock_gettime(CLOCK_MONOTONIC, &recv_ctx.start_time);
		}
	}
	free(recv_ctx.buf);
	close(recv_ctx.sd);
	return 0;
}

static int allocate_tag(int sd, mctp_eid_t eid, int net, uint8_t *tag)
{
	int rc = -1;

#if !defined(SIOCMCTPALLOCTAG2) && !defined(SIOCMCTPALLOCTAG)
#error No ALLOCTAG ioctl available
#endif

#if defined(SIOCMCTPALLOCTAG2)
	struct mctp_ioc_tag_ctl2 ctl2 = {
		.peer_addr = eid,
		.net = net,
	};

	errno = 0;
	rc = ioctl(sd, SIOCMCTPALLOCTAG2, &ctl2);
	if (!rc) {
		*tag = ctl2.tag;
		return 0;
	}

	/*
         * If Alloctag V2 does not exist, we would get EINVAL.
         * In that case we want to fallback to Alloctag V1.
         * All other cases we return the error.
         */
	if (errno != EINVAL) {
		return rc;
	}
#endif

#if defined(SIOCMCTPALLOCTAG)
	struct mctp_ioc_tag_ctl ctl = {
		.peer_addr = eid,
	};

	/* Alloctag V1 only works with default net. */
	if (net != DEFAULT_NET) {
		warnx("Can't use ALLOCTAG V1 for non-default net:%d", net);
		return -1;
	}

	rc = ioctl(sd, SIOCMCTPALLOCTAG, &ctl);
	if (!rc) {
		*tag = ctl.tag;
		return 0;
	}
#endif
	return rc;
}

static int mctp_bench_send(struct mctp_bench_send_args send_args)
{
	struct sockaddr_mctp addr = { 0 };
	struct msg_header *hdr;
	unsigned char *buf;
	uint32_t sequence = SEQ_START;
	uint8_t tag;
	int rc, sd, last_rc;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "send: socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = send_args.net;
	addr.smctp_addr.s_addr = send_args.eid;
	addr.smctp_type = MCTP_TYPE_VENDOR_PCIE;
	printf("send: eid = %d, net = %d, type = %d, msg_len = %zu bytes\n",
	       send_args.eid, send_args.net, addr.smctp_type, send_args.len);

	buf = malloc(send_args.len);
	if (!buf)
		err(EXIT_FAILURE, "send: malloc");

	rc = allocate_tag(sd, send_args.eid, send_args.net, &tag);
	if (rc)
		err(EXIT_FAILURE, "send: alloc tag failed");

	for (size_t i = MSG_HEADER_LEN; i < send_args.len; i++)
		buf[i] = i & 0xff;

	hdr = (struct msg_header *)buf;
	memcpy(hdr->vendor_prefix, VENDOR_TYPE_BENCH,
	       sizeof(VENDOR_TYPE_BENCH));
	hdr->magic = MAGIC_VAL;

	/* will not match a sensible sendto() return value */
	last_rc = 0;

	while (1) {
		addr.smctp_tag = tag;
		hdr->seq_no = sequence;

		rc = sendto(sd, buf, send_args.len, 0, (struct sockaddr *)&addr,
			    sizeof(addr));
		if (rc != (int)send_args.len && rc != last_rc) {
			last_rc = rc;
			warn("send: sendto(%zd bytes)", send_args.len);
		}

		sequence++;
	}
	free(buf);
	close(sd);
	return 0;
}

static void usage(void)
{
	fprintf(stderr, "'mctp-bench send' [len <value>] eid [<net>,]<eid>\n");
	fprintf(stderr,
		"'mctp-bench recv' [eid [<net>,]<eid>] [len <value>] [count <value>]\n");
}

static int parse_int(const char *opt, unsigned int *out)
{
	char *endptr;

	errno = 0;
	*out = strtoul(opt, &endptr, 0);
	if (endptr == opt || errno == ERANGE) {
		return -1;
	}
	return 0;
}

static int parse_u64(const char *opt, uint64_t *out)
{
	char *endptr;

	static_assert(sizeof(uint64_t) == sizeof(unsigned long long), "u64");

	errno = 0;
	*out = strtoull(opt, &endptr, 0);
	if (endptr == opt || errno == ERANGE) {
		return -1;
	}
	return 0;
}

static int parse_net_and_eid(const char *opt, mctp_eid_t *eid, int *net)
{
	const char *comma;
	unsigned int tmp, rc;

	for (size_t i = 0; i < strlen(opt); i++) {
		if ((opt[i] < '0' || opt[i] > '9') && opt[i] != ',') {
			warnx("send: invalid eid or net value:\"%s\"", opt);
			return -1;
		}
	}
	comma = strchr(opt, ',');

	rc = parse_int(opt, &tmp);
	if (rc) {
		warn("send: invalid eid or net value:\"%s\"", opt);
		return -1;
	}

	if (comma) {
		if (!tmp) {
			warnx("send: eid cannot be set to 0\n");
			return -1;
		}

		*net = tmp;
		comma++;

		rc = parse_int(comma, &tmp);
		if (rc) {
			warn("send: invalid eid or net value:\"%s\"", opt);
			return -1;
		}
	}
	*eid = tmp;
	return 0;
}

static int parse_len(struct mctp_bench_send_args *send_args, char *opt)
{
	unsigned int tmp = 0;
	int rc = 0;

	rc = parse_int(opt, &tmp);
	if (rc || tmp > MAX_LEN) {
		warnx("send: invalid len value:\"%s\", max len:%zd bytes", opt,
		      MAX_LEN);
		return -1;
	}

	if (tmp >= MSG_HEADER_LEN) {
		send_args->len = tmp;
	} else {
		printf("send: min len is %zd bytes, len set to %zd bytes\n",
		       MSG_HEADER_LEN, MSG_HEADER_LEN);
		send_args->len = MSG_HEADER_LEN;
	}
	return 0;
}

static int parse_recv_args(int argc, char **argv,
			   struct mctp_bench_recv_args *recv_args)
{
	const char *optname, *optval;
	int rc;

	memset(recv_args, 0x0, sizeof(*recv_args));
	for (int i = 2; i < argc; i += 2) {
		optname = argv[i];
		optval = argv[i + 1];
		if (!strcmp(optname, "eid")) {
			rc = parse_net_and_eid(optval, &recv_args->eid,
					       &recv_args->net);
			if (rc) {
				usage();
				return EXIT_FAILURE;
			}
		} else if (!strcmp(optname, "len")) {
			rc = parse_int(optval, &recv_args->payload_size);
			if (rc) {
				usage();
				return EXIT_FAILURE;
			}
		} else if (!strcmp(optname, "count")) {
			rc = parse_u64(optval, &recv_args->message_count);
			if (rc) {
				usage();
				return EXIT_FAILURE;
			}
		} else {
			warnx("recv: unknown argument:\"%s\"\n", optname);
			usage();
			return EXIT_FAILURE;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	char *optname, *optval;
	int rc = 0;

	if (argc < 2 || argc > 8) {
		warnx("%s\n", (argc < 2) ? "error: missing command" :
					   "error: too many arguments");
		usage();
		return EXIT_FAILURE;
	}

	if (!strcmp(argv[1], "send")) {
		struct mctp_bench_send_args send_args = {
			.eid = 0,
			.len = MSG_HEADER_LEN,
			.net = DEFAULT_NET,
		};
		for (int i = 2; i < argc; i += 2) {
			optname = argv[i];
			optval = argv[i + 1];
			if (!strcmp(optname, "eid")) {
				rc = parse_net_and_eid(optval, &send_args.eid,
						       &send_args.net);
				if (rc) {
					usage();
					return EXIT_FAILURE;
				}
			} else if (!strcmp(optname, "len")) {
				rc = parse_len(&send_args, optval);
				if (rc) {
					usage();
					return EXIT_FAILURE;
				}
			} else {
				warnx("send: unknown argument:\"%s\"\n",
				      optname);
				usage();
				return EXIT_FAILURE;
			}
		}

		if (!send_args.eid) {
			warnx("send: missing eid\n");
			usage();
			return EXIT_FAILURE;
		}
		return mctp_bench_send(send_args);
	} else if (!strcmp(argv[1], "recv")) {
		struct mctp_bench_recv_args recv_args;
		if (parse_recv_args(argc, argv, &recv_args)) {
			usage();
			return EXIT_FAILURE;
		}
		return mctp_bench_recv(&recv_args);
	} else {
		warnx("error: unknown command:\"%s\"\n", argv[1]);
		usage();
		return EXIT_FAILURE;
	}
	return EXIT_FAILURE;
}

static int request_recv(const struct mctp_bench_recv_args *recv_args)
{
	if (recv_args->eid == 0) {
		return 0;
	}

	if (recv_args->payload_size > UINT16_MAX) {
		errx(EXIT_FAILURE, "Payload too large");
	}

	struct command_request_bench body = {
		.flags = 0,
		.payload_size = (uint16_t)recv_args->payload_size,
		.message_count = recv_args->message_count,
	};

	if (body.payload_size == 0) {
		// arbitrary TODO
		body.payload_size = 100;
	}

	if (body.message_count == 0) {
		// nearly 2**64
		body.message_count = 18000000000000000000ULL;
	}

	printf("Requesting %llu %u byte chunks\n",
	       (unsigned long long)body.message_count, body.payload_size);

	int status = command(recv_args->eid, recv_args->net,
			     COMMAND_REQUEST_BENCH, &body, sizeof(body));

	return status;
}

static int command(mctp_eid_t eid, int net, enum command command,
		   const void *body, size_t body_len)
{
	static_assert(sizeof(struct command_msg) >= sizeof(struct msg_header),
		      "command msg size");

	struct sockaddr_mctp addr = { 0 };
	int sd;
	int rc;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0) {
		err(EXIT_FAILURE, "command socket");
	}

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = net;
	addr.smctp_addr.s_addr = eid;
	addr.smctp_type = MCTP_TYPE_VENDOR_PCIE;
	addr.smctp_tag = MCTP_TAG_OWNER;

	size_t req_len = sizeof(struct command_msg) + body_len;
	struct command_msg *req = malloc(req_len);
	if (!req) {
		errx(EXIT_FAILURE, "out of memory");
	}

	memcpy(&req->vendor_prefix, VENDOR_TYPE_BENCH,
	       sizeof(VENDOR_TYPE_BENCH));
	req->magic = COMMAND_MAGIC;
	req->version = COMMAND_VERSION;
	req->command = command;
	getrandom(&req->iid, sizeof(req->iid), 0);
	memcpy(req->body, body, body_len);

	rc = sendto(sd, req, req_len, 0, (struct sockaddr *)&addr,
		    sizeof(addr));
	if (rc != (ssize_t)req_len) {
		err(EXIT_FAILURE, "command send failed");
	}

	size_t resp_len = sizeof(struct command_msg) + 2000;
	struct command_msg *resp = malloc(resp_len);
	if (!resp) {
		errx(EXIT_FAILURE, "out of memory");
	}

	rc = recv(sd, resp, resp_len, 0);
	if (rc < 0) {
		err(EXIT_FAILURE, "command recv failed");
	}
	resp_len = (size_t)rc;
	if (resp_len !=
	    sizeof(struct command_msg) + sizeof(struct command_response)) {
		errx(EXIT_FAILURE, "command wrong length");
	}

	if (validate_vendor_prefix(resp, resp_len) != 0) {
		errx(EXIT_FAILURE, "command bad response");
	}

	if (resp->magic != COMMAND_MAGIC) {
		errx(EXIT_FAILURE, "command bad magic");
	}

	if (resp->version != COMMAND_VERSION) {
		errx(EXIT_FAILURE, "command bad version");
	}

	if (resp->iid != req->iid) {
		errx(EXIT_FAILURE, "command wrong instance ID");
	}

	if (resp->command != COMMAND_RESPONSE) {
		errx(EXIT_FAILURE, "command wrong response");
	}

	struct command_response resp_body;
	memcpy(&resp_body, resp->body, sizeof(struct command_response));
	if (resp_body.status != 0) {
		errx(EXIT_FAILURE, "Response failed, status %d",
		     resp_body.status);
	}

	free(req);
	free(resp);
	return resp_body.status;
}

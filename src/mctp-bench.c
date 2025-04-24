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

#include "mctp.h"

struct mctp_bench_send_args {
        mctp_eid_t eid;
        size_t len;
        int net;
};

struct msg_header {
        uint16_t magic;
        uint32_t seq_no;
};

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

static const size_t MSG_HEADER_LEN = sizeof(struct msg_header);
static const size_t MAX_LEN = 64 * 1024 - 1;
static const uint32_t SEQ_START = UINT32_MAX - 5;
static const uint16_t MAGIC_VAL = 0xbeca;
static const int DEFAULT_NET = MCTP_NET_ANY;
static const int DEFAULT_SECONDS_INTERVAL = 10;

static float get_throughput(float total_len, float elapsed_time)
{
        return total_len / (elapsed_time * 1024);
}

static void print_stats(struct recv_ctx *recv_ctx)
{
        float throughput = get_throughput(recv_ctx->stats.total_received_len,
                                          recv_ctx->stats.elapsed_time);
        printf("Throughput: %.2f kB/s | Recevied: %lu msgs | "
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

static int handle_incoming_msg(struct recv_ctx *recv_ctx)
{
        struct msg_header *hdr;

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

        hdr = (struct msg_header *)recv_ctx->buf;
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

static int mctp_bench_recv()
{
        struct recv_ctx recv_ctx = {0};
        struct sockaddr_mctp addr = {0};
        int rc;

        recv_ctx.sd = socket(AF_MCTP, SOCK_DGRAM, 0);
        if (recv_ctx.sd < 0)
                err(EXIT_FAILURE, "recv: socket");

        addr.smctp_family = AF_MCTP;
        addr.smctp_network = MCTP_NET_ANY;
        addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
        addr.smctp_type = 1;
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
        struct sockaddr_mctp addr = {0};
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
        addr.smctp_type = 1;
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
        fprintf(stderr, "'mctp-bench recv'\n");
}

static int parse_int(char *opt, unsigned int *out)
{
        char *endptr;

        errno = 0;
        *out = strtoul(opt, &endptr, 0);
        if (endptr == opt || errno == ERANGE) {
                return -1;
        }
        return 0;
}

static int parse_net_and_eid(struct mctp_bench_send_args *send_args, char *opt)
{
        char *comma;
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

                send_args->net = tmp;
                comma++;

                rc = parse_int(comma, &tmp);
                if (rc) {
                        warn("send: invalid eid or net value:\"%s\"", opt);
                        return -1;
                }
        }
        send_args->eid = tmp;
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

int main(int argc, char **argv)
{
        char *optname, *optval;
        int rc = 0;

        if (argc < 2 || argc > 6) {
                warnx("%s\n", (argc < 2) ? "error: missing command"
                                         : "error: too many arguments");
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
                                rc = parse_net_and_eid(&send_args, optval);
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
                if (argc > 2) {
                        warnx("recv: does not take extra arguments\n");
                        usage();
                        return EXIT_FAILURE;
                }
                return mctp_bench_recv();
        } else {
                warnx("error: unknown command:\"%s\"\n", argv[1]);
                usage();
                return EXIT_FAILURE;
        }
        return EXIT_FAILURE;
}

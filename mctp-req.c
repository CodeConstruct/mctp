
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/socket.h>

#include "mctp.h"

int main(void)
{
	struct _sockaddr_mctp addr;
	socklen_t addrlen;
	int rc, sd;
	char c, r;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = 1;
	addr.smctp_addr.s_addr = 8;
	addr.smctp_type = 1;
	addr.smctp_tag = MCTP_TAG_OWNER;

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

	printf("message from (net %d, eid %d): 0x%02x\n",
			addr.smctp_network, addr.smctp_addr.s_addr,
			r);

	if (c != r)
		errx(EXIT_FAILURE,
				"payload mismatch; sent 0x%x, received 0x%x",
				c, r);

	return EXIT_SUCCESS;
}


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
	int rc, sd;
	char c;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = 1;
	addr.smctp_addr.s_addr = 8;
	addr.smctp_type = 1;
	addr.smctp_tag = MCTP_TAG_OWNER;

	c = 1;

	rc = sendto(sd, &c, sizeof(c), 0,
			(struct sockaddr *)&addr, sizeof(addr));
	if (rc != sizeof(c))
		err(EXIT_FAILURE, "sendto");

	return EXIT_SUCCESS;
}


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/socket.h>

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

int main(void)
{
	char c;
	int sd;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		err(EXIT_FAILURE, "socket");

	printf("socket created\n");

	read(0, &c, 1);

	return EXIT_SUCCESS;
}

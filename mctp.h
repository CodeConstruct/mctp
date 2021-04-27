
#ifndef _MCTP_H
#define _MCTP_H

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

#include <stdint.h>

typedef uint8_t			mctp_eid_t;

struct _mctp_addr {
	mctp_eid_t		s_addr;
};

struct _sockaddr_mctp {
	unsigned short int	smctp_family;
	int			smctp_network;
	struct _mctp_addr	smctp_addr;
	uint8_t			smctp_type;
	uint8_t			smctp_tag;
};

#define MCTP_NET_ANY 0
#define MCTP_ADDR_ANY 0xff
#define MCTP_TAG_OWNER 0x08


#endif /* _MCTP_H */

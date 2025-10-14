
#include <stdint.h>

#include <linux/netlink.h>

#include "mctp.h"

enum {
	CONTROL_OP_INIT,
	CONTROL_OP_SOCKET_MCTP,
	CONTROL_OP_SOCKET_NL,
	CONTROL_OP_TIMER,
};

struct control_msg_req {
	uint8_t type;
};

struct control_msg_rsp {
	uint8_t val;
};

union sock_msg_sockaddr {
	struct sockaddr_mctp mctp;
	struct sockaddr_mctp_ext mctp_ext;
	struct sockaddr_nl nl;
	unsigned char buf[56];
};

struct sock_msg {
	enum {
		SOCK_RECV,
		SOCK_SEND,
		SOCK_SETSOCKOPT,
		SOCK_BIND,
	} type;
	union {
		struct sock_msg_recv {
			union sock_msg_sockaddr addr;
			socklen_t addrlen;
			uint8_t data[];
		} recv;
		struct sock_msg_send {
			union sock_msg_sockaddr addr;
			socklen_t addrlen;
			uint8_t data[];
		} send;
		struct sock_msg_setsockopt {
			int level;
			int optname;
			uint8_t optdata[];
		} setsockopt;
		struct sock_msg_bind {
			union sock_msg_sockaddr addr;
			socklen_t addrlen;
		} bind;
	};
};

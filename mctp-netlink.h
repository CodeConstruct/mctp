#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/rtnetlink.h>

struct mctp_nl;
typedef struct mctp_nl mctp_nl;

/* Allocates the structure, connects to netlink, and populates
   the list of interfaces */
// verbose flag controls dumping error response packets
mctp_nl * mctp_nl_new(bool verbose);
/* Cleans and deallocates nl */
int mctp_nl_close(mctp_nl *nl);

/* Sends a message. If NLM_F_ACK flag is set it will wait for a
   response then print and return any error */
int mctp_nl_send(mctp_nl *nl, struct nlmsghdr *msg);
/* Sends a message and returns the responses.
   respp is optional, should be freed by the caller */
int mctp_nl_query(mctp_nl *nl, struct nlmsghdr *msg,
		struct nlmsghdr **respp, size_t *resp_lenp);

/* Lookup MCTP interfaces */
int mctp_nl_ifindex_byname(const mctp_nl *nl, const char *ifname);
const char* mctp_nl_if_byindex(const mctp_nl *nl, int index);
int mctp_nl_net_byindex(const mctp_nl *nl, int index);
void mctp_nl_linkmap_dump(const mctp_nl *nl);

/* Helpers */

void* mctp_get_rtnlmsg_attr(int rta_type, struct rtattr *rta, size_t len,
	size_t *ret_len);
bool mctp_get_rtnlmsg_attr_u32(int rta_type, struct rtattr *rta, size_t len,
				uint32_t *ret_value);
bool mctp_get_rtnlmsg_attr_u8(int rta_type, struct rtattr *rta, size_t len,
				uint8_t *ret_value);
/* Returns the space used */
size_t mctp_put_rtnlmsg_attr(struct rtattr **prta, size_t *rta_len,
	unsigned short type, const void* value, size_t val_len);

void mctp_dump_nlmsg_error(struct nlmsgerr *errmsg, size_t errlen);
void mctp_display_nlmsg_error(struct nlmsgerr *errmsg, size_t errlen);

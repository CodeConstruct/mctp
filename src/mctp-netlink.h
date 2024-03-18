#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/rtnetlink.h>

#include "mctp.h"

struct mctp_nl;
typedef struct mctp_nl mctp_nl;

struct mctp_nl_change {
#define MCTP_NL_OP_COUNT 6
	enum {
		MCTP_NL_ADD_LINK,
		MCTP_NL_DEL_LINK,
		MCTP_NL_CHANGE_NET,
		MCTP_NL_CHANGE_UP,
		MCTP_NL_ADD_EID,
		MCTP_NL_DEL_EID,
	} op;

	int ifindex;

	// Filled for ADD_EID, DEL_EID
	mctp_eid_t eid;

	// Filled for DEL_EID, DEL_LINK, CHANGE_NET
	int old_net;

	// Filled for CHANGE_UP
	bool old_up;
};
typedef struct mctp_nl_change mctp_nl_change;

/* Allocates the structure, connects to netlink, and populates
   the list of interfaces */
// verbose flag controls dumping error response packets
mctp_nl * mctp_nl_new(bool verbose);
/* Cleans and deallocates nl */
void mctp_nl_close(mctp_nl *nl);

/* Avoids printing warnings for EEXIST */
void mctp_nl_warn_eexist(mctp_nl *nl, bool warn);

/* Sends a message. If NLM_F_ACK flag is set it will wait for a
   response then print and return any error */
int mctp_nl_send(mctp_nl *nl, struct nlmsghdr *msg);
/* Sends a message and returns the responses.
   respp is optional, should be freed by the caller */
int mctp_nl_query(mctp_nl *nl, struct nlmsghdr *msg,
		struct nlmsghdr **respp, size_t *resp_lenp);

int mctp_nl_recv_all(mctp_nl *nl, int sd,
	struct nlmsghdr **respp, size_t *resp_lenp);

/* Lookup MCTP interfaces */
int mctp_nl_ifindex_byname(const mctp_nl *nl, const char *ifname);
const char* mctp_nl_if_byindex(const mctp_nl *nl, int index);
int mctp_nl_net_byindex(const mctp_nl *nl, int index);
bool mctp_nl_up_byindex(const mctp_nl *nl, int index);
/* Caller to free */
mctp_eid_t *mctp_nl_addrs_byindex(const mctp_nl *nl, int index,
	size_t *ret_num);
void mctp_nl_linkmap_dump(const mctp_nl *nl);
/* Returns an allocated list of nets, caller to free */
int *mctp_nl_net_list(const mctp_nl *nl, size_t *ret_num_nets);
/* Returns an allocated list of ifindex, caller to free */
int *mctp_nl_if_list(const mctp_nl *nl, size_t *ret_num_if);

/* MCTP route helper */
int mctp_nl_route_add(struct mctp_nl *nl, uint8_t eid, const char* ifname,
		uint32_t mtu);
int mctp_nl_route_del(struct mctp_nl *nl, uint8_t eid, const char* ifname);

/* MCTP neigh helper */
int mctp_nl_neigh_add(struct mctp_nl *nl, uint8_t eid, const char *ifname,
		      uint8_t *haddr, uint8_t halen);
int mctp_nl_neigh_del(struct mctp_nl *nl, uint8_t eid, const char *ifname);

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

void mctp_dump_nlmsg_error(const mctp_nl *nl, struct nlmsgerr *errmsg, size_t errlen);
void mctp_display_nlmsg_error(const mctp_nl *nl, struct nlmsgerr *errmsg, size_t errlen);

/* enable=true will return the socket listening for netlink messages.
   enable=false stops receiving
 */
int mctp_nl_monitor(mctp_nl *nl, bool enable);

/* Drains the monitor socket and refreshes link/address state from netlink.
   Updates are returned in 'changes', with the new state reflected in the nl
   struct */
int mctp_nl_handle_monitor(mctp_nl *nl, mctp_nl_change **changes,
	size_t *num_changes);

void mctp_nl_changes_dump(mctp_nl *nl, mctp_nl_change *changes,
	size_t num_changes);


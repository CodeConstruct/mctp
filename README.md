mctp: Userspace tools for MCTP stack management
===============================================

The `mctp` utility provides a userspace interface to query and manage the
state of the kernel MCTP stack, in a similar way to iproute2's `ip` utility.

Usage
-----

Use `mctp help` for the list of available commands:

    $ mctp help
    mctp link
    mctp link show [ifname]
    mctp link set <ifname> [up|down] [mtu <mtu>] [network <net>] [bus-owner <physaddr>]

    mctp address
    mctp address show [IFNAME]
    mctp address add <eid> dev <IFNAME>
    mctp address del <eid> dev <IFNAME>

    mctp route
    mctp route show [net <network>]
    mctp route add <eid> via <dev> [mtu <mtu>]
    mctp route del <eid> via <dev>

    mctp neigh
    mctp neigh show [dev <network>]
    mctp neigh add <eid> dev <device> lladdr <physaddr>
    mctp neigh del <eid> dev <device>

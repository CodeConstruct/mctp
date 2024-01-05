mctp: Userspace tools for MCTP stack management
===============================================

This project contains two utilities for running a MCTP network from the local
machine:

 - `mctp`: A small command-line utility to query and manage the state of the
   kernel MCTP stack, in a similar way to iproute2's `ip` utility.

 - `mctpd`: A daemon implementing the MCTP control protocol; you'll need this
   for the local host to perform as a bus-owner. The main function of `mctpd`
   is to assign EIDs to remote endpoints, and manage the resulting routes and
   neighbour-table entries for those endpoints.

Building & installing
---------------------

This project uses meson for building. To configure and compile:

    $ meson obj
    $ ninja -C obj

to install to the default prefix (/usr/local), with optional `DESTDIR`:

    $ meson install -C obj

For integration with systemd, there are a few example configuration files and
systemd target definitions under the `conf/` directory. These are not installed
by default.

`mctp` Usage
-------------

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

`mctpd` Usage
-------------

`mctpd` should be run as a system service, once the local MCTP stack has been
configured (ie., interfaces are enabled, and local addresses have been
assigned). There are two sample systemd unit files under the conf/ directory, to
coordinate the local setup and the supervision of the mctpd process.

The `mctpd` daemon will expose a dbus interface, claiming the bus name
`xyz.openbmc_project.MCTP` and object path `/xyz/openbmc_project/mctp`. This
provides a few functions for configuring remote endpoints:

    # busctl introspect xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp
    NAME                                TYPE      SIGNATURE  RESULT/VALUE  FLAGS
    au.com.CodeConstruct.MCTP           interface -          -             -
    .AssignEndpoint                     method    say        yisb          -
    .LearnEndpoint                      method    say        yisb          -
    .SetupEndpoint                      method    say        yisb          -

Results of mctpd enumeration are also represented as dbus objects, using the
OpenBMC-specified MCTP endpoint format. Each endpoint appears on the bus at the
object path:

    /xyz/openbmc_project/mctp/<network-id>/<endpoint-id>

where `mctpd` exposes three dbus interfaces for each:

 - `xyz.openbmc_project.MCTP.Endpoint`: Provides MCTP address information
   (`EID` and `NetworkID` properties) and message-type support
   `SupportedMessageTypes` property).

   This interface is defined by the MCTP.Endpoint phosphor-dbus specification.

 - `xyz.openbmc_project.Common.UUID`: MCTP UUID of the discovered endpoint
   (`UUID` property).

   This interface is defined by the Common.UUID phosphor-dbus specification.

 - `au.com.CodeConstruct.MCTP.EndPoint`: Additional control methods for the
   endpoint - for example, `Remove`

Testing
-------

We have an initial test suite under tests/. To run:

```sh
meson setup obj
ninja -C obj
cd obj
pytest
```

This depends on a few python packages, including the pytest binary. You can
use a python `venv` to provide these:

```sh
python3 -m venv venv
venv/bin/pip install -r tests/requirements.txt
```

Then run the tests using the new `venv`'s `pytest`:

```sh
../venv/bin/pytest
```


import pytest

from mctp_test_utils import mctpd_mctp_obj, mctpd_mctp_endpoint_obj

""" Test the SetupEndpoint dbus call

Using the default system & network ojects, call SetupEndpoint on our mock
endpoint. We expect the dbus call to return the endpoint details, and
the new kernel neighbour and route entries.

We have a few things provided by the test infrastructure:

 - dbus is the dbus connection, call the mctpd_mctp_obj helper to
   get the MCTP dbus object

 - mctpd is our wrapper for the mctpd process and mock MCTP environment. This
   has two properties that represent external state:

   mctp.system: the local system info - containing MCTP interfaces
     (mctp.system.interfaces), addresses (.addresses), neighbours (.neighbours)
     and routes (.routes). These may be updated by the running mctpd process
     during tests, over the simlated netlink socket.

   mctp.network: the set of remote MCTP endpoints connected to the system. Each
     endpoint has a physical address (.lladdr) and an EID (.eid), and a tiny
     MCTP control protocol implementation, which the mctpd process will
     interact with over simulated AF_MCTP sockets.

By default, we get some minimal defaults for .system and .network:

 - The system has one interface ('mctp0'), assigned local EID 8. This is
   similar to a MCTP-over-i2c interface, in that physical addresses are
   a single byte.

 - The network has one endpoint (lladdr 0x1d) connected to mctp0, with no EID
   assigned. It also has a random UUID, and advertises support for MCTP
   Control Protocol and PLDM (but note that it doesn't actually implement
   any PLDM!).

But these are only defaults; .system and .network can be altered as required
for each test.
"""
async def test_setup_endpoint(dbus, mctpd):
    # shortcuts to the default system/network configuration
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    # our proxy dbus object for mctpd
    mctp = await mctpd_mctp_obj(dbus)

    # call SetupEndpoint. This will raise an exception on any dbus error.
    (eid, net, path, new) = await mctp.call_setup_endpoint(iface.name, ep.lladdr)

    # ep.eid will be updated (through the Set Endpoint ID message); this
    # should match the returned EID
    assert eid == ep.eid

    # we should have a neighbour for the new endpoint
    assert len(mctpd.system.neighbours) == 1
    neigh = mctpd.system.neighbours[0]
    assert neigh.lladdr == ep.lladdr
    assert neigh.eid == ep.eid

    # we should have a route for the new endpoint too
    assert len(mctpd.system.routes) == 2

""" Test neighbour removal """
async def test_remove_endpoint(dbus, mctpd):
    mctp = await mctpd_mctp_obj(dbus)

    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]
    (_, _, path, _) = await mctp.call_setup_endpoint(iface.name, ep1.lladdr)

    assert(len(mctpd.system.neighbours) == 1)

    ep = await mctpd_mctp_endpoint_obj(dbus, path)

    await ep.call_remove()
    assert(len(mctpd.system.neighbours) == 0)

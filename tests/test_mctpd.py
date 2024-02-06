import pytest
import trio
import uuid
import asyncdbus

from mctp_test_utils import mctpd_mctp_obj, mctpd_mctp_endpoint_obj
from conftest import Endpoint

# DBus constant symbol suffixes:
#
# - C: Connection
# - P: Path
# - I: Interface
MCTPD_C = 'au.com.codeconstruct.MCTP1'
MCTPD_MCTP_P = '/au/com/codeconstruct/mctp1'
MCTPD_MCTP_I = 'au.com.codeconstruct.MCTP.BusOwner1'
MCTPD_ENDPOINT_I = 'au.com.codeconstruct.MCTP.Endpoint1'
DBUS_OBJECT_MANAGER_I = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROPERTIES_I = 'org.freedesktop.DBus.Properties'

MCTPD_TRECLAIM = 5

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

""" Test that we correctly handle address conflicts on EID assignment.

We have the following scenario:

 1. A configured peer at physaddr 1, EID A, allocated by mctpd
 2. A non-configured peer at physaddr 2, somehow carrying a default EID also A
 3. Attempt to enumerate physaddr 2

At (3), we should reconfigure the EID to B.
"""
async def test_setup_endpoint_conflict(dbus, mctpd):
    mctp = await mctpd_mctp_obj(dbus)

    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]
    (eid1, _, _, _) = await mctp.call_setup_endpoint(iface.name, ep1.lladdr)

    # endpoint configured with eid1 already
    ep2 = Endpoint(iface, bytes([0x1e]), eid=eid1)
    mctpd.network.add_endpoint(ep2)

    (eid2, _, _, _) = await mctp.call_setup_endpoint(iface.name, ep2.lladdr)
    assert eid1 != eid2

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

async def test_recover_endpoint_present(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_obj(dbus)
    (eid, net, path, new) = await mctp.call_setup_endpoint(iface.name, dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Available' == changed['Connectivity'].value:
                recovered.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await recovered.acquire()

    # Cancellation implies failure to acquire recovered, which implies failure
    # to transition 'Connectivity' to 'Available', which is a test failure.
    assert not expected.cancelled_caught

async def test_recover_endpoint_removed(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_mctp = await mctp.get_interface(MCTPD_MCTP_I)
    (eid, net, path, new) = await mctp_mctp.call_setup_endpoint(iface.name, dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    degraded = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    mctp_objmgr = await mctp.get_interface(DBUS_OBJECT_MANAGER_I)

    removed = trio.Semaphore(initial_value = 0)
    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    del mctpd.network.endpoints[0]
    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await removed.acquire()
        await degraded.acquire()

    assert not expected.cancelled_caught

async def test_recover_endpoint_reset(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_mctp = await mctp.get_interface(MCTPD_MCTP_I)
    (eid, net, path, new) = await mctp_mctp.call_setup_endpoint(iface.name, dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Available' == changed['Connectivity'].value:
                recovered.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    # Disable the endpoint device
    del mctpd.network.endpoints[0]

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    # Force the first poll to fail
    await trio.sleep(1)

    # Reset the endpoint device and re-enable it
    dev.reset()
    mctpd.network.add_endpoint(dev)

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await recovered.acquire()

    assert not expected.cancelled_caught

async def test_recover_endpoint_exchange(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_mctp = await mctp.get_interface(MCTPD_MCTP_I)
    (eid, net, path, new) = await mctp_mctp.call_setup_endpoint(iface.name, dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    degraded = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    mctp_objmgr = await mctp.get_interface(DBUS_OBJECT_MANAGER_I)

    removed = trio.Semaphore(initial_value = 0)
    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    added = trio.Semaphore(initial_value = 0)
    def ep_added(ep_path, content):
        if MCTPD_ENDPOINT_I in content:
            added.release()

    await mctp_objmgr.on_interfaces_added(ep_added)

    # Remove the current device
    del mctpd.network.endpoints[0]

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    # Force the first poll to fail
    await trio.sleep(1)

    # Add a new the endpoint device at the same physical address (different UUID)
    mctpd.network.add_endpoint(Endpoint(dev.iface, dev.lladdr, types = dev.types))

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await added.acquire()
        await removed.acquire()
        await degraded.acquire()

    assert not expected.cancelled_caught

""" Test that we get the correct EID allocated (and the usual route/neigh setup)
on an AssignEndpointStatic call """
async def test_assign_endpoint_static(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_obj(dbus)
    static_eid = 12

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        iface.name,
        dev.lladdr,
        static_eid
    )

    assert eid == static_eid
    assert new

    assert len(mctpd.system.neighbours) == 1
    neigh = mctpd.system.neighbours[0]
    assert neigh.lladdr == dev.lladdr
    assert neigh.eid == static_eid
    assert len(mctpd.system.routes) == 2

""" Test that we can repeat an AssignEndpointStatic call with the same static
EID"""
async def test_assign_endpoint_static_allocated(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_obj(dbus)
    dev = mctpd.network.endpoints[0]
    static_eid = 12

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        iface.name,
        dev.lladdr,
        static_eid,
    )

    assert eid == static_eid
    assert new

    # repeat, same EID
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        iface.name,
        dev.lladdr,
        static_eid,
    )

    assert eid == static_eid
    assert not new

""" Test that we cannot assign a conflicting static EID """
async def test_assign_endpoint_static_conflict(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_obj(dbus)
    dev1 = mctpd.network.endpoints[0]

    dev2 = Endpoint(iface, bytes([0x1e]))
    mctpd.network.add_endpoint(dev2)

    # dynamic EID assigment for dev1
    (eid, _, _, new) = await mctp.call_assign_endpoint(
        iface.name,
        dev1.lladdr,
    )

    assert new

    # try to assign dev2 with the dev1's existing EID
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_assign_endpoint_static(iface.name, dev2.lladdr, eid)

    assert str(ex.value) == "Address in use"

""" Test that we cannot re-assign a static EID to an endpoint that already has
a different EID allocated"""
async def test_assign_endpoint_static_varies(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_obj(dbus)
    static_eid = 12

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        iface.name,
        dev.lladdr,
        static_eid
    )

    assert eid == static_eid
    assert new

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_assign_endpoint_static(iface.name, dev.lladdr, 13)

    assert str(ex.value) == "Already assigned a different EID"

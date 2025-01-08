import pytest
import trio
import uuid
import asyncdbus

from mctp_test_utils import (
    mctpd_mctp_iface_obj,
    mctpd_mctp_network_obj,
    mctpd_mctp_endpoint_common_obj,
    mctpd_mctp_endpoint_control_obj
)
from conftest import Endpoint, MCTPSockAddr

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

 - dbus is the dbus connection, call the mctpd_mctp_iface_obj helper to
   get the MCTP dbus interface object

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
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # call SetupEndpoint. This will raise an exception on any dbus error.
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

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
    iface = mctpd.system.interfaces[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    ep1 = mctpd.network.endpoints[0]
    (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)

    # endpoint configured with eid1 already
    ep2 = Endpoint(iface, bytes([0x1e]), eid=eid1)
    mctpd.network.add_endpoint(ep2)

    (eid2, _, _, _) = await mctp.call_setup_endpoint(ep2.lladdr)
    assert eid1 != eid2

""" Test neighbour removal """
async def test_remove_endpoint(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (_, _, path, _) = await mctp.call_setup_endpoint(ep1.lladdr)

    assert(len(mctpd.system.neighbours) == 1)

    ep = await mctpd_mctp_endpoint_control_obj(dbus, path)

    await ep.call_remove()
    assert(len(mctpd.system.neighbours) == 0)

async def test_recover_endpoint_present(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp.call_setup_endpoint(dev.lladdr)

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
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

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
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

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
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

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
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
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
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev = mctpd.network.endpoints[0]
    static_eid = 12

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
    )

    assert eid == static_eid
    assert new

    # repeat, same EID
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
    )

    assert eid == static_eid
    assert not new

""" Test that we cannot assign a conflicting static EID """
async def test_assign_endpoint_static_conflict(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev1 = mctpd.network.endpoints[0]

    dev2 = Endpoint(iface, bytes([0x1e]))
    mctpd.network.add_endpoint(dev2)

    # dynamic EID assigment for dev1
    (eid, _, _, new) = await mctp.call_assign_endpoint(
        dev1.lladdr,
    )

    assert new

    # try to assign dev2 with the dev1's existing EID
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_assign_endpoint_static(dev2.lladdr, eid)

    assert str(ex.value) == "Address in use"

""" Test that we cannot re-assign a static EID to an endpoint that already has
a different EID allocated"""
async def test_assign_endpoint_static_varies(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid
    )

    assert eid == static_eid
    assert new

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_assign_endpoint_static(dev.lladdr, 13)

    assert str(ex.value) == "Already assigned a different EID"

""" Test that the mctpd control protocol responder support has support
for a basic Get Endpoint ID command"""
async def test_get_endpoint_id(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev.eid = 12

    await mctpd.system.add_route(mctpd.system.Route(iface, dev.eid, 0))
    await mctpd.system.add_neighbour(
        mctpd.system.Neighbour(iface, dev.lladdr, dev.eid)
    )

    rsp = await dev.send_control(mctpd.network.mctp_socket, 0x02)

    # command code
    assert rsp[1] == 0x02
    # completion code indicates success
    assert rsp[2] == 0x00
    # EID matches the system
    assert rsp[3] == mctpd.system.addresses[0].eid

""" During a LearnEndpoint's Get Endpoint ID exchange, return a response
from a different command; in this case Get Message Type Support, which happens
to be the same length as a the expected Get Endpoint ID response."""
async def test_learn_endpoint_invalid_response_command(dbus, mctpd):
    class BusyEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 2:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            msg = bytes([flags & 0x1f, 0x05, 0x00, 0x02, 0x00, 0x01])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = BusyEndpoint(iface, bytes([0x1e]), eid = 15)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        rc = await mctp.call_learn_endpoint(ep.lladdr)

    assert str(ex.value) == "Request failed"

""" Ensure a response with an invalid IID is discarded """
async def test_learn_endpoint_invalid_response_iid(dbus, mctpd):
    class InvalidIIDEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            # bump IID
            flags = msg[0]
            iid_mask = 0x1d
            flags = (flags & ~iid_mask) | ((flags + 1) & iid_mask)
            msg = bytes([flags]) + msg[1:]
            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = InvalidIIDEndpoint(iface, bytes([0x1e]), eid = 15)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_learn_endpoint(ep.lladdr)

    assert str(ex.value) == "Request failed"

""" Ensure we're parsing Get Message Type Support responses"""
async def test_query_message_types(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    ep_types = [0, 1, 5]
    ep.types = ep_types

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    assert eid == ep.eid

    ep = await mctpd_mctp_endpoint_common_obj(dbus, path)

    query_types = list(await ep.get_supported_message_types())
    ep_types.sort()
    query_types.sort()

    assert ep_types == query_types

""" Network1.LocalEIDs should reflect locally-assigned EID state """
async def test_network_local_eids_single(dbus, mctpd):
    iface = mctpd.system.interfaces[0]

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    eids = list(await net.get_local_eids())

    assert eids == [8]

async def test_network_local_eids_multiple(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    await mctpd.system.add_address(mctpd.system.Address(iface, 9))

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    eids = list(await net.get_local_eids())

    assert eids == [8, 9]

async def test_network_local_eids_none(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    await mctpd.system.del_address(mctpd.system.Address(iface, 8))

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    eids = list(await net.get_local_eids())

    assert eids == []

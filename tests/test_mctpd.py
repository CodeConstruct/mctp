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
from mctpenv import Endpoint, MCTPSockAddr, MCTPControlCommand

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

async def _introspect_path_recursive(dbus, path, node_set):
    node_set.add(path)
    dups = set()

    obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
    iface = await obj.get_interface('org.freedesktop.DBus.Introspectable')
    data = await iface.call_introspect()
    node = asyncdbus.introspection.Node.parse(data)

    for subnode in node.nodes:
        if path == '/':
            subnode_path = '/' + subnode.name
        else:
            subnode_path = path + '/' + subnode.name

        if subnode_path in node_set:
            dups.add(subnode_path)

        d = await _introspect_path_recursive(dbus, subnode_path, node_set)
        dups.update(d)

    return dups

""" Test that the dbus object tree is sensible: we can introspect all
objects, and that there are no duplicates
"""
async def test_enumerate(dbus, mctpd):
    dups = await _introspect_path_recursive(dbus, '/', set())
    assert not dups


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

    await mctpd.system.add_route(mctpd.system.Route(dev.eid, 0, iface = iface))
    await mctpd.system.add_neighbour(
        mctpd.system.Neighbour(iface, dev.lladdr, dev.eid)
    )

    cmd = MCTPControlCommand(True, 0, 0x02)
    rsp = await dev.send_control(mctpd.network.mctp_socket, cmd)

    # command code
    assert rsp[1] == 0x02
    # completion code indicates success
    assert rsp[2] == 0x00
    # EID matches the system
    assert rsp[3] == mctpd.system.addresses[0].eid

""" Test that instance ID is populated correctly on control protocol responses
"""
async def test_response_iid(mctpd):
    peer = mctpd.network.endpoints[0]
    for iid in [0, 1, 30, 31]:
        cmd = MCTPControlCommand(True, iid, 0x02)
        rsp = await peer.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp[0] == iid

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

""" During a SetupEndpoint's Set Endpoint ID exchange, return a response
that indicates that the EID has been set, but report an invalid (0) EID
in the response."""
async def test_setup_endpoint_invalid_set_eid_response(dbus, mctpd):
    class InvalidEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            self.eid = msg[3]
            msg = bytes([
                flags & 0x1f, # Rsp
                0x01, # opcode: Set Endpoint ID
                0x00, # cc: success
                0x00, # assignment accepted, no pool
                0x00, # set EID: invalid
                0x00, # pool size: 0
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = InvalidEndpoint(iface, bytes([0x1e]), eid = 0)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        rc = await mctp.call_setup_endpoint(ep.lladdr)

    assert str(ex.value) == "Endpoint returned failure to Set Endpoint ID"

""" During a SetupEndpoint's Set Endpoint ID exchange, return a response
that indicates that the EID has been set, but report a different set EID
in the response."""
async def test_setup_endpoint_vary_set_eid_response(dbus, mctpd):
    class VaryEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            self.eid = msg[3] + 1
            msg = bytes([
                flags & 0x1f, # Rsp
                0x01, # opcode: Set Endpoint ID
                0x00, # cc: success
                0x00, # assignment accepted, no pool
                self.eid, # set EID: valid, but not what was assigned
                0x00, # pool size: 0
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = VaryEndpoint(iface, bytes([0x1e]))
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    assert eid == ep.eid

""" During a SetupEndpoint's Set Endpoint ID exchange, return a response
that indicates that the EID has been set, but report a different set EID
in the response, which conflicts with another endpoint"""
async def test_setup_endpoint_conflicting_set_eid_response(dbus, mctpd):

    class ConflictingEndpoint(Endpoint):
        def __init__(self, iface, lladdr, conflict_eid):
            super().__init__(iface, lladdr)
            self.conflict_eid = conflict_eid

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            # reject reality, use a conflicting eid
            self.eid = self.conflict_eid
            msg = bytes([
                flags & 0x1f, # Rsp
                0x01, # opcode: Set Endpoint ID
                0x00, # cc: success
                0x00, # assignment accepted, no pool
                self.eid, # set EID: valid, but not what was assigned
                0x00, # pool size: 0
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)
    assert eid1 == ep1.eid

    ep2 = ConflictingEndpoint(iface, bytes([0x1f]), ep1.eid)
    mctpd.network.add_endpoint(ep2)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_setup_endpoint(ep2.lladdr)

    assert "already used" in str(ex.value)

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

async def test_concurrent_recovery_setup(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp_i = await mctpd_mctp_iface_obj(dbus, iface)

    # mctpd context tracks 20 peer objects by default, add and set up 19 so we
    # reach the allocation boundary.
    split = 19
    for i in range(split):
        pep = Endpoint(iface, bytes([0x1e + i]))
        mctpd.network.add_endpoint(pep)
        (_, _, path, _) = await mctp_i.call_setup_endpoint(pep.lladdr)

    # Grab the DBus path for an endpoint that we will cause to be removed from
    # the network through the recovery path. Arbitrarily use the most recent
    # one added
    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    # Set up a match for Connectivity transitioning to Degraded on the endpoint
    # for which we request recovery
    degraded = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()
    await ep_props.on_properties_changed(ep_connectivity_changed)

    # Set up a match for the recovery endpoint object being removed from DBus
    mctp_p = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_objmgr = await mctp_p.get_interface(DBUS_OBJECT_MANAGER_I)
    removed = trio.Semaphore(initial_value = 0)
    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    # Delete the endpoint from the network so its recovery will fail after
    # timeout. Note we delete at the split index as the network was already
    # populated with the default endpoint
    del mctpd.network.endpoints[split]

    # Begin recovery for the endpoint ...
    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    # ... and wait until we're notified the recovery process has begun
    with trio.move_on_after(1) as expected:
        await degraded.acquire()
    assert not expected.cancelled_caught

    # Now that we're asynchronously waiting for the endpoint recovery process
    # to complete, force a realloc() of the peer object array by adding a new
    # peer, which will invalidate the recovering peer's pointer
    pep = Endpoint(iface, bytes([0x1e + split]))
    mctpd.network.add_endpoint(pep)
    (_, _, _, new) = await mctp_i.call_setup_endpoint(pep.lladdr)
    assert new

    # Verify the recovery process completed gracefully with removal of the
    # endpoint's DBus object
    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await removed.acquire()
    assert not expected.cancelled_caught

""" Bridged EP can be discovered via Network1.LearnEndpoint """
async def test_bridged_learn_endpoint(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    br_ep = Endpoint(iface, bytes(), eid = 10, types = [0, 2])
    ep.add_bridged_ep(br_ep)
    mctpd.network.add_endpoint(br_ep)

    await mctpd.system.add_route(mctpd.system.Route(br_ep.eid, 1, iface = iface))
    # static neighbour; no gateway route support at present
    await mctpd.system.add_neighbour(mctpd.system.Neighbour(iface, ep.lladdr, br_ep.eid))

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    (path, new) = await net.call_learn_endpoint(br_ep.eid)

    assert path == f'/au/com/codeconstruct/mctp1/networks/1/endpoints/{br_ep.eid}'
    assert new

""" Change a network id, while we have an active endpoint on that net """
async def test_change_network(dbus, mctpd):
    iface = mctpd.system.interfaces[0];
    ep = mctpd.network.endpoints[0]

    net = await mctpd_mctp_network_obj(dbus, 1)
    assert net is not None

    iface.net = 2
    await mctpd.system.notify_interface(iface)

    # we should now have a new net at 2
    net = await mctpd_mctp_network_obj(dbus, 2)
    assert net is not None

    # and nothing at 1
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctpd_mctp_network_obj(dbus, 1)
    assert str(ex.value) == "Unknown object '/au/com/codeconstruct/mctp1/networks/1'."

    # endpoint should be present under 2/
    ep = await mctpd_mctp_endpoint_common_obj(dbus,
        '/au/com/codeconstruct/mctp1/networks/2/endpoints/8'
    )
    assert ep is not None

""" Delete our only interface """
async def test_del_interface_last(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    await mctpd.system.del_interface(iface)

    # interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)

    # network should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_network_obj(dbus, iface.net)

""" Remove and re-add an interface """
async def test_add_interface(dbus, mctpd):
    net = 1
    # Create a new netdevice
    iface = mctpd.system.Interface('mctpnew', 10, net, bytes([]), 68, 254, True)
    await mctpd.system.add_interface(iface)
    await mctpd.system.add_address(mctpd.system.Address(iface, 88))
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Add an endpoint on the interface
    mctpd.network.add_endpoint(Endpoint(iface, bytes([]), types = [0, 1]))

    static_eid = 30
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        bytes([]),
        static_eid
    )
    assert eid == static_eid
    assert new
    assert mctpd.system.lookup_route(net, static_eid).iface == iface

    # Remove the netdevice
    await mctpd.system.del_interface(iface)

    # Interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)
    assert mctpd.system.lookup_route(net, static_eid) is None

    # Re-add the same interface name again, with a new ifindex 11
    iface = mctpd.system.Interface('mctpnew', 11, net, bytes([]), 68, 254, True)
    await mctpd.system.add_interface(iface)
    await mctpd.system.add_address(mctpd.system.Address(iface, 89))
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Add an endpoint on the interface
    mctpd.network.add_endpoint(Endpoint(iface, bytes([]), types = [0, 1]))

    # Old route should still be gone
    assert mctpd.system.lookup_route(net, static_eid) is None

    static_eid = 40
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        bytes([]),
        static_eid
    )
    assert eid == static_eid
    assert new
    assert mctpd.system.lookup_route(net, static_eid).iface == iface

async def test_interface_rename(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(iface.name)

    new_name = "newmctp0"
    iface.name = new_name
    await mctpd.system.notify_interface(iface)

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(new_name)

async def test_interface_rename_with_peers(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(iface.name)

    # access the endpoint object before rename
    (_, _, ep_path, _) = await iface_obj.call_setup_endpoint(ep.lladdr)
    ep_obj = await dbus.get_proxy_object(MCTPD_C, ep_path)

    new_name = "newmctp0"
    iface.name = new_name
    await mctpd.system.notify_interface(iface)

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(new_name)

    # ensure the endpoint persists after rename
    ep_obj = await dbus.get_proxy_object(MCTPD_C, ep_path)
    assert ep_obj is not None
""" Test bridge endpoint dynamic EID assignment and downstream
endpoint EID allocation

Tests that:
- Bridge endpoint can be assigned a dynamic EID
- Downstream endpoints get contiguous EIDs after bridge's own eid
"""
async def test_assign_dynamic_bridge_eid(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]

    pool_size = 2

    # Set up bridged endpoints as undiscovered EID 0
    for i in range(pool_size):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(
        ep.lladdr,
    )

    assert new
    # Assert for assigned bridge endpoint ID
    assert path == f'/au/com/codeconstruct/mctp1/networks/1/endpoints/{eid}'
    assert new

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    for i in range(pool_size):
        br_ep = ep.bridged_eps[i]
        #check if the downstream endpoint eid is contiguous to the bridge endpoint eid
        assert (eid + i + 1) == br_ep.eid
        (path, new) = await net.call_learn_endpoint(br_ep.eid)
        assert path == f'/au/com/codeconstruct/mctp1/networks/1/endpoints/{br_ep.eid}'

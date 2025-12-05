import pytest
import trio
import uuid
import asyncdbus

from mctp_test_utils import (
    mctpd_mctp_iface_obj,
    mctpd_mctp_network_obj,
    mctpd_mctp_endpoint_common_obj,
    mctpd_mctp_endpoint_control_obj,
    mctpd_mctp_base_iface_obj
)
from mctpenv import Endpoint, MCTPSockAddr, MCTPControlCommand, MctpdWrapper

# DBus constant symbol suffixes:
#
# - C: Connection
# - P: Path
# - I: Interface
MCTPD_C = 'au.com.codeconstruct.MCTP1'
MCTPD_MCTP_P = '/au/com/codeconstruct/mctp1'
MCTPD_MCTP_I = 'au.com.codeconstruct.MCTP.BusOwner1'
MCTPD_ENDPOINT_I = 'au.com.codeconstruct.MCTP.Endpoint1'
MCTPD_ENDPOINT_BRIDGE_I = 'au.com.codeconstruct.MCTP.Bridge1'
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

async def test_recover_endpoint_removed(dbus, mctpd, autojump_clock):
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

async def test_recover_endpoint_reset(dbus, mctpd, autojump_clock):
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

async def test_recover_endpoint_exchange(dbus, mctpd, autojump_clock):
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
async def test_get_endpoint_id(dbus, mctpd, routed_ep):
    ep = routed_ep
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    cmd = MCTPControlCommand(True, 0, 0x02)
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)

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

async def test_concurrent_recovery_setup(dbus, mctpd, autojump_clock):
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

async def test_network_learn_endpoint_absent(dbus, mctpd):
    iface = mctpd.system.interfaces[0]

    net = await mctpd_mctp_network_obj(dbus, iface.net)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await net.call_learn_endpoint(10)

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

""" Delete an interface with peers attached, ensure all are gone """
async def test_del_interface_with_peers(dbus, mctpd):
    net = mctpd.system.interfaces[0].net
    iface = mctpd.system.Interface(
        'mctp1', 2, net,  bytes([0x10]), 68, 254, True,
    )
    await mctpd.system.add_interface(iface)

    eps = [
        Endpoint(iface, bytes([0x11])),
        Endpoint(iface, bytes([0x12])),
        Endpoint(iface, bytes([0x13])),
    ]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    paths = []
    for ep in eps:
        mctpd.network.add_endpoint(ep)
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        assert eid == ep.eid
        paths.append(path)

    await mctpd.system.del_interface(iface)

    # interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)

    # .. but the network should remain, as the default interface is still
    # present
    _ = await mctpd_mctp_network_obj(dbus, net)

    for path in paths:
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            ep = await mctpd_mctp_endpoint_common_obj(dbus, path)
        assert str(ex.value).startswith("Unknown object")

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

""" Test that we use the minimum EID from the dynamic_eid_range config """
async def test_config_dyn_eid_range_min(nursery, dbus, sysnet):
    (min_dyn_eid, max_dyn_eid) = (20, 254)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    # since we're specifying per-test config, we create the wrapper directly
    # rather than using the fixture.
    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)
    assert eid == min_dyn_eid
    assert ep.eid == eid

    res = await mctpd.stop_mctpd()
    assert res == 0

""" Test that we use the maximum EID from the dynamic_eid_range config """
async def test_config_dyn_eid_range_max(nursery, dbus, sysnet):
    (min_dyn_eid, max_dyn_eid) = (20, 21)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    mctpd.network.add_endpoint(Endpoint(iface, bytes([0x01]), types = [0, 1]))
    mctpd.network.add_endpoint(Endpoint(iface, bytes([0x02]), types = [0, 1]))

    for i in range(0, 2):
        ep = mctpd.network.endpoints[i]
        (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)
        assert eid >= 20 and eid <= 21

    # we should have run out of EIDs
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        ep = mctpd.network.endpoints[2]
        (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    assert str(ex.value) == "Ran out of EIDs"
    assert mctpd.network.endpoints[2].eid == 0

    res = await mctpd.stop_mctpd()
    assert res == 0

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
        br_ep = Endpoint(iface, bytes(), types=[0])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)

    assert new
    assert ep.allocated_pool == (eid + 1, pool_size)

""" Test that static allocations are not permitted, if they would conflict
with a bridge pool"""
async def test_bridge_ep_conflict_static(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    n_bridged = 3

    # add downstream devices
    for i in range(n_bridged):
        br_ep = Endpoint(iface, bytes())
        ep.add_bridged_ep(br_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert ep.allocated_pool == (eid + 1, n_bridged)

    # ensure no static assignment can be made from the bridged range
    for i in range(n_bridged):
        dev = Endpoint(iface, bytes([0x30 + i]))
        mctpd.network.add_endpoint(dev)
        with pytest.raises(asyncdbus.errors.DBusError):
            await mctp.call_assign_endpoint_static(dev.lladdr, ep.eid + 1 + i)

    # ... but we're okay with the EID following
    dev = Endpoint(iface, bytes([0x30 + n_bridged]))
    mctpd.network.add_endpoint(dev)
    static_eid = ep.eid + 1 + n_bridged
    (eid, _, _, _) = await mctp.call_assign_endpoint_static(
        dev.lladdr, static_eid
    )

    assert eid == static_eid

""" Test that learnt allocations (ie, pre-assigned device EIDs) are not
permitted, if they would conflict with a bridge pool """
async def test_bridge_ep_conflict_learn(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    n_bridged = 3

    # add downstream devices
    for i in range(n_bridged):
        br_ep = Endpoint(iface, bytes())
        ep.add_bridged_ep(br_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert ep.allocated_pool == (eid + 1, n_bridged)

    # ensure no learnt assignment can be made from the bridged range
    for i in range(n_bridged):
        dev = Endpoint(iface, bytes([0x30 + i]), eid=ep.eid + 1 + i)
        mctpd.network.add_endpoint(dev)
        with pytest.raises(asyncdbus.errors.DBusError):
            await mctp.call_learn_endpoint(dev.lladdr)

    # ... but we're okay with the EID following
    dev_eid = ep.eid + 1 + n_bridged
    dev = Endpoint(iface, bytes([0x30 + n_bridged]), eid=dev_eid)
    mctpd.network.add_endpoint(dev)
    (eid, _, _, _) = await mctp.call_learn_endpoint(dev.lladdr)

    assert eid == dev_eid

""" Test that learnt allocations (ie, pre-assigned device EIDs) are not
permitted through SetupEndpoint, if they would conflict with a bridge pool """
async def test_bridge_ep_conflict_setup(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    n_bridged = 3

    # add downstream devices
    for i in range(n_bridged):
        br_ep = Endpoint(iface, bytes())
        ep.add_bridged_ep(br_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert ep.allocated_pool == (eid + 1, n_bridged)
    pool_range = range(ep.allocated_pool[0], ep.allocated_pool[1] + 1)

    # ensure no SetupEndpoint assignment can be made from the bridged range;
    # these should get reassigned elsewhere.
    for i in range(n_bridged):
        dev = Endpoint(iface, bytes([0x30 + i]), eid=ep.eid + 1 + i)
        mctpd.network.add_endpoint(dev)
        (eid, _, _, _) = await mctp.call_setup_endpoint(dev.lladdr)
        assert eid not in pool_range

""" Test that mctpd will reassign a bridge endpoints (pre-configured) EID
if necessary to satisfy the bridge pool allocation"""
async def test_bridge_setup_reassign(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # ep: regular endpoint, will conflict with a bridge pool
    ep = mctpd.network.endpoints[0]
    static_eid = 10
    (eid, _, _, _) = await mctp.call_assign_endpoint_static(
        ep.lladdr,
        static_eid
    )

    assert eid == static_eid

    # br: our bridge
    conflict_eid = 9
    br = Endpoint(iface, bytes([ep.lladdr[0] + 1]), eid=conflict_eid)
    br.add_bridged_ep(Endpoint(iface, bytes()))
    mctpd.network.add_endpoint(br)

    (eid, _, _, _) = await mctp.call_setup_endpoint(br.lladdr)
    assert eid != conflict_eid
    assert br.allocated_pool is not None
    assert br.allocated_pool[0] == eid + 1

""" Test that we truncate the requested pool size to
    the max_pool_size config """
async def test_assign_dynamic_eid_limited_pool(nursery, dbus, sysnet):
    max_pool_size = 1
    config = f"""
    [bus-owner]
    max_pool_size = {max_pool_size}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up bridged endpoints as undiscovered EID 0
    for i in range(0, 2):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)

    assert new

    bridge_obj = await dbus.get_proxy_object(MCTPD_C, path)
    props_iface = await bridge_obj.get_interface(DBUS_PROPERTIES_I)
    pool_end = await props_iface.call_get(MCTPD_ENDPOINT_BRIDGE_I, "PoolEnd")
    pool_size = pool_end.value - eid
    assert pool_size == max_pool_size

    res = await mctpd.stop_mctpd()
    assert res == 0

""" Test that a limited pool is assigned if we run out of space for a full
allocation"""
async def test_bridge_pool_assign_limited(nursery, dbus, sysnet):
    (min_dyn_eid, max_dyn_eid) = (8, 13)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up bridged endpoints as undiscovered EID 0; three bridged EPs,
    # which is larger than the available space
    for i in range(0, 3):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    # consume middle eid from the range to dev2
    dev2 = Endpoint(iface, bytes([0x09]))
    mctpd.network.add_endpoint(dev2)
    (eid, _, path, new) = await mctp.call_assign_endpoint_static(
        dev2.lladdr,
        10
    )
    assert new

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new
    assert ep.allocated_pool is not None
    # we should have the largest range possible; the 8,9-9 range is smaller
    # than the 11,12-13
    assert ep.allocated_pool == (12, 2)

    res = await mctpd.stop_mctpd()
    assert res == 0

"""During Allocate Endpoint ID exchange, return completion code failure
to indicate no pool has been assigned to the bridge"""
async def test_assign_dynamic_eid_allocation_failure(dbus, mctpd):
    class BridgeEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 0x8:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)

            msg = bytes([
                flags & 0x1f, # Rsp
                0x08, # opcode: Allocate Endpoint ID
                0x01, # cc: failure
                0x01, # allocation rejected
                0x00, # pool size
                0x00, # pool start
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = BridgeEndpoint(iface, bytes([0x1e]))
    mctpd.network.add_endpoint(ep)
    # Set up downstream endpoints as undiscovered EID 0
    for i in range(0, 2):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new
    # Interface should not be present for failed pool allocation
    with pytest.raises(asyncdbus.errors.InterfaceNotFoundError):
        bridge_obj = await dbus.get_proxy_object(MCTPD_C, path)
        await bridge_obj.get_interface(MCTPD_ENDPOINT_BRIDGE_I)

""" Test assigning a non-bridge endpoint, when we don't have capacity for
the speculatively-allocated bridge range"""
async def test_assign_without_bridge_range(dbus, sysnet, nursery):
    (dyn_eid_min, dyn_eid_max) = (10, 20)
    max_pool_size = (dyn_eid_max - dyn_eid_min) + 1
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{dyn_eid_min}, {dyn_eid_max}]
    max_pool_size = {max_pool_size}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, _, _, _) = await mctp.call_assign_endpoint(ep.lladdr)

    assert eid == dyn_eid_min
    res = await mctpd.stop_mctpd()
    assert res == 0

""" Test that we can still allocate a bridge pool even though we may not have
the maximum EID range available. The bridge pool's full allocation is still
possible, since it is smaller than the configured max"""
async def test_bridge_pool_range_limited(dbus, sysnet, nursery):
    # configure for:
    #     10: bridge A
    #  11-13: bridge A pool
    #     14: bridge B
    #  15-17: bridge B pool
    (dyn_eid_min, dyn_eid_max) = (10, 17)
    bridge_downstreams = 3
    # max pool size would consume more than half of the range, so bridge B
    # cannot be allocated this max
    max_pool_size = 5
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{dyn_eid_min}, {dyn_eid_max}]
    max_pool_size = {max_pool_size}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    bridges = [
        Endpoint(iface, bytes([0x30])),
        Endpoint(iface, bytes([0x31])),
    ]
    for bridge in bridges:
        mctpd.network.add_endpoint(bridge)
        for i in range(bridge_downstreams):
            bridge.add_bridged_ep(Endpoint(iface, bytes()))

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    for bridge in bridges:
        (eid, _, _, _) = await iface_obj.call_assign_endpoint(bridge.lladdr)
        assert bridge.allocated_pool is not None
        assert bridge.allocated_pool[1] == 3

    res = await mctpd.stop_mctpd()
    assert res == 0

async def test_get_message_types(dbus, mctpd, routed_ep):
    ep = routed_ep

    # Check default response when no responder registered
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 01 00'

    # Register spdm responder with a random version
    mctp = await mctpd_mctp_base_iface_obj(dbus)
    await mctp.call_register_type_support(5, [0xF1F2F3F4])

    # Verify get message type response includes spdm
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 02 00 05'

    # Verify version passed in dbus call is responded back
    cmd = MCTPControlCommand(True, 0, 0x04, bytes([0x05]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 04 00 01 f4 f3 f2 f1'

""" Test RegisterVDMTypeSupport when no responders are registered """
async def test_register_vdm_type_support_empty(mctpd, routed_ep):
    ep = routed_ep

    # Verify error response when no VDM is registered
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'

""" Test RegisterVDMTypeSupport when a single PCIe VDM is registered """
async def test_register_vdm_type_support_pcie_only(dbus, mctpd, routed_ep):
    ep = routed_ep
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Register PCIe VDM: format=0x00, VID=0xABCD, command_set=0x0001
    v_type = asyncdbus.Variant('q', 0xABCD)
    await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)

    # Verify PCIe VDM (selector 0)
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 00 ff 00 ab cd 00 01'

    # Verify error with incorrect selector
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x05]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'

""" Test RegisterVDMTypeSupport when a single IANA VDM is registered """
async def test_register_vdm_type_support_iana_only(dbus, mctpd, routed_ep):
    ep = routed_ep
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Register IANA VDM: format=0x01, VID=0x1234ABCD, command_set=0x5678
    v_type = asyncdbus.Variant('u', 0x1234ABCD)
    await mctp.call_register_vdm_type_support(0x01, v_type, 0x5678)

    # Verify IANA VDM (selector 0)
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 00 ff 01 12 34 ab cd 56 78'

""" Test RegisterVDMTypeSupport with dbus disconnect """
async def test_register_vdm_type_support_dbus_disconnect(mctpd, routed_ep):
    ep = routed_ep

    # Verify error response when no VDM is registered
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'

    async with asyncdbus.MessageBus().connect() as temp_bus:
        mctp = await mctpd_mctp_base_iface_obj(temp_bus)

        # Register PCIe VDM: format=0x00, VID=0xABCD, command_set=0x0001
        v_type = asyncdbus.Variant('q', 0xABCD)
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)

        # Verify PCIe VDM (selector 0)
        cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp.hex(' ') == '00 06 00 ff 00 ab cd 00 01'

    # Give mctpd a moment to process the disconnection
    await trio.sleep(0.1)

    # Verify VDM type is removed after disconnect
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'  # Should be error again

""" Test RegisterVDMTypeSupport error handling """
async def test_register_vdm_type_support_errors(dbus, mctpd):
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Verify DBus call fails with invalid format 0x02
    v_type = asyncdbus.Variant('q', 0xABCD)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x02, v_type, 0x0001)
    assert "Unsupported VID format" in str(ex.value)

    # Verify incorrect VID type raises error
    v_type = asyncdbus.Variant('u', 0xABCDEF12)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
    assert "Expected format is PCIe but variant contains" in str(ex.value)

    v_type = asyncdbus.Variant('q', 0xABCD)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x01, v_type, 0x5678)
    assert "Expected format is IANA but variant contains" in str(ex.value)

    # Verify duplicate VDM raises error
    await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
    assert str(ex.value) == "VDM type already registered"

async def test_query_peer_properties_retry_timeout(nursery, dbus, sysnet):

    # activate mctpd
    mctpd = MctpdWrapper(dbus, sysnet)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # add a bridged endpoint to ep
    fake_ep = Endpoint(iface, b'\x12\x34', types=[0, 2])
    fake_ep.response_timeout_control(5)
    ep.add_bridged_ep(fake_ep)
    mctpd.network.add_endpoint(fake_ep)

    # call assign_endpoint on ep, which will allocate a pool for fake_ep
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    await mctp.call_setup_endpoint(ep.lladdr)

    assert any("Retrying to get endpoint types" in l for l in mctpd.stderr_logs)

    # exit mctpd
    res = await mctpd.stop_mctpd()
    assert res == 0
import pytest
import asyncdbus
from mctp_test_utils import *
from mctpenv import *

"""Simple endpoint setup.

Contains one interface (lladdr 0x1d), and one bus-owner (lladdr 0x1d, eid 8),
that reports support for MCTP control and PLDM.
"""

@pytest.fixture
def config():
    return """
    mode = "endpoint"
    """


@pytest.fixture
async def iface():
    return System.Interface("mctp0", 1, 1, bytes([0x1D]), 68, 254, True)


@pytest.fixture
async def bo(iface):
    return Endpoint(iface, bytes([0x10]), eid=8)


@pytest.fixture
async def sysnet(iface, bo):
    system = System()
    await system.add_interface(iface)
    network = Network()
    network.add_endpoint(bo)
    return Sysnet(system, network)


""" Test if mctpd is running as an endpoint """
async def test_endpoint_role(dbus, mctpd):
    obj = await mctpd_mctp_iface_control_obj(dbus, mctpd.system.interfaces[0])
    role = await obj.get_role()
    assert str(role) == "Endpoint"


""" mctpd returns null EID on no EID """
async def test_respond_get_eid_with_no_eid(dbus, mctpd):
    bo = mctpd.network.endpoints[0]

    assert len(mctpd.system.addresses) == 0

    # no EID yet
    cmd = MCTPControlCommand(True, 0, 0x02)
    rsp = await bo.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 02 00 00 02 00'


""" Test if mctpd accepts Set EID when no EID """
async def test_accept_set_eid(dbus, mctpd):
    bo = mctpd.network.endpoints[0]

    assert len(mctpd.system.addresses) == 0

    # no EID yet
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
    assert rsp.hex(' ') == '00 02 00 00 02 00'

    # set EID = 42
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, 0x42])))
    assert rsp.hex(' ') == '00 01 00 00 42 00'

    # get EID, expect receive 42 back
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
    assert rsp.hex(' ') == '00 02 00 42 02 00'


async def test_accept_multiple_set_eids_for_single_interface(dbus, mctpd):
    bo = mctpd.network.endpoints[0]

    assert len(mctpd.system.addresses) == 0

    # if we are only reachable through one interfaces,
    # accept all Set EIDs
    assert len(mctpd.system.interfaces) == 1

    # no EID yet
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
    assert rsp.hex(' ') == '00 02 00 00 02 00'

    # set EID = 42
    first_eid = 42
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, first_eid])))
    assert rsp.hex(' ') == f'00 01 00 00 {first_eid:02x} 00'

    # get EID, expect receive 42 back
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
    assert rsp.hex(' ') == f'00 02 00 {first_eid:02x} 02 00'

    # set EID = 66
    second_eid = 66
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, second_eid])))
    assert rsp.hex(' ') == f'00 01 00 00 {second_eid:02x} 00'

    # get EID, expect receive 66 back
    rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
    assert rsp.hex(' ') == f'00 02 00 {second_eid:02x} 02 00'

    # expect previous EID removed on D-Bus
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctpd_mctp_endpoint_control_obj(dbus, f"/au/com/codeconstruct/mctp1/networks/1/endpoints/{first_eid}")
    assert str(ex.value) == f"Unknown object '/au/com/codeconstruct/mctp1/networks/1/endpoints/{first_eid}'."

    # expect new EID on D-Bus
    assert await mctpd_mctp_endpoint_control_obj(dbus, f"/au/com/codeconstruct/mctp1/networks/1/endpoints/{second_eid}")


class TestDiscovery:
    @pytest.fixture
    async def iface(self):
        return System.Interface("mctp0", 1, 1, bytes([0x1D]), 68, 254, True, PhysicalBinding.PCIE_VDM)

    @pytest.fixture
    async def bo(self, iface):
        return TestDiscovery.BusOwnerEndpoint(iface, bytes([0x00]), eid=8)


    class BusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)

        async def handle_mctp_control(self, sock, addr, data):
            print(addr, data)
            flags, opcode = data[0:2]
            if opcode != 0x0D:
                return await super().handle_mctp_control(sock, addr, data)
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)
            await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00]))
            self.sem.release()


    """ Test simple Discovery sequence """
    async def test_simple_discovery_sequence(self, dbus, mctpd):
        bo = mctpd.network.endpoints[0]

        assert len(mctpd.system.addresses) == 0

        # BMC should send a Discovery Notify message
        with trio.move_on_after(5) as expected:
            await bo.sem.acquire()
        assert not expected.cancelled_caught

        # no EID yet
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
        assert rsp.hex(' ') == '00 02 00 00 02 00'

        # BMC response to Prepare for Discovery
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x0B))
        assert rsp.hex(' ') == '00 0b 00'

        # BMC response to Endpoint Discovery
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x0C))
        assert rsp.hex(' ') == '00 0c 00'

        # set EID = 42
        eid = 42
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, eid])))
        assert rsp.hex(' ') == f'00 01 00 00 {eid:02x} 00'

        # BMC should contains two object paths: bus owner and itself
        assert await mctpd_mctp_endpoint_control_obj(dbus, f"/au/com/codeconstruct/mctp1/networks/1/endpoints/{bo.eid}")
        assert await mctpd_mctp_endpoint_control_obj(dbus, f"/au/com/codeconstruct/mctp1/networks/1/endpoints/{eid}")


class TestDiscoveryRetry:
    @pytest.fixture
    async def iface(self):
        return System.Interface("mctp0", 1, 1, bytes([0x1D]), 68, 254, True, PhysicalBinding.PCIE_VDM)

    @pytest.fixture
    async def bo(self, iface):
        return TestDiscoveryRetry.BusOwnerEndpoint(iface, bytes([0x00]), eid=8)


    class BusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)
            self.retry_left = 1

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 0x0D:
                return await super().handle_mctp_control(sock, src_addr, msg)

            # only reply after 2 retries
            if self.retry_left == 0:
                dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
                await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00]))
                self.sem.release()
            else:
                self.retry_left -= 1


    """ Test simple Discovery sequence """
    async def test_discovery_after_one_retry(self, dbus, mctpd, autojump_clock):
        bo = mctpd.network.endpoints[0]

        assert len(mctpd.system.addresses) == 0

        # BMC should send a Discovery Notify message
        with trio.move_on_after(10) as expected:
            await bo.sem.acquire()
        assert not expected.cancelled_caught

        # no EID yet
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x02))
        assert rsp.hex(' ') == '00 02 00 00 02 00'

        # BMC response to Prepare for Discovery
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x0B))
        assert rsp.hex(' ') == '00 0b 00'

        # BMC response to Endpoint Discovery
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x0C))
        assert rsp.hex(' ') == '00 0c 00'

        # set EID = 42
        eid = 42
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, eid])))
        assert rsp.hex(' ') == f'00 01 00 00 {eid:02x} 00'

        # BMC should contains two object paths: bus owner and itself
        assert await mctpd_mctp_endpoint_control_obj(dbus, f"/au/com/codeconstruct/mctp1/networks/1/endpoints/{bo.eid}")
        assert await mctpd_mctp_endpoint_control_obj(dbus, f"/au/com/codeconstruct/mctp1/networks/1/endpoints/{eid}")


class TestUnsupportedDiscovery:
    @pytest.fixture
    async def iface(self):
        return System.Interface("mctp0", 1, 1, bytes([0x1D]), 68, 254, True, PhysicalBinding.SMBUS)

    """ Discovery command on unsupported interface """
    async def test_simple(self, dbus, mctpd):
        bo = mctpd.network.endpoints[0]

        # BMC response ERROR_UNSUPPORTED_CMD to Prepare for Discovery
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x0B))
        assert rsp.hex(' ') == '00 0b 05'


class TestGetEmptyRoutingTable:
    @pytest.fixture
    async def bo(self, iface):
        return TestGetEmptyRoutingTable.BusOwnerEndpoint(iface, bytes([0x00]), eid=8)


    class BusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)

        async def handle_mctp_control(self, sock, addr, data):
            flags, opcode = data[0:2]
            if opcode != 0x0A:
                return await super().handle_mctp_control(sock, addr, data)
            assert len(data) == 3
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)
            await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0xFF,
                                            0x02, # len
                                            0x01, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                            0x01, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11]))
            self.sem.release()

    async def test(self, dbus, mctpd, autojump_clock):
        bo = mctpd.network.endpoints[0]

        # trigger get routing table via set eid
        await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, 0x09])))

        with trio.move_on_after(5) as expected:
            await bo.sem.acquire()

        assert not expected.cancelled_caught


class TestGetThreeEntriesRoutingTable:
    @pytest.fixture
    async def bo(self, iface):
        return TestGetThreeEntriesRoutingTable.BusOwnerEndpoint(iface, bytes([0x00]), eid=8)


    class BusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)

        async def handle_mctp_control(self, sock, addr, data):
            flags, opcode = data[0:2]
            if opcode != 0x0A:
                return await super().handle_mctp_control(sock, addr, data)
            assert len(data) == 3
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)
            await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0xFF,
                                            0x03, # len
                                            0x01, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                            0x01, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11,
                                            0x01, 66, 0b00_0_00000, 0x00, 0x00, 0x01, 0x12]))
            self.sem.release()

    async def test(self, dbus, mctpd, autojump_clock):
        bo = mctpd.network.endpoints[0]

        # trigger get routing table via set eid
        await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, 0x09])))

        with trio.move_on_after(5) as expected:
            await bo.sem.acquire()

        assert not expected.cancelled_caught

        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/66")




class TestGetNestedRoutingTables:
    """
    Test sending nested routing table.

    This is the topology (we are eid=9):

    ┌───────┐  ┌───────┐
    │       ┼──► EID 9 │
    │       │  └───────┘
    │       │
    │       │
    │ EID 8 │
    │       │  ┌────────┐  ┌──────┐
    │       │  │        ┼──►EID 11│
    │       │  │        │  └──────┘
    │       ┼──► EID 10 │
    │       │  │        │  ┌──────┐
    │       │  │        ├──►EID 12│
    └───────┘  └────────┘  └──────┘
    """

    # Stub for Bus Owner with eid=8
    class FirstBusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)

        async def handle_mctp_control(self, sock, addr, data):
            flags, opcode = data[0:2]
            if opcode != 0x0A:
                return await super().handle_mctp_control(sock, addr, data)
            assert len(data) == 3
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)
            await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0xFF,
                                            0x03, # len
                                            0x01, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                            0x01, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11,
                                            0x03, 10, 0b01_0_00000, 0x00, 0x00, 0x01, 0x12]))
            self.sem.release()

    # Stub for Bus Owner with eid=10
    class SecondBusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)

        async def handle_mctp_control(self, sock, addr, data):
            flags, opcode = data[0:2]
            if opcode != 0x0A:
                return await super().handle_mctp_control(sock, addr, data)
            assert len(data) == 3
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)
            await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0xFF,
                                            0x05, # len
                                            0x10, 10, 0b10_0_00000, 0x00, 0x00, 0x01, 0x12,
                                            0x10, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11,
                                            0x10, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                            0x01, 11, 0b00_0_00001, 0x00, 0x00, 0x01, 0x13,
                                            0x01, 12, 0b00_0_00001, 0x00, 0x00, 0x01, 0x14]))
            self.sem.release()

    @pytest.fixture
    async def bo(self, iface):
        return TestGetNestedRoutingTables.FirstBusOwnerEndpoint(iface, bytes([0x00]), eid=8)

    async def test(self, dbus, mctpd, autojump_clock):
        bo1 = mctpd.network.endpoints[0]
        bo2 = TestGetNestedRoutingTables.SecondBusOwnerEndpoint(mctpd.system.interfaces[0], bytes([0x12]), eid=10)
        mctpd.network.add_endpoint(bo2)

        ep1 = Endpoint(iface, bytes([0x13]), eid=11)
        ep2 = Endpoint(iface, bytes([0x14]), eid=12)

        bo1.add_bridged_ep(bo2)
        bo2.add_bridged_ep(ep1)
        bo2.add_bridged_ep(ep2)


        # trigger get routing table via set eid
        await bo1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, 0x09])))

        with trio.move_on_after(5) as expected:
            await bo1.sem.acquire()
            await bo2.sem.acquire()

        assert not expected.cancelled_caught

        await trio.sleep(1)

        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/8")
        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/9")
        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/10")
        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/11")
        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/12")


class TestGetMultipleRoutingTableHandles:
    @pytest.fixture
    async def bo(self, iface):
        return TestGetMultipleRoutingTableHandles.BusOwnerEndpoint(iface, bytes([0x00]), eid=8)


    class BusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)

        async def handle_mctp_control(self, sock, addr, data):
            flags, opcode = data[0:2]
            if opcode != 0x0A:
                return await super().handle_mctp_control(sock, addr, data)
            assert len(data) == 3
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)

            if data[2] == 0x00:
                await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0x01,
                                                0x02, # len
                                                0x01, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                                0x01, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11]))
                return

            if data[2] == 0x01:
                await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0xFF,
                                                0x01, # len
                                                0x01, 66, 0b00_0_00000, 0x00, 0x00, 0x01, 0x12]))
                self.sem.release()
                return

            assert False

    async def test(self, dbus, mctpd, autojump_clock):
        bo = mctpd.network.endpoints[0]

        # trigger get routing table via set eid
        await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, 0x09])))

        await trio.sleep(10)

        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/66")


class TestResetRoutingTableOnSetEid:
    @pytest.fixture
    async def bo(self, iface):
        return TestGetMultipleRoutingTableHandles.BusOwnerEndpoint(iface, bytes([0x00]), eid=8)


    class BusOwnerEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sem = trio.Semaphore(initial_value=0)
            self.network_is_down = False

        async def handle_mctp_control(self, sock, addr, data):
            flags, opcode = data[0:2]
            if opcode != 0x0A:
                return await super().handle_mctp_control(sock, addr, data)
            assert len(data) == 3
            dst_addr = MCTPSockAddr.for_ep_resp(self, addr, sock.addr_ext)

            if self.network_is_down:
                await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0x01,
                                                0x02, # len
                                                0x01, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                                0x01, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11]))
            else:
                await sock.send(dst_addr, bytes([flags & 0x1F, opcode, 0x00, 0xFF,
                                                0x03, # len
                                                0x01, 8, 0b10_0_00000, 0x00, 0x00, 0x01, 0x10,
                                                0x01, 9, 0b00_0_00000, 0x00, 0x00, 0x01, 0x11,
                                                0x01, 66, 0b00_0_00000, 0x00, 0x00, 0x01, 0x12]))
            self.sem.release()

    async def test(self, dbus, mctpd, autojump_clock):
        bo = mctpd.network.endpoints[0]

        # set our eid=09
        await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x00, 0x09])))

        with trio.move_on_after(5) as expected:
            await bo.sem.acquire()

        assert not expected.cancelled_caught

        await trio.sleep(5)

        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/66")

        # here, assume network is reset and bus owner reset our EID
        bo.network_is_down = True

        # force set our EID, expect EID 66 is gone
        await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x01, bytes([0x01, 0x09])))

        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/66")

        assert str(ex.value) == "Unknown object '/au/com/codeconstruct/mctp1/networks/1/endpoints/66'."

        # bus owner finished assigning all EIDs, network is up and routing table is ok again
        # expect EID 66 is live
        bo.network_is_down = False
        with trio.move_on_after(5) as expected:
            await bo.sem.acquire()

        await trio.sleep(5)

        assert await mctpd_mctp_endpoint_control_obj(dbus, "/au/com/codeconstruct/mctp1/networks/1/endpoints/66")

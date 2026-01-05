import pytest
import asyncdbus
from mctp_test_utils import (
    mctpd_mctp_iface_control_obj,
    mctpd_mctp_endpoint_control_obj
)
from mctpenv import (
    Endpoint, MCTPControlCommand, Network, PhysicalBinding, Sysnet, System
)


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
async def sysnet(iface):
    system = System()
    await system.add_interface(iface)
    network = Network()
    network.add_endpoint(Endpoint(iface, bytes([0x10]), eid=8))
    return Sysnet(system, network)


async def test_endpoint_role(dbus, mctpd):
    """Test if mctpd is running as an endpoint"""
    obj = await mctpd_mctp_iface_control_obj(dbus, mctpd.system.interfaces[0])
    role = await obj.get_role()
    assert str(role) == "Endpoint"


async def test_respond_get_eid_with_no_eid(dbus, mctpd):
    """mctpd returns null EID on no EID"""
    bo = mctpd.network.endpoints[0]

    assert len(mctpd.system.addresses) == 0

    # no EID yet
    cmd = MCTPControlCommand(True, 0, 0x02)
    rsp = await bo.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 02 00 00 02 00'


async def test_accept_set_eid(dbus, mctpd):
    """Test if mctpd accepts Set EID when no EID"""
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

    async def test_simple_discovery_sequence(self, dbus, mctpd):
        """Test simple Discovery sequence"""
        bo = mctpd.network.endpoints[0]

        assert len(mctpd.system.addresses) == 0

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

    async def test_simple(self, dbus, mctpd):
        """Discovery command on unsupported interface"""
        bo = mctpd.network.endpoints[0]

        # BMC response ERROR_UNSUPPORTED_CMD to Prepare for Discovery
        rsp = await bo.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, 0, 0x0B))
        assert rsp.hex(' ') == '00 0b 05'

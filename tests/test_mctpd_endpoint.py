import pytest
from mctp_test_utils import *
from mctpenv import *

@pytest.fixture
def config():
    return """
    mode = "endpoint"
    """

@pytest.fixture
async def sysnet():
    system = System()
    iface = System.Interface("mctp0", 1, 1, bytes([0x1D]), 68, 254, True)
    await system.add_interface(iface)
    network = Network()
    network.add_endpoint(Endpoint(iface, bytes([0x10]), eid=8))
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

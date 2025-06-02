import pytest
from mctp_test_utils import *
from mctpd import *

@pytest.fixture(name="config")
def endpoint_config():
    return """
    mode = "endpoint"
    """

""" Test if mctpd is running as an endpoint """
async def test_endpoint_role(dbus, mctpd):
    obj = await mctpd_mctp_iface_control_obj(dbus, mctpd.system.interfaces[0])
    role = await obj.get_role()
    assert str(role) == "Endpoint"

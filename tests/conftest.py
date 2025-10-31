
import sys

import pytest
import asyncdbus
import trio.testing

import mctpenv

"""Simple system & network.

Contains one interface (lladdr 0x10, local EID 8), and one endpoint (lladdr
0x1d), that reports support for MCTP control and PLDM.
"""
@pytest.fixture
async def sysnet():
    return await mctpenv.default_sysnet()

@pytest.fixture
async def dbus():
    async with asyncdbus.MessageBus().connect() as bus:
        yield bus

@pytest.fixture
def config():
    return None

@pytest.fixture
async def mctpd(nursery, dbus, sysnet, config):
    m = mctpenv.MctpdWrapper(dbus, sysnet, config = config)
    await m.start_mctpd(nursery)
    yield m
    res = await m.stop_mctpd()
    assert res == 0

@pytest.fixture
async def mctp(nursery, sysnet):
    return mctpenv.MctpWrapper(nursery, sysnet)

@pytest.fixture
def autojump_clock():
    """
    Custom autojump clock with a reasonable threshold for non-time I/O waits
    """
    return trio.testing.MockClock(autojump_threshold=0.01)

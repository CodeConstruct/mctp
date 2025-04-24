
import sys

import pytest
import asyncdbus

import mctpd as fake_mctpd

"""Simple system & network.

Contains one interface (lladdr 0x10, local EID 8), and one endpoint (lladdr
0x1d), that reports support for MCTP control and PLDM.
"""
@pytest.fixture
async def sysnet():
    return await fake_mctpd.default_sysnet()

@pytest.fixture
async def dbus():
    async with asyncdbus.MessageBus().connect() as bus:
        yield bus

@pytest.fixture
async def mctpd(nursery, dbus, sysnet):
    m = fake_mctpd.MctpdWrapper(dbus, sysnet)
    await m.start_mctpd(nursery)
    yield m
    res = await m.stop_mctpd()
    assert res == 0


from mctpenv import MctpWrapper

async def test_link_simple(mctp):
    proc = await mctp.run(["link"])
    assert proc.returncode == 0
    assert 'dev mctp0' in proc.stdout

async def test_route_single_direct(mctp):
    rt = mctp.system.Route(9, 0, iface = mctp.system.interfaces[0])
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 9 max 9 net 1 dev mctp0 mtu 0'

async def test_route_range_direct(mctp):
    rt = mctp.system.Route(9, 1, iface = mctp.system.interfaces[0])
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 9 max 10 net 1 dev mctp0 mtu 0'

async def test_route_single_gw(mctp):
    rt = mctp.system.Route(10, 0, gw = (1, 9))
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 10 max 10 net 1 gw 9 mtu 0'

async def test_route_range_gw(mctp):
    rt = mctp.system.Route(10, 1, gw = (1, 9))
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 10 max 11 net 1 gw 9 mtu 0'

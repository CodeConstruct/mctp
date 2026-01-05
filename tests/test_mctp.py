async def test_link_simple(mctp):
    proc = await mctp.run(["link"])
    assert proc.returncode == 0
    assert 'dev mctp0' in proc.stdout


async def test_route_single_direct(mctp):
    rt = mctp.system.Route(9, 0, iface=mctp.system.interfaces[0])
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 9 max 9 net 1 dev mctp0 mtu 0'


async def test_route_range_direct(mctp):
    rt = mctp.system.Route(9, 1, iface=mctp.system.interfaces[0])
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 9 max 10 net 1 dev mctp0 mtu 0'


async def test_route_single_gw(mctp):
    rt = mctp.system.Route(10, 0, gw=(1, 9))
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 10 max 10 net 1 gw 9 mtu 0'


async def test_route_range_gw(mctp):
    rt = mctp.system.Route(10, 1, gw=(1, 9))
    await mctp.system.add_route(rt)

    proc = await mctp.run(["route"])
    assert proc.returncode == 0
    assert proc.stdout.strip() == 'eid min 10 max 11 net 1 gw 9 mtu 0'


async def test_route_add_single_direct(mctp):
    proc = await mctp.run(["route", "add", "9", "via", "mctp0"])
    assert proc.returncode == 0

    assert len(mctp.system.routes) == 1
    route = mctp.system.routes[0]
    assert route.iface.name == "mctp0"
    assert route.gw is None
    assert route.start_eid == 9
    assert route.end_eid == 9
    assert route.mtu == 0


async def test_route_add_single_gw(mctp):
    proc = await mctp.run(["route", "add", "10", "gw", "9"])
    assert proc.returncode == 0

    assert len(mctp.system.routes) == 1
    route = mctp.system.routes[0]
    assert route.iface is None
    assert route.gw[0] == 1
    assert route.gw[1] == 9
    assert route.start_eid == 10
    assert route.end_eid == 10
    assert route.mtu == 0

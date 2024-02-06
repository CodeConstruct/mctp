
async def mctpd_mctp_obj(dbus):
    obj = await dbus.get_proxy_object(
            'au.com.codeconstruct.MCTP1',
            '/au/com/codeconstruct/mctp1'
        )
    return await obj.get_interface('au.com.codeconstruct.MCTP.BusOwner1')

async def mctpd_mctp_endpoint_obj(dbus, path):
    obj = await dbus.get_proxy_object(
            'au.com.codeconstruct.MCTP1',
            path,
        )
    return await obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')


async def mctpd_mctp_iface_obj(dbus, iface):
    obj = await dbus.get_proxy_object(
            'au.com.codeconstruct.MCTP1',
            '/au/com/codeconstruct/mctp1/interfaces/' + iface.name
        )
    return await obj.get_interface('au.com.codeconstruct.MCTP.BusOwner1')

async def mctpd_mctp_endpoint_obj(dbus, path, iface):
    obj = await dbus.get_proxy_object(
            'au.com.codeconstruct.MCTP1',
            path,
        )
    return await obj.get_interface(iface)

async def mctpd_mctp_endpoint_control_obj(dbus, path):
    return await mctpd_mctp_endpoint_obj(
            dbus,
            path,
            'au.com.codeconstruct.MCTP.Endpoint1'
        )

async def mctpd_mctp_endpoint_common_obj(dbus, path):
    return await mctpd_mctp_endpoint_obj(
            dbus,
            path,
            'xyz.openbmc_project.MCTP.Endpoint'
        )

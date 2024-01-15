
async def mctpd_mctp_obj(dbus):
    obj = await dbus.get_proxy_object(
            'xyz.openbmc_project.MCTP',
            '/xyz/openbmc_project/mctp'
        )
    return await obj.get_interface('au.com.CodeConstruct.MCTP')

async def mctpd_mctp_endpoint_obj(dbus, path):
    obj = await dbus.get_proxy_object(
            'xyz.openbmc_project.MCTP',
            path,
        )
    return await obj.get_interface('au.com.CodeConstruct.MCTP.Endpoint')

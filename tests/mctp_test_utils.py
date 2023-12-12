
async def mctpd_mctp_obj(dbus):
    obj = await dbus.get_proxy_object(
            'xyz.openbmc_project.MCTP',
            '/xyz/openbmc_project/mctp'
        )
    return await obj.get_interface('au.com.CodeConstruct.MCTP')

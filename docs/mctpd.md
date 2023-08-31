# `mctpd`

## D-Bus

`mctpd` provides a D-Bus path of `/xyz/openbmc_project/mctp`. For each known MCTP endpoint, `mctpd`
will populate an object `/xyz/openbmc_project/mctp/<NetworkId>/<EID>`. The objects have interface
`xyz.openbmc_project.MCTP.Endpoint`, as per 
[OpenBMC documentation](https://github.com/openbmc/phosphor-dbus-interfaces/tree/master/yaml/xyz/openbmc_project/MCTP).

As well as the standard interfaces, `mctpd` provides methods to add and configure MCTP endpoints.
These are provided by the `au.com.CodeConstruct.MCTP` D-Bus interface.

### `.SetupEndpoint`

This method is the normal method used to add a MCTP endpoint.
The endpoint is identified by MCTP network interface, and physical address.
`mctpd` will query for the endpoint's current EID, and assign an EID to the endpoint if needed.
`mctpd` will add local MCTP routes and neighbour table entries for endpoints as they are added.

`SetupEndpoint <interface name> <hwaddr>`

Returns
```
eid  (byte)
net  (integer)
path (string)
new  (bool) - true if a new EID was assigned
```

`<interface name>` is an interface such as `mctpi2c6`.

`<hwaddr>` depends on the transport type - for i2c it is a 1 byte client address (7-bit, the same as other Linux tools like `i2cdetect`).


An example:

```shell
busctl call xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp \
        au.com.CodeConstruct.MCTP SetupEndpoint say mctpi2c6 1 0x1d
```
`1` is the length of the hwaddr array.

### `.AssignEndpoint`

Similar to SetupEndpoint, but will always assign an EID rather than querying for existing ones.
Will return `new = false` when an endpoint is already known to `mctpd`.

### `.LearnEndpoint`

Like SetupEndpoint but will not assign EIDs, will only query endpoints for a current EID.
The `new` return value is set to `false` for an already known endpoint, or `true` when an
endpoint's EID is newly discovered.

## `.NotifyDiscovery`

This method is used to trigger the MCTP over PCIe-VDM discovery process on a
PCIe-VDM interface.

This method sends a Discovery Notify message to the Root Complex on the PCIe bus
with null EID, null physical address and Route-To-Root-Complex PCIe-VDM routing
type.

This method should only be used when `mctpd` is running on an endpoint.

`NotifyDiscovery <interface name>`

`<interface name>` is an PCIe-VDM interface such as `mctppcie0`.


Example:

```shell
busctl call xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp \
        au.com.CodeConstruct.MCTP NotifyDiscovery s mctppcie0
```

## Endpoint Methods

Each endpoint object has methods to configure it, with `au.com.CodeConstruct.MCTP.Endpoint`
interface on each endpoint.

## `.SetMTU`

Sets the MTU (maximum transmission unit) on the route for that endpoint. This must be within
the MTU range allowed for the network device. For i2c that is [68, 254].

If a route-specific MTU has not been set (or set to 0), Linux will use the per-interface
MTU, configurable with `mctp link set <ifname> mtu <value>`.

An example, setting MTU of 80:

```shell
busctl call xyz.openbmc_project.MCTP  /xyz/openbmc_project/mctp/1/11 \
        au.com.CodeConstruct.MCTP.Endpoint  SetMTU u 80
```

## `.Remove`

Removes the MCTP endpoint from `mctpd`, and deletes routes and neighbour entries.




# `mctpd`

## D-Bus

`mctpd` provides a D-Bus service named `au.com.codeconstruct.MCTP1`, and a base
object path of `/au/com/codeconstruct/mctp1`. For each known MCTP endpoint,
`mctpd` will populate an object at
`/au/com/codeconstruct/mctp1/networks/<NetworkId>/endpoints/<EID>`. The objects have
interface `xyz.openbmc_project.MCTP.Endpoint`, as per [OpenBMC
documentation](https://github.com/openbmc/phosphor-dbus-interfaces/tree/master/yaml/xyz/openbmc_project/MCTP).

As well as those standard interfaces, `mctpd` provides methods to add and
configure MCTP endpoints. These are provided by the `au.com.codeconstruct.MCTP1`
D-Bus interface.

## Bus-owner methods: `au.com.codeconstruct.MCTP.BusOwner1.DRAFT` interface

This interface exposes bus-owner level functions.

### `.SetupEndpoint`: `say` → `yisb`

This method is the normal method used to add a MCTP endpoint. The endpoint is
identified by MCTP network interface, and physical address. `mctpd` will query
for the endpoint's current EID, and assign an EID to the endpoint if needed.
`mctpd` will add local MCTP routes and neighbour table entries for endpoints as
they are added.

`SetupEndpoint <interface name> <hwaddr>`

Returns
```
eid  (byte)
net  (integer)
path (string)
new  (bool) - true if a new EID was assigned
```

`<interface name>` is an interface such as `mctpi2c6`.

`<hwaddr>` depends on the transport type - for i2c it is a 1 byte client address
(7-bit, the same as other Linux tools like `i2cdetect`).


An example:

```shell
busctl call au.com.codeconstruct.MCTP1 \
    /au/com/codeconstruct/mctp1 \
    au.com.codeconstruct.MCTP1 \
    SetupEndpoint say mctpi2c6 1 0x1d
```
`1` is the length of the hwaddr array.

### `.AssignEndpoint`: `say` → `yisb`

Similar to SetupEndpoint, but will always assign an EID rather than querying for
existing ones. Will return `new = false` when an endpoint is already known to
`mctpd`.

### `.AssignEndpointStatic`: `sayy` → `yisb`

Similar to AssignEndpoint, but takes an additional EID argument:

```
AssignEndpointStatic <interface name> <hwaddr> <static-EID>
```

to assign `<static-EID>` to the endpoint with hardware address `hwaddr`.

This call will fail if the endpoint already has an EID, and that EID is
different from `static-EID`, or if `static-EID` is already assigned to another
endpoint.

### `.LearnEndpoint`: `say` → `yisb`

Like SetupEndpoint but will not assign EIDs, will only query endpoints for a
current EID. The `new` return value is set to `false` for an already known
endpoint, or `true` when an endpoint's EID is newly discovered.

## Endpoint methods: the `au.com.codeconstruct.MCTP.Endpoint1` interface

Each endpoint object has methods to configure it, through the
`au.com.codeconstruct.MCTP.Endpoint1` interface on each endpoint.

## `.SetMTU`: `u`

Sets the MTU (maximum transmission unit) on the route for that endpoint. This
must be within the MTU range allowed for the network device. For i2c that is
[68, 254].

If a route-specific MTU has not been set (or set to 0), Linux will use the
per-interface MTU, configurable with `mctp link set <ifname> mtu <value>`.

An example, setting MTU of 80:

```shell
busctl call au.com.codeconstruct.MCTP1 \
    /au/com/codeconstruct/mctp1/networks/1/endpoints/11 \
    au.com.codeconstruct.MCTP.Endpoint1 \
    SetMTU u 80
```

## `.Remove`

Removes the MCTP endpoint from `mctpd`, and deletes routes and neighbour entries.


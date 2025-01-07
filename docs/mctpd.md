# `mctpd`

## D-Bus

`mctpd` provides a D-Bus service named `au.com.codeconstruct.MCTP1`, and a base
object path of `/au/com/codeconstruct/mctp1`. This tree represents both the
local MCTP stack state and the results of remote device enumeration.

```
Service au.com.codeconstruct.MCTP1:
└─ /au
  └─ /au/com
    └─ /au/com/codeconstruct
      └─ /au/com/codeconstruct/mctp1
        ├─ /au/com/codeconstruct/mctp1/interfaces
        │ ├─ /au/com/codeconstruct/mctp1/interfaces/lo
        │ └─ /au/com/codeconstruct/mctp1/interfaces/mctpi2c1
        └─ /au/com/codeconstruct/mctp1/networks
          └─ /au/com/codeconstruct/mctp1/networks/1
            └─ /au/com/codeconstruct/mctp1/networks/1/endpoints
              ├─ /au/com/codeconstruct/mctp1/networks/1/endpoints/8
              └─ /au/com/codeconstruct/mctp1/networks/1/endpoints/10
```


## Top-level object: `/au/com/codeconstruct/mctp1`

This object serves as the global MCTP daemon namespace; it doesn't contain
much at present, but hosts two trees of MCTP objects:

 * Interfaces: Local hardware transport bindings that connect us to a MCTP bus
 * Endpoints: MCTP endpoints that `mctpd` knows about, both remote and local

This object implements the `org.freedesktop.DBus.ObjectManager` interface,
allowing enumeration of managed networks, endpoints and interfaces.

## MCTP Interface objects: `/au/com/codeconstruct/interfaces/<name>`

The interface objects represent a connection to a MCTP bus; these will be
1:1 with the MCTP network interfaces on the system.

### MCTP interface interface: `au.com.codeconstruct.MCTP.Interface1`

All MCTP interface objects host the `au.com.codeconstruct.Interface1` dbus
interface:

```
NAME                                 TYPE      SIGNATURE RESULT/VALUE FLAGS
au.com.codeconstruct.MCTP.Interface1 interface -         -            -
.Role                                property  s         "BusOwner"   emits-change writable
```

The D-Bus interface includes the `Role` property which reports BMC roles
in the link. The possible value of `Role` are:

 * `BusOwner`: this link is the owner of the attached bus,
 * `Endpoint`: this link is not the owner of the attached bus; and
 * `Unknown`: not yet configured.

The `Role` property is writable, but it can only be changed when the current
configured value is `Unknown`. Other platform setup infrastructure may use
this to configure the initial MCTP state of the platform.

When the interface `Role` is `BusOwner`, the MCTP interface object will
also host the `BusOwner1` dbus interface:

### Bus-owner interface: `au.com.codeconstruct.MCTP.BusOwner1` interface

This interface exposes bus-owner level functions, on each interface object that
represents the bus-owner side of a transport.

```
NAME                                 TYPE      SIGNATURE RESULT/VALUE FLAGS
au.com.codeconstruct.MCTP.Interface1 interface -         -            -
.Role                                property  s         "BusOwner"   emits-change writable
au.com.codeconstruct.MCTP.BusOwner1  interface -         -            -
.AssignEndpoint                      method    ay        yisb         -
.AssignEndpointStatic                method    ayy       yisb         -
.LearnEndpoint                       method    ay        yisb         -
.SetupEndpoint                       method    ay        yisb         -
```

Those BusOwner methods are:

#### `.SetupEndpoint`: `ay` → `yisb`

This method is the normal method used to add a MCTP endpoint on this interface.
The endpoint is identified by physical address. `mctpd` will query for the
endpoint's current EID, and assign an EID to the endpoint if needed. `mctpd`
will add local MCTP routes and neighbour table entries for endpoints as they are
added.

`SetupEndpoint <hwaddr>`

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
    /au/com/codeconstruct/mctp1/interfaces/mctpi2c6 \
    au.com.codeconstruct.MCTP.BusOwner1 \
    SetupEndpoint ay 1 0x1d
```

`1` is the length of the hwaddr array.

#### `.AssignEndpoint`: `ay` → `yisb`

Similar to SetupEndpoint, but will always assign an EID rather than querying for
existing ones. Will return `new = false` when an endpoint is already known to
`mctpd`.

#### `.AssignEndpointStatic`: `ayy` → `yisb`

Similar to AssignEndpoint, but takes an additional EID argument:

```
AssignEndpointStatic <hwaddr> <static-EID>
```

to assign `<static-EID>` to the endpoint with hardware address `hwaddr`.

This call will fail if the endpoint already has an EID, and that EID is
different from `static-EID`, or if `static-EID` is already assigned to another
endpoint.

#### `.LearnEndpoint`: `ay` → `yisb`

Like SetupEndpoint but will not assign EIDs, will only query endpoints for a
current EID. The `new` return value is set to `false` for an already known
endpoint, or `true` when an endpoint's EID is newly discovered.

## Network objects: `/au/com/codeconstruct/networks/<net>`

These objects represent MCTP networks which have been added use `mctp link`
commands. These will be 1:1 with the MCTP networks on the system.

These objects host the interface `au.com.codeconstruct.MCTP.Network1`.

### MCTP network interface: `au.com.codeconstruct.MCTP.Network1`

All MCTP networks objects host the `au.com.codeconstruct.MCTP.Network1` dbus
interface:

```
NAME                                 TYPE      SIGNATURE RESULT/VALUE FLAGS
au.com.codeconstruct.MCTP.Network1  interface -         -            -
.LocalEIDs                          property  ay        1 8          const
```

The D-Bus interface includes the `LocalEIDs` property which reports BMC local EIDs
in the network.

## Endpoint objects: `/au/com/codeconstruct/networks/<net>/endpoints/<eid>`

These objects represent MCTP endpoints that `mctpd` has either discovered
locally (typically: MCTP addresses assigned to the local stack), or remote
interfaces discovered during device enumeration.

These objects host the interface `xyz.openbmc_project.MCTP.Endpoint`, as per
[OpenBMC
documentation](https://github.com/openbmc/phosphor-dbus-interfaces/tree/master/yaml/xyz/openbmc_project/MCTP).

Each endpoint object has methods to configure it, through the
`au.com.codeconstruct.MCTP.Endpoint1` interface on each endpoint.

### `.SetMTU`: `u`

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

### `.Remove`

Removes the MCTP endpoint from `mctpd`, and deletes routes and neighbour entries.

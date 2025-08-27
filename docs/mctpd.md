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

This object serves as the global MCTP daemon namespace.
It hosts `au.com.codeconstruct.MCTP1` dbus interface to modify properties of
the MCTP stack, such as supported message types.
```
NAME                                TYPE      SIGNATURE  RESULT/VALUE  FLAGS
au.com.codeconstruct.MCTP1          interface -          -             -
.RegisterTypeSupport                  method    yau        -             -
.RegisterVDMTypeSupport               method    yvq        -             -
```

#### `.RegisterTypeSupport`: `yau`

This method is used to add support for mctp message types other than control
messages. Once called successfully subsequent response for Get Message Type
Support control commands will include this new message type. Versions passed to
this method will be used to respond to Get MCTP Version Support commands.

`RegisterTypeSupport <msg type> <versions>`

If the message type is already registered, then dbus call will fail.

 - `<msg type>` Message type, as defined in DSP0239.
 - `<versions>` Versions supported for this message type formatted as uint32
   integers as specified in DSP0236

The `msg_type` value must be a valid message type, and cannot be one of the
VDM types (0x7e or 0x7f). Those VDM types are handled by the
`RegisterVDMTypeSupport` method instead.

De-registration is automatic - the specified types (and versions) are registered
for as long as the dbus sender remains attached to the message bus, and are
unregistered on disconnect.

#### `.RegisterVDMTypeSupport`: `yvq`

This method is used to add support for MCTP Vendor Defined Message (VDM) types.
Once called successfully, subsequent responses for Get Vendor Defined Message
Support control commands will include this new VDM type.

`RegisterVDMTypeSupport <vid format> <vendor id> <command set type>`

If the VDM type is already registered, then dbus call will fail.

 - `<vid format>` Vendor ID format:
   - `0x00` - PCI/PCIe Vendor ID (16-bit)
   - `0x01` - IANA Enterprise Number (32-bit)
 - `<vendor id>` Vendor identifier as a variant type:
   - For PCIe format: 16-bit unsigned integer (`q`)
   - For IANA format: 32-bit unsigned integer (`u`)
 - `<command set type>` Command set type (16-bit unsigned integer) as defined by the vendor

Registering a VDM type will cause the corresponding VDM type value (0x7e or
0x7f) to be returned in mctpd's Get Message Type Support response.

De-registration is automatic - the specified VDM types are registered for as
long as the dbus sender remains attached to the message bus, and are
removed when the sender disconnects.

Also it hosts two trees of MCTP objects:

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
.NetworkId                           property  u         1            emits-change
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

The `NetworkId` property represents the network on which this interface is
present.

### Bus-owner interface: `au.com.codeconstruct.MCTP.BusOwner1` interface

This interface exposes bus-owner level functions, on each interface object that
represents the bus-owner side of a transport.

```
NAME                                 TYPE      SIGNATURE RESULT/VALUE FLAGS
au.com.codeconstruct.MCTP.Interface1 interface -         -            -
.NetworkId                           property  u         1            emits-change
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
`mctpd`. If the endpoint is an MCTP bridge (indicated by requesting a pool size
in its Set Endpoint ID response), this method attempts to allocate a contiguous
range of EIDs for the bridge's downstream endpoints. If sufficient contiguous
EIDs are not available within the dynamic allocation pool for the network, only
the bridge's own EID will be assigned, and downstream EID allocation will fail.

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

Because we are not issuing a Set Endpoint ID as part of the LearnEndpoint call,
we do not have any details of the endpoint's bridge pool range. So,
LearnEndpoint is unsuitable for use with bridge endpoints - it cannot provide
the bridge with its own EID pool. `mctpd` will warn if the device type
reports as a bridge.

Bridge endpoints should be initialised with `AssignEndpoint` instead.

## Network objects: `/au/com/codeconstruct/networks/<net>`

These objects represent MCTP networks which have been added use `mctp link`
commands. These will be 1:1 with the MCTP networks on the system.

These objects host the interface `au.com.codeconstruct.MCTP.Network1`.

### MCTP network interface: `au.com.codeconstruct.MCTP.Network1`

All MCTP networks objects host the `au.com.codeconstruct.MCTP.Network1` dbus
interface:

```
NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
au.com.codeconstruct.MCTP.Network1  interface -         -            -
.LearnEndpoint                      method    y         sb           -
.LocalEIDs                          property  ay        1 8          const
```

### `.LearnEndpoint`: `y`

The `LearnEndpoint` method allows a caller to perform enumeration of a
static endpoint that we can already route to. This may be useful to discover
bridged endpoints, where the EID assigment has already been handled by the
bridge.

`LearnEndpoint` takes an EID as its only argument, and returns the endpoint's
path, and a boolean indicating whether the endpoint was newly discovered.

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
If endpoint is a bridge (have EID pool allocated for downstream devices) removing
it will cause removal of all downstream devices endpoint objects as well.

### MCTP bridge interface: `au.com.codeconstruct.MCTP.Bridge1` interface

MCTP endpoints that are set up as a bridge device (and therefore have an
EID pool allocated to them, for downstream devices) also carry the
`MCTP.Bridge1` interface. This provides details of the allocated EID pool, via
two properties:

### `.PoolStart`: `y`

A constant property representing the first EID in the range allocated for
downstream endpoints.

### `.PoolEnd`: `y`

A constant property representing the last EID in the range allocated for
downstream endpoints.

## Configuration

`mctpd` reads configuration data from a TOML file, typically `/etc/mctpd.conf`.
An alternative configuration file can be specified using the `--config`
command-line option.

The configuration file has a global section, plus function-specific sections.

### Global settings

These apply to all modes of `mctpd` operation. One top-level setting is defined:

#### `mode`: mctpd mode of operation

* type: string enum: `bus-owner` or `endpoint`
* default: `bus-owner`

This sets the overall mode of `mctpd`, either as a Bus Owner (`mode =
"bus-owner"`) or Endpoint (`mode = "endpoint"`). In bus owner mode, mctpd will
assume responsibility for allocating addresses to other endpoints. In endpoint
mode, mctpd will not allocate addresses, but instead accept allocations from an
external bus owner.

### `[mctp]` section

This section affects MCTP protocol behaviour, and any common values used for
both bus-owner and endpoint modes.

#### `message_timeout_ms`: global MCTP message timeout

* type: integer, in milliseconds
* default: 250

This sets the timeout for outgoing request messages. A message will be
considered lost if no response is received within this timeout.

Long timeouts may degrade `mctpd` performance, as we typically wait for
operations synchronously.

#### `uuid`: endpoint UUID value

* type: string, UUID format
* default: queried from system

This sets the UUID used to identify this endpoint to peers, as returned in the
MCTP "Get Endpoint UUID" command.

This is not typically needed; if no `uuid` configuration is specified, `mctpd`
will use the system-wide UUID value, which has generally correct semantics
for the MCTP endpoint UUID.

The UUID should be formatted as a RFC 4122 UUID string, for example:

```
uuid = "21f0f554-7f7c-4211-9ca1-6d0f000ea9e7"
```

#### `[bus-owner]` section

This section affects behaviour when `mctpd` is running in bus owner mode

#### `dynamic_eid_range`: Range for dynamic EID allocations

* type: array of integers, 2 elements
* default: `[ 8, 254 ]`

This setting specifies the range of dynamic EIDs that `mctpd` will allocate
new peers' EIDs from. Values are inclusive.

Local interface EIDs and statically-allocated EIDs may fall outside this range;
it is only used when a peer needs a new dynamic address.

The default value makes the entire MCTP EID address space available for dynamic
allocations.

#### `max_pool_size`: Maximum peer allocation pool size

* type: integer
* default: 15

This setting determines the maximum EID pool size that a bridge peer may request
via their Set Endpoint ID response. Requests larger than this size will be
truncated.

#### `endpoint_poll_ms`: Periodic polling interval for briged peers.

* type: integer, in milliseconds
* default: 0

This is periodic polling interval time in milliseconds, which bus owner/bridge
needs to perform to identify accessible bridged eid among the allocated pool
space. Value should be between [```0.5 * TRECLAIM (5)```- ```10```] seconds.
Such periodic polling is common for all the briged endpoints among allocated
pool space [`.PoolStart` - `.PoolEnd`] of the bridge.
Polling could be provisioned to be disabled via setting the value as ```0```.

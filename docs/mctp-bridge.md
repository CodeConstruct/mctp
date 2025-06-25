# MCTP Bridge

<!--toc:start-->
- [MCTP Bridge](#mctp-bridge)
	- [References](#references)
	- [Requirement](#requirement)
	- [Relevant Components](#relevant-components)
	- [Dbus method AssignBridgeStatic](#dbus-method-assignbridgestatic)
		- [`.AssignBridgeStatic`: `ayyyy` → `yisbs`](#assignbridgestatic-ayyyy--yisbs)
	- [Polling Mechanism](#polling-mechanism)
		- [Asynchronous Polling](#asynchronous-polling)
		- [Polling Configuration](#polling-configuration)
	- [Reservation of EIDs](#reservation-of-eids)
	- [Proposed Design](#proposed-design)
<!--toc:end-->

Here we capture the reasoning around design and implementation of bridge endpoint discovery and polling mechanisms for downstream devices in MCTP networks.

## References

1. [DSP0236 - Management Component Transport Protocol (MCTP) Base Specification][dmtf-dsp0236]
2. [DSP0283 - MCTP over USB Binding Specification][dmtf-dsp0283]


[dmtf-dsp0236]: https://www.dmtf.org/sites/default/files/standards/documents/DSP0236_1.3.1.pdf

[dmtf-dsp0283]: https://www.dmtf.org/sites/default/files/standards/documents/DSP0283_0.1.5WIP10.pdf

## Requirement

We need to improve the MCTP endpoint discovery process, especially to handle bridge endpoints and their downstream devices more effectively.

Each MCTP endpoint is identified by a system-wide unique Endpoint ID (EID), which can be dynamically assigned during system startup or hot-plug events.

A MCTP Bridge is assigned range of EIDs for its downstream endpoints depending upon bridge's applicable pool size. MCTP Base Spec introduces MCTP control command `AllocateEndpointID` to allocate these set of range of EIDs. It's possible to have downstream endpoints detached/undiscovered due to some error in its internal bus or via physical hotplug removal (such as usb bus aligned devices). To detect the removal/presence of its downstream devices, the bridge probes on each endpoint using the Get Endpoint ID command. If a device fails to respond, it is treated as no longer present on the bus. The corresponding EID (if was assigned) is then released back to the bridge pool for reassignment.


Once MCTP Bridge is allocated set of Endpoint IDs, it would assign the upcoming discoverable downstream devices among those range of eids. For a discovered downstream device i.e once it responds to poll command, **`mctpd` then creates a peer for it and exposes its D-bus object and marks that eid as used from its EID pool**. This creates a scenario where some other MCTP endpoint could end up consuming the EID from Bridge's set of allocated EID (via dynamically or statically). For such reasons, these Bridge's allocated set of EIDs are not to be touched/used by bus owner for assigning to any other MCTP devices. Thus it creates a need to reserve some set of EIDs among the managed pool of a bus owner.

The support for MCTP Bridge devices required `mctpd` to introduce the following new aspects:

1. New Dbus Method : `AssignBridgeStatic`
2. Polling Mechanism
3. Bus Owner reservation eids for Bridge's Endpoints

## Relevant Components

1. MCTP Bridge such as FPGA
2. Downstream Endpoint devices
3. `mctpd`
4. USB bus (or any such bus where MCTP Bridge is supported on)

## Dbus method AssignBridgeStatic

We have introduced a new d-bus method `AssignBridgeStatic` under  `au.com.codeconstruct.Interface1` dbus interface. This interface exposes other bus owner level functions, on each interface object that
represents the bus owner side of a transport.

```
NAME                                 TYPE      SIGNATURE RESULT/VALUE FLAGS
au.com.codeconstruct.MCTP.Interface1 interface -         -            -
.Role                                property  s         "BusOwner"   emits-change writable
au.com.codeconstruct.MCTP.BusOwner1  interface -         -            -
.AssignBridgeStatic                 method    ayyyy     yisbs        -
.AssignEndpoint                      method    ay        yisb         -
.AssignEndpointStatic                method    ayy       yisb         -
.LearnEndpoint                       method    ay        yisb         -
.SetupEndpoint                       method    ay        yisb         -
```
### `.AssignBridgeStatic`: `ayyyy` → `yisbs`

This new method is similar to `.SetupEndpoint` which is used to add a MCTP endpoint on its interface, but along with its own (bridge) eid, it also allocates range of eids for its downstream endpoints based on required pool-size and start of pool passed as arguments.

`AssignBridgeStatic <hwaddr> <static-EID> <pool-start> <pool-size>`

Returns
```
eid  (byte)
net  (integer)
path (string)
new  (bool) - true if a bridge EID was assigned
msg (string)
```

An example:

```shell
busctl call au.com.codeconstruct.MCTP1 \
	/au/com/codeconstruct/mctp1/interfaces/mctpusb0 \
	au.com.codeconstruct.MCTP.BusOwner1 \
	AssignBridgeStatic ayyyy 0 12 13 15
```

## Polling Mechanism

Substatiating from [DSP0236 v1.3.1 8.17.6 Reclaiming EIDs from hot-plug
devices][dmtf-dsp0236] we have:

> - A bus owner shall confirm that an endpoint has been removed by attempting to access it after `TRECLAIM` (5 sec `MCTPoUSB`) has expired. It can do this by issuing a `Get Endpoint ID` command to the endpoint to verify that the endpoint is still non-responsive. It is recommended that this be done at least three times, with a delay of at least 1/2 * `TRECLAIM` between tries if possible. If the endpoint continues to be non-responsive, it can be assumed that it is safe to return its EID to the pool of EIDs available for assignment.
>

`mctpd` has been introduced with a new Periodic Polling mechanism for all MCTP Bridges. Using `Get Endpoint ID` command messages, it aims to target all downstream endpoints of the bridge that have/haven't been enumerated and likely to keep track of health/status of such endpoints.

**A continuous poll will happen throughout the MCTP Bridge's existence on MCTP network**.
If the endpoint responds to any of the sent poll command, it is assumed to have been successfully enumerated. For such devices polling should continue to monitor the endpoint's health and detect if it goes offline or becomes unresponsive.
If the endpoint fails to respond to sent poll commands for more than  [`EP_REMOVAL_THRESHOLD`](#polling-configuration), its is marked as unresponsive and polling should still continue to monitor in case becomes responsive again.

If due to some reason `.Recovery` is invoked on the MCTP Bridge EID via some application, the polling mechanism too needs to be shut down for that Bridge.

### Asynchronous Polling

In order to avoid  blocking and putting much strain on `mctpd` main process due to complexity of handling back to back GetEndpointID request response for each downstream individually, we propose an asynchronous message based communication which would address these request response for each downstream device individually and separately.

### Polling Configuration

We're concerned with the `TRECLAIM` relevant to MCTPoUSB Bridge devices for now, which
leads us to DSP0283. [DSP0283 v0.1.5wip10][dmtf-dsp0283] defines `TRECLAIM` as 5
seconds, while minimum number of attempts of poll needed before considering downstream device being out of bus is considered as `3` referring it as `EP_REMOVAL_THRESHOLD` (`mctpd` coined). Thus a continuous poll after every `2.5` sec (1/2 * `TRECLAIM`) is needed with response timeout for each Get EndpointID command as `MT2` (defined in DSP0283).

## Reservation of EIDs

A Bus Owner controls and maintains pool of EIDs which it assigns to its Endpoints on a given network. For special endpoints such as MCTP Bridges, a set of EIDs are to be allocated to them which would later be used by Bridge to assign to its downstream endpoints. Once assigned, these allocated set range of EIDs needs to be preserved for its Bridge's use only. `mctpd` introduces set of reservation eids which is maintained per network by bus owner. ([mentioned here](#requirement))


## Proposed Design

One of the salient approach to achieve MCTP Bridge support is stated below

1. Once `AllocateBridgeStatic `D-Bus API for MCTP Bridge is invoked, `mctpd` assigns the asked bridge endpoint EID to the Bridge while initiating `AllocateEndpointID` MCTP control messages for its downstream endpoints EID assignment.

2. Netlink routes are established via new gateway implementation for all allocated EID range [link][#link]

[#link]:https://github.com/CodeConstruct/mctp/tree/dev/gateway

3. Polling mechanism ([above](#polling-configuration)) is then started separately and asynchronously for each bridge downstream endpoints to identify their presence before establishing their D-bus object and their peer structures.

4. Reserved EID set is maintained separately for each Bridge under its network, to prevent conflicts with non-bridge endpoints during polling.

5. If the downstream endpoint responds to sent poll command (`Get Endpoint ID`), a peer structure is created for it and its representing D-bus object is exposed, also that EID is removed from Reserved EID set of the Bridge. Polling would still continue to happen to monitor status of the endpoint.
   
6. If after being discovered, endpoint stops responding to monitor polls more than [`EP_REMOVAL_THRESHOLD`](#polling-configuration), its object is then taken off the D-bus and peer structure is released and corresponding EID returned back to Reserved EID set for the Bridge.

7. If `.Recovery` on MCTP Bridge EID is invoked, the polling mechanism would stop and Resevered EID set would be cleared recovering the eids back to bus owner's pool which could later be used by other MCTP devices.


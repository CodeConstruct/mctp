# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## Fixed

1. mctpd: fixed an issue where endpoints may persist when their dependent
   interface is deleted

2. Header compatibility fixes for environments without a recent linux/mctp.h

## Added

1. `mctp-bench` now supports a "request receive" mode, where
   `mctp-bench recv eid <...>` sends a command to start the benchmark session.

2. `mctpd` now supports a bus-owner configuration section

3. Added documentation for `mctpd.conf` settings

4. `mctpd`'s dynamic EID range is now configurable

5. When in endpoint mode, `mctpd` now handles to Set Endpoint ID messages,
   assigning an EID to local interfaces.

6. `mctpd` now handles downstream MCTP bridges, which may request an EID
   pool from their Set Endpoint ID response. It will attempt an EID allocation
   from the dynamic range, and pass this to the bridge using a subsequent
   Allocate Endpoint IDs command.

## [2.2] - 2025-07-28

### Fixed

1. Fixed an issue where peer pointers are kept over a potential realloc()

2. Netlink handling now handles interface deletion correctly; we no longer
   lose sync with the internal linkmap

3. When operating as a responder, mctpd now uses the correct instance id (IID)
   in the control protocol header

4. `mctpd` now correctly handles error responses that contain only the CC,
   as permitted by the spec

5. Ensure that `mctpd` error response data is initialised

### Added

1. New debug tool, `mctp-bench`, for sending and receiving a stream of MCTP
   messages between two processes.

2. mctpd: Add `au.com.codeconstruct.MCTP.Network1` interface, including
    - a `LocalEIDs` property, representing the local EIDs assigned on this
      network
    - a `LearnEndpoint` method, for enumerating endpoints that already have an
      address assigned, and are routable

3. tests: the fake mctp environment can now be run standalone, allowing
   experimentation with different system and network configurations

4. mctpd: Add a `NetworkId` property to the
   `au.com.codecontruct.MCTP.Interface1` interface, allowing link-to-network
   lookups

5. mctpd: Better handling of strange cases of Set Endpoint ID responses,
   where the reported endpoint EID may either be different from expected,
   or invalid

6. New debug/test tool, `mctp-bench`, for performing basic requests to MCTP
   endpoints, and printing their responses

7. `mctp` now supports gateway routes

8. `mctp` route can add & delete range routes, using a <min>-<max> range format

9. In-tree tests now include coverage for the `mctp` utility

10. `mctpd` now handles interface name changes, updating dbus objects to
    reflect new interface names.

### Changed

1. tests are now run with address sanitizer enabled (-fsanitize=address)

2. `mctp neigh` hardware address formatting is improved.

3. `mctp-bench` now reports at 2-second intervals rather than 10.

### Removed

1. mctpd: Test mode (`-N`) has been removed, as we have a more comprehensive
   test environment with the python mctpd wrapper code.

   To run using the wrapper:

       (cd obj; python3 ../tests/mctpd/__init__.py)

3. mctp-bench, mctp-req, mctp-echo: Message format has changed to use a
   vendor-defined message type, rather than MCTP type 1.

## [2.1] - 2024-12-16

### Fixed

1. Fixed build on musl; we were relying on an implicit definition for `AF_MCTP`

2. Fixed some header includes where we were previously assuming a glibc layout

3. Fixed incorrect setup of peer message type data, where peer endpoints would
   report no types supported over dbus.

4. Interface objects (MCTP.Interface1) are now under au.com.codeconstruct
   prefix, to be consistent with the other interface names.

### Changed

1. We now enforce IID checks on MCTP control protocol responses; this
   prevents odd behaviour from delayed or invalid responses.

2. In mctpd the initial route MTU for an endpoint is now set to the minimum MTU
   of the interface. This allows better compatibility with devices that 
   have a low initial allowed packet size and require application negotiation
   to increase that packet size. Previously the initial MTU was left as the
   interface default (normally the maximum MTU).
   The .SetMTU method can be used to set the endpoint route MTU.

3. Hardware address formatting has been improved in cases where the address
   size is something other than a 1-byte value.

## [2.0] - 2024-09-19

### Added

1. mctpd: Add support for endpoint recovery
2. mctpd: Allow recovery of devices reporting a nil UUID for development
3. mctpd: Allow configuring .Connectivity as writable for development
4. mctpd: Add AssignEndpointStatic for static EID allocations
5. mctpd: New test infrastructure for control procotol messaging to mctpd
6. mctpd: Add a configuration file facility, defaulting to /etc/mctpd.conf.
7. mctpd: Add mctp/interfaces/<name> D-Bus object

### Changed

1. dbus interface: the NetworkID field is now a `u` rather than an `i`, to
   match OpenBMC's MCTP endpoint specification

2. Use Github Actions for CI

   Note that this bumps the meson requirement from >=0.47.0 to >=0.59.0. The
   bump allows us to exploit some features helpful for chaining the solution
   together.

3. The `tests` option has changed type from `feature` to `boolean`. Tests are
   enabled by default.

4. The dbus interface has undergone a major rework, using standard prefixes
   and version interface, bus owner and entry-point object names. See
   docs/mctpd.md for full details on the new interface.

5. In line with the above, bus-owner related dbus methods (SetupEndpoint and
   friends) now exist on the MCTP interface objects, and only when those
   interface objects have the bus owner role. Because those methods are
   now associated with the interface object, they no longer take the
   interface name as their first argument.

### Fixed

1. mctpd: EID assignments now work in the case where a new endpoint has a
   pre-configured EID that would conflict with other (already enumerated)
   endpoints. The new endpoint will get a non-conflicting address assigned.

2. mctpd: fix incorrect error detection on control socket reads

## [1.1] - 2023-04-13

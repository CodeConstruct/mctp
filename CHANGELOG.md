# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Added

1. mctpd: Add support for endpoint recovery
2. mctpd: Allow recovery of devices reporting a nil UUID for development
3. mctpd: Allow configuring .Connectivity as writable for development
4. mctpd: Add AssignEndpointStatic for static EID allocations
5. mctpd: Add a configuration file facility, defaulting to /etc/mctpd.conf.

### Changed

1. dbus interface: the NetworkID field is now a `u` rather than an `i`, to
   match OpenBMC's MCTP endpoint specification

2. Use Github Actions for CI

   Note that this bumps the meson requirement from >=0.47.0 to >=0.59.0. The
   bump allows us to exploit some features helpful for chaining the solution
   together.

3. The `tests` option has changed type from `feature` to `boolean`. Tests are
   enabled by default.

### Fixed

1. mctpd: EID assignments now work in the case where a new endpoint has a
   pre-configured EID that would conflict with other (already enumerated)
   endpoints. The new endpoint will get a non-conflicting address assigned.

## [1.1] - 2023-04-13

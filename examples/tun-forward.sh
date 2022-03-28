#!/bin/sh

# SPDX-License-Identifier: GPL-2.0
# (c) 2022 Code Construct

# Set up tunA and tunB MCTP devices with routing between them.
# Each device is assigned to a different MCTP network so that packets
# will be routed between interfaces on a single machine.

# This script can be split to run Side A and Side B on separate machines
IPA=127.0.0.1
IPB=127.0.0.1

# This would run on both sides
mctp-echo&

# Side A is eid 160
socat  tun,iff-up,tun-name=tunA udp-datagram:$IPB:9933,bind=$IPA:9922 &
sleep 0.5
mctp link set tunA net 10
mctp addr add 160 dev tunA
mctp route add 161 via tunA

# Side B is eid 161
socat tun,iff-up,tun-name=tunB udp-datagram:$IPA:9922,bind=$IPB:9933 &
sleep 0.5
mctp link set tunB net 11
mctp addr add 161 dev tunB
mctp route add 160 via tunB

# Side A sending
mctp-req eid 161 net 10

# Side B sending
mctp-req eid 160 net 11

# socat continues running here, kill it to clean up devices

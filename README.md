<!--SPDX-License-Identifier: GPL-2.0-only-->
<!--SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>-->
# Tstest - TimeStamp Testing

A tool to test the functionalities required by Linuxptp in a controlled manner.
Rather than running the complex daemons you can use tstest to try out one
functionality at a time. Great for debugging purposes.

## Features
- `tstest pkt` can send and receive individual packets with timestamps.
- `tstest delay` can perform basic peer delay measurement.
- `tstest extts` can listen to EXTTS events from the kernel.


## TODO
- Add PPS configuration
- Add E2E delay
- Idea: `tstest check` mode that takes a config file of actions it should check
  (send, receive, verify values). Should be run with a looped cable, else it
  would require two instances (which might be an option too).

## TODO: TC Mode
- Better handling for finding the initial max/min values. Use INT MIN/MAX?
- Change to use capture time and interval, rather than packet count
- P2P measurement
- build_msg() should take portIdentity
- Export Delay and Twoway error. Alternatively, only export packet
  data and calculate externally (note: internal calculation is also
  desired since we want to give quick output).
- BC mode
- Refactor stats.c to better map messages???

## Credit
A lot of the code is directly taken from the Linuxptp project and the Linux
kernel and simplified/modified.

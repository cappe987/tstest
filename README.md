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
- `tstest tc` can measure TC time error, latency, and more.
- `tstest te` can measure time error, latency, and more. Some overlap with `tc`.
- `tstest pps` can configure PPS.


## TODO
- Add GM mode (send out Announce indiscriminately, send Sync and
  respond to Delay). Can be paired with `te` mode which runs the slave
  to measure the results instead of a full ptp4l GM.
- Add BC Time Error support (either just receiver, or act as both GM and Slave).
- Add E2E delay
- Idea: Mock send/receive/poll/tstamp/socket via stdin/stdout for testing?
- Idea: `tstest check` mode that takes a config file of actions it should check
  (send, receive, verify values). Should be run with a looped cable, else it
  would require two instances (which might be an option too).
- tstest faketc, better than the libpcap Python script. Open sockets
  and forward with random correctionField.

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
- Fix SeqID handling to have separate counters for each packet type.

## Credit
Some of the code is directly taken from the Linuxptp project and the Linux
kernel and simplified/modified.

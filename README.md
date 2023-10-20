<!--SPDX-License-Identifier: GPL-2.0-only-->
<!--SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>-->
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


## Credit
A lot of the code is directly taken from the Linuxptp project and the Linux
kernel and simplified/modified.

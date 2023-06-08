# Tstest - TimeStamp Testing

A tool to test the functionalities required by Linuxptp in a controlled manner.
Rather than running the complex daemons you can use tstest to try out one
functionality at a time. Great for debugging purposes.

Currently supports:
- Sending timestamped packets of different PTP types and one-step. Note that
  some PTP types are not expected to be timestamped.
- Receiving timestamped packets



## TODO
- Don't expect TX timestamp when sending non-event PTP types (e.g. announce),
  unless in -a mode.
- Add EXTTS support
- Add PPS configuration


## Credit
A lot of the code is directly taken from the Linuxptp project and
simplified/modified for debugging purposes.

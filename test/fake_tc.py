from scapy.all import *
import sys

import tstest_util

i = 0
silent = False
corrfield = 2**16 << 16

def change_send(pkt):
    if pkt.haslayer(tstest_util.PTP):
        ptp = pkt.getlayer(tstest_util.PTP)
    else:
        return

    # Sniffing on both and forwarding causes it to sniff its own packets
    # Skip packets we already modified/forwarded to avoid infinite loops
    if ptp.reserved2 != 0:
        return

    ptp.reserved2 = 1
    ptp.correctionField = corrfield
    global i

    if pkt.sniffed_on == 'veth2':
        sendp(pkt, iface='veth3', verbose=False)
        if not silent:
            print(f"{i}: Forwarded veth2 -> veth3")
    elif pkt.sniffed_on == 'veth3':
        sendp(pkt, iface='veth2', verbose=False)
        if not silent:
            print(f"{i}: Forwarded veth3 -> veth2")

    i += 1
    
if '-q' in sys.argv:
    silent = True

sniff(filter='ether proto 0x88f7', iface=['veth2', 'veth3'], prn=change_send)




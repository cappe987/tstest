from scapy.all import *

i = 0
corrfield = b"\x00\x00\x00\x01\x00\x00"

def change_send(pkt):
    payload = pkt.lastlayer()
    # Sniffing on both and forwarding causes it to sniff its own packets
    # Skip packets we already modified/forwarded to avoid infinite loops
    if payload.load[8:14] == corrfield:
        return

    payload.load = payload.load[:8] + corrfield + payload.load[14:]
    global i

    if pkt.sniffed_on == 'veth2':
        sendp(pkt, iface='veth3', verbose=False)
        print(f"{i}: Forwarded veth2 -> veth3")
    elif pkt.sniffed_on == 'veth3':
        sendp(pkt, iface='veth2', verbose=False)
        print(f"{i}: Forwarded veth3 -> veth2")

    i += 1

sniff(filter='ether proto 0x88f7', iface=['veth2', 'veth3'], prn=change_send)




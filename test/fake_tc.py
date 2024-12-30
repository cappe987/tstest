from scapy.all import *

i = 0

def change_send(pkt):
    payload = pkt.lastlayer()
    payload.load = payload.load[:8] + b"\x00\x00\x00\x01\x00\x00" + payload.load[14:]
    global i

    # if pkt.sniffed_on == 'veth2':
    sendp(pkt, iface='veth3', verbose=False)
    print(f"{i}: Forwarded veth2 -> veth3")
    i += 1
    # elif pkt.sniffed_on == 'veth3':
        # sendp(pkt, iface='veth2', verbose=False)
        # print("Forwarded veth3 -> veth2")


# Sniffing on both and forwarding causes it to sniff its own packets
# sniff(iface=['veth2', 'veth3'], prn=change_send)
sniff(iface='veth2', prn=change_send)




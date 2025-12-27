import subprocess
import os
import time
from scapy.all import *

NS_PER_SEC = 1000000000

def parse_ts(ts):
    s,ns = ts.split('.')
    return int(s) * NS_PER_SEC + int(ns)

def parse_rx(s):
    _, typ, _ts, ts = s.split()
    if typ != "sync.":
        raise AssertionError(f"Expected receiving Sync message")

    if _ts != "TS:":
        raise AssertionError(f"Expected timestamp")

    return parse_ts(ts)

def parse_tx(s):
    _ts, ts = s.split()
    if _ts != "TS:":
        raise AssertionError(f"Expected timestamp")

    return parse_ts(ts)

def test_pkt_rx_tx(tstest):
    server = subprocess.Popen([tstest, 'pkt', '-S', '-i', 'veth1', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.2)

    client = subprocess.run([tstest, 'pkt', '-S', '-i', 'veth2', '-c', '1'], capture_output=True, text=True)
    server.terminate()
    out, err = server.communicate(timeout=1)
    # print(f"\nSTDOUT: {out}")
    # print(f"STDERR: {err}")
    rx_ns = parse_rx(out)
    tx_ns = parse_tx(client.stdout)
    abs_diff = abs(rx_ns-tx_ns)
    threshold = 100000
    assert abs_diff < threshold, f"Expected absolute diff < {threshold}. Got {abs_diff}"

def test_pkt_rx_tx_many(tstest):
    server = subprocess.Popen([tstest, 'pkt', '-S', '-i', 'veth1', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.2)

    client = subprocess.run([tstest, 'pkt', '-S', '-i', 'veth2', '-c', '10'], capture_output=True, text=True)
    server.terminate()
    out, err = server.communicate(timeout=1)
    # print(f"\nSTDOUT: {out}")
    # print(f"STDERR: {err}")
    assert len(out.splitlines()) == 10, f"Expected 10 received packets. Got {len(out.splitlines())}"

    threshold = 100000
    for rx_line,tx_line in zip(out.splitlines(), client.stdout.splitlines()):
        rx_ns = parse_rx(rx_line)
        tx_ns = parse_tx(tx_line)
        abs_diff = abs(rx_ns - tx_ns)
        assert abs_diff < threshold, f"Expected absolute diff < {threshold}. Got {abs_diff}"

class PTP(Packet):
    name = "PTP"
    fields_desc = [
        BitField("transportSpecific", 0, 4),
        BitField("messageType", 0, 4),
        BitField("minorVersion", 0, 4),
        BitField("majorVersion", 2, 4),
        ShortField("messageLength", 44),
        ByteField("domainNumber", 0),
        ByteField("reserved1", 0),
        ShortField("flags", 0),
        LongField("correctionField", 0),
        IntField("reserved2", 0),
        StrFixedLenField("sourcePortIdentity", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", length=10),
        ShortField("sequenceId", 0),
        ByteField("controlField", 0),
        ByteField("logMessageInterval", 0),
        BitField("originTSSeconds", 0, 48),
        BitField("originTSFracNano", 0, 32),
    ]

bind_layers(Ether, PTP, type=0x88f7)

def test_pkt_seqid(tstest):
    seqid = 123
    cnt = 10
    sniffer = AsyncSniffer(filter='ether proto 0x88f7', iface=['veth2'])
    sniffer.start()
    time.sleep(0.2)
    client = subprocess.run([tstest, 'pkt', '-S', '-i', 'veth1', '-c', '1', '-s', str(seqid), '-c', str(cnt)], capture_output=True, text=True)
    time.sleep(0.2)
    res = sniffer.stop()

    assert len(res) == cnt, f"Expected {cnt} packets. Got {len(res)}"
    for i, pkt in enumerate(res):
        assert pkt.sequenceId == seqid+i, f"Expected sequenceId {seqid}. Got {pkt.sequenceId}"

# def test_pkt_vlan(tstest):
# TODO: need to implement VLAN support first

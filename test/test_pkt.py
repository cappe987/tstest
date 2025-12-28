import subprocess
import os
import time
from scapy.all import *

import tstest_util

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

def test_pkt_tstamp_types(tstest):
    server = subprocess.Popen([tstest, 'pkt', '-S', '-i', 'veth1', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.2)

    types = ['sync', 'delay_req', 'pdelay_req', 'pdelay_resp']

    for msg_type in types:
        subprocess.run([tstest, 'pkt', '-S', '-i', 'veth2', '-c', '1', '-T', msg_type], capture_output=True, text=True)
    time.sleep(0.2)

    server.terminate()
    out, err = server.communicate(timeout=1)
    # print(f"\nSTDOUT: {out}")
    # print(f"STDERR: {err}")
    assert len(out.splitlines()) == len(types), f"Expected {len(types)} received packets. Got {len(out.splitlines())}"
    for t,line in zip(types, out.splitlines()):
        typ = line.split()[1][:-1]  # remove the dot
        if typ != t:
            raise AssertionError(f"Expected receiving {t} message. Got {typ}")

def test_pkt_seqid_domain(tstest):
    seqid = 123
    cnt = 10
    domain = 44
    sniffer = AsyncSniffer(filter='ether proto 0x88f7', iface=['veth2'])
    sniffer.start()
    time.sleep(0.2)
    client = subprocess.run([tstest, 'pkt', '-S', '-i', 'veth1', '-c', '1', '-s', str(seqid), '-c', str(cnt), '-D', str(domain)], capture_output=True, text=True)
    time.sleep(0.2)
    res = sniffer.stop()

    assert len(res) == cnt, f"Expected {cnt} packets. Got {len(res)}"
    for i, pkt in enumerate(res):
        assert pkt.sequenceId == seqid+i, f"Expected sequenceId {seqid}. Got {pkt.sequenceId}"
        assert pkt.domainNumber == domain, f"Expected domain {domain}. Got {pkt.domainNumber}"

# def test_pkt_vlan(tstest):
# TODO: need to implement VLAN support first

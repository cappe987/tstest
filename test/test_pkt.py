import subprocess
import os
import time

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
    time.sleep(1)

    client = subprocess.run([tstest, 'pkt', '-S', '-i', 'veth2', '-c', '1'], capture_output=True, text=True)

    server.terminate()
    out, err = server.communicate(timeout=1)
    rx_ns = parse_rx(out)
    tx_ns = parse_tx(client.stdout)
    abs_diff = abs(rx_ns-tx_ns)
    threshold = 10000
    assert abs_diff < threshold, f"Expected absolute diff < {threshold}. Got {abs_diff}"

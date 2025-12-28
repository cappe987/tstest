import subprocess
import os
import time
from scapy.all import *

import tstest_util

def parse_data(lines):
    fields = {
        'sync_te': lines[3:6],
        'delay_te': lines[7:10],
        'twoway_te': lines[11:14],
        'latency': lines[15:18],
    }
    
    data = {}
    for field, data_lines in fields.items():
        data[field] = {}
        data[field]["mean"] = int(data_lines[0].split()[-1])
        data[field]["max"] = int(data_lines[1].split()[-1])
        data[field]["min"] = int(data_lines[2].split()[-1])
    return data

def test_tc(tstest):
    target = subprocess.run([tstest, 'tc', '-S', '-i', 'veth1', '-i', 'veth2', '-d'], capture_output=True, text=True)
    time.sleep(0.2)
    lines = target.stdout.splitlines()
    data = parse_data(lines)
    # print(data)
    
    # Threshold (ns) is chosen based on reasonable values for SW timestamping.
    # May need adjustment based on environment.
    threshold = 10_000
    for field, stats in data.items():
            mean = stats["mean"]
            maxv = stats["max"]
            minv = stats["min"]
            assert mean < threshold, f"Expected {field} mean < {threshold}. Got {mean}"
            assert maxv < threshold, f"Expected {field} max < {threshold}. Got {maxv}"
            assert minv < threshold, f"Expected {field} min < {threshold}. Got {minv}"


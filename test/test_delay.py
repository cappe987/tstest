import subprocess
import os
import time

def test_delay_single(tstest):
    server = subprocess.Popen([tstest, 'delay', 'server', '-S', '-i', 'veth1'])
    time.sleep(1)

    client = subprocess.run([tstest, 'delay', 'client', '-S', '-i', 'veth2', '-c', '1'], capture_output=True, text=True)
    os.system(f"kill {server.pid}")
    num = int(client.stdout.split()[1])
    if num >= 10000 or num <= 0:
        raise AssertionError(f"Expected delay between 0 and 10000 ns, got {num} ns")

def test_delay_timeout(tstest):
    client = subprocess.run([tstest, 'delay', 'client', '-S', '-i', 'veth2', '-c', '1'], capture_output=True, text=True)

    if "timed out waiting for pdelay_resp" not in client.stderr:
        raise AssertionError("Expected timeout error message in stderr")

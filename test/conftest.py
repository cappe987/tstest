
import os
import pytest

@pytest.fixture(scope="session", autouse=True)
def setup():
    os.system("ip link set lo up")
    os.system("ip link add veth1 type veth peer name veth2")
    os.system("ip link set veth1 up")
    os.system("ip link set veth2 up")
    os.system("ip link add veth3 type veth peer name veth4")
    os.system("ip link set veth3 up")
    os.system("ip link set veth4 up")
    yield
    os.system("killall tstest 2>/dev/null")

@pytest.fixture(scope="session")
def tstest():
    return "./build/tstest"

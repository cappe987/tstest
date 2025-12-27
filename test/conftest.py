
import os
import pytest

@pytest.fixture(scope="session", autouse=True)
def setup():
    os.system("ip link add veth1 type veth peer name veth2")
    os.system("ip link set veth1 up")
    os.system("ip link set veth2 up")

@pytest.fixture(scope="session")
def tstest():
    return "build/tstest"

#!/usr/bin/python3

import socket
import subprocess
import sys
import os

# if no port is passed, a connection to localhost is assumed and a server is spun up to listen
# if we're connecting to a local server, we spin through a list of 100 ports to find whatever's available
def conntest(host, portIn=None):
    cdemo = os.path.join(sys.path[0], "../cdemo/cdemo")
    if not os.path.isfile(cdemo):
        cdemo += ".exe"
    if not os.path.isfile(cdemo):
        print("Test code must be compiled prior to running test.")
        sys.exit(1)

    if portIn is None:
        addr = socket.getaddrinfo(host, 0,0, socket.SOCK_STREAM)
        af,socktype, proto, canonname, sa = addr[0]
        s = socket.socket(af, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for port in range (8000,8100):
            try:
                s.bind((host, port))
                break
            except OSError:
                pass
        s.listen(1)
    else:
        port = portIn
    p = subprocess.Popen([cdemo, host, str(port)])
    if portIn is None:
        conn, addr = s.accept()

        while True:
            try:
                data = conn.recv(1024)
            except socket.timeout:
                print("timeout")
            if not data:
                break
            else:
                conn.send(data)
                conn.send(data)
                conn.send(data)
                conn.close()
                s.close()
                break

    return p.wait()

def setup_module():
    os.environ['LD_LIBRARY_PATH'] = '..'

def test_ack_loop_v4():
    assert conntest("127.0.0.1") == 0, "IPv4 loopback test"

def test_ack_loop_v6():
    assert conntest("::1") == 0, "IPv6 loopback test"

def test_ack_remote_v4():
    assert conntest("ipv4.google.com", 80) == 0, "IPv4 remote test"

def test_ack_remote_v6():
    assert conntest("ipv6.google.com", 80) == 0, "IPv6 remote test"

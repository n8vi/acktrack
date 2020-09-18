#!/usr/bin/python3

import socket
import subprocess
import sys
import os

def looptest(host):

    cdemo = os.path.join(sys.path[0], "../cdemo/cdemo")
    if not os.path.isfile(cdemo):
        cdemo += ".exe"
    if not os.path.isfile(cdemo):
        print("Test code must be compiled prior to running test.")
        sys.exit(1)

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
    p = subprocess.Popen([cdemo, host, str(port)])
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

ret = looptest("127.0.0.1")

if ret:
    sys.exit(ret)

print("")

ret = looptest("::1")

if ret:
    sys.exit(ret)

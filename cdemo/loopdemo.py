#!/usr/bin/python3

import socket
import subprocess
import sys
import os

if len(sys.argv) > 2:
    print("Invalid arguments")
    sys.exit(1)

host = "127.0.0.1"

if len(sys.argv) > 1:
    host = sys.argv[1]

cdemo = os.path.join(sys.path[0], "cdemo")
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
# print("\nlistening")
p = subprocess.Popen([cdemo, host, str(port)])
# print("client running")
conn, addr = s.accept()
# print("connection accepted")

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

sys.exit(p.wait())

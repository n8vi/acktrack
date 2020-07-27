#!/usr/bin/python3

import socket
import subprocess
import sys
import os

cdemo = os.path.join(sys.path[0], "cdemo")
if not os.path.isfile(cdemo):
    cdemo += ".exe"
if not os.path.isfile(cdemo):
    print("Test code must be compiled prior to running test.")
    sys.exit(1)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
for port in range (8000,8100):
    try:
        s.bind(('127.0.0.1', port))
        break
    except OSError:
        pass
s.listen(1)
print("\nlistening")
p = subprocess.Popen([cdemo, '127.0.0.1', str(port)])
print("client running")
conn, addr = s.accept()
print("connection accepted")

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

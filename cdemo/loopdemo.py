#!/usr/bin/python3

import socket
import subprocess
import sys
import os

cdemo = os.path.join(sys.path[0], "cdemo")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 8008))
s.listen(1)
print("\nlistening")
p = subprocess.Popen([cdemo, '127.0.0.1', '8008'])
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

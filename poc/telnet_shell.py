#!/usr/bin/env python3
"""Minimal telnet client: connect, send commands, print output.
Usage: ./telnet_shell.py <host> <port> ["commands"]"""
import socket, time, sys

host, port = sys.argv[1], int(sys.argv[2])
cmds = sys.argv[3] if len(sys.argv) > 3 else "id; uname -a"
s = socket.create_connection((host, port), timeout=6)
s.settimeout(1.0)

def drain(t=1.5):
    data = b""
    t0 = time.time()
    while time.time() - t0 < t:
        try:
            d = s.recv(4096)
            if not d: break
            data += d
        except socket.timeout:
            break
    return data

banner = drain(2.0)
s.sendall(cmds.encode() + b"\n")
time.sleep(1.5)
out = drain(2.5)
s.close()
# strip telnet IAC negotiation bytes
clean = bytearray()
i = 0
raw = banner + out
while i < len(raw):
    if raw[i] == 0xFF and i+2 < len(raw):
        i += 3
    else:
        clean.append(raw[i]); i += 1
print(clean.decode(errors="replace"))

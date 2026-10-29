#!/usr/bin/env bash
# One command to start the demo Manager + console, verify they are actually
# working (not just launched), and print what the Windows agent needs.
#
#   tools/demo_up.sh [options]          start (detaches; logs + pids in the state dir)
#   tools/demo_up.sh --stop             stop both
#   python tools/demo_check.py          re-check a running stack at any time
#
# Options:
#   --bind HOST:PORT     Manager listen address (default 127.0.0.1:8000, i.e.
#                        behind an HTTPS reverse proxy such as the lab's nginx)
#   --tls CERT KEY       Manager terminates TLS itself (see tools/demo_cert.py)
#   --ca FILE            CA that verifies the Manager's cert (default: CERT)
#   --public-url URL     URL the agent uses (default https://<bind>), printed only
#   --state-dir DIR      DB, alerts, tokens, logs, pids (default ./demo-state)
#   --console-dir DIR    panopticon-console checkout (default ../panopticon-console)
#   --console-bind H:P   console address (default 127.0.0.1:8787; widen deliberately)
#   --no-console         Manager only
#   --fresh              start on a new empty DB; the old one is renamed, never deleted
#   --python PATH        interpreter (default $PYTHON, ./.venv/bin/python, python3)
#
# One Manager process only (ADR 003): this refuses to start if its port is taken
# or a previous demo Manager is still running.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIND=127.0.0.1:8000
TLS_CERT=""
TLS_KEY=""
CA=""
PUBLIC_URL=""
STATE_DIR="$ROOT/demo-state"
CONSOLE_DIR="$ROOT/../panopticon-console"
CONSOLE_BIND=127.0.0.1:8787
CONSOLE=1
FRESH=0
ACTION=up
PY="${PYTHON:-}"
MIN_FREE_GB="${MIN_FREE_GB:-3}"

say() { echo "demo_up: $*"; }
die() { echo "demo_up: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --bind) BIND="$2"; shift 2 ;;
    --tls) TLS_CERT="$2"; TLS_KEY="$3"; shift 3 ;;
    --ca) CA="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --console-dir) CONSOLE_DIR="$2"; shift 2 ;;
    --console-bind) CONSOLE_BIND="$2"; shift 2 ;;
    --no-console) CONSOLE=0; shift ;;
    --fresh) FRESH=1; shift ;;
    --stop) ACTION=stop; shift ;;
    --python) PY="$2"; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

mkdir -p "$STATE_DIR"
STATE_DIR=$(cd "$STATE_DIR" && pwd)

pid_alive() { [ -f "$STATE_DIR/$1.pid" ] && kill -0 "$(cat "$STATE_DIR/$1.pid")" 2>/dev/null; }

stop_one() {
  if pid_alive "$1"; then
    pid=$(cat "$STATE_DIR/$1.pid")
    kill "$pid"
    for _ in $(seq 1 40); do
      if ! kill -0 "$pid" 2>/dev/null; then break; fi
      sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then die "$1 (pid $pid) did not stop; check $STATE_DIR/$1.log"; fi
    say "stopped $1 (pid $pid)"
  fi
  rm -f "$STATE_DIR/$1.pid"
}

if [ "$ACTION" = stop ]; then
  stop_one console
  stop_one manager
  exit 0
fi

# -- preflight ----------------------------------------------------------------
if [ -z "$PY" ]; then
  if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"; else PY=python3; fi
fi
command -v "$PY" >/dev/null 2>&1 || die "python not found ($PY); pass --python"
command -v curl >/dev/null 2>&1 || die "curl is required"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "$PY is older than 3.10"

if [ ! -d "$ROOT/vendor/eyedetect/panopticon_detection" ] || [ -z "$(ls -A "$ROOT/vendor/response_engine" 2>/dev/null)" ]; then
  die "vendored engines missing: cd $ROOT && git submodule update --init --recursive"
fi
RULES=$(find "$ROOT/vendor/eyedetect/rules" -name '*.y*ml' | wc -l | tr -d ' ')
[ "$RULES" -gt 0 ] || die "no detection rules under vendor/eyedetect/rules"
(cd "$ROOT" && "$PY" -c 'import fastapi, uvicorn, cryptography, yaml, response_engine
import manager.vendor_path, panopticon_detection') 2>/dev/null \
  || die "dependencies missing: $PY -m pip install -r requirements.txt -r vendor/eyedetect/requirements.txt"
if [ "$CONSOLE" = 1 ] && [ ! -f "$CONSOLE_DIR/app.py" ]; then
  die "console not found at $CONSOLE_DIR (pass --console-dir or --no-console)"
fi
if [ -n "$TLS_CERT" ] && { [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; }; then
  die "--tls files not found: $TLS_CERT $TLS_KEY"
fi
if pid_alive manager; then die "a demo Manager is already running (pid $(cat "$STATE_DIR/manager.pid")); run --stop first"; fi
if pid_alive console; then die "a demo console is already running (pid $(cat "$STATE_DIR/console.pid")); run --stop first"; fi

HOST=${BIND%:*}
PORT=${BIND##*:}
CHOST=${CONSOLE_BIND%:*}
CPORT=${CONSOLE_BIND##*:}
port_free() {
  "$PY" - "$1" "$2" <<'EOF'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((sys.argv[1], int(sys.argv[2])))
except OSError:
    sys.exit(1)
EOF
}
who_listens() {
  { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || ss -ltnp "sport = :$1" 2>/dev/null || true; } | tail -n +2 | head -3
}
port_free "$HOST" "$PORT" || die "port $PORT is in use -- another Manager (e.g. the systemd unit) must be stopped first:
$(who_listens "$PORT")"
if [ "$CONSOLE" = 1 ]; then
  port_free "$CHOST" "$CPORT" || die "console port $CPORT is in use:
$(who_listens "$CPORT")"
fi
FREE_GB=$("$PY" -c 'import shutil, sys; print(int(shutil.disk_usage(sys.argv[1]).free / 1e9))' "$STATE_DIR")
[ "$FREE_GB" -ge "$MIN_FREE_GB" ] || die "only ${FREE_GB} GB free under $STATE_DIR (need ${MIN_FREE_GB}); telemetry is ~40 KB/record and is never pruned"

# -- state: DB, tokens --------------------------------------------------------
umask 077
DB="$STATE_DIR/panopticon.db"
ALERTS="$STATE_DIR/alerts.ndjson"
if [ "$FRESH" = 1 ] && [ -f "$DB" ]; then
  STAMP=$(date +%Y%m%d-%H%M%S)
  for f in "$DB" "$DB-wal" "$DB-shm" "$ALERTS"; do
    if [ -f "$f" ]; then mv "$f" "$f.$STAMP.bak"; fi
  done
  say "previous DB kept as $DB.$STAMP.bak (agents must enroll again: delete the agent identity file)"
fi
new_token() { "$PY" -c 'import secrets; print(secrets.token_urlsafe(32))'; }
for t in bootstrap analyst-bootstrap command; do
  if [ ! -s "$STATE_DIR/$t.token" ]; then new_token >"$STATE_DIR/$t.token"; fi
done

SCHEME=http
if [ -n "$TLS_CERT" ]; then SCHEME=https; fi
LOCAL_HOST=$HOST
if [ "$HOST" = 0.0.0.0 ]; then LOCAL_HOST=127.0.0.1; fi
MANAGER_URL="$SCHEME://$LOCAL_HOST:$PORT"
CA_FILE=""
if [ "$SCHEME" = https ]; then CA_FILE=${CA:-$TLS_CERT}; fi
echo "$MANAGER_URL" >"$STATE_DIR/manager.url"
echo "$DB" >"$STATE_DIR/db.path"
if [ -n "$CA_FILE" ]; then echo "$CA_FILE" >"$STATE_DIR/ca.path"; else rm -f "$STATE_DIR/ca.path"; fi
rm -f "$STATE_DIR/console.url"

# -- Manager ------------------------------------------------------------------
say "starting Manager on $BIND ($RULES rules, db $DB)"
(
  cd "$ROOT"
  export PANOPTICON_DB_PATH="$DB" PANOPTICON_ALERTS_PATH="$ALERTS"
  PANOPTICON_ENROLLMENT_TOKEN=$(cat "$STATE_DIR/bootstrap.token")
  PANOPTICON_ANALYST_ENROLLMENT_TOKEN=$(cat "$STATE_DIR/analyst-bootstrap.token")
  PANOPTICON_COMMAND_TOKEN=$(cat "$STATE_DIR/command.token")
  export PANOPTICON_ENROLLMENT_TOKEN PANOPTICON_ANALYST_ENROLLMENT_TOKEN PANOPTICON_COMMAND_TOKEN
  if [ -n "$TLS_CERT" ]; then
    nohup "$PY" -m uvicorn manager.app:app --host "$HOST" --port "$PORT" \
      --ssl-certfile "$TLS_CERT" --ssl-keyfile "$TLS_KEY" >>"$STATE_DIR/manager.log" 2>&1 &
  else
    nohup "$PY" -m uvicorn manager.app:app --host "$HOST" --port "$PORT" \
      >>"$STATE_DIR/manager.log" 2>&1 &
  fi
  echo $! >"$STATE_DIR/manager.pid"
)

manager_code() {
  if [ -n "$CA_FILE" ]; then
    curl -s -o /dev/null -w '%{http_code}' --cacert "$CA_FILE" "$1" || true
  else
    curl -s -o /dev/null -w '%{http_code}' "$1" || true
  fi
}
for i in $(seq 1 120); do
  if ! pid_alive manager; then tail -n 30 "$STATE_DIR/manager.log" >&2; die "Manager exited during startup (log above)"; fi
  if [ "$(manager_code "$MANAGER_URL/readyz")" = 200 ]; then break; fi
  if [ "$i" = 120 ]; then
    tail -n 30 "$STATE_DIR/manager.log" >&2
    die "Manager not ready after 60s: $(curl -s ${CA_FILE:+--cacert "$CA_FILE"} "$MANAGER_URL/readyz" || true)"
  fi
  sleep 0.5
done
say "Manager ready at $MANAGER_URL (schema migrated, detection worker alive)"

ANALYST_TOKEN=$(curl -sS ${CA_FILE:+--cacert "$CA_FILE"} -X POST "$MANAGER_URL/api/v1/analysts/enroll" \
  -H 'Content-Type: application/json' \
  -H "X-Panopticon-Analyst-Enrollment-Token: $(cat "$STATE_DIR/analyst-bootstrap.token")" \
  -d '{"analyst_id": "demo-analyst", "role": "analyst"}' |
  "$PY" -c 'import json, sys; print(json.load(sys.stdin)["access_token"])') \
  || die "analyst enrollment failed; see $STATE_DIR/manager.log"
echo "$ANALYST_TOKEN" >"$STATE_DIR/analyst.token"

# -- console ------------------------------------------------------------------
CONSOLE_URL=""
if [ "$CONSOLE" = 1 ]; then
  CLOCAL=$CHOST
  if [ "$CHOST" = 0.0.0.0 ]; then CLOCAL=127.0.0.1; fi
  CONSOLE_URL="http://$CLOCAL:$CPORT"
  say "starting console on $CONSOLE_BIND"
  (
    cd "$CONSOLE_DIR"
    export PANOPTICON_MANAGER_TOKEN="$ANALYST_TOKEN"
    if [ -n "$CA_FILE" ]; then export SSL_CERT_FILE="$CA_FILE"; fi
    nohup "$PY" app.py --manager-url "$MANAGER_URL" --host "$CHOST" --port "$CPORT" \
      >>"$STATE_DIR/console.log" 2>&1 &
    echo $! >"$STATE_DIR/console.pid"
  )
  for i in $(seq 1 40); do
    if ! pid_alive console; then tail -n 30 "$STATE_DIR/console.log" >&2; die "console exited during startup (log above)"; fi
    code=$(curl -s -o /dev/null -w '%{http_code}' "$CONSOLE_URL/api/status" || true)
    if [ "$code" = 200 ]; then break; fi
    if [ "$i" = 40 ]; then tail -n 30 "$STATE_DIR/console.log" >&2; die "console /api/status is $code after 20s"; fi
    sleep 0.5
  done
  echo "$CONSOLE_URL" >"$STATE_DIR/console.url"
fi

# -- verify + summary -----------------------------------------------------------
echo
"$PY" "$ROOT/tools/demo_check.py" --state-dir "$STATE_DIR" \
  || die "stack started but the check failed (logs: $STATE_DIR/*.log; stop: $0 --stop --state-dir $STATE_DIR)"

AGENT_URL=${PUBLIC_URL:-https://$LOCAL_HOST:$PORT}
cat <<EOF

Panopticon demo is up.
  Manager   $MANAGER_URL   (agent-facing: $AGENT_URL)
  Console   ${CONSOLE_URL:-disabled}
  Logs      $STATE_DIR/manager.log $STATE_DIR/console.log
  Check     $PY tools/demo_check.py --state-dir $STATE_DIR
  Stop      $0 --stop --state-dir $STATE_DIR

Windows agent (elevated PowerShell in the guest; copy $STATE_DIR/bootstrap.token
to C:\\pano\\bootstrap.token first; a fresh DB needs a fresh identity file + spool):
  officer-agent.exe --source all --manager-url $AGENT_URL --enable-response \`
    --bootstrap-token-path C:\\pano\\bootstrap.token --identity-path C:\\pano\\identity \`
    --keypair-path C:\\pano\\agent.key --spool-directory C:\\pano\\spool-demo
EOF
if [ "$CONSOLE" = 1 ] && [ "$CHOST" = 127.0.0.1 ]; then
  echo "Console is loopback-only; from another machine: ssh -L $CPORT:127.0.0.1:$CPORT <this host>"
fi

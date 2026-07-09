#!/usr/bin/env bash
# =============================================================================
# dev.sh -- LOCAL development launcher for GeneratorPi.
#
#   ****  DEVELOPMENT ONLY -- mock hardware; do not expose publicly  ****
#
# A convenience wrapper around tools/dev.py: start/stop/restart/status/logs a local
# dev server that runs the single-file Flask app with MOCK GPIO (never touches real
# hardware, never actuates the relay). This is a dev aid ONLY -- it is NOT part of the
# shipped app and is NOT in the updater manifest.
#
# Usage:
#   ./dev.sh start   [--port N] [--host H] [--no-auth] [--ssl] [--user U] [--pass P]
#   ./dev.sh stop    [--port N]
#   ./dev.sh restart [--port N] [ ...same flags as start... ]
#   ./dev.sh status  [--port N]
#   ./dev.sh logs    [--port N]
#
# STATE TRACKING: the running dev server is tracked by a pidfile (dev.pid), with its console
# output captured to dev.log -- both in the repo root, right next to this script, and both
# gitignored so neither is ever committed. The tracked pid is RECONCILED against the real
# running harness after launch (see cmd_start), and every lookup is cross-checked against the
# listen socket, so start/stop/restart/status act on exactly the right process and state never
# drifts. --port selects the bind port (and is what stop/status/restart verify against).
# =============================================================================
set -euo pipefail

# --- Resolve the repo root from THIS script's own location (robust to the caller's cwd),
# then cd there so all relative paths (.venv, tools/, dev.pid, dev.log) resolve correctly.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PY=".venv/bin/python"          # the repo venv interpreter
HARNESS="tools/dev.py"         # the Python dev harness this script drives
PID_FILE="dev.pid"             # tracks the running dev server, in the repo root (gitignored)
LOG_FILE="dev.log"             # server console log, in the repo root next to this script (gitignored)

# --- Defaults (overridable via flags). PORT drives the pidfile/logfile names so each
# port is tracked separately; the rest are forwarded verbatim to the harness.
PORT=5000
HOST="0.0.0.0"
NO_AUTH=0
SSL=0
USER_ARG="dev"
PASS_ARG="dev"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Print an error to stderr and exit non-zero.
die() { echo "dev.sh: $*" >&2; exit 1; }

# The unmissable development-only banner. Printed on start/restart, and atop every
# help/usage dump. The middle line is the EXACT project-mandated wording -- it sits on
# its own line, boxed + blank-line-separated, so it stands out and is never reworded.
dev_warning_banner() {
    echo ""
    echo "######################################################################"
    echo "WARNING: FOR DEVELOPMENT USE ONLY. DO NOT RUN ON A LIVE DEVICE."
    echo "######################################################################"
    echo ""
}

# The running dev server is tracked by a single pidfile (dev.pid) with its console output
# in dev.log -- both in the repo root, right next to this script, and both gitignored.
pidfile() { echo "${PID_FILE}"; }
logfile() { echo "${LOG_FILE}"; }

# The scheme depends on whether --ssl was passed.
scheme() { if [ "$SSL" -eq 1 ]; then echo "https"; else echo "http"; fi; }

# The open-me URL for the current flags (embeds creds unless --no-auth).
url() {
    if [ "$NO_AUTH" -eq 1 ]; then
        echo "$(scheme)://${HOST}:${PORT}/"
    else
        echo "$(scheme)://${USER_ARG}:${PASS_ARG}@${HOST}:${PORT}/"
    fi
}

# Is a PID alive? (kill -0 probes without signaling.)
alive() { kill -0 "$1" 2>/dev/null; }

# Robustly find the GENUINE harness pid bound to this PORT (empty if none). pgrep -f matches
# any process whose ARGV merely CONTAINS the pattern -- an unrelated shell that just mentions
# "tools/dev.py --port 5099" (a grep, an editor, this very script's caller) would false-match
# and get mistaken for a dev server. So we validate every candidate against /proc/<pid>/comm:
# the real harness is a PYTHON interpreter, whereas a shell that merely references the string
# has comm=bash/sh and is correctly rejected. Scoped to the exact port so we never adopt a
# server on a different port (belt-and-suspenders: never the live :5000 server unless asked).
harness_pid_on_port() {
    local p comm
    # pgrep pattern requires the harness path AND an exact "--port <PORT>" token (\b end-anchor
    # so "--port 509" can't match "5099"). The harness is always launched with an explicit
    # --port (see cmd_start), so a genuine server always carries it.
    for p in $(pgrep -f "${HARNESS}.*--port ${PORT}\b" 2>/dev/null || true); do
        alive "$p" || continue
        comm="$(cat "/proc/$p/comm" 2>/dev/null || true)"   # process name of the executable
        case "$comm" in
            python*|.venv*) echo "$p"; return 0 ;;          # a real python harness -> accept
            *) : ;;                                         # bash/grep/etc mentioning it -> skip
        esac
    done
    echo ""
}

# Resolve the RUNNING dev pid. Prefer the pidfile (authoritative), then fall back to the
# validated harness matcher above so a lost/stale pidfile still recovers the real process.
# Echoes the pid (empty if none). Cleans up a stale pidfile as a side effect.
running_pid() {
    local pf pid
    pf="$(pidfile)"
    if [ -f "$pf" ]; then
        pid="$(cat "$pf" 2>/dev/null || true)"
        if [ -n "${pid:-}" ] && alive "$pid"; then
            echo "$pid"; return 0
        fi
        rm -f "$pf"                                  # stale -> remove it
    fi
    harness_pid_on_port                              # validated pgrep fallback (may be empty)
}

# Is the TCP port bound/listening? Uses ss; returns 0 if something listens on :PORT.
port_listening() {
    ss -tlnH "( sport = :${PORT} )" 2>/dev/null | grep -q .
}

# Byte-compile the app BEFORE we (re)start it, so a syntax error is caught here -- fail-closed
# -- instead of after the harness launches (or, on restart, after we've already stopped the old
# server, which would leave the dev box with NOTHING running on broken code). The app is now the
# genpi/ package, so compileall byte-compiles EVERY submodule (still fast, and it mirrors the
# eager-import guarantee: if any module won't compile, we refuse to (re)start).
preflight_compile() {
    local out
    if ! out="$("$PY" -m compileall -q genpi 2>&1)"; then
        echo "" >&2
        echo "dev.sh: the genpi package FAILED to compile -- NOT (re)starting:" >&2
        echo "$out" >&2
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Subcommands
# -----------------------------------------------------------------------------

cmd_start() {
    # Preflight: the interpreter + harness must exist (fail-closed with a clear message).
    [ -x "$PY" ] || die "missing venv interpreter: $PY (create it, e.g. python3 -m venv .venv)"
    [ -f "$HARNESS" ] || die "missing harness: $HARNESS"
    preflight_compile          # refuse to launch broken code (auto byte-compile check)

    # Refuse to double-start on the same port (belt: pidfile/pgrep AND the listen socket).
    local existing
    existing="$(running_pid)"
    if [ -n "$existing" ]; then
        die "a dev server is already running on port ${PORT} (pid ${existing}). Use './dev.sh restart --port ${PORT}' or './dev.sh stop --port ${PORT}'."
    fi
    if port_listening; then
        die "port ${PORT} is already in use by another process. Refusing to start (this may be your live server -- NOT touching it)."
    fi

    # Assemble the flags forwarded to the harness.
    local args=(--host "$HOST" --port "$PORT" --user "$USER_ARG" --pass "$PASS_ARG")
    [ "$NO_AUTH" -eq 1 ] && args+=(--no-auth)
    [ "$SSL" -eq 1 ] && args+=(--ssl)

    # Loud dev banner. The mandated warning first, then the run-specific detail line.
    dev_warning_banner
    echo "======================================================================"
    echo "GeneratorPi DEV server -- DEVELOPMENT ONLY (mock hardware; do not expose publicly)"
    echo "  port ${PORT}  host ${HOST}  auth $([ "$NO_AUTH" -eq 1 ] && echo disabled || echo "${USER_ARG}/${PASS_ARG}")  ssl $([ "$SSL" -eq 1 ] && echo on || echo off)"
    echo "======================================================================"

    # Launch detached (setsid + nohup) so it survives this shell; redirect all output to
    # the logfile. $! is the backgrounded job's pid, but `setsid` may fork (making $! a
    # short-lived shim whose child is the REAL python). We reconcile below so the pidfile
    # always holds the true harness pid -- robust process tracking, not a best-guess.
    local lf pf
    lf="$(logfile)"; pf="$(pidfile)"
    setsid nohup "$PY" "$HARNESS" "${args[@]}" >"$lf" 2>&1 < /dev/null &
    local pid=$!
    echo "$pid" > "$pf"            # provisional: overwritten with the reconciled pid below

    # Brief settle so it can fork/exec + bind (cheroot takes a moment), then reconcile the
    # tracked pid against the ACTUAL running harness. The validated matcher (harness path +
    # exact port + python /proc/comm) is authoritative, so prefer it; fall back to $! only if
    # the matcher can't see the process yet.
    sleep 1
    local real_pid
    real_pid="$(harness_pid_on_port)"
    if [ -n "$real_pid" ] && alive "$real_pid"; then
        pid="$real_pid"
        echo "$pid" > "$pf"        # authoritative: the real python pid now owns the pidfile
    elif ! alive "$pid"; then
        # Neither a matching harness NOR the launch shim is alive -> it died on startup.
        echo "-- startup FAILED; last log lines:" >&2
        tail -n 20 "$lf" >&2 || true
        rm -f "$pf"
        die "dev server exited immediately (see $lf)"
    fi
    echo "started (pid ${pid})"
    echo "  Open me -> $(url)"
    echo "  Logs    -> ./dev.sh logs   (file: ${lf})"
}

cmd_stop() {
    local pid pf
    pf="$(pidfile)"
    pid="$(running_pid)"
    if [ -z "$pid" ]; then
        echo "no dev server running on port ${PORT}"
        rm -f "$pf"
        return 0
    fi
    echo "stopping dev server on port ${PORT} (pid ${pid})..."
    # SIGTERM first (graceful), then escalate to SIGKILL if it won't die.
    kill -TERM "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 20); do          # up to ~5s for a clean shutdown
        alive "$pid" || break
        sleep 0.25
    done
    if alive "$pid"; then
        echo "  still alive -> SIGKILL"
        kill -KILL "$pid" 2>/dev/null || true
        sleep 0.5
    fi
    rm -f "$pf"
    # Confirm the port is actually freed (belt: process gone AND socket released).
    for i in $(seq 1 12); do
        port_listening || break
        sleep 0.25
    done
    if port_listening; then
        echo "  WARNING: port ${PORT} still shows a listener after stop" >&2
    else
        echo "stopped; port ${PORT} is free"
    fi
}

cmd_restart() {
    # Validate the code compiles BEFORE we stop the running server, so a syntax error never
    # leaves the dev box down on broken code (cmd_start re-checks, but this is the safe gate).
    preflight_compile
    # The "find the existing process and kill it, then relaunch" flow.
    cmd_stop
    cmd_start
}

cmd_status() {
    local pid
    pid="$(running_pid)"
    if [ -n "$pid" ]; then
        echo "RUNNING  port ${PORT}  pid ${pid}"
        echo "  URL  -> $(url)"
        echo "  Log  -> $(logfile)"
    else
        echo "STOPPED  port ${PORT}  (no dev server tracked/running)"
    fi
    # Independent cross-check of the listen socket.
    if port_listening; then
        echo "  socket: something IS listening on :${PORT}"
    else
        echo "  socket: nothing listening on :${PORT}"
    fi
}

cmd_logs() {
    local lf
    lf="$(logfile)"
    [ -f "$lf" ] || die "no dev log yet: $lf (start a dev server first)"
    echo "-- tailing ${lf} (Ctrl-C to stop) --"
    tail -n 40 -f "$lf"
}

# -----------------------------------------------------------------------------
# Arg parsing: first positional is the subcommand; the rest are flags.
# -----------------------------------------------------------------------------
# The help/usage body (subcommands, every flag + default, examples). Kept separate from
# usage() so it can be routed to stdout (help path) or stderr (arg-error path) verbatim.
usage_text() {
    cat <<EOF
dev.sh -- GeneratorPi LOCAL dev launcher (mock hardware; DEV ONLY)

A convenience wrapper around tools/dev.py that runs the single-file Flask app with
MOCK GPIO on THIS machine (never touches real hardware, never actuates the relay). It
is NOT part of the shipped app and is NOT in the updater manifest. Do not expose it
publicly, and NEVER run it on a live device.

Subcommands:
  start    [flags]     start a dev server (flags below)
  stop     [--port N]  stop the dev server tracked on that port
  restart  [flags]     stop, then start again with the given flags
  status   [--port N]  show whether a dev server is running on that port
  logs                 tail the dev server console log (dev.log)

Flags (start / restart):
  --port N     listen port                              (default 5000)
  --host H     bind address (0.0.0.0 = reachable on LAN/Tailscale)  (default 0.0.0.0)
  --no-auth    disable auth entirely for a purely local UI test (DEV ONLY)
  --ssl        serve HTTPS via the app's self-signed cert (default: plain HTTP)
  --user U     dev Basic-auth username                  (default dev)
  --pass P     dev Basic-auth password                  (default dev)
  -h, --help   show this help and exit

Examples:
  ./dev.sh start                        # dev/dev Basic auth on http://0.0.0.0:5000/
  ./dev.sh start --port 8080 --no-auth  # no auth at all, on port 8080
  ./dev.sh restart --port 5000 --ssl    # relaunch over the self-signed HTTPS cert
  ./dev.sh stop --port 8080             # stop that port's server, free the socket
EOF
}

# Print the dev warning + help. code 0 => help was requested (stdout); anything else =>
# an arg error (stderr). Either way the mandated dev-only warning leads the output.
usage() {
    local code="${1:-2}"
    if [ "$code" -eq 0 ]; then
        dev_warning_banner
        usage_text
    else
        dev_warning_banner >&2
        usage_text >&2
    fi
    exit "$code"
}

# No arguments at all => show help and exit 0 (help is not an error).
[ $# -ge 1 ] || usage 0
SUBCMD="$1"; shift || true

# A bare help request as the subcommand (help | -h | --help) => help, exit 0.
case "$SUBCMD" in
    -h|--help|help) usage 0 ;;
esac

# Parse flags (shared across subcommands; ignored ones are harmless per subcommand).
while [ $# -gt 0 ]; do
    case "$1" in
        --port)    PORT="${2:?--port needs a value}"; shift 2 ;;
        --host)    HOST="${2:?--host needs a value}"; shift 2 ;;
        --user)    USER_ARG="${2:?--user needs a value}"; shift 2 ;;
        --pass)    PASS_ARG="${2:?--pass needs a value}"; shift 2 ;;
        --no-auth) NO_AUTH=1; shift ;;
        --ssl)     SSL=1; shift ;;
        -h|--help) usage 0 ;;
        *) die "unknown flag: $1 (try ./dev.sh --help)" ;;
    esac
done

# Validate the port is a plausible integer (fail-closed on garbage).
case "$PORT" in
    ''|*[!0-9]*) die "invalid --port: '${PORT}' (must be a number)" ;;
esac

case "$SUBCMD" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_restart ;;
    status)  cmd_status ;;
    logs)    cmd_logs ;;
    -h|--help) usage 0 ;;
    *) die "unknown subcommand: '${SUBCMD}' (try ./dev.sh --help)" ;;
esac

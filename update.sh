#!/bin/bash
# =============================================================================
# update.sh -- Robust, self-healing MANUAL updater for GeneratorPi.
#
# Brings the on-device checkout to EXACTLY match the released code on GitHub
# (origin/main), re-runs the FULL setup so systemd/dependencies/permissions are
# re-asserted, verifies the app comes back healthy, and AUTO-ROLLS-BACK to the
# previous version if anything goes wrong. It is the manual counterpart to the
# in-app self-updater -- the path for releases the web updater deliberately
# refuses (systemd entrypoint / package-layout changes; see the manifest's
# incompatible_versions gate).
#
# Usage (on the device):
#     ~/generatorpi/update.sh
# Typically over SSH:
#     ssh pi@generatorpi "~/generatorpi/update.sh"
# (A non-interactive run needs passwordless sudo -- standard for the 'pi' user on
#  Raspberry Pi OS. An interactive SSH session works too, and additionally lets
#  the updater run the FULL interactive setup to heal missing credentials.)
#
# SAFETY MODEL (belt-and-suspenders):
#   * `git fetch` happens BEFORE the service is stopped -- a network failure
#     leaves the device completely untouched and still running.
#   * A verified, timestamped backup tarball is written to backups/ before any
#     change (a git-independent restore point; secrets are excluded).
#   * `git reset --hard origin/main` forces an EXACT match to the release. Device
#     SECRETS + STATE (generator_control.env, events.db, TLS certs, logs) are
#     gitignored / untracked, so `reset --hard` NEVER touches them.
#   * The full setup is re-run every update (deps, systemd unit, scoped sudoers,
#     compileall), so config/layout changes in the new release are applied and
#     drift/misconfig is caught -- not assumed away.
#   * On ANY failure (stop, reset, setup, or the post-update HEALTH check) it
#     rolls the checkout back to the previous commit, re-runs setup, and
#     re-checks health. The service is ALWAYS left running; the backup tarball
#     remains for manual recovery.
#
# The entire body is wrapped in a { } block so bash reads it fully into memory
# before executing -- so a `git reset` that overwrites THIS file mid-run is safe.
# =============================================================================
{
# No `set -e`: this script does its OWN error handling (each critical step is
# checked and routed to a rollback), which is far more predictable than -e for a
# recovery-oriented script. -u catches typos in variable names; pipefail makes a
# failing stage in a pipeline visible.
set -uo pipefail

# ---- constants + tiny helpers ------------------------------------------------
SERVICE="generator_control.service"
KEEP_BACKUPS=10                                    # timestamped pre-update tarballs to retain
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}" || { printf '\n!!! ERROR: cannot cd to %s\n' "${SCRIPT_DIR}" >&2; exit 1; }
ENV_FILE="${SCRIPT_DIR}/generator_control.env"
BACKUP_DIR="${SCRIPT_DIR}/backups"

log()  { printf '\n>>> %s\n' "$*"; }
warn() { printf '\n!!! WARNING: %s\n' "$*" >&2; }
die()  { printf '\n!!! ERROR: %s\n' "$*" >&2; exit 1; }   # fatal BEFORE any mutation (no rollback needed)

# sudo shim: run directly as root, else require sudo (passwordless expected on the Pi).
if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
else die "root privileges (or sudo) are required to manage the ${SERVICE} service"; fi

# Rollback bookkeeping.
PREV_SHA=""          # commit we can roll back to
STOPPED=false        # have we stopped the service?
MUTATED=false        # have we changed the checkout (reset --hard)?
BACKUP=""            # path to the pre-update backup tarball

# Final safety net: never leave the service stopped on an abnormal exit (e.g. a
# SIGINT mid-run that the explicit handlers didn't catch). Idempotent -- starting
# an already-running service is a no-op.
_on_exit() {
  local rc=$?
  if [ "${rc}" -ne 0 ] && [ "${STOPPED}" = true ]; then
    warn "exiting abnormally -- ensuring ${SERVICE} is running"
    ${SUDO} systemctl start "${SERVICE}" >/dev/null 2>&1 || true
  fi
}
trap _on_exit EXIT

# ---- health probe: is the local app answering? ------------------------------
# Reads the configured scheme/port from the env file, falling back to the
# documented default (https on 9400). ANY HTTP response -- INCLUDING a 401 --
# proves the server is UP; only a refused/failed connection is "down".
# TLS verification is intentionally DISABLED (-k / CERT_NONE): this is a LIVENESS
# probe to 127.0.0.1 (loopback) against the app's OWN self-signed cert -- there is
# no network path to MITM, and no data is read from the response (only "did it
# answer"). This matches the in-app updater's own health bootstrap. Do NOT reuse
# this pattern for any client that leaves the host or trusts the response body.
env_get() {  # $1=key  $2=default  -> last matching "KEY=value" from the env file, else default
  local v=""
  [ -f "${ENV_FILE}" ] && v="$(grep -E "^$1=" "${ENV_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '[:space:]')"
  printf '%s' "${v:-$2}"
}
health_url() {
  local port scheme ssl
  port="$(env_get PORT 9400)"
  ssl="$(env_get SSL_ENABLED 1)"
  case "${ssl}" in 0|false|False|no|No|off|Off) scheme=http ;; *) scheme=https ;; esac
  printf '%s://127.0.0.1:%s/' "${scheme}" "${port}"
}
health_ok() {  # 0 = the app responded (up), non-zero = no response (down)
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    # No --fail: a 401/403 is a valid "server is up" response, not a failure.
    curl -sk -o /dev/null --max-time 5 "${url}" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "${url}" <<'PY' >/dev/null 2>&1
import sys, ssl, urllib.request, urllib.error
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen(sys.argv[1], timeout=5, context=ctx)
except urllib.error.HTTPError:
    pass          # a 401/403 still proves the server is UP
except Exception:
    sys.exit(1)
sys.exit(0)
PY
  else
    return 0      # no probe tool available -> can't check; treat as ok (warned in preflight)
  fi
}
wait_healthy() {  # poll for up to ~30s
  local url
  url="$(health_url)"
  for _ in $(seq 1 30); do
    health_ok "${url}" && return 0
    sleep 1
  done
  return 1
}

# ---- run the full setup (self-healing) --------------------------------------
# Interactive TTY -> `setup.sh install`: re-validates deps/unit/sudoers/compile
# AND heals credentials if the env is missing/empty (prompting ONLY then).
# Otherwise -> `setup.sh reinstall`: identical but never prompts. Either way the
# ENTIRE setup is re-asserted on every update, catching config/layout drift from
# the new release. Pass "reinstall" to force the non-interactive path (rollback).
run_setup() {
  if [ "${1:-auto}" = "reinstall" ]; then
    ./setup.sh reinstall
  elif [ -t 0 ] && [ -t 1 ]; then
    ./setup.sh install
  else
    ./setup.sh reinstall
  fi
}

# ---- rollback: restore the previous version, re-setup, re-check --------------
do_rollback() {
  warn "Rolling back to the previous version..."
  if [ "${MUTATED}" = true ] && [ -n "${PREV_SHA}" ] \
       && git rev-parse -q --verify "${PREV_SHA}^{commit}" >/dev/null 2>&1; then
    git reset --hard "${PREV_SHA}" >/dev/null 2>&1 || warn "git rollback to ${PREV_SHA} did not fully succeed"
    run_setup reinstall || warn "setup during rollback reported an error"
  else
    ${SUDO} systemctl start "${SERVICE}" >/dev/null 2>&1 || true
  fi
  if wait_healthy; then
    STOPPED=false
    log "Rolled back. Service is healthy on the previous version."
  else
    ${SUDO} systemctl start "${SERVICE}" >/dev/null 2>&1 || true
    warn "Rollback did NOT become healthy. A full pre-update backup is at:"
    warn "    ${BACKUP:-<none>}"
    warn "Inspect: systemctl status ${SERVICE}   and   journalctl -u ${SERVICE} -n 50"
  fi
}
fail() { warn "$1"; do_rollback; exit 1; }   # fatal AFTER mutation: roll back, then exit

# ---- Preflight (NOTHING is mutated here; the service stays up) ---------------
log "GeneratorPi update -- preflight checks"
command -v git       >/dev/null 2>&1 || die "git is required but not installed"
command -v tar       >/dev/null 2>&1 || die "tar is required but not installed"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found -- this updater targets a systemd host (Raspberry Pi OS)"
[ -f "${SCRIPT_DIR}/VERSION" ] && [ -d "${SCRIPT_DIR}/genpi" ] \
  || die "run this from the GeneratorPi repo -- VERSION + genpi/ not found in ${SCRIPT_DIR}"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || die "${SCRIPT_DIR} is not a git checkout -- reinstall via a fresh 'git clone' (see README)"
command -v curl >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1 \
  || warn "neither curl nor python3 found -- the post-update health check will be skipped"

# Fetch the release BEFORE stopping anything: a network failure must not take the device down.
log "Fetching latest from origin (service still running)..."
git fetch --prune origin >/dev/null 2>&1 \
  || die "git fetch failed (network?). Nothing changed; the service is untouched."

PREV_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
TARGET_SHA="$(git rev-parse origin/main 2>/dev/null || true)"
[ -n "${TARGET_SHA}" ] || die "could not resolve origin/main after fetch"
OLD_VER="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo '?')"

# Setup-completeness gate: an update must land on a properly-configured install. If credentials
# are missing we can only fix that INTERACTIVELY -- so bail EARLY (service untouched) on a
# non-interactive run, or let the interactive setup.sh install heal it during setup below.
if [ -f "${ENV_FILE}" ] && grep -q "^USER_" "${ENV_FILE}" 2>/dev/null; then
  :
elif [ -t 0 ] && [ -t 1 ]; then
  warn "No credentials configured yet -- the interactive setup will prompt you to add them."
else
  die "No credentials configured (no USER_ line in ${ENV_FILE##*/}). Run './setup.sh install' interactively on the device first, then re-run the update."
fi

[ "${PREV_SHA}" = "${TARGET_SHA}" ] \
  && log "Already at the latest commit (v${OLD_VER}) -- re-asserting setup + health anyway."

# ---- Backup (still non-destructive; a git-independent restore point) ---------
# A full snapshot of the current install EXCLUDING secrets (env/TLS keys), local-only
# files (CLAUDE.md/scratchpads/dev.*), and regenerables (venv/caches/logs/backups/staging).
# events.db (history + persisted run/fuel state) IS included as a data-loss safety net.
mkdir -p "${BACKUP_DIR}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="${BACKUP_DIR}/pre-update-${TS}-v${OLD_VER}.tar.gz"
TAR_EXCLUDES=(
  --exclude='./.git' --exclude='./.venv' --exclude='./backups' --exclude='./.update_staging'
  --exclude='./.pytest_cache' --exclude='./.playwright-mcp' --exclude='./.coverage'
  --exclude='__pycache__' --exclude='*.pyc'
  --exclude='./generator_control.env' --exclude='./.env' --exclude='./.env_tmp_*'
  --exclude='*.pem' --exclude='./generator_control.log*'
  --exclude='./CLAUDE.md' --exclude='./scratchpads' --exclude='./dev.log' --exclude='./dev.pid'
  --exclude='*-recording*.json'
)
log "Backing up current install -> ${BACKUP##*/}"
tar -C "${SCRIPT_DIR}" "${TAR_EXCLUDES[@]}" -czf "${BACKUP}" . >/dev/null 2>&1 \
  || die "backup failed -- aborting before any change (service untouched)."
tar -tzf "${BACKUP}" >/dev/null 2>&1 \
  || die "backup archive failed its integrity check -- aborting (service untouched)."
# Prune to the newest KEEP_BACKUPS pre-update tarballs (best-effort; never fatal).
ls -1t "${BACKUP_DIR}"/pre-update-*.tar.gz 2>/dev/null | tail -n +"$((KEEP_BACKUPS + 1))" \
  | while IFS= read -r old; do rm -f "${old}"; done

# ---- Apply (DESTRUCTIVE from here; any failure triggers do_rollback) ---------
log "Stopping ${SERVICE}..."
${SUDO} systemctl stop "${SERVICE}" || fail "could not stop the service"
STOPPED=true

log "Resetting checkout to origin/main (exact match; secrets + state untouched)..."
git reset --hard origin/main >/dev/null 2>&1 || fail "git reset --hard failed"
MUTATED=true
# Sanity: no TRACKED file may differ from the release after the reset.
[ -z "$(git status --porcelain --untracked-files=no)" ] \
  || fail "working tree still differs from origin/main after reset"

NEW_VER="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo '?')"
log "Now at v${NEW_VER} (was v${OLD_VER}). Running full setup..."
run_setup || fail "setup failed after the update"

log "Verifying the app came back healthy..."
if wait_healthy; then
  STOPPED=false
  log "Update complete: v${OLD_VER} -> v${NEW_VER}. Service is healthy."
  log "Backup retained: ${BACKUP##*/} (newest ${KEEP_BACKUPS} kept)."
else
  fail "the app did not become healthy after the update"
fi

exit 0
}

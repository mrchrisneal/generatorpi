#!/bin/bash
# =============================================================================
# setup.sh -- install / reinstall / uninstall / status for the GeneratorPi
#             systemd service (generator_control).
#
# WHAT: Provisions the app on a Raspberry Pi Zero 2 W (Raspberry Pi OS): copies
#       the env file, installs the apt-only Python dependencies, pre-compiles the
#       genpi package, writes the systemd unit + a SCOPED passwordless sudoers
#       rule for the in-app self-updater, then enables + (re)starts the service
#       and health-checks it. On non-target hosts (no systemd / no apt / no sudo)
#       it degrades LOUDLY -- every skipped step prints exactly what was skipped,
#       why, and how to do it by hand -- and fails CLOSED where a service really
#       cannot be installed, so a broken install can never masquerade as success.
#
# WHY (contracts other code depends on -- do not weaken):
#   * `reinstall` MUST be fully non-interactive (update.sh + the in-app updater
#     call it over SSH): it never prompts, never hangs, exits 0 on success and
#     NON-ZERO on any real failure so update.sh's ERR trap can roll back.
#   * The unit MUST keep `KillMode=process` -- the updater's detached /tmp
#     bootstrap survives the service restart ONLY because of it (see the inline
#     comment on that line, and genpi/updater.py:_write_bootstrap_script).
#   * The sudoers rule MUST stay scoped to EXACTLY the 3 systemctl verbs
#     (restart/start/stop) on THIS one unit for the current user -- never broaden.
#   * Deps come from apt (the system Python has NO pip). compileall is the
#     install-time syntax gate. We NEVER `import genpi` here -- importing the
#     package constructs the GPIO relay object, and the relay must ONLY ever be
#     touched by the running service, never by an install script.
#
# Usage:
#   ./setup.sh install      - Interactive install + enable on boot
#   ./setup.sh reinstall    - Non-interactive install (used by update.sh / updater)
#   ./setup.sh uninstall    - Stop, disable, and remove the service + sudoers rule
#   ./setup.sh status       - Show service status and configuration
# =============================================================================

# Strict mode: -e abort on any unchecked error, -u treat unset vars as errors
# (catches typos), -o pipefail so a failure anywhere in a pipeline is not masked
# by a later success. Every genuinely-allowed-to-fail probe below is guarded with
# `if`/`|| true`, so strict mode only ever trips on an UNEXPECTED failure.
set -euo pipefail

# ----------------------------- constants -------------------------------------
SERVICE_NAME="generator_control"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SUDOERS_FILE="/etc/sudoers.d/generatorpi-updater"
# Resolve the directory THIS script lives in (the repo root on a real install),
# following the invocation path. `pwd` after cd gives an absolute, symlink-free
# path so WorkingDirectory in the unit is always correct even if invoked oddly.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CURRENT_USER="$(whoami)"
ENV_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.env"
ENV_EXAMPLE="${SCRIPT_DIR}/${SERVICE_NAME}.env.example"
BACKUP_DIR="${SCRIPT_DIR}/backups"          # timestamped unit-file backups land here (gitignored)

# Temp files we create during install (unit + sudoers staging). Cleaned on exit
# via the trap below so a failed run never leaves scratch files around.
_TMP_FILES=()
# shellcheck disable=SC2317  # invoked indirectly by the EXIT trap
_cleanup() { local f; for f in "${_TMP_FILES[@]:-}"; do [ -n "${f}" ] && rm -f "${f}"; done; }
trap _cleanup EXIT

# ----------------------------- output helpers --------------------------------
# Uniform, greppable prefixes. WARN/ERROR go to stderr so callers capturing
# stdout still see diagnostics; everything is plain text (no color codes) so it
# reads cleanly in journald and over SSH.
say()  { printf '%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
err()  { printf 'ERROR: %s\n'   "$*" >&2; }
# die: print an error and exit non-zero (fail-closed). Used for conditions that
# make a real install impossible -- reinstall relies on this to signal update.sh.
die()  { err "$*"; exit 1; }

# have: is a command available on PATH? The single portability primitive.
have() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------- privilege model -------------------------------
# Privileged steps (writing /etc, apt, systemctl) need root. Prefer running as
# root directly; otherwise use sudo. If NEITHER is available we cannot install
# the service -- record that and fail closed when a privileged step is reached.
SUDO=""
HAVE_PRIV=true
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""                       # already root: run privileged commands directly
elif have sudo; then
    SUDO="sudo"                   # escalate per-command via sudo
else
    HAVE_PRIV=false               # no root, no sudo -> privileged steps impossible
fi
# priv: run a command with privilege. Intentionally leaves $SUDO UNQUOTED so an
# empty value (already root) expands to nothing rather than an empty argv[0].
# Fails closed if we somehow reach it without any privilege path.
priv() {
    if [ "${HAVE_PRIV}" != "true" ]; then
        die "root privileges required for: $* -- run as root or install sudo"
    fi
    $SUDO "$@"
}

# ----------------------------- systemd unit ----------------------------------
# Generate the unit pointing at the resolved dir + current user. Emitted to
# stdout so callers can pipe it (validate a temp copy, then tee into /etc).
generate_service_file() {
    cat <<UNIT
[Unit]
Description=Powermate PM9400E Generator Control (Flask + GPIOZero)
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/python3 -m genpi
Restart=always
RestartSec=10
# KillMode=process: on stop/restart, kill ONLY the main app process, not the whole cgroup.
# This is what lets the in-app self-updater's detached /tmp bootstrap survive the restart it
# triggers (default control-group killing would SIGTERM the bootstrap mid-swap and brick the
# service). Do NOT change without revisiting the updater's restart/rollback flow.
KillMode=process
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
}

# ----------------------------- preflight -------------------------------------
# Confirm we are actually sitting in a GeneratorPi checkout (VERSION file +
# genpi/ package). Running from the wrong directory would otherwise generate a
# unit with a bogus WorkingDirectory and "install" nothing useful -- fail early
# with an unmistakable message. Belt-and-suspenders per house rules.
check_repo_root() {
    local missing=()
    [ -f "${SCRIPT_DIR}/VERSION" ] || missing+=("VERSION")
    [ -d "${SCRIPT_DIR}/genpi" ]   || missing+=("genpi/")
    if [ "${#missing[@]}" -gt 0 ]; then
        die "not a GeneratorPi checkout (missing: ${missing[*]} in ${SCRIPT_DIR}). Run setup.sh from the repo root."
    fi
}

# Validate python3 exists and is a sane version. python3 is non-negotiable: it
# runs compileall (the syntax gate) and is the service's interpreter. A too-old
# interpreter is a loud WARNING (the app targets modern Raspberry Pi OS) but not
# fatal -- the operator may know better than us on an odd host.
check_python() {
    have python3 || die "python3 not found on PATH -- install it (apt install python3) before running setup."
    if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        info "[ok]      python3 $(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo '?')"
    else
        warn "python3 is older than 3.9 (found $(python3 -V 2>&1)). GeneratorPi targets modern Raspberry Pi OS; continuing, but the app may not run correctly."
    fi
}

# Report on the tools this install (and the sibling update.sh / self-updater)
# rely on, so a degraded environment is diagnosed up front rather than mid-run.
# Nothing here aborts on its own -- the individual steps decide fail-vs-skip --
# but every absence is stated plainly with the manual remedy.
preflight_report() {
    say ""
    say "Preflight (environment check):"
    if [ "${HAVE_PRIV}" = "true" ]; then
        info "[ok]      privilege via $([ -z "${SUDO}" ] && echo 'root' || echo 'sudo')"
    else
        warn "no root and no 'sudo' -- cannot write /etc, run apt, or manage systemd. Run as root or install sudo."
    fi
    if have systemctl; then info "[ok]      systemctl"; else warn "systemctl not found -- not a systemd host; the service cannot be installed here (run the app directly: python3 -m genpi)."; fi
    if have apt-get;   then info "[ok]      apt-get";   else warn "apt-get not found -- not a Debian/Raspberry Pi OS host; Python deps must be installed by hand (see the apt package list printed during the dependency step)."; fi
    if have openssl;   then info "[ok]      openssl";   else warn "openssl not found -- fine for setup (the app self-provisions its TLS cert via Python 'cryptography'), noted only for completeness."; fi
    if have git;       then info "[ok]      git";       else warn "git not found -- setup.sh does not need it, but update.sh (git pull) does; install git if you use the pull-based updater."; fi
}

# ----------------------------- dependencies ----------------------------------
# `apt-get update` is expensive on the flaky, single-core Pi, so run it AT MOST
# ONCE and only when a dependency actually needs installing (the common reinstall
# path -- all deps already present -- pays nothing). Non-fatal: a stale index may
# still install fine, so a failed refresh only warns.
_APT_UPDATED=false
ensure_apt_updated() {
    [ "${_APT_UPDATED}" = "true" ] && return 0
    _APT_UPDATED=true
    info "Refreshing apt package index (once)..."
    if ! priv apt-get update >/dev/null 2>&1; then
        warn "apt-get update failed (network/index issue) -- attempting installs against the existing index."
    fi
}

# Track whether any REQUIRED dependency could not be satisfied. A required-dep
# failure must ultimately fail the install (the app won't run without flask etc.),
# so we accumulate here and gate on it after the loop.
_REQUIRED_MISSING=0

# check_dep <import_name> <apt_package> [optional]
# 1) already importable -> ok. 2) apt available -> install + re-check. 3) missing:
#    optional -> informational skip; required -> loud error + increment the gate.
# We test importability with a bare `python3 -c import`, which does NOT import
# genpi and so never touches the relay -- it only probes third-party modules.
check_dep() {
    local mod="$1" pkg="$2" kind="${3:-required}"
    if python3 -c "import ${mod}" 2>/dev/null; then
        info "[ok]      ${mod}"
        return 0
    fi
    # Not importable. Try apt IF we have both apt and privilege.
    if have apt-get && [ "${HAVE_PRIV}" = "true" ]; then
        ensure_apt_updated
        if priv apt-get install -y "${pkg}" >/dev/null 2>&1 && python3 -c "import ${mod}" 2>/dev/null; then
            info "[ok]      ${mod} (installed ${pkg})"
            return 0
        fi
    fi
    # Could not satisfy it. Optional -> skip with guidance; required -> gate it.
    if [ "${kind}" = "optional" ]; then
        info "[skip]    ${mod} is OPTIONAL and unavailable -- continuing (to add later: sudo apt install ${pkg})"
        return 0
    fi
    if have apt-get && [ "${HAVE_PRIV}" = "true" ]; then
        err "REQUIRED dependency '${mod}' could not be installed -- try manually: sudo apt install ${pkg}"
    else
        err "REQUIRED dependency '${mod}' is missing and cannot be auto-installed here (no apt/privilege) -- install it manually: apt package '${pkg}'"
    fi
    _REQUIRED_MISSING=$((_REQUIRED_MISSING + 1))
    return 0   # keep going so the operator sees the FULL list of what's missing
}

install_dependencies() {
    say ""
    say "Checking Python dependencies (installed via apt -- the system Python has no pip)..."
    if ! have apt-get || [ "${HAVE_PRIV}" != "true" ]; then
        warn "cannot auto-install deps (need apt-get + root/sudo). Required apt packages: python3-flask python3-gpiozero python3-lgpio python3-cryptography python3-cheroot. Optional (Web Push): python3-py-vapid python3-http-ece python3-requests. Verifying what is already importable..."
    fi
    # ---- Required: the app will not run without these ----
    check_dep flask         python3-flask
    check_dep gpiozero      python3-gpiozero
    check_dep lgpio         python3-lgpio
    check_dep cryptography  python3-cryptography
    check_dep cheroot       python3-cheroot                     # HTTP keep-alive server (big CPU win vs. werkzeug)
    # ---- Optional: Web Push. There is NO apt 'pywebpush' on Raspberry Pi OS, so the app uses its
    #      apt-available building blocks directly: py-vapid signs the VAPID JWT, http-ece encrypts the
    #      aes128gcm payload, requests makes the HTTPS POST (cryptography, required above, underpins them).
    check_dep py_vapid      python3-py-vapid      optional      # Web Push: VAPID JWT signing
    check_dep http_ece      python3-http-ece      optional      # Web Push: aes128gcm payload encryption
    check_dep requests      python3-requests      optional      # Web Push: HTTPS POST to the push service
    # Gate: a missing REQUIRED dep is fatal -- the service would crash-loop on boot, so fail closed
    # here (reinstall returns non-zero, letting update.sh roll back) rather than install a dead unit.
    if [ "${_REQUIRED_MISSING}" -gt 0 ]; then
        die "${_REQUIRED_MISSING} required Python dependency(ies) unavailable (see above) -- the service cannot run. Install them, then re-run setup."
    fi
}

# ----------------------------- compile gate ----------------------------------
# Pre-compile the genpi package: builds the eager __pycache__ (so first boot pays
# no per-module compile cost on the single core) AND acts as a SYNTAX gate -- a
# syntax error in any shipped module is caught NOW, at install, not at service
# start. Deliberately NOT `import genpi` (that would build the GPIO relay object);
# compileall only parses/byte-compiles, it never executes module top-level code.
# Non-fatal: on failure the app just compiles lazily on first import (still correct).
compile_package() {
    say ""
    say "Pre-compiling the genpi package (eager .pyc cache + syntax gate)..."
    if python3 -m compileall -q "${SCRIPT_DIR}/genpi"; then
        info "[ok]      genpi package compiled"
    else
        warn "compileall reported an issue -- modules will compile on first import (check for a syntax error in genpi/)."
    fi
}

# ----------------------------- env file --------------------------------------
# Ensure the (gitignored, owner-only) env file exists and holds credentials.
# Interactive install opens the editor; non-interactive prints a NOTE. Missing
# example is fatal (we can't fabricate credentials). `interactive` is forced off
# when stdin is not a TTY so we can NEVER hang waiting on a prompt/editor.
setup_env_file() {
    local interactive="$1"
    # Guard: interactivity requires a real terminal. If not, downgrade to
    # non-interactive so prompts/editor calls don't block a headless run.
    if [ "${interactive}" = "true" ] && [ ! -t 0 ]; then
        warn "interactive install requested but stdin is not a terminal -- proceeding non-interactively (no editor/prompts)."
        interactive="false"
    fi

    if [ ! -f "${ENV_FILE}" ]; then
        if [ -f "${ENV_EXAMPLE}" ]; then
            # chmod 600 BEFORE the operator can add plaintext USER_ passwords, closing the
            # window where the freshly-copied file inherits a looser ambient umask.
            cp "${ENV_EXAMPLE}" "${ENV_FILE}"
            chmod 600 "${ENV_FILE}"
            say "Created ${SERVICE_NAME}.env from example."
            if [ "${interactive}" = "true" ]; then
                say "Opening editor -- add your username/password lines, then save and exit."
                say ""
                sleep 1
                # If the chosen editor is missing/exits non-zero, don't abort the whole
                # install under set -e -- warn and fall through to the USER_ check.
                "${EDITOR:-nano}" "${ENV_FILE}" || warn "editor exited abnormally -- verify ${ENV_FILE} by hand."
            else
                say "NOTE: Edit ${ENV_FILE} to set credentials before use."
            fi
        else
            die "no ${SERVICE_NAME}.env or ${SERVICE_NAME}.env.example found -- create ${SERVICE_NAME}.env with at least one USER_<name>=<password> line."
        fi
    else
        # Existing env file: make sure it is not world/group readable (it holds secrets).
        chmod 600 "${ENV_FILE}" 2>/dev/null || warn "could not tighten permissions on ${ENV_FILE} -- ensure it is chmod 600 (owner-only)."
    fi

    # At least one USER_ line must be present or the web UI rejects every login.
    if ! grep -q "^USER_" "${ENV_FILE}" 2>/dev/null; then
        say ""
        warn "no USER_ entries found in ${SERVICE_NAME}.env -- the web UI will reject all logins until credentials are added."
        if [ "${interactive}" = "true" ]; then
            # -t 0 already guaranteed above, so this read cannot hang.
            read -r -p "Continue anyway? [y/N] " reply
            case "${reply}" in
                [Yy]*) : ;;   # operator accepts; proceed
                *) die "aborted -- add credentials and re-run: ./setup.sh install" ;;
            esac
        fi
    fi
}

# ----------------------------- unit install ----------------------------------
# Back up an existing unit, sanity-check the freshly-generated one, then install
# it. Backing up first means a bad regeneration can be restored by hand from
# backups/. The grep sanity gate is a hard, fail-closed guarantee that the unit
# we install carries the load-bearing directives (ExecStart / User / KillMode).
install_unit() {
    # Back up any current unit before we overwrite it (timestamped, gitignored).
    if [ -f "${SERVICE_FILE}" ]; then
        mkdir -p "${BACKUP_DIR}"
        local stamp backup
        stamp="$(date +%Y%m%d-%H%M%S)"
        backup="${BACKUP_DIR}/${SERVICE_NAME}.service.${stamp}.bak"
        # Unit files are world-readable (0644); a plain cp suffices. Fall back to a
        # privileged copy just in case, and only warn (a missing backup must not
        # block the install itself).
        if cp "${SERVICE_FILE}" "${backup}" 2>/dev/null || priv cp "${SERVICE_FILE}" "${backup}" 2>/dev/null; then
            info "backed up existing unit -> ${backup}"
        else
            warn "could not back up the existing unit at ${SERVICE_FILE} (continuing)."
        fi
    fi

    # Stage the generated unit in a temp file so we validate BEFORE touching /etc. Suffix it with
    # .service so the advisory `systemd-analyze verify` below accepts the filename -- systemd refuses
    # to validate a unit whose name lacks a valid unit suffix (it would otherwise always warn "Failed
    # to prepare filename ... Invalid argument"). Fall back to a plain mktemp where --suffix is
    # unsupported; the verify step is advisory either way, so the fallback only loses that extra check.
    local tmp_unit
    tmp_unit="$(mktemp --suffix=.service 2>/dev/null || mktemp)"
    _TMP_FILES+=("${tmp_unit}")
    generate_service_file > "${tmp_unit}"

    # Hard sanity gate: the essentials MUST be present. These are generated by us,
    # so a miss means a bug -- fail closed rather than install a broken unit.
    grep -q '^ExecStart=/usr/bin/python3 -m genpi$' "${tmp_unit}" || die "generated unit missing the expected ExecStart line -- refusing to install."
    grep -q "^User=${CURRENT_USER}$"                "${tmp_unit}" || die "generated unit missing 'User=${CURRENT_USER}' -- refusing to install."
    grep -q '^WorkingDirectory='                    "${tmp_unit}" || die "generated unit missing WorkingDirectory -- refusing to install."
    grep -q '^Restart=always$'                       "${tmp_unit}" || die "generated unit missing 'Restart=always' -- refusing to install."
    grep -q '^RestartSec='                           "${tmp_unit}" || die "generated unit missing RestartSec -- refusing to install."
    # KillMode=process is CRITICAL to the updater's survival -- guard it explicitly.
    grep -q '^KillMode=process$'                      "${tmp_unit}" || die "generated unit missing 'KillMode=process' -- refusing to install (the self-updater's bootstrap depends on it)."

    # Advisory deep validation with systemd's own parser, if present. This can
    # emit style warnings and occasionally a non-zero for benign reasons, so it
    # is INFORMATIONAL only -- the grep gate above is the authoritative check.
    if have systemd-analyze; then
        local verify_out
        if verify_out="$(systemd-analyze verify "${tmp_unit}" 2>&1)"; then
            info "[ok]      systemd-analyze verify passed"
        else
            warn "systemd-analyze verify flagged the unit (advisory): ${verify_out}"
        fi
    fi

    # Install the validated unit and reload systemd so it is picked up.
    priv tee "${SERVICE_FILE}" < "${tmp_unit}" > /dev/null
    priv systemctl daemon-reload
    info "[ok]      installed ${SERVICE_FILE}"
}

# ----------------------------- sudoers ---------------------------------------
# Install the SCOPED, passwordless sudoers rule the in-app updater's detached
# bootstrap uses to restart the service without a TTY (it would otherwise hang on
# a password prompt). Limited to EXACTLY the 3 systemctl verbs on THIS unit for
# the current user -- NEVER broaden. We stage in a temp file, validate it with
# `visudo -cf`, and only install it if valid, so a malformed rule is never even
# briefly placed under /etc/sudoers.d (a bad file there can lock out sudo).
install_sudoers() {
    local systemctl_bin tmp_sudoers
    systemctl_bin="$(command -v systemctl || echo /usr/bin/systemctl)"
    tmp_sudoers="$(mktemp)"
    _TMP_FILES+=("${tmp_sudoers}")
    # Three explicit verb rules, each pinned to this unit -- no wildcards, no general sudo.
    printf '%s ALL=(root) NOPASSWD: %s restart %s, %s start %s, %s stop %s\n' \
        "${CURRENT_USER}" \
        "${systemctl_bin}" "${SERVICE_NAME}.service" \
        "${systemctl_bin}" "${SERVICE_NAME}.service" \
        "${systemctl_bin}" "${SERVICE_NAME}.service" \
        > "${tmp_sudoers}"

    # Validate the STAGED file before it goes anywhere near /etc. Run visudo WITH privilege: visudo
    # needs root to run its syntax check (as a non-root user it fails with a permission error even on
    # a file the user owns), which would otherwise make a fresh install silently skip the rule entirely.
    if ! priv visudo -cf "${tmp_sudoers}" >/dev/null 2>&1; then
        warn "generated sudoers rule failed 'visudo -cf' validation -- NOT installing it. In-app updates will need passwordless 'systemctl restart ${SERVICE_NAME}.service' configured manually."
        return 0
    fi
    # Install atomically-ish with the correct owner/mode. `install` sets mode in
    # one step (no window at a looser mode). Re-validate the on-disk copy as a
    # belt-and-suspenders check; remove it if that somehow fails.
    priv install -o root -g root -m 0440 "${tmp_sudoers}" "${SUDOERS_FILE}"
    if priv visudo -cf "${SUDOERS_FILE}" >/dev/null 2>&1; then
        info "[ok]      installed scoped sudoers rule ${SUDOERS_FILE}"
    else
        warn "installed sudoers rule failed re-validation -- removing it for safety."
        priv rm -f "${SUDOERS_FILE}"
    fi
}

# ----------------------------- health check ----------------------------------
# Read the effective port + scheme from the env file for the optional HTTP probe.
# Honors an operator override (uncommented PORT=/SSL_ENABLED= line); the LAST such
# line wins (matching the app's own last-assignment-wins env parsing). Defaults
# mirror genpi/config.py (PORT 9400, SSL on).
_env_value() {
    # $1 = key; echoes the value of the last uncommented `KEY=...` line, or nothing.
    [ -f "${ENV_FILE}" ] || return 0
    grep -E "^[[:space:]]*$1=" "${ENV_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '[:space:]' || true
}

# Confirm the service actually came up. `systemctl is-active` is the AUTHORITATIVE
# gate: if it is not active we dump the recent journal and exit NON-ZERO so
# update.sh's ERR trap rolls back to the previous version. A short retry absorbs
# the tiny race between `restart` returning (Type=simple forks immediately) and
# the process settling. An optional local HTTP probe is a bonus signal only.
health_check() {
    say ""
    say "Health check:"
    # is-active with a couple of quick retries (the fork may lag the restart return).
    local active="no" _attempt
    for _attempt in 1 2 3 4 5; do
        if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
            active="yes"; break
        fi
        sleep 1
    done
    if [ "${active}" != "yes" ]; then
        err "service ${SERVICE_NAME} did NOT reach 'active' after restart. Recent logs:"
        journalctl -u "${SERVICE_NAME}.service" -n 30 --no-pager 2>&1 || say "(journal unavailable)"
        die "post-install health check failed -- the service is not running. Fix the cause above (or restore a unit from ${BACKUP_DIR}), then re-run."
    fi
    info "[ok]      systemctl is-active: active"

    # Optional HTTP probe of the configured port. Any HTTP response (even 401 from
    # auth, or a self-signed TLS handshake we bypass with -k) proves the server is
    # listening. Absence of curl, or a probe failure, is only a WARNING -- is-active
    # already gated the real go/no-go, and the socket may still be binding.
    if have curl; then
        local port scheme url code
        port="$(_env_value PORT)";        [ -n "${port}" ]   || port="9400"
        scheme="$(_env_value SSL_ENABLED)"
        # SSL_ENABLED empty/1/true -> https; explicit 0/false/off -> http.
        case "${scheme}" in
            0|false|False|no|No|off|Off) scheme="http" ;;
            *) scheme="https" ;;
        esac
        url="${scheme}://127.0.0.1:${port}/"
        code=""
        # Poll for up to ~15s: right after a restart the Type=simple process is already "active"
        # but cheroot may not have bound the socket yet (slower on the single ARM core, especially
        # just after compileall spiked the CPU). A too-short window would warn spuriously even though
        # the app is fine, so give the socket real time to come up before deciding it's unreachable.
        for _attempt in $(seq 1 15); do
            # -k tolerate self-signed TLS, -s quiet, -o discard body, -m short timeout,
            # -w print only the status code. `|| true` so a failed probe never trips set -e.
            code="$(curl -k -s -o /dev/null -m 3 -w '%{http_code}' "${url}" 2>/dev/null || true)"
            if [ -n "${code}" ] && [ "${code}" != "000" ]; then break; fi
            sleep 1
        done
        if [ -n "${code}" ] && [ "${code}" != "000" ]; then
            info "[ok]      HTTP probe ${url} -> ${code}"
        else
            warn "HTTP probe of ${url} did not get a response (service reports active; it may still be binding, or the port/scheme differs). Verify manually if the UI is unreachable."
        fi
    else
        info "[skip]    curl not present -- skipping the optional HTTP probe (is-active already confirmed the service)."
    fi
}

# ----------------------------- install driver --------------------------------
do_install() {
    local interactive="${1:-true}"

    say "Installing ${SERVICE_NAME} service..."
    say "  User: ${CURRENT_USER}"
    say "  Directory: ${SCRIPT_DIR}"

    # Fail-closed preconditions first (wrong dir / no python are unrecoverable).
    check_repo_root
    preflight_report
    check_python

    # A real service install needs BOTH systemd and privilege. If either is
    # missing we still did the portable prep (env/deps/compile can run anywhere),
    # but we cannot create the unit -- fail closed with the manual alternative so
    # reinstall signals failure to update.sh and no half-install looks "done".
    if ! have systemctl || [ "${HAVE_PRIV}" != "true" ]; then
        # Do the host-agnostic prep so the checkout is at least usable by hand.
        setup_env_file "${interactive}"
        install_dependencies
        compile_package
        say ""
        if ! have systemctl; then
            die "cannot install the systemd service: this is not a systemd host. Env, dependencies, and byte-cache are prepared -- run the app directly instead:  cd '${SCRIPT_DIR}' && python3 -m genpi"
        else
            die "cannot install the systemd service: no root/sudo to write /etc + manage systemd. Re-run as root (or install sudo). Env, dependencies, and byte-cache are already prepared."
        fi
    fi

    # ---- Full managed install (systemd + privilege available) ----
    setup_env_file "${interactive}"       # env + credentials
    install_dependencies                  # apt deps (fatal if a REQUIRED one is missing)
    compile_package                       # byte-compile + syntax gate
    install_unit                          # backup + validate + write unit, daemon-reload
    install_sudoers                       # scoped, validated passwordless restart rule

    # Enable on boot and (re)start now. enable/restart are idempotent, so a
    # re-run simply converges -- no duplicate state.
    priv systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || warn "systemctl enable reported an issue -- the service may not autostart on boot; check 'systemctl is-enabled ${SERVICE_NAME}'."
    say ""
    say "Restarting ${SERVICE_NAME}..."
    priv systemctl restart "${SERVICE_NAME}.service"

    # Verify it actually came up (fatal + rollback signal if not).
    health_check

    say ""
    say "Installed and started. The service will start automatically on boot."
    say ""
    # Advisory final status; never let a non-zero here fail the (already healthy) install.
    systemctl status "${SERVICE_NAME}.service" --no-pager || true
}

# ----------------------------- subcommands -----------------------------------
case "${1:-}" in
    install)
        # Interactive: prompts + opens the editor for credentials.
        do_install true
        ;;

    reinstall)
        # Non-interactive install -- used by update.sh + the in-app updater over SSH.
        # MUST never prompt/hang and MUST exit non-zero on any real failure so the
        # caller's rollback can trigger (guaranteed by die on every fatal path above).
        do_install false
        ;;

    uninstall)
        say "Uninstalling ${SERVICE_NAME} service..."
        check_repo_root
        if have systemctl && [ "${HAVE_PRIV}" = "true" ]; then
            # Stop + disable are best-effort (already-stopped/absent is fine).
            priv systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
            priv systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
            priv rm -f "${SERVICE_FILE}"
            priv rm -f "${SUDOERS_FILE}"
            priv systemctl daemon-reload
            say "Service stopped, disabled, and removed (unit + updater sudoers rule)."
        else
            # Degraded host: still remove whatever files we can, and say what we couldn't.
            warn "systemctl and/or root unavailable -- removing files best-effort only."
            if [ "${HAVE_PRIV}" = "true" ]; then
                priv rm -f "${SERVICE_FILE}" "${SUDOERS_FILE}"
            else
                warn "no privilege to remove ${SERVICE_FILE} / ${SUDOERS_FILE} -- remove them by hand as root."
            fi
        fi
        say "Application files in ${SCRIPT_DIR} are untouched."
        ;;

    status)
        say "=== Service File ==="
        if [ -f "${SERVICE_FILE}" ]; then
            say "Installed at: ${SERVICE_FILE}"
        else
            say "NOT INSTALLED (${SERVICE_FILE} does not exist)"
            say ""
            say "Run './setup.sh install' to install."
            exit 0
        fi

        if ! have systemctl; then
            warn "systemctl not present -- cannot query live service state on this host."
            exit 0
        fi

        say ""
        say "=== Service Status ==="
        systemctl status "${SERVICE_NAME}.service" --no-pager 2>&1 || true

        say ""
        say "=== Boot Enabled ==="
        # is-enabled prints the state and exits non-zero when not enabled; guard so
        # set -e/pipefail don't abort, and report plainly either way.
        if systemctl is-enabled "${SERVICE_NAME}.service" 2>/dev/null | grep -q "enabled"; then
            say "Yes (starts on boot)"
        else
            say "No (will NOT start on boot)"
        fi

        say ""
        say "=== Recent Logs (last 20 lines) ==="
        journalctl -u "${SERVICE_NAME}.service" -n 20 --no-pager 2>/dev/null || say "(no logs)"
        ;;

    *)
        say "Usage: $0 {install|reinstall|uninstall|status}"
        exit 1
        ;;
esac

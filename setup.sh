#!/bin/bash
# Install, uninstall, or check status of the generator control systemd service.
#
# Usage:
#   ./setup.sh install      - Install and enable the service (starts on boot)
#   ./setup.sh reinstall    - Same as install but non-interactive (for update.sh)
#   ./setup.sh uninstall    - Stop, disable, and remove the service
#   ./setup.sh status       - Show service status and configuration

set -e

SERVICE_NAME="generator_control"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CURRENT_USER="$(whoami)"
ENV_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.env"
ENV_EXAMPLE="${SCRIPT_DIR}/${SERVICE_NAME}.env.example"

# Generate a systemd service file pointing to the actual install location and user
generate_service_file() {
    cat <<UNIT
[Unit]
Description=Powermate PM9400E Generator Control (Flask + GPIOZero)
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/generator_control.py
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

do_install() {
    local interactive="${1:-true}"

    echo "Installing ${SERVICE_NAME} service..."
    echo "  User: ${CURRENT_USER}"
    echo "  Directory: ${SCRIPT_DIR}"
    echo ""

    # If no env file, copy from example
    if [ ! -f "${ENV_FILE}" ]; then
        if [ -f "${ENV_EXAMPLE}" ]; then
            cp "${ENV_EXAMPLE}" "${ENV_FILE}"
            # Lock the copy down to owner-only immediately. It will hold plaintext
            # USER_ passwords (added below/by the operator) and inherits the ambient
            # umask from cp until the service later tightens it -- close that window now.
            chmod 600 "${ENV_FILE}"
            echo "Created ${SERVICE_NAME}.env from example."
            if [ "${interactive}" = "true" ]; then
                echo "Opening editor -- add your username/password lines, then save and exit."
                echo ""
                sleep 1
                ${EDITOR:-nano} "${ENV_FILE}"
            else
                echo "NOTE: Edit ${ENV_FILE} to set credentials before use."
            fi
        else
            echo "ERROR: No ${SERVICE_NAME}.env or .env.example found."
            echo "Create ${SERVICE_NAME}.env with at least one USER_<name>=<password> line."
            exit 1
        fi
    fi

    # Verify at least one user is configured
    if ! grep -q "^USER_" "${ENV_FILE}" 2>/dev/null; then
        echo ""
        echo "WARNING: No USER_ entries found in ${SERVICE_NAME}.env."
        echo "The web UI will reject all logins until credentials are added."
        if [ "${interactive}" = "true" ]; then
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Aborted. Add credentials and re-run: ./setup.sh install"
                exit 1
            fi
        fi
    fi

    # Web Push (OPTIONAL): the controller runs fine without it, but push notifications
    # need the 'pywebpush' library. Best-effort install -- never fatal.
    if ! /usr/bin/python3 -c "import pywebpush" 2>/dev/null; then
        echo ""
        echo "Web Push dependency 'pywebpush' not found -- attempting a best-effort install."
        echo "(Push is OPTIONAL; the controller runs without it. See the README.)"
        sudo apt-get install -y python3-cryptography >/dev/null 2>&1 || true
        # Newer Raspberry Pi OS / Debian mark the system Python "externally managed",
        # so fall back to --break-system-packages if a plain pip install is refused.
        if ! sudo pip3 install pywebpush >/dev/null 2>&1 \
           && ! sudo pip3 install --break-system-packages pywebpush >/dev/null 2>&1; then
            echo "  Could not auto-install pywebpush. To enable push later, run:"
            echo "    sudo apt install -y python3-cryptography"
            echo "    sudo pip3 install --break-system-packages pywebpush"
            echo "  then: sudo systemctl restart ${SERVICE_NAME}"
        fi
    fi

    # Generate and install the service file
    generate_service_file | sudo tee "${SERVICE_FILE}" > /dev/null
    sudo systemctl daemon-reload

    # Install a SCOPED, passwordless sudoers rule so the in-app self-updater's detached bootstrap
    # can restart the service without a TTY/password prompt (it would otherwise hang: "no tty").
    # Limited to EXACTLY the three systemctl verbs on THIS unit -- no general sudo is granted.
    SUDOERS_FILE="/etc/sudoers.d/generatorpi-updater"
    SYSTEMCTL_BIN="$(command -v systemctl || echo /usr/bin/systemctl)"
    printf '%s ALL=(root) NOPASSWD: %s restart %s, %s start %s, %s stop %s\n' \
        "${CURRENT_USER}" \
        "${SYSTEMCTL_BIN}" "${SERVICE_NAME}.service" \
        "${SYSTEMCTL_BIN}" "${SERVICE_NAME}.service" \
        "${SYSTEMCTL_BIN}" "${SERVICE_NAME}.service" \
        | sudo tee "${SUDOERS_FILE}" > /dev/null
    sudo chmod 0440 "${SUDOERS_FILE}"
    # Validate; a malformed sudoers file is dangerous, so remove it if visudo rejects it.
    if ! sudo visudo -cf "${SUDOERS_FILE}" > /dev/null 2>&1; then
        echo "WARNING: sudoers rule failed validation; removing it. In-app updates will need"
        echo "         passwordless 'systemctl restart ${SERVICE_NAME}.service' configured manually."
        sudo rm -f "${SUDOERS_FILE}"
    fi

    # Enable (start on boot) and start/restart now
    sudo systemctl enable "${SERVICE_NAME}.service"
    sudo systemctl restart "${SERVICE_NAME}.service"

    echo ""
    echo "Installed and started. Service will start automatically on boot."
    echo ""
    systemctl status "${SERVICE_NAME}.service" --no-pager
}

case "${1}" in
    install)
        do_install true
        ;;

    reinstall)
        # Non-interactive install -- used by update.sh over SSH
        do_install false
        ;;

    uninstall)
        echo "Uninstalling ${SERVICE_NAME} service..."

        # Stop and disable
        sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
        sudo systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true

        # Remove service file, the updater sudoers rule, and reload
        sudo rm -f "${SERVICE_FILE}"
        sudo rm -f "/etc/sudoers.d/generatorpi-updater"
        sudo systemctl daemon-reload

        echo "Service stopped, disabled, and removed."
        echo "Application files in ${SCRIPT_DIR} are untouched."
        ;;

    status)
        echo "=== Service File ==="
        if [ -f "${SERVICE_FILE}" ]; then
            echo "Installed at: ${SERVICE_FILE}"
        else
            echo "NOT INSTALLED (${SERVICE_FILE} does not exist)"
            echo ""
            echo "Run './setup.sh install' to install."
            exit 0
        fi

        echo ""
        echo "=== Service Status ==="
        systemctl status "${SERVICE_NAME}.service" --no-pager 2>&1 || true

        echo ""
        echo "=== Boot Enabled ==="
        if systemctl is-enabled "${SERVICE_NAME}.service" 2>/dev/null | grep -q "enabled"; then
            echo "Yes (starts on boot)"
        else
            echo "No (will NOT start on boot)"
        fi

        echo ""
        echo "=== Recent Logs (last 20 lines) ==="
        journalctl -u "${SERVICE_NAME}.service" -n 20 --no-pager 2>/dev/null || echo "(no logs)"
        ;;

    *)
        echo "Usage: $0 {install|reinstall|uninstall|status}"
        exit 1
        ;;
esac

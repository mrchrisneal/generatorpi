#!/bin/bash
# Install, uninstall, or check status of the generator control systemd service.
#
# Usage:
#   ./setup.sh install    - Install and enable the service (starts on boot)
#   ./setup.sh uninstall  - Stop, disable, and remove the service
#   ./setup.sh status     - Show service status and configuration

set -e

SERVICE_NAME="generator_control"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_SERVICE_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.service"

case "${1}" in
    install)
        echo "Installing ${SERVICE_NAME} service..."

        # Check that the env file exists (app won't work without credentials)
        if [ ! -f "${SCRIPT_DIR}/${SERVICE_NAME}.env" ]; then
            echo ""
            echo "WARNING: ${SERVICE_NAME}.env not found."
            echo "Copy the example and add your credentials first:"
            echo "  cp ${SERVICE_NAME}.env.example ${SERVICE_NAME}.env"
            echo "  nano ${SERVICE_NAME}.env"
            echo ""
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Aborted."
                exit 1
            fi
        fi

        # Copy service file and reload systemd
        sudo cp "${LOCAL_SERVICE_FILE}" "${SERVICE_FILE}"
        sudo systemctl daemon-reload

        # Enable (start on boot) and start now
        sudo systemctl enable "${SERVICE_NAME}.service"
        sudo systemctl start "${SERVICE_NAME}.service"

        echo ""
        echo "Installed and started. Service will start automatically on boot."
        echo ""
        systemctl status "${SERVICE_NAME}.service" --no-pager
        ;;

    uninstall)
        echo "Uninstalling ${SERVICE_NAME} service..."

        # Stop and disable
        sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
        sudo systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true

        # Remove service file and reload
        sudo rm -f "${SERVICE_FILE}"
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
        echo "Usage: $0 {install|uninstall|status}"
        exit 1
        ;;
esac

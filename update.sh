#!/bin/bash
# Pull latest code from GitHub and restart the generator control service.
# Usage: ssh pi@generatorpi "~/generatorpi/update.sh"
#
# The entire script body is inside a block so bash reads it fully into memory
# before executing. This allows git pull to safely overwrite this file.

{
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# If anything fails after stopping the service, restart it so the generator
# isn't left unreachable.
service_stopped=false
trap '
    if [ "$service_stopped" = true ]; then
        echo "ERROR: Update failed. Restarting service with previous version..."
        sudo systemctl start generator_control.service
    fi
' ERR

echo "Stopping generator_control service..."
sudo systemctl stop generator_control.service
service_stopped=true

echo "Pulling latest code..."
git pull origin main

echo "Re-installing service (picks up any service/script changes)..."
./setup.sh reinstall

# Only clear the flag after setup.sh reinstall succeeds (service is running)
service_stopped=false

exit
}

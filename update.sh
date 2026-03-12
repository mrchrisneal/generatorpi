#!/bin/bash
# Pull latest code from GitHub and restart the generator control service.
# Usage: ssh pi@generatorpi "~/generatorpi/update.sh"

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

echo "Stopping generator_control service..."
sudo systemctl stop generator_control.service

echo "Pulling latest code..."
git pull origin main

echo "Re-installing service (picks up any service file changes)..."
./setup.sh install

#!/bin/bash
# Pull latest code from GitHub and restart the generator control service.
# Usage: ssh pi@generatorpi "bash ~/generatorpi/update.sh"

set -e

cd /home/pi/generatorpi

echo "Stopping generator_control service..."
sudo systemctl stop generator_control.service

echo "Pulling latest code..."
git pull origin main

echo "Reloading systemd (in case service file changed)..."
sudo cp generator_control.service /etc/systemd/system/generator_control.service
sudo systemctl daemon-reload

echo "Starting generator_control service..."
sudo systemctl start generator_control.service

echo ""
echo "Done. Service status:"
systemctl status generator_control.service --no-pager

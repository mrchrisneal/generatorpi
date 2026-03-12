#!/bin/bash
# Pull latest code from GitHub and restart the generator control service.
# Usage: ssh pi@generatorpi "bash ~/generatorpi/update.sh"

set -e

cd /home/pi/generatorpi

echo "Stopping generator_control service..."
sudo systemctl stop generator_control.service

echo "Pulling latest code..."
git pull origin main

echo "Installing dependencies..."
pip3 install -r requirements.txt --break-system-packages -q

echo "Restarting generator_control service..."
sudo systemctl daemon-reload
sudo systemctl start generator_control.service

echo "Done. Service status:"
systemctl status generator_control.service --no-pager

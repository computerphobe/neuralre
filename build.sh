#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "[~] Updating and installing dependencies..."
apt-get update
apt-get install -y radare2

echo "[✓] Radare2 installed successfully"

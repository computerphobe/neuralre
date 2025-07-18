#!/bin/bash

echo "[~] Installing radare2 from source..."
git clone https://github.com/radareorg/radare2.git --depth=1
cd radare2
./sys/install.sh
cd ..

echo "[~] Installing Python dependencies..."
pip install -r requirements.txt

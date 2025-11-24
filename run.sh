#!/bin/bash

echo "========================================================"
echo "  Genesys Cloud Data Table Manager - Startup Script"
echo "========================================================"

# Ensure we are in the script's directory
cd "$(dirname "$0")"

# Define central installation path (User's home directory)
INSTALL_DIR="$HOME/PilviContactCenter"
VENV_DIR="$INSTALL_DIR/venv"

# 1. Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not found. Please install Python 3."
    exit 1
fi

# 2. Create Install Directory if missing
if [ ! -d "$INSTALL_DIR" ]; then
    echo "[INFO] Creating directory $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
fi

# 3. Create Virtual Environment if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "[INFO] First time setup: Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

# 4. Activate Virtual Environment
source "$VENV_DIR/bin/activate"

# 5. Install Dependencies
echo "[INFO] Checking and installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[WARN] Failed to install dependencies silently. Retrying with output..."
    pip install -r requirements.txt
fi

# 6. Start Application
echo ""
echo "[INFO] Starting Application..."
echo "[INFO] The browser will open automatically."
echo ""
echo "Press Ctrl+C to stop the server."
echo ""

# Open Browser in background after 2 seconds
(sleep 2 && open http://127.0.0.1:5000) &

# Run Flask App
python3 -u app.py

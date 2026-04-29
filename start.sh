#!/bin/bash
# MalGuard — Fileless Malware Detection Dashboard
# Run this once to set up and launch. Works on Mac and Linux.

set -e
cd "$(dirname "$0")"

# ── Python check ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.9+ from https://python.org"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_VER" -lt 9 ]; then
    echo "ERROR: Python 3.9 or newer required."
    exit 1
fi

# ── Virtual environment ───────────────────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# ── Dependencies ──────────────────────────────────────────────────────────────
echo "Installing dependencies..."
pip install -q -r requirements.txt

# ── Model check ───────────────────────────────────────────────────────────────
if [ ! -f "models/fileless_detector.pkl" ]; then
    echo "No trained model found. Training now (this takes ~30 seconds)..."
    python main.py --train-only 2>/dev/null || python main.py
fi

# ── Launch ────────────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   MalGuard SOC Dashboard                 ║"
echo "  ║   Open http://localhost:5000              ║"
echo "  ║   Press Ctrl+C to stop                   ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Auto-open browser after 2s
(sleep 2 && open "http://localhost:5000" 2>/dev/null || xdg-open "http://localhost:5000" 2>/dev/null) &

python app.py

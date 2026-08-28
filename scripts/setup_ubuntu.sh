#!/usr/bin/env bash
#
# One-shot Ubuntu setup for Argus.
#   bash scripts/setup_ubuntu.sh
#
# Creates a virtual environment, installs dependencies, initialises the
# database, and prints readiness. Idempotent and safe to re-run.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "=== Argus Ubuntu setup ==="
echo "Project: $ROOT"

# 1. Python 3.10+ is required.
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found."
    echo "Install it with:  sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi
echo -n "Python: "; python3 --version

# 2. Virtual environment.
if [ ! -d .venv ]; then
    echo "Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

# 3. Dependencies (dnspython + PyYAML).
echo "Installing dependencies..."
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

# 4. Initialise the database (schema + resolvers/domains from config; never deletes).
echo "Initialising database..."
python scripts/init_db.py

echo
echo "=== Setup complete ==="
echo "Activate the environment:   source .venv/bin/activate"
echo "Then try:"
echo "  python -m argus status         # configuration + readiness"
echo "  python -m argus run-once       # one monitoring sweep"
echo "  python -m argus dashboard      # live dashboard at http://127.0.0.1:8080"
echo
echo "Optional DNS tools for MANUAL cross-checking (NOT required by Argus):"
echo "  sudo apt install -y dnsutils bind9-dnsutils   # provides dig, delv"

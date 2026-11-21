#!/bin/bash
# Usage: ./run.sh [--port N] [--no-browser]
# Run with sudo to also capture DNS lookups.
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  echo "[mac-siem] setting up virtualenv"
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
if ! ls data/*city*.mmdb >/dev/null 2>&1; then
  echo "[mac-siem] no GeoIP database yet, run ./setup_geoip.sh to get countries on the map"
fi
exec .venv/bin/python mac_siem.py "$@"

#!/bin/bash
set -e

echo "=== Ice-Leak-Monitor Starting ==="
echo "Timezone: ${TZ:-UTC}"
echo "Database: /data/iceleakmonitor.db"

# Ensure data directory
mkdir -p /data

# Verify tools
echo "Checking tools..."
which trufflehog && trufflehog --version 2>/dev/null || echo "WARN: trufflehog not found"
which gitleaks && gitleaks version 2>/dev/null || echo "WARN: gitleaks not found"
which git && git --version || echo "ERROR: git not found"
test -f /opt/blackbird/blackbird.py && echo "blackbird OK (/opt/blackbird)" || echo "WARN: blackbird not found (OSINT disabled)"

echo "Starting uvicorn on port 8080..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 1 --log-level info

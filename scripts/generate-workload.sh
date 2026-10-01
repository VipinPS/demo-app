#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# generate-workload.sh — thin wrapper around generate_crypto_workload.py
#
# Usage:
#   ./scripts/generate-workload.sh [--iterations N] [--base-url URL] [--delay D]
#
# Examples:
#   ./scripts/generate-workload.sh
#   ./scripts/generate-workload.sh --iterations 20
#   ./scripts/generate-workload.sh --iterations 50 --base-url http://localhost:8080
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

exec python3 "${SCRIPT_DIR}/generate_crypto_workload.py" "$@"

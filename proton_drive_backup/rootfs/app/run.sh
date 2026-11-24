#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
if [[ "${PROTON_DRIVE_CREDENTIALS_STORE:-pass}" == "unsafe_file" ]]; then
  exit 64
fi

# Resolve the package independently of the container's initial directory.
cd -- "${BASH_SOURCE[0]%/*}"
if [[ "${1:-}" == "--check" ]]; then
  exec python3 -c 'import proton_backup.__main__; print("Python app import OK")'
fi
exec python3 -m proton_backup

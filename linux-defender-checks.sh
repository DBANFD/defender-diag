#!/usr/bin/env bash
# Run with bash on a supported Linux endpoint. No configuration changes.
# Results can contain tenant/device identifiers and internal URLs. Keep private.
# Connectivity test contacts Microsoft's configured cloud endpoints.
set -u
if ! command -v mdatp >/dev/null 2>&1; then
  printf '%s\n' 'mdatp not found in PATH; verify installation and PATH.' >&2
  exit 127
fi
failed=0
run_check() {
  printf '\nCheck: %s\n' "$*"
  "$@"
  result=$?
  if [ "$result" -ne 0 ]; then
    printf 'Command failed with exit code %s\n' "$result" >&2
    failed=1
  fi
}
run_check date -u '+%Y-%m-%dT%H:%M:%SZ'
run_check mdatp health
run_check mdatp connectivity test
# Exit 0 means commands completed, NOT that all protection fields are healthy.
exit "$failed"

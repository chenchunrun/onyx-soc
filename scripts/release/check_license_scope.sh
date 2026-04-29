#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

EXIT_CODE=0

info() { printf "[INFO] %s\n" "$*"; }
pass() { printf "[PASS] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*"; }
fail() { printf "[FAIL] %s\n" "$*"; EXIT_CODE=1; }

info "Repository: $ROOT_DIR"
info "Checking release license scope..."

# 1) Root license file
if [[ -f "LICENSE" ]]; then
  pass "Root LICENSE exists"
else
  fail "Root LICENSE missing"
fi

# 2) EE license files declared in root LICENSE
EE_LICENSE_PATHS=(
  "backend/ee/LICENSE"
  "web/src/app/ee/LICENSE"
  "web/src/ee/LICENSE"
)

for path in "${EE_LICENSE_PATHS[@]}"; do
  if [[ -f "$path" ]]; then
    pass "EE license file exists: $path"
  else
    fail "EE license file missing: $path"
  fi
done

# 3) Sanity-check root LICENSE contains mixed-license notice
if rg -n "All content that resides under \"ee\" directories" LICENSE >/dev/null; then
  pass "Root LICENSE documents EE directory restriction"
else
  fail "Root LICENSE missing EE directory restriction notice"
fi

# 4) Detect EE directory footprint (for packaging decisions)
EE_FILES_COUNT="$(find backend/ee web/src/app/ee web/src/ee -type f 2>/dev/null | wc -l | tr -d ' ')"
if [[ "${EE_FILES_COUNT:-0}" -gt 0 ]]; then
  warn "EE files detected: $EE_FILES_COUNT files under EE directories"
  warn "If publishing MIT-only package, exclude EE directories from artifact"
else
  pass "No EE files detected"
fi

# 5) Detect risky "all MIT" claims in docs/readme
if rg -n "(all|entire|whole).*(MIT|mit)" README.md docs 2>/dev/null | rg -vi "community edition|ce" >/dev/null; then
  warn "Potential broad MIT claims found in docs. Review wording before release."
else
  pass "No obvious broad 'entire project is MIT' claims detected"
fi

# 6) Presence of dependency lock files (for third-party license traceability)
LOCK_FILES=(
  "uv.lock"
  "web/package-lock.json"
)

for lock in "${LOCK_FILES[@]}"; do
  if [[ -f "$lock" ]]; then
    pass "Dependency lock file exists: $lock"
  else
    warn "Dependency lock file missing: $lock"
  fi
done

if [[ "$EXIT_CODE" -eq 0 ]]; then
  info "License scope check completed successfully."
else
  info "License scope check completed with failures."
fi

exit "$EXIT_CODE"

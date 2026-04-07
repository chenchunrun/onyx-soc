#!/usr/bin/env bash
set -euo pipefail

# Generated archive action script for phase-2-nvd-authoritative-historical
ACTION_MODE="${ACTION_MODE:-preview}"
echo "[INFO] Archive batch: phase-2-nvd-authoritative-historical mode=$ACTION_MODE"
PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
  if [ -x ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
  elif [ -x "/Users/newmba/Downloads/onyx-main/.venv/bin/python" ]; then
    PYTHON_BIN="/Users/newmba/Downloads/onyx-main/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

if [ "$ACTION_MODE" != "preview" ] && [ "$ACTION_MODE" != "apply" ]; then
  echo "[ERROR] ACTION_MODE must be preview or apply" >&2
  exit 1
fi

if [ "$ACTION_MODE" = "preview" ]; then
  echo '[INFO] Preview mode: no files will be removed'
else
git rm \
  'knowledge-base/威胁情报/feeds/CVE_2008_0176.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_2568.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_2772.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_4740.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_1565.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_1566.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_1567.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_1568.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_2214.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_2959.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3322.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3386.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3490.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3495.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3496.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3497.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_4050.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_4053.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_4535.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_4537.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_5087.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_5163.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1824.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_3011.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_3815.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4353.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4354.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4355.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4356.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4357.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4358.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4359.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4700.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0657.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2791.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2793.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2794.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2796.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2824.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2829.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_6142.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_7462.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0751.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0752.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0753.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0779.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2342.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2343.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2375.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2376.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2377.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_5408.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_5411.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_5412.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_5413.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_5429.md'
fi

$PYTHON_BIN knowledge-base/build_threat_intel_manifest.py --write
$PYTHON_BIN knowledge-base/assess_threat_intel_lifecycle.py --write-report
$PYTHON_BIN knowledge-base/build_threat_intel_archive_worklist.py --batch-id phase-2-nvd-authoritative-historical --write-report
$PYTHON_BIN knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id phase-2-nvd-authoritative-historical --write-report
$PYTHON_BIN knowledge-base/build_threat_intel_archive_execution_result.py --batch-id phase-2-nvd-authoritative-historical --mode "$ACTION_MODE" --write-result --show-summary --result-path 'knowledge-base/threat-intelligence/archive_execution_results/phase-2-nvd-authoritative-historical.json'
$PYTHON_BIN knowledge-base/setup_security_threat_intel.py --verify --local-only

echo '[OK] Archive batch script completed'

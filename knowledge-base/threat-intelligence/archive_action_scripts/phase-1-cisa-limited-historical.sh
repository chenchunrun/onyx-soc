#!/usr/bin/env bash
set -euo pipefail

# Generated archive action script for phase-1-cisa-limited-historical
ACTION_MODE="${ACTION_MODE:-preview}"
echo "[INFO] Archive batch: phase-1-cisa-limited-historical mode=$ACTION_MODE"
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
  'knowledge-base/威胁情报/feeds/CVE_2002_0367.md' \
  'knowledge-base/威胁情报/feeds/CVE_2004_0210.md' \
  'knowledge-base/威胁情报/feeds/CVE_2004_1464.md' \
  'knowledge-base/威胁情报/feeds/CVE_2005_2773.md' \
  'knowledge-base/威胁情报/feeds/CVE_2006_1547.md' \
  'knowledge-base/威胁情报/feeds/CVE_2006_2492.md' \
  'knowledge-base/威胁情报/feeds/CVE_2007_0671.md' \
  'knowledge-base/威胁情报/feeds/CVE_2007_3010.md' \
  'knowledge-base/威胁情报/feeds/CVE_2007_5659.md' \
  'knowledge-base/威胁情报/feeds/CVE_2008_0015.md' \
  'knowledge-base/威胁情报/feeds/CVE_2008_0655.md' \
  'knowledge-base/威胁情报/feeds/CVE_2008_2992.md' \
  'knowledge-base/威胁情报/feeds/CVE_2008_3431.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_0556.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_0557.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_0563.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_0927.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_1123.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_1151.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_1862.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_2055.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_3129.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_3953.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_3960.md' \
  'knowledge-base/威胁情报/feeds/CVE_2009_4324.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_0188.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_0232.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_0738.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_0840.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_1297.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_1428.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_1871.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_2572.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_2861.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_2883.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_3035.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_3333.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_3765.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_3904.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_3962.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_4344.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_4345.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_4398.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_5326.md' \
  'knowledge-base/威胁情报/feeds/CVE_2010_5330.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_0609.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_0611.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_1823.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_1889.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_2005.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_2462.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3402.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_3544.md' \
  'knowledge-base/威胁情报/feeds/CVE_2011_4723.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0151.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0158.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0391.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0507.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0518.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0754.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_0767.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1535.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1710.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1723.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1823.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1856.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_1889.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_2034.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_2539.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_3152.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4681.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4792.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_4969.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_5054.md' \
  'knowledge-base/威胁情报/feeds/CVE_2012_5076.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0074.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0422.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0431.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0625.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0629.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0631.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0632.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0640.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0641.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0643.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_0648.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_1331.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_1347.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_1675.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_1690.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2094.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2251.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2423.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2465.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2551.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2596.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2597.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_2729.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3163.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3346.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3660.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3893.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3896.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3897.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3900.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3906.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3918.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_3993.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_4810.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_5065.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_5223.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_6282.md' \
  'knowledge-base/威胁情报/feeds/CVE_2013_7331.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0130.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0160.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0196.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0322.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0496.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0497.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0502.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0546.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_0780.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_100005.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_1761.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_1776.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_1812.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2120.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_2817.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_3120.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_3153.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_3931.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_4077.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_4113.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_4114.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_4123.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_4148.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_4404.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_6271.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_6278.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_6287.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_6324.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_6332.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_6352.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_7169.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_8361.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_8439.md' \
  'knowledge-base/威胁情报/feeds/CVE_2014_9163.md'
fi

$PYTHON_BIN knowledge-base/build_threat_intel_manifest.py --write
$PYTHON_BIN knowledge-base/assess_threat_intel_lifecycle.py --write-report
$PYTHON_BIN knowledge-base/build_threat_intel_archive_worklist.py --batch-id phase-1-cisa-limited-historical --write-report
$PYTHON_BIN knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id phase-1-cisa-limited-historical --write-report
$PYTHON_BIN knowledge-base/build_threat_intel_archive_execution_result.py --batch-id phase-1-cisa-limited-historical --mode "$ACTION_MODE" --write-result --show-summary --result-path 'knowledge-base/threat-intelligence/archive_execution_results/phase-1-cisa-limited-historical.json'
$PYTHON_BIN knowledge-base/setup_security_threat_intel.py --verify --local-only

echo '[OK] Archive batch script completed'

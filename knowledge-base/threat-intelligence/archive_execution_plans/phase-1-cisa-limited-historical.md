# Threat-Intel Archive Execution Plan

## Batch

- `batch_id`: `phase-1-cisa-limited-historical`
- `description`: First archive review batch for low-value historical CISA placeholder feeds.
- `recommended_action`: Archive or remove placeholder-heavy historical CISA feeds from the governed package after review.

## Scope

- `candidate_count`: `147`
- `source`: `CISA Known Exploited Vulnerabilities Catalog`
- `quality_tier`: `limited`
- `years`: `2002, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014`

## Projected Impact

- `projected_governed_total`: `1755`
- `removal_size_bytes`: `141712`
- `removed_sources`: `CISA Known Exploited Vulnerabilities Catalog=147`
- `projected_sources`: `CISA Known Exploited Vulnerabilities Catalog=1406, NIST National Vulnerability Database (NVD)=349`

## Sample Paths

- `knowledge-base/威胁情报/feeds/CVE_2002_0367.md`
- `knowledge-base/威胁情报/feeds/CVE_2004_0210.md`
- `knowledge-base/威胁情报/feeds/CVE_2004_1464.md`
- `knowledge-base/威胁情报/feeds/CVE_2005_2773.md`
- `knowledge-base/威胁情报/feeds/CVE_2006_1547.md`
- `knowledge-base/威胁情报/feeds/CVE_2006_2492.md`
- `knowledge-base/威胁情报/feeds/CVE_2007_0671.md`
- `knowledge-base/威胁情报/feeds/CVE_2007_3010.md`
- `knowledge-base/威胁情报/feeds/CVE_2007_5659.md`
- `knowledge-base/威胁情报/feeds/CVE_2008_0015.md`

## Preconditions

- Run in a clean git worktree or disposable branch.
- Ensure the repo-level Python environment is available.
- Confirm no unrelated `knowledge-base/威胁情报/feeds` edits are pending.
- Rebuild the worklist and patch preview before execution.

## Execution Steps

1. `python knowledge-base/build_threat_intel_manifest.py --verify`
2. `python knowledge-base/assess_threat_intel_lifecycle.py --write-report --show-summary`
3. `python knowledge-base/build_threat_intel_archive_worklist.py --batch-id phase-1-cisa-limited-historical --write-report --show-summary`
4. `python knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id phase-1-cisa-limited-historical --write-report --show-summary`
5. `bash /Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_action_scripts/phase-1-cisa-limited-historical.sh`

## Validation Targets

- `git rm` removes the expected `147` files.
- `feed_manifest.json` rebuilds successfully.
- `lifecycle_report.json` rebuilds successfully.
- `archive_worklists/phase-1-cisa-limited-historical.json` becomes `candidate_count=0`.
- `archive_patch_previews/phase-1-cisa-limited-historical.json` becomes `removal_candidate_count=0`.
- `python knowledge-base/setup_security_threat_intel.py --verify --local-only` returns success.

## Rollback

1. `git reset --hard HEAD`
2. `git clean -fd knowledge-base/threat-intelligence/archive_worklists knowledge-base/threat-intelligence/archive_patch_previews knowledge-base/threat-intelligence/archive_action_scripts knowledge-base/threat-intelligence/archive_execution_plans`
3. `python knowledge-base/build_threat_intel_manifest.py --verify`

## Notes

- Action script path: `/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_action_scripts/phase-1-cisa-limited-historical.sh`
- This plan is generated from the current worklist and patch preview and should be regenerated if the corpus changes.

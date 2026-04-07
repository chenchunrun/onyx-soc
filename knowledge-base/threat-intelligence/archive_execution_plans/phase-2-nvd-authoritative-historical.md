# Threat-Intel Archive Execution Plan

## Batch

- `batch_id`: `phase-2-nvd-authoritative-historical`
- `description`: Second archive review batch for historical authoritative NVD feeds.
- `recommended_action`: Review whether historical authoritative NVD feeds should be archived into a separate historical package.

## Scope

- `candidate_count`: `56`
- `source`: `NIST National Vulnerability Database (NVD)`
- `quality_tier`: `authoritative`
- `years`: `2008, 2010, 2011, 2012, 2013, 2014`

## Projected Impact

- `projected_governed_total`: `1846`
- `removal_size_bytes`: `100440`
- `removed_sources`: `NIST National Vulnerability Database (NVD)=56`
- `projected_sources`: `CISA Known Exploited Vulnerabilities Catalog=1553, NIST National Vulnerability Database (NVD)=293`

## Sample Paths

- `knowledge-base/威胁情报/feeds/CVE_2008_0176.md`
- `knowledge-base/威胁情报/feeds/CVE_2010_2568.md`
- `knowledge-base/威胁情报/feeds/CVE_2010_2772.md`
- `knowledge-base/威胁情报/feeds/CVE_2010_4740.md`
- `knowledge-base/威胁情报/feeds/CVE_2011_1565.md`
- `knowledge-base/威胁情报/feeds/CVE_2011_1566.md`
- `knowledge-base/威胁情报/feeds/CVE_2011_1567.md`
- `knowledge-base/威胁情报/feeds/CVE_2011_1568.md`
- `knowledge-base/威胁情报/feeds/CVE_2011_2214.md`
- `knowledge-base/威胁情报/feeds/CVE_2011_2959.md`

## Preconditions

- Run in a clean git worktree or disposable branch.
- Ensure the repo-level Python environment is available.
- Confirm no unrelated `knowledge-base/威胁情报/feeds` edits are pending.
- Rebuild the worklist and patch preview before execution.

## Execution Steps

1. `python knowledge-base/build_threat_intel_manifest.py --verify`
2. `python knowledge-base/assess_threat_intel_lifecycle.py --write-report --show-summary`
3. `python knowledge-base/build_threat_intel_archive_worklist.py --batch-id phase-2-nvd-authoritative-historical --write-report --show-summary`
4. `python knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id phase-2-nvd-authoritative-historical --write-report --show-summary`
5. `bash /Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_action_scripts/phase-2-nvd-authoritative-historical.sh`

## Validation Targets

- `git rm` removes the expected `56` files.
- `feed_manifest.json` rebuilds successfully.
- `lifecycle_report.json` rebuilds successfully.
- `archive_worklists/phase-2-nvd-authoritative-historical.json` becomes `candidate_count=0`.
- `archive_patch_previews/phase-2-nvd-authoritative-historical.json` becomes `removal_candidate_count=0`.
- `python knowledge-base/setup_security_threat_intel.py --verify --local-only` returns success.

## Rollback

1. `git reset --hard HEAD`
2. `git clean -fd knowledge-base/threat-intelligence/archive_worklists knowledge-base/threat-intelligence/archive_patch_previews knowledge-base/threat-intelligence/archive_action_scripts knowledge-base/threat-intelligence/archive_execution_plans`
3. `python knowledge-base/build_threat_intel_manifest.py --verify`

## Notes

- Action script path: `/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_action_scripts/phase-2-nvd-authoritative-historical.sh`
- This plan is generated from the current worklist and patch preview and should be regenerated if the corpus changes.

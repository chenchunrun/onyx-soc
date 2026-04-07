# Threat-Intel Archive Execution Record

## Batch

- `batch_id`: `phase-2-nvd-authoritative-historical`
- `description`: Second archive review batch for historical authoritative NVD feeds.
- `recommended_action`: Review whether historical authoritative NVD feeds should be archived into a separate historical package.

## Approval

- `requested_by`:
- `approved_by`:
- `approval_date`:
- `change_ticket`:

## Execution Context

- `operator`:
- `execution_date`:
- `branch_or_worktree`:
- `execution_mode`: `preview` / `apply`
- `result`: `pending`

## Scope Snapshot

- `candidate_count`: `56`
- `source`: `NIST National Vulnerability Database (NVD)`
- `quality_tier`: `authoritative`
- `years`: `2008, 2010, 2011, 2012, 2013, 2014`
- `projected_governed_total_after_apply`: `1846`
- `removal_size_bytes`: `100440`

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

## Reference Artifacts

- `execution_plan`: `/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_execution_plans/phase-2-nvd-authoritative-historical.md`
- `worklist`: `knowledge-base/threat-intelligence/archive_worklists/phase-2-nvd-authoritative-historical.json`
- `patch_preview`: `knowledge-base/threat-intelligence/archive_patch_previews/phase-2-nvd-authoritative-historical.json`
- `execution_result`: `/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_execution_results/phase-2-nvd-authoritative-historical.json`

## Execution Checklist

- [ ] Manifest verification completed before execution
- [ ] Lifecycle report refreshed before execution
- [ ] Archive worklist refreshed before execution
- [ ] Patch preview refreshed before execution
- [ ] Archive action script executed in clean worktree or disposable branch

## Validation Results

- [ ] `git rm` removed the expected `56` files
- [ ] `feed_manifest.json` rebuilt successfully
- [ ] `lifecycle_report.json` rebuilt successfully
- [ ] `archive_worklists/phase-2-nvd-authoritative-historical.json` reached `candidate_count=0`
- [ ] `archive_patch_previews/phase-2-nvd-authoritative-historical.json` reached `removal_candidate_count=0`
- [ ] `setup_security_threat_intel.py --verify --local-only` returned success

## Observed Outputs

- `git diff summary`:
- `post-apply governed_total`:
- `post-apply unmanaged_local_feeds`:
- `post-apply archive_candidates`:

## Rollback

- `rollback_triggered`: `no`
- `rollback_reason`:
- `rollback_commands_executed`:

## Notes

- This record is a template. Fill it during the real archive execution.
- Regenerate it if the corresponding execution plan, worklist, or patch preview changes.

# Threat-Intel Archive Execution Record

## Batch

- `batch_id`: `phase-1-cisa-limited-historical`
- `description`: First archive review batch for low-value historical CISA placeholder feeds.
- `recommended_action`: Archive or remove placeholder-heavy historical CISA feeds from the governed package after review.

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

- `candidate_count`: `147`
- `source`: `CISA Known Exploited Vulnerabilities Catalog`
- `quality_tier`: `limited`
- `years`: `2002, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014`
- `projected_governed_total_after_apply`: `1755`
- `removal_size_bytes`: `141712`

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

## Reference Artifacts

- `execution_plan`: `/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_execution_plans/phase-1-cisa-limited-historical.md`
- `worklist`: `knowledge-base/threat-intelligence/archive_worklists/phase-1-cisa-limited-historical.json`
- `patch_preview`: `knowledge-base/threat-intelligence/archive_patch_previews/phase-1-cisa-limited-historical.json`
- `execution_result`: `/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence/archive_execution_results/phase-1-cisa-limited-historical.json`

## Execution Checklist

- [ ] Manifest verification completed before execution
- [ ] Lifecycle report refreshed before execution
- [ ] Archive worklist refreshed before execution
- [ ] Patch preview refreshed before execution
- [ ] Archive action script executed in clean worktree or disposable branch

## Validation Results

- [ ] `git rm` removed the expected `147` files
- [ ] `feed_manifest.json` rebuilt successfully
- [ ] `lifecycle_report.json` rebuilt successfully
- [ ] `archive_worklists/phase-1-cisa-limited-historical.json` reached `candidate_count=0`
- [ ] `archive_patch_previews/phase-1-cisa-limited-historical.json` reached `removal_candidate_count=0`
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

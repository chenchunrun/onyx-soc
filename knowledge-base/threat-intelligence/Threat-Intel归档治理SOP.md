# Threat-Intel 归档治理 SOP

## 1. 目标

本文档用于规范 threat-intel 生命周期治理中的归档动作，明确：

- 什么内容继续保留为运行态 feed
- 什么内容进入 historical package
- 什么内容进入 archive 执行批次
- 归档前审批、执行、验证、回滚的固定步骤


## 2. 对象边界

### 2.1 运行态 feed

指仍保留在 `knowledge-base/威胁情报/feeds/` 下、继续进入主知识包和运行态同步的内容。

适用条件：

- 生命周期评估结果为 `active`
- 或虽较旧，但被评估为 `retained_historical`
- 或仍有当前调查、检索、研判价值


### 2.2 historical package

指已经脱离主运行态 feed，但仍保存在：

- `knowledge-base/threat-intelligence/historical_packages/`

适用条件：

- 生命周期评估结果为 `archive_candidate`
- 且经评审确认应从主运行态包移出
- 但仍需保留可审计、可追溯、可重建的历史内容


### 2.3 archive batch

指一次具体归档执行单元，包含：

- `archive_worklists/`
- `archive_patch_previews/`
- `archive_action_scripts/`
- `archive_execution_plans/`
- `archive_execution_records/`
- `archive_execution_results/`

它不是长期状态，而是一次可审查、可执行、可验证的变更记录。


## 3. 准入规则

只有同时满足以下条件，条目才可进入 archive review：

1. `assess_threat_intel_lifecycle.py` 判定为 `archive_candidate`
2. 不在 `archive_exempt_sources` 或 `archive_exempt_cve_ids` 中
3. 当前批次有明确的 `source / quality_tier / years` 分组依据
4. 本轮归档不会破坏主运行态知识包的最小覆盖目标

以下情况不应直接归档：

- 仍被当前 playbook、知识问答或调查流程高频引用的内容
- 虽旧但属于权威基础资料、且尚无替代聚合形式的内容
- 尚未完成 manifest / lifecycle / patch preview 一致性检查的内容


## 4. 审批前准备

在创建或批准 archive batch 前，必须先完成：

1. `python knowledge-base/build_threat_intel_manifest.py --verify`
2. `python knowledge-base/assess_threat_intel_lifecycle.py --write-report --show-summary`
3. `python knowledge-base/build_threat_intel_archive_worklist.py --write-report --show-summary`
4. `python knowledge-base/build_threat_intel_archive_patch_preview.py --write-report --show-summary`
5. 如需形成历史知识包，先准备对应 historical package 输出

审批材料至少应包含：

- `batch_id`
- `candidate_count`
- `source`
- `quality_tier`
- `years`
- `recommended_action`
- `projected_governed_total`
- `removal_size_bytes`
- sample paths / sample CVE IDs


## 5. 审批要求

每个 batch 在执行前应明确以下结论：

- 是否批准执行
- 执行模式是 `preview` 还是 `apply`
- 执行窗口和负责人
- 回滚负责人
- 执行后验收标准

最小审批结论建议记录在：

- `archive_execution_plans/<batch_id>.md`
- 或组织内部工单 / 评审单中


## 6. 执行步骤

推荐执行顺序：

1. 确认当前 git worktree 干净，或在专用分支执行
2. 重新生成 manifest / lifecycle / worklist / patch preview
3. 生成 execution plan
4. 执行 `archive_action_script`
5. 重建 manifest 和 lifecycle report
6. 构建 execution result
7. 如需要，重建 historical package catalog

最低执行命令链应包含：

1. `python knowledge-base/build_threat_intel_manifest.py --verify`
2. `python knowledge-base/assess_threat_intel_lifecycle.py --write-report --show-summary`
3. `python knowledge-base/build_threat_intel_archive_worklist.py --batch-id <batch_id> --write-report --show-summary`
4. `python knowledge-base/build_threat_intel_archive_patch_preview.py --batch-id <batch_id> --write-report --show-summary`
5. `bash knowledge-base/threat-intelligence/archive_action_scripts/<batch_id>.sh`
6. `python knowledge-base/build_threat_intel_archive_execution_result.py --batch-id <batch_id> --write-result --show-summary`


## 7. 执行后验证

执行完成后，至少确认：

1. `feed_manifest.json` 可重建且通过校验
2. `lifecycle_report.json` 可重建
3. `archive_execution_results/<batch_id>.json` 中：
   - `completed=true`
   - `remaining_candidate_count=0`
   - `remaining_batch_candidate_count=0`
   - `consistency_issue_count=0`
4. `archive_worklists/<batch_id>.json` 与 lifecycle report 一致
5. `historical_packages/index.json` 与实际 package 目录一致
6. `python knowledge-base/setup_security_threat_intel.py --verify --local-only` 返回成功


## 8. 回滚规则

以下情况必须回滚或停止继续推进：

- execution result 显示 `completed=false`
- batch 内目标项仍残留在 lifecycle report
- manifest 总量与 patch preview 预测不一致
- historical package catalog 与实际产物不一致
- 执行中混入无关 feed 变更

最小回滚步骤：

1. 回退本次 archive action script 造成的文件删除/移动
2. 重建 manifest
3. 重建 lifecycle report
4. 重新执行 consistency 检查
5. 在 execution record 中记录回滚原因


## 9. 运行节奏建议

建议采用固定节奏，而不是临时清理：

- 每次 threat-intel 正式知识包更新后，重新评估 lifecycle
- archive candidates 超过阈值时，生成新一轮 archive plan
- 每次只执行一到两个批次，避免一次性大范围移除
- historical package catalog 每次变更后都重新生成


## 10. 关联脚本与产物

- `knowledge-base/assess_threat_intel_lifecycle.py`
- `knowledge-base/build_threat_intel_archive_worklist.py`
- `knowledge-base/build_threat_intel_archive_patch_preview.py`
- `knowledge-base/build_threat_intel_archive_action_script.py`
- `knowledge-base/build_threat_intel_archive_execution_plan.py`
- `knowledge-base/build_threat_intel_archive_execution_result.py`
- `knowledge-base/check_threat_intel_historical_package_consistency.py`

关联目录：

- `knowledge-base/threat-intelligence/archive_worklists/`
- `knowledge-base/threat-intelligence/archive_patch_previews/`
- `knowledge-base/threat-intelligence/archive_action_scripts/`
- `knowledge-base/threat-intelligence/archive_execution_plans/`
- `knowledge-base/threat-intelligence/archive_execution_records/`
- `knowledge-base/threat-intelligence/archive_execution_results/`
- `knowledge-base/threat-intelligence/historical_packages/`

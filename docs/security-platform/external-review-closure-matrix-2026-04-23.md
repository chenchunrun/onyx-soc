# 外部代码评审闭环矩阵（2026-04-23）

## 1. 文档目的
本文件用于对外部评审意见进行“可追溯闭环”说明，覆盖：
- 风险项到工程改动的映射
- 已完成项的证据（Commit / 关键文件 / 测试）
- 未完成项的剩余风险与下一步验收标准

适用范围：`onyx-main`（当前分支：`codex-perf-security-hardening-pack`）。

## 2. 外部评审关注点（归并）
外部评审核心关注三条主线：
1. 边界清晰：平台主干与定制层解耦，避免多处重复判定逻辑。
2. 权限统一：runtime skill / MCP / billing 的权限与安全边界可治理、可审计。
3. 异步可控：连接器任务、billing 失败、运行时激活失败要有可恢复降级路径。

## 3. 闭环矩阵（P0/P1/P2）

### P0（事故预防优先）

| 评审项 | 状态 | 落地说明 | 证据 |
|---|---|---|---|
| Runtime Skill 授权统一化 | 已完成（第一批） | 将 `persona runtime profile` 中分散可访问判定收敛到 registry 统一入口；授权规则复用单一判定函数 | `6426d974a`；`backend/onyx/server/manage/skills/registry.py`；`backend/onyx/server/features/persona/runtime_profile.py` |
| Runtime Skill 激活审计 | 已完成（第一批） | 新增 runtime 激活审计记录（用户、技能、目标、审批引用、阻断原因）并接入管理端 API | `9edfaca45`；`backend/onyx/server/manage/skills/registry.py`；`backend/onyx/server/manage/skills/api.py`；`backend/onyx/chat/process_message.py` |
| MCP 头安全边界（默认拒绝） | 已完成 | 请求透传头由 denylist 升级为 allowlist（默认拒绝），支持 `MCP_REQUEST_HEADER_ALLOWLIST` 扩展 | `2ec5b6488`；`backend/onyx/tools/tool_implementations/mcp/mcp_tool.py` |
| Billing / License 状态机语义化 | 已完成（第一版） | 新增运营态 `valid/grace_period/expired/verification_failed/disconnected_cached`，并输出到 license/billing API | `dd05eb2aa`；`backend/ee/onyx/server/license/models.py`；`backend/ee/onyx/server/license/runtime_state.py`；`backend/ee/onyx/server/billing/models.py` |
| Billing circuit breaker 降级策略 | 已完成（可配置） | 新增开关 `BILLING_CIRCUIT_RETURN_CACHED_STATE_ENABLED`，circuit-open 时可返回缓存态而非直接 503 | `931ea7c27`；`backend/ee/onyx/configs/app_configs.py`；`backend/ee/onyx/server/billing/api.py` |
| 前端重复语义渲染修复 | 已完成 | 修复 agent 描述区域 Prompt/Skill 重复展示问题 | `6426d974a`；`web/src/app/app/components/AgentDescription.tsx` |

### P1（演进成本与可升级性）

| 评审项 | 状态 | 当前结论 | 下一步 |
|---|---|---|---|
| `main.py` 路由聚合过重 | 未开始 | 仍存在主入口聚合过厚问题 | 按领域拆分路由（chat / connector / persona-skill / billing-license / security-platform） |
| `models.py` 大文件拆分 | 未开始 | 仍存在模型集中定义导致认知负担与迁移耦合 | 按领域拆分（identity/chat/connector/persona/security-platform） |
| service/usecase 分层约束 | 部分完成 | skill 与 billing 已开始出现统一入口，但未形成统一分层规范 | 对 connector 删除、skill 绑定、license 判定补 service 层边界 |
| security-platform 与 upstream 解耦 | 未开始 | 定制层仍需进一步梳理侵入点 | 建立扩展点清单：配置型/插件型/资产型，限制主干语义改写 |

### P2（可观测性与体验）

| 评审项 | 状态 | 落地说明 | 证据 |
|---|---|---|---|
| Billing / License 运行态前端可见 | 已完成（首批） | Admin Billing 页面展示 `operational_state` 风险提示；AccessRestricted 页面展示恢复指引；LicenseActivationCard 显示状态修复建议 | `a07200dd1`、`7a02bf7e9`、`d4d5d1001`；`web/src/app/admin/billing/page.tsx`；`web/src/app/admin/billing/LicenseActivationCard.tsx`；`web/src/components/errorPages/AccessRestrictedPage.tsx` |
| Runtime Skill 激活失败可解释 | 已完成（首批） | 阻断原因结构化返回并可审计 | `9edfaca45` |
| RAG token 预算器 / SSE resumable /工具降级统一 | 未开始 | 仍为风险高发区 | 纳入下一批迭代，先出技术设计与验收指标 |

## 4. 本轮提交清单（与评审意见直接相关）
- `6426d974a` Unify runtime skill access checks and remove duplicate agent bindings
- `9edfaca45` Add runtime skill activation audit trail
- `2ec5b6488` Harden MCP request header forwarding with allowlist
- `dd05eb2aa` Add license operational state model for billing and license APIs
- `931ea7c27` Add configurable cached fallback when billing circuit is open
- `a07200dd1` Show billing operational state banners in admin billing UI
- `7a02bf7e9` Add operational-state recovery guidance to license activation card
- `d4d5d1001` Show license operational guidance on access restricted page

## 5. 测试与验证快照
- 后端单测：
  - `backend/tests/unit/onyx/server/manage/test_skill_registry.py`（通过）
  - `backend/tests/unit/onyx/server/features/persona/test_runtime_profile.py`（通过）
  - `backend/tests/unit/ee/onyx/server/license/test_runtime_state.py`（通过）
- 前端测试：
  - `web/src/app/admin/billing/page.test.tsx`（通过）
  - `web/src/app/admin/billing/LicenseActivationCard.test.tsx`（通过）
  - `web/src/components/errorPages/AccessRestrictedPage.test.tsx`（通过）
- 环境限制说明：
  - `external_dependency_unit` 中依赖本地 Postgres 的测试在受限沙箱下会受网络权限影响，需在完整本地环境复验。

## 6. 剩余高优先风险（未闭环）
1. Connector 删除与运行中任务并发一致性（fence/version 状态机化尚未完成）。
2. Chat 主链路 token 预算器、SSE 断连恢复、tool failure 标准降级尚未落地。
3. 架构层大文件/聚合入口拆分未启动，升级成本与知识集中风险仍在。

## 7. 下一批建议执行项（建议按序）
1. Connector 生命周期状态机（`active/pausing/deleting/deleted/error/reauth_required`）+ 任务幂等 fence。
2. Chat token 预算器（system/history/retrieval/tool/output 五段预算）+ 工具失败降级统一路径。
3. `main.py` 路由按领域拆分 + service/usecase 边界收口。


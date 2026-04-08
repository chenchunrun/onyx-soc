# Onyx 智能安全底座文档维护清单

## 1. 文档目标

本文档用于明确当前 `docs/security-platform/` 文档体系的维护边界，减少后续重复修改、口径漂移和历史材料误用。


## 2. 当前正式真相源

以下文档应视为当前版本的正式真相源，功能、状态或交付边界变化时应优先维护：

- `docs/TODO.md`
- `docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md`
- `docs/security-platform/README.md`
- `docs/security-platform/1-requirements.md`
- `docs/security-platform/2-architecture.md`
- `docs/security-platform/6-implementation-guide.md`
- `docs/security-platform/7-deployment.md`
- `docs/security-platform/8-expert-review-notes.md`
- `docs/security-platform/9-minimal-acceptance-checklist.md`
- `docs/security-platform/12-development-backlog.md`
- `docs/security-platform/17-release-notes.md`
- `docs/security-platform/18-deliverable-boundary.md`


## 3. 当前正式能力文档

以下文档用于描述系统本体能力，应随功能变化同步维护：

- `docs/security-platform/4-agents/`
- `docs/security-platform/5-integrations/`
- `docs/security-platform/playbooks/`


## 4. 当前阶段性材料

以下文档主要用于阶段性汇报、沟通和同步，不应替代正式真相源：

- `docs/security-platform/10-phase-update-summary.md`
- `docs/security-platform/11-leadership-update-draft.md`
- `docs/security-platform/13-leadership-brief.md`
- `docs/security-platform/14-weekly-status-message.md`
- `docs/security-platform/15-meeting-minutes-version.md`
- `docs/security-platform/16-external-update-email.md`

维护原则：

- 若只是项目状态变化，优先更新正式真相源，不要求同步逐份改写所有阶段性材料
- 只有在需要再次发送、汇报或复用这些材料时，再做一次性更新


## 5. 当前可归档但保留的材料

以下文档建议保留，但默认不再高频维护：

- `docs/security-platform/17-release-notes.md`
  用于版本对外说明，可在阶段冻结时更新
- `docs/security-platform/18-deliverable-boundary.md`
  用于对外交付边界说明，只有版本定位变化时更新
- `docs/security-platform/19-document-maintenance-checklist.md`
  用于维护规则说明，只有文档体系发生变化时更新


## 6. 更新优先级建议

当后续再次发生功能变化时，建议按以下顺序更新：

1. `docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md`
2. `docs/TODO.md`
3. `docs/security-platform/12-development-backlog.md`
4. `docs/security-platform/README.md`
5. 对应正式能力文档
6. 必要时再更新阶段性材料


## 7. 何时需要更新文档

以下变化发生时，应更新正式真相源：

- 新增或移除 persona / tools / playbooks
- deployment profile、required env、Secret 规则变化
- 验收链路、健康检查或安全工作台摘要变化
- threat-intel 生命周期治理规则变化
- 企业能力最小收口状态变化
- 版本定位或可交付边界变化


## 8. 何时不需要全量改写

以下情况一般不需要把所有阶段性材料全部重写：

- 单个测试结果数量变化
- 某条周报表述过期，但不会再次复用
- 某次会议纪要中的历史过程描述

处理原则：

- 保证正式真相源始终正确
- 阶段性材料只在再次被使用前更新

# Onyx 智能安全底座文档索引

## 1. 文档目标

本文档用于作为 `docs/security-platform/` 的统一入口，帮助团队快速定位当前有效文档、阶段性材料和后续待办。


## 2. 阅读顺序

如果你是第一次接触该项目，建议按以下顺序阅读：

1. [需求说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/1-requirements.md)
2. [架构说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/2-architecture.md)
3. [实施指南](/Users/newmba/Downloads/onyx-main/docs/security-platform/6-implementation-guide.md)
4. [部署指南](/Users/newmba/Downloads/onyx-main/docs/security-platform/7-deployment.md)
5. [Secret 管理说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/20-secret-management.md)
6. [最小验收清单](/Users/newmba/Downloads/onyx-main/docs/security-platform/9-minimal-acceptance-checklist.md)
7. [开发 Backlog](/Users/newmba/Downloads/onyx-main/docs/security-platform/12-development-backlog.md)


## 3. 当前有效文档

以下文档优先代表当前仓库真实状态：

- [项目状态报告](/Users/newmba/Downloads/onyx-main/docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md)
  说明当前完成度、已完成能力、剩余缺口和下一步建议。
- [项目 TODO](/Users/newmba/Downloads/onyx-main/docs/TODO.md)
  维护项目级别的简版待办。
- [开发 Backlog](/Users/newmba/Downloads/onyx-main/docs/security-platform/12-development-backlog.md)
  维护 `security-platform` 目录下的详细 backlog。
- [需求说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/1-requirements.md)
- [架构说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/2-architecture.md)
- [实施指南](/Users/newmba/Downloads/onyx-main/docs/security-platform/6-implementation-guide.md)
- [部署指南](/Users/newmba/Downloads/onyx-main/docs/security-platform/7-deployment.md)
- Helm overlays 已包含 `live / gateway / demo`
- [Secret 管理说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/20-secret-management.md)
- [专家评审记录](/Users/newmba/Downloads/onyx-main/docs/security-platform/8-expert-review-notes.md)
- [最小验收清单](/Users/newmba/Downloads/onyx-main/docs/security-platform/9-minimal-acceptance-checklist.md)


## 4. 角色与集成文档

### 4.1 Agent 定义

- [安全事件分析师](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/incident-analyst.md)
- [应急响应指挥官](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/emergency-commander.md)
- [漏洞评估专家](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/vulnerability-expert.md)
- [合规审计员](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/compliance-auditor.md)
- [威胁狩猎工程师](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/threat-hunter.md)
- [恶意软件分析师](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/malware-analyst.md)
- [检测工程师](/Users/newmba/Downloads/onyx-main/docs/security-platform/4-agents/detection-engineer.md)

### 4.2 集成配置

- [集成说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/README.md)
- [profiles](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/profiles.yaml)
- [schema](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/schema.md)
- [authoring guide](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/authoring-guide.md)

### 4.3 Playbooks

- [Playbook 说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/playbooks/README.md)
- [事件研判只读流程](/Users/newmba/Downloads/onyx-main/docs/security-platform/playbooks/incident-triage-readonly.yaml)
- [事件止损与工单联动流程](/Users/newmba/Downloads/onyx-main/docs/security-platform/playbooks/incident-containment-and-ticketing.yaml)


## 5. 阶段性材料

以下文档主要用于阶段性沟通、汇报或外部同步，不应替代当前状态报告和 backlog：

- [阶段性汇报摘要](/Users/newmba/Downloads/onyx-main/docs/security-platform/10-phase-update-summary.md)
- [领导汇报草稿](/Users/newmba/Downloads/onyx-main/docs/security-platform/11-leadership-update-draft.md)
- [领导简报](/Users/newmba/Downloads/onyx-main/docs/security-platform/13-leadership-brief.md)
- [周报消息版](/Users/newmba/Downloads/onyx-main/docs/security-platform/14-weekly-status-message.md)
- [会议纪要版](/Users/newmba/Downloads/onyx-main/docs/security-platform/15-meeting-minutes-version.md)
- [外部更新邮件版](/Users/newmba/Downloads/onyx-main/docs/security-platform/16-external-update-email.md)
- [发布说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/17-release-notes.md)
- [可交付版本边界说明](/Users/newmba/Downloads/onyx-main/docs/security-platform/18-deliverable-boundary.md)
- [文档维护清单](/Users/newmba/Downloads/onyx-main/docs/security-platform/19-document-maintenance-checklist.md)

使用原则：

- 若和当前实现冲突，以 [项目状态报告](/Users/newmba/Downloads/onyx-main/docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md)、[项目 TODO](/Users/newmba/Downloads/onyx-main/docs/TODO.md)、[开发 Backlog](/Users/newmba/Downloads/onyx-main/docs/security-platform/12-development-backlog.md) 为准。


## 6. 当前文档分工

- [项目状态报告](/Users/newmba/Downloads/onyx-main/docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md)
  用于回答“当前做到了什么、还差什么”。
- [项目 TODO](/Users/newmba/Downloads/onyx-main/docs/TODO.md)
  用于回答“项目级下一步做什么”。
- [开发 Backlog](/Users/newmba/Downloads/onyx-main/docs/security-platform/12-development-backlog.md)
  用于回答“安全底座目录下详细要继续做什么”。
- `1-9` 正式文档
  用于回答“这套东西是什么、怎么实现、怎么部署、怎么验收”。
- `20` Secret 管理文档
  用于回答“生产环境里的敏感配置应如何注入、轮换和校验”。
- `10-17` 阶段性材料
  用于沟通、汇报、发布，不作为唯一真相源。


## 7. 企业能力收口状态

当前这轮优先级清单里的企业能力，已经按“管理面可见 + 验收可记录 + 健康检查可诊断”的标准完成最小收口：

- `Inherit Document Permissions`
- `Role Based Access Control (RBAC)`
- `Service Account API Keys`
- `SCIM / Group Sync`
- `Encryption of Secrets`
- `Query History and Usage Dashboard`
- `Custom Roles and Permissions`
- `Configurable Usage Limits`
- `Hook Extensions`
- `Custom Theming`
- `Full White-labeling`
- `Custom Deployments`
- `Region-Specific Data Processing`
- `Self-hosting (Optional)`

说明：

- 上述“完成”表示当前仓库已经具备基础能力，并且已接入安全工作台、验收脚本与统一健康检查。
- 这不等同于每一项都已经发展成完整独立产品线；若继续投入，会进入更深的产品化或架构演进阶段。
- `Enterprise SLAs and Priority Support` 不属于代码功能项，不纳入本收口列表。


## 8. 维护建议

- 新增正式能力时，优先更新 `1-9` 正式文档和本索引。
- 进度变化时，优先更新 [项目状态报告](/Users/newmba/Downloads/onyx-main/docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md)、[项目 TODO](/Users/newmba/Downloads/onyx-main/docs/TODO.md)、[开发 Backlog](/Users/newmba/Downloads/onyx-main/docs/security-platform/12-development-backlog.md)。
- 新增汇报材料时，放在阶段性材料区域，不要替代正式文档。

# Onyx 智能安全底座需求说明

## 1. 文档目标

本文档说明当前 Onyx 智能安全底座二开版本的目标范围、核心能力、交付边界和约束条件。


## 2. 项目目标

基于 Onyx 主平台构建一套面向安全运营场景的智能底座，满足以下需求：

- 支持安全知识检索与问答
- 支持面向安全角色的 persona / agent 使用方式
- 支持告警、工单、威胁情报等安全工具联动
- 支持安全团队账号、可见性和权限初始化
- 支持通过统一脚本完成首次初始化
- 支持将威胁情报 feed 同步到 Onyx


## 3. 当前范围

当前版本已覆盖以下范围：

- 安全知识库 markdown 内容沉淀
- 知识库导入脚本
- 四个标准安全 persona 初始化
- 四个安全 Agent 定义文档
- OpenAPI 安全工具创建与绑定
- 声明式工具集成配置管理
- 安全技能（Skills）库与 persona 绑定
- `load_skill` 工具支持按需加载技能指令
- 威胁情报 feed 同步与校验
- threat-intel manifest、curation、生命周期治理、historical package 管理
- 安全团队 RBAC 初始化
- 统一 bootstrap 编排脚本
- 安全工作台 API 与前端页面
- 最小验收、smoke、基础回归测试
- 安全工作台轻量运维摘要：
  - 工具调用审计摘要
  - 配置漂移检查
  - 最近失败项摘要
- 主要企业能力的管理面可见性与验收收口：
  - Document Permissions / RBAC / Custom Permissions
  - Service Accounts / SCIM / Query History / Usage Limits
  - Hooks / Secrets Encryption
  - Custom Theming / White-labeling
  - Custom Deployments / Region Processing / Self-hosting

当前版本暂不包含：

- 独立 Helm chart 或独立 compose 项目
- 完整商业化情报源接入
- 面向企业 secret manager 的完整生产化接入说明
- 完整运维审计与观测体系


## 4. 目标用户

- 安全事件分析师
- 应急响应指挥官
- 漏洞评估专家
- 合规审计员
- 平台管理员


## 5. 核心功能需求

### 5.1 安全知识能力

- 能导入 `knowledge-base/` 下的安全文档
- 能将知识纳入 Onyx 检索体系
- 能支撑 persona 在安全场景中的 RAG 问答


### 5.2 安全 persona 能力

- 具备一组标准安全 persona，至少覆盖事件分析、应急指挥、漏洞评估、合规审计、威胁狩猎、恶意软件分析、检测工程
- persona 拥有明确角色说明、提示词和基础工具集
- 四个角色具备独立 Agent 定义文档
- persona 可通过脚本创建或更新
- persona 不依赖固定 ID 才能完成初始化链路


### 5.3 安全工具联动

- 支持告警发送
- 支持安全工单创建
- 支持威胁情报查询
- 支持安全告警检索
- 支持终端隔离动作
- 支持资产上下文查询
- 工具可按 persona 绑定
- 工具定义与 persona 绑定关系应通过声明式配置管理


### 5.3.1 安全技能（Skills）

- 具备一组可复用的安全技能，覆盖日志分析、OSINT、漏洞评估、恶意软件分析、威胁狩猎、合规审计等场景
- 技能以 `SKILL.md` 形式沉淀在 `skills/` 目录，包含完整工作流、脚本和参考文件
- persona 可通过 `skill_keys` 绑定技能，运行时通过 `load_skill` 工具按需加载技能完整指令
- 技能访问控制（risk_level / access_scope / execution_scope）通过 `registry.yaml` 声明式管理
- 高风险技能（如主动侦察、逆向工程）默认 quarantined，需审批后方可启用


### 5.4 权限与团队初始化

- 可创建安全团队测试账号
- 可为不同角色绑定 persona 可见性
- 可为用户绑定目标 document set
- 可执行环境预检查


### 5.5 初始化与可运维性

- 提供统一 bootstrap 脚本
- 支持 `dry-run / apply / verify`
- 支持按阶段执行
- 支持失败中断和结果汇总
- 提供最小验收与 smoke 校验入口
- 提供运行状态查看入口
- 提供轻量级管理面摘要，支持定位配置、权限、同步和部署模式问题


## 6. 非功能要求

- 尽量复用 Onyx 现有 API 和数据模型
- 避免依赖固定 persona ID
- 支持幂等执行，重复运行不应破坏已有配置
- 文档必须与当前仓库实现一致


## 7. 当前交付物

- `docs/security-platform/1-requirements.md`
- `docs/security-platform/2-architecture.md`
- `docs/security-platform/4-agents/`
- `docs/security-platform/5-integrations/`
- `docs/security-platform/playbooks/`
- `docs/security-platform/6-implementation-guide.md`
- `docs/security-platform/7-deployment.md`
- `docs/security-platform/8-expert-review-notes.md`
- `docs/security-platform/9-minimal-acceptance-checklist.md`
- `knowledge-base/bootstrap_security_platform.py`
- `knowledge-base/setup_security_threat_intel.py`
- `knowledge-base/setup_security_personas.py`
- `knowledge-base/run_security_playbook.py`
- `knowledge-base/upload_to_onyx.py`
- `knowledge-base/security-automation/setup_security_tools.py`
- `knowledge-base/sso-rbac/provision_security_team.py`
- `knowledge-base/verify_security_platform_acceptance.py`
- `skills/` 安全技能库（35 个技能，含 `SKILL.md`、脚本和参考文件）
- `backend/onyx/server/manage/skills/registry.yaml` 技能访问控制注册表
- `backend/onyx/tools/tool_implementations/skill/skill_tool.py` `load_skill` 工具实现
- `docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md`
- `docs/TODO.md`


## 8. 当前缺口

- 部署资产仍以主仓部署方式为主
- 生产化配置与 Secret 管理说明仍需继续收口
- 威胁情报上游刷新仍依赖外部网络与源站可用性
- 商业情报源仍未扩展
- 更深的运营统计、长期趋势看板与生产化审计策略仍未完善

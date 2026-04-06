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


## 3. 当前范围

当前版本已覆盖以下范围：

- 安全知识库 markdown 内容沉淀
- 知识库导入脚本
- 四个标准安全 persona 初始化
- OpenAPI 安全工具创建与绑定
- 安全团队 RBAC 初始化
- 统一 bootstrap 编排脚本
- 部分集成测试与新增单元测试

当前版本暂不包含：

- 安全底座专属前端产品壳
- 独立 Helm chart 或独立 compose 项目
- 完整商业化情报源接入
- 专门的专家评审记录体系


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

- 具备四个标准安全 persona
- persona 拥有明确角色说明、提示词和基础工具集
- persona 可通过脚本创建或更新
- persona 不依赖固定 ID 才能完成初始化链路


### 5.3 安全工具联动

- 支持告警发送
- 支持安全工单创建
- 支持威胁情报查询
- 工具可按 persona 绑定


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


## 6. 非功能要求

- 尽量复用 Onyx 现有 API 和数据模型
- 避免依赖固定 persona ID
- 支持幂等执行，重复运行不应破坏已有配置
- 文档必须与当前仓库实现一致


## 7. 当前交付物

- `knowledge-base/bootstrap_security_platform.py`
- `knowledge-base/setup_security_personas.py`
- `knowledge-base/upload_to_onyx.py`
- `knowledge-base/security-automation/setup_security_tools.py`
- `knowledge-base/sso-rbac/provision_security_team.py`
- `knowledge-base/Bootstrap-初始化指南.md`
- `docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md`
- `docs/TODO.md`


## 8. 当前缺口

- agent 定义文档尚未全部补齐
- 部署资产仍以主仓部署方式为主
- 真实环境下的完整验收链路仍需补充
- 商业情报源和生产化审计策略仍未完善

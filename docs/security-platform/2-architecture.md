# Onyx 智能安全底座架构说明

## 1. 架构目标

当前安全底座不是独立产品代码仓，而是基于 Onyx 主仓叠加安全知识、persona、工具和初始化脚本形成的定制层。


## 2. 架构分层

### 2.1 平台底座层

由 Onyx 主平台提供：

- FastAPI 后端
- Persona / Tool / Document Set 数据模型
- 检索、聊天、工具调用链路
- RBAC / SSO / 审计基础能力


### 2.2 安全知识层

目录：

- `knowledge-base/`

作用：

- 提供安全策略、应急响应、威胁情报、合规基线、最佳实践内容
- 作为安全 persona 的主要知识来源


### 2.3 安全角色层

入口：

- `knowledge-base/setup_security_personas.py`

当前标准角色：

- 安全事件分析师
- 应急响应指挥官
- 漏洞评估专家
- 合规审计员

角色通过 persona 实体落地，而不是单独的运行时子系统。


### 2.4 威胁情报层

入口：

- `knowledge-base/setup_security_threat_intel.py`
- `knowledge-base/threat-intelligence/threat_intel_aggregator.py`

主要职责：

- 管理 `knowledge-base/威胁情报/feeds` 下的本地威胁情报 feed
- 将本地 threat-intel 文档同步到 Onyx ingestion
- 按需从上游源刷新本地 feed
- 为 bootstrap 提供 `dry-run / apply / verify` 标准入口
- 通过 `sync_plan.yaml` 和 `sync_state.json` 提供周期化同步入口


### 2.5 文档集层

入口：

- `knowledge-base/setup_security_document_set.py`

主要职责：

- 确保名称为 `安全知识库` 的 document set 存在
- 为 persona 初始化和 RBAC 授权提供统一目标对象


### 2.6 安全工具层

入口：

- `knowledge-base/security-automation/setup_security_tools.py`
- `docs/security-platform/5-integrations/`

当前主要工具：

- `send_security_alert`
- `create_security_ticket`
- `threat_intel_lookup`

这些工具通过 Onyx OpenAPI custom tool 机制创建，并附着到 persona。

实现方式：

- `docs/security-platform/5-integrations/*.yaml` 负责声明工具名称、模板、环境变量和 persona 绑定
- `knowledge-base/security-automation/openapi_templates/` 提供 OpenAPI 模板
- `setup_security_tools.py` 读取声明式配置并执行创建与绑定


### 2.7 权限与用户层

入口：

- `knowledge-base/sso-rbac/provision_security_team.py`

主要职责：

- 创建安全团队测试账号
- 设置 persona 可见性
- 绑定用户与 document set
- 建立 persona 与 user 的访问控制关系


### 2.8 初始化编排层

入口：

- `knowledge-base/bootstrap_security_platform.py`

负责串联以下阶段：

- `knowledge-base`
- `threat-intel`
- `document-set`
- `personas`
- `tools`
- `rbac`


## 3. 关键数据依赖

### 3.1 Document Set

当前通过专用脚本确保存在一个名称为 `安全知识库` 的 document set，供 persona 绑定与用户授权使用。


### 3.2 Persona

当前 persona 不再依赖固定 ID，而是通过名称进行解析，降低初始化顺序和环境差异带来的风险。


### 3.3 Tool

内置工具通过 display name 匹配：

- `Internal Search`
- `Web Search`
- `Open URL`
- `Code Interpreter`

安全自定义工具通过名称匹配：

- `send_security_alert`
- `create_security_ticket`
- `threat_intel_lookup`


## 4. 初始化数据流

1. 导入安全知识文档到 Onyx
2. 同步本地威胁情报 feed 到 Onyx
3. 创建或更新四个安全 persona
4. 创建 OpenAPI 安全工具
5. 将工具绑定到 persona
6. 创建安全团队用户并绑定权限


## 5. 当前实现特点

- 高度复用 Onyx 现有 API
- 以脚本编排为主，而非 migration/seed 框架
- 适合 PoC 和内部试运行
- 已开始向标准化交付结构收敛
- 威胁情报同步已进入 bootstrap 主链路


## 6. 当前主要限制

- 对环境准备有一定前置依赖
- 威胁情报上游刷新依赖外部网络与源站可用性
- 真正的一键部署资产尚未补齐
- 完整生产验收文档仍在补齐阶段

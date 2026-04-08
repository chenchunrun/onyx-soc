# Onyx 智能安全底座项目完成情况报告

## 1. 报告目的

本文档基于仓库当前代码、知识库内容、自动化脚本、测试与项目文档，对安全底座二开方案的当前落地情况进行复核，并给出完成度判断、已完成能力、剩余缺口与下一步建议。


## 2. 评估范围

本次评估主要基于以下内容：

- 安全底座文档目录：`docs/security-platform/`
- 安全底座脚本与知识目录：`knowledge-base/`
- 安全工作台 API 与页面
- Docker Compose / Helm 安全底座覆盖资产
- 单测与集成回归：
  - `backend/tests/unit/knowledge_base/`
  - `backend/tests/unit/onyx/server/manage/test_security_platform_api.py`
  - `backend/tests/integration/tests/security_tools/test_security_tools_chain.py`
  - `backend/tests/integration/tests/security_platform/test_security_platform_regression.py`


## 3. 总体判断

### 3.1 总体完成度

综合当前仓库状态判断，项目完成度约为 **80% - 85%**。

### 3.2 结论摘要

当前项目已经从“零散脚本 + 方案设想”推进到“可部署、可初始化、可验收、可演示”的阶段。

已经具备的关键特征包括：

- `docs/security-platform/` 交付文档结构已形成
- 四个安全 Agent 定义已落库
- `bootstrap` 初始化链路已闭环
- `安全知识库`、persona、tools、RBAC 可自动创建并校验
- threat-intel 同步、manifest、curation、生命周期治理、historical package 管理已落地
- 安全工作台 API 与 Web 页面已可展示运行状态
- 最小验收、smoke、工具链回归、安全平台回归已具备基础覆盖
- 安全工作台已补齐轻量运维面：
  - 工具调用审计摘要
  - 配置漂移检查
  - 最近失败项摘要
- 企业能力最小收口已完成：
  - Document Permissions
  - RBAC / Custom Permissions
  - Service Account API Keys
  - SCIM / Group Sync
  - Encryption of Secrets
  - Query History and Usage Dashboard
  - Configurable Usage Limits
  - Hook Extensions
  - Custom Theming / White-labeling
  - Custom Deployments
  - Region-Specific Data Processing
  - Self-hosting
- Docker Compose / Helm 安全底座覆盖配置已提供

当前整体已经达到：

- `PoC / 内部试运行基线版本`

并且已经具备：

- 主要企业能力的管理面可见性
- 与验收脚本一致的健康检查与修复建议
- 基于安全工作台的轻量运维与诊断入口

当前剩余工作重点不再是“功能能否成立”，而是：

- 生产化配置收口
- 回归矩阵继续增强
- threat-intel 生命周期持续治理
- 运维观测与审计能力补强


## 4. 已完成项

### 4.1 交付文档主结构已成型

当前仓库已经具备完整的安全底座文档目录：

- `docs/security-platform/1-requirements.md`
- `docs/security-platform/2-architecture.md`
- `docs/security-platform/4-agents/`
- `docs/security-platform/5-integrations/`
- `docs/security-platform/6-implementation-guide.md`
- `docs/security-platform/7-deployment.md`
- `docs/security-platform/8-expert-review-notes.md`
- `docs/security-platform/9-minimal-acceptance-checklist.md`

这意味着方案文档承诺的主交付结构已经基本落库，不再是缺口。


### 4.2 初始化链路已闭环

当前已完成以下自动化能力：

- 安全知识导入
- `安全知识库` document set 自动创建
- 四个安全 persona 自动创建/更新
- 六个安全 OpenAPI 工具自动创建与绑定
- 安全团队用户与 RBAC 自动初始化
- `bootstrap --dry-run / --apply / --verify` 统一编排

核心入口：

- `knowledge-base/bootstrap_security_platform.py`


### 4.3 四个安全 Agent 已形成标准化定义

当前四个安全角色已形成独立 Agent 定义文件：

- `incident-analyst.md`
- `emergency-commander.md`
- `vulnerability-expert.md`
- `compliance-auditor.md`

文档中已经说明：

- 角色目标
- 系统提示词语义
- 任务提示词语义
- 工具边界
- 知识边界
- 风险边界


### 4.4 安全工具集成面已扩展到六个工具

当前安全工具已不再局限于最初三项，而是形成六个声明式集成：

- `send_security_alert`
- `create_security_ticket`
- `threat_intel_lookup`
- `search_security_alerts`
- `isolate_endpoint_host`
- `lookup_asset_context`

相关配置已统一收敛到：

- `docs/security-platform/5-integrations/`

工具创建与绑定由以下脚本负责：

- `knowledge-base/security-automation/setup_security_tools.py`


### 4.5 Playbook / 流程化能力已落地

当前已新增声明式 playbook 目录和统一 runner：

- `docs/security-platform/playbooks/`
- `knowledge-base/run_security_playbook.py`

已落地的最小流程包括：

- `incident-triage-readonly`
- `incident-containment-and-ticketing`

这意味着 persona 已经不只是“静态角色”，而是可以承载可重复执行的最小安全流程。


### 4.6 最小验收与安全工作台已落地

当前已完成：

- 最小验收脚本：`knowledge-base/verify_security_platform_acceptance.py`
- 管理后台安全工作台 API：`backend/onyx/server/manage/security_platform/api.py`
- 管理后台安全工作台页面：`web/src/app/admin/security-platform/page.tsx`

安全工作台当前可展示：

- deployment profile / required env / missing env
- threat-intel sync / corpus / historical packages
- playbooks
- personas / tools / RBAC
- permission inheritance / service accounts / SCIM
- query history / usage limits / hooks
- custom theming / white-labeling / custom deployments
- region processing / self-hosting / secrets encryption
- tool audit / config drift / recent failures
- 健康状态、recommended next actions、remediation commands


### 4.7 Threat-Intel 生命周期治理已进入可操作阶段

当前已具备：

- manifest 构建
- corpus curation
- lifecycle 评估
- archive plan
- archive batches
- worklist / patch preview / action script
- execution plan / record / result
- historical package 生成与 index catalog

相关资产已实际写入：

- `knowledge-base/threat-intelligence/`

这说明 threat-intel 已经不只是“抓取和导入”，而是进入可治理、可归档、可追踪阶段。


### 4.8 测试基线已形成

当前测试已覆盖以下层面：

- bootstrap、persona、document set、acceptance、playbook 等单测
- 安全工作台 API 单测
- 安全工具链集成测试
- 安全平台资源、RBAC、工具矩阵、live chat、live tool、playbook 执行回归
- smoke / acceptance / playbook CLI 入口回归
- threat-intel archive execution artifact 一致性回归

本次复核中抽样执行了以下单测集合：

- `test_bootstrap_security_platform.py`
- `test_run_security_playbook.py`
- `test_verify_security_platform_acceptance.py`
- `test_security_platform_api.py`

结果为：

- `55 passed`


## 5. 当前仍待完成的内容

### 5.1 生产化配置仍需收口

当前虽然已经有 Compose / Helm 覆盖层、deployment profile、required env 契约，但仍然主要停留在：

- 示例值
- 示例 Secret 映射
- 环境变量级别说明

尚未完全形成：

- 面向企业 secret manager 的落地说明
- 更细的生产环境配置分层模板
- 更完整的配置漂移控制约束


### 5.2 回归矩阵仍可继续加深

当前已经覆盖：

- 核心资源存在性
- persona / tool / RBAC 绑定
- live chat、live tool、playbook 基础回归
- smoke / acceptance / playbook CLI 入口
- 跨 persona 与多步工具链路的部分长链路回归

但仍可继续增强：

- 更长链路的跨 persona 联调
- 更多真实模型下的场景回归
- 更细的 smoke / acceptance / regression 分层


### 5.3 Threat-Intel 扩源还未完成

当前 threat-intel 仍以 CISA / NVD 为主，生命周期治理已经走在前面，但上游源覆盖仍有扩展空间。

后续仍需决定：

- 是否引入更多公开情报源
- 是否引入商业 API
- 每个新增源的刷新、鉴权、失败策略如何约束


### 5.4 运维观测与审计仍需增强

当前已经有健康状态、修复建议和运行摘要，并新增了：

- 工具调用审计摘要
- 最近失败项摘要
- 配置漂移检查
- 权限、SCIM、Service Account、Query History、Hooks、自托管等运营摘要

但仍未扩展到更强的运营视角能力，例如：

- persona 使用统计
- threat-intel 同步失败看板
- 更细的阶段级失败分布与长期趋势


## 6. 风险判断

当前主要风险已不再是“能力不可用”，而是以下几类：

### 6.1 配置风险

- 真实 webhook、ticket、threat-intel 密钥若未按环境规范管理，部署时仍可能出现配置漂移

### 6.2 运维风险

- 如果后续继续手工修改 persona、tool、RBAC 配置，可能偏离脚本约定，增加环境差异

### 6.3 文档漂移风险

- 部分历史阶段性文档仍保留早期判断，若不明确标记适用范围，容易误导项目进度判断


## 7. 建议下一步

建议下一阶段不要再把重点放在“大面积扩功能”，而应优先收口以下事项：

1. 完成一版面向真实环境的配置收口
- 明确 Secret 管理方式
- 收敛 live/demo/profile 约束

2. 增强业务回归矩阵
- 补更多 live 场景与长链路回归
- 明确 smoke / acceptance / regression 的边界

3. 持续推进 threat-intel 生命周期治理
- 组织 archive candidate 评审与分批处理
- 维护 historical package catalog 与执行记录一致性

4. 按需增强运维观测与审计能力
- 优先补关键失败阶段、工具调用和配置漂移可见性


## 8. 里程碑建议

建议将当前版本标记为：

- `安全底座 PoC / 内部试运行基线版本`

建议后续阶段目标：

- `V1`：完成生产化配置与交付收口
- `V1.1`：补强长链路联调回归
- `V2`：增强 threat-intel 扩源、运维观测与审计能力


## 9. 最终结论

当前项目已经完成了从“安全场景定制尝试”到“阶段性交付基线”的跃迁。

与早期状态相比，最大的变化不是多了几份文档，而是已经形成：

- 可初始化的安全底座
- 可验证的验收与回归链路
- 可演示的安全工作台与流程能力
- 可持续推进的 threat-intel 生命周期治理基础

因此，当前更准确的判断不是“还缺少主体能力”，而是“主体能力已基本成型，后续重点转向生产化收口和长期运维质量”。

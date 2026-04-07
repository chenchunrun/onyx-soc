# Onyx 智能安全底座开发 Backlog

## 1. 文档目标

本文档用于整理当前安全智能底座版本的有效 backlog，并作为 `docs/TODO.md` 在 `security-platform/` 文档目录下的详细版补充。

范围原则：

- 只保留尚未完成、尚未完全收口或需要继续增强的事项
- 已完成能力只作为当前基线说明，不再重复列为主待办
- 待办按 `Next / Later` 分层，便于继续开发和验收

状态说明：

- `Done`：已完成并已有代码、文档或测试支撑
- `Next`：建议下一阶段优先推进
- `Later`：增强项，不阻塞当前基线版本


## 2. 当前已完成基线

以下能力已完成，不再列为 backlog 主任务：

- 安全知识库导入与校验
- threat-intel 同步、manifest、curation、周期同步入口
- 四个标准安全 persona 初始化
- 四个安全 Agent 定义文档落库
- `安全知识库` document set 创建
- 六个安全 OpenAPI 工具创建与绑定
- 安全团队用户与 RBAC 初始化
- 统一 `bootstrap` 主链路
- `acceptance`、`smoke`、安全平台基础回归链路
- Docker Compose / Helm 覆盖层
- `live / mock / demo` profile 分层
- threat-intel 生命周期治理基础能力
- 安全工作台 API 与前端页面
- 安全工作台轻量运维摘要：
  - 工具调用审计摘要
  - 配置漂移检查
  - 最近失败项摘要
- 企业能力最小收口：
  - permission inheritance
  - service accounts
  - SCIM / group sync
  - secrets encryption
  - query history / usage
  - custom permissions
  - usage limits
  - hooks
  - custom theming / white-labeling
  - custom deployments
  - region processing
  - self-hosting

当前可视为：

- `PoC / 内部试运行基线版本`


## 3. Next Backlog

### 3.1 收口生产化配置管理

状态：`Next`

目标：

- 将当前示例级配置入口继续收口为更接近真实交付的配置方案

待办：

- 明确真实环境 Secret 管理方式
- 补齐与企业 secret manager 对接说明
- 继续细化 live/demo 环境差异说明
- 收口工具、threat-intel、deployment profile 的生产配置边界
- 视部署目标继续补强 Helm 生产 values 模板

验收标准：

- deployment profile、required env、密钥来源完整可追踪
- demo/live 环境切换规则清晰
- 不再依赖口头约定配置 mock/live 端点
- 新环境可以按文档完成稳定部署

当前进展：

- 已新增统一 deployment profile 契约：`live / demo`
- 已收口：
  - threat-intel source profile
  - security tools profile
  - required env / missing env
- `bootstrap --verify`、`acceptance`、安全工作台当前共用同一套健康模型和修复建议
- `demo` Docker 场景已固化 `host.docker.internal` 约束
- 当前剩余重点是企业 Secret 管理说明与更细的生产环境模板


### 3.2 增强业务回归测试矩阵

状态：`Next`

目标：

- 把当前最小回归能力扩展为更接近真实安全场景的回归集合

待办：

- 扩展更多真实模型下的工具联动回归
- 继续增加跨 persona 的长链路场景回归
- 补更多长链路 playbook / chat / tool 联调路径
- 继续扩大 smoke、acceptance、regression 三类测试边界覆盖

验收标准：

- 工具调用、角色问答、流程场景均有明确自动化回归入口
- 新增工具/流程时有对应回归补位要求
- 回归矩阵可直接服务部署验收

当前进展：

- 已补齐 6 个安全工具的矩阵回归
- 已补齐 4 个 persona 的 live 聊天回归
- 已补齐多条 live 工具调用回归
- 已补 smoke / acceptance / playbook CLI 入口回归
- 已补 playbook `continue-on-failure` 语义与 CLI 入口回归
- 已补齐 playbook 定义校验与执行回归
- 下一步重点已从“补 playbook 基础回归”转为“补更长链路和更多 live 场景”


### 3.3 完善 threat-intel 生命周期治理

状态：`Next`

目标：

- 从“可治理”提升到“长期可维护”

待办：

- 按 `source / year / quality` 推进 archive candidate 评审
- 收敛运行态 feed 与正式知识包的发布边界
- 评估是否需要更细的治理视图或归档节奏
- 明确 archive 执行、审批、验证与回滚的操作规范

验收标准：

- 内容治理状态不只停留在 managed/unmanaged 二分
- 可以说明何时纳管、何时归档、何时仅保留运行态
- historical package catalog 与实际归档动作持续一致

当前进展：

- 已新增 governed corpus 生命周期评估脚本：`knowledge-base/assess_threat_intel_lifecycle.py`
- 已新增 archive 行动清单脚本：`knowledge-base/plan_threat_intel_archive.py`
- 已补质量分层：
  - `authoritative`
  - `standard`
  - `limited`
- 已补生命周期状态：
  - `active`
  - `archive_candidate`
  - `retained_historical`
- 已补两批 historical package 与统一 catalog：
  - `phase-1-cisa-limited-historical`
  - `phase-2-nvd-authoritative-historical`
- 已补 archive batches、worklists、patch previews、action scripts、execution plans、execution records、execution results
- 当前下一步已收敛为按批次推进 archive candidate 评审和归档执行规范化


## 4. Later Backlog

### 4.1 扩展 threat-intel 上游源

状态：`Later`

目标：

- 补足当前以 CISA/NVD 为主的情报覆盖面

待办：

- 调研新增公开情报源
- 评估商业 API 接入方式
- 为每个源定义刷新频率、鉴权和失败策略
- 统一新增源输出格式和同步策略

验收标准：

- threat-intel source 清单可配置
- 每个新增源有明确同步策略和输出格式


### 4.2 增强运维观测与审计

状态：`Later`

目标：

- 在现有轻量摘要基础上，按需补更强的运营视角能力

待办：

- 评估是否需要 persona 使用统计或任务执行记录
- 评估是否需要 threat-intel 同步失败专门看板
- 评估是否需要更细的失败阶段归因
- 维持工作台为轻量诊断入口，不扩成复杂报表系统

验收标准：

- 管理员已经可以定位失败阶段和配置漂移
- 如果继续增强，应直接服务排障与交付运维


### 4.3 形成更稳定的版本说明

状态：`Later`

目标：

- 为对外或跨团队交付形成更稳定的版本边界

待办：

- 增加版本基线说明
- 增加升级说明
- 增加已知限制与非目标说明

验收标准：

- 非原开发成员也能理解当前版本边界


### 4.4 收敛文档结构与统一入口

状态：`Later`

目标：

- 减少文档分散和重复维护成本

待办：

- 明确 `docs/TODO.md` 与本 backlog 的关系
- 统一 security-platform 文档索引入口
- 标记已过时的阶段性文档

验收标准：

- 团队成员能快速找到当前有效文档
- 历史文档不再被误认为现状


## 5. 建议推进顺序

建议按以下顺序继续开发：

1. 收口生产化配置管理
2. 增强业务回归测试矩阵
3. 完善 threat-intel 生命周期治理
4. 再扩上游情报源与运维观测能力

原因：

- 当前底座和初始化闭环已经成立
- 最大缺口已经从“功能能不能跑”转移到“配置是否可控、回归是否足够、治理是否长期可维护”
- 继续大面积扩功能的边际收益已经低于收口和稳态化


## 6. 近期建议里程碑

### 里程碑 A：V1 配置收口

完成标志：

- live/demo/profile 规则清晰
- 真实 Secret 管理方式明确
- 部署文档与配置约束一致


### 里程碑 B：V1 验收增强

完成标志：

- 长链路 regression 覆盖增强
- live 工具与 playbook 回归边界清晰
- 验收脚本可直接支撑部署后验证


### 里程碑 C：V2 运维治理增强

完成标志：

- archive 生命周期治理流程稳定
- 运维观测与审计摘要落地
- 威胁情报扩展策略清晰

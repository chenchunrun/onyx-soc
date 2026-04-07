# Onyx 智能安全底座开发 Backlog

## 1. 文档目标

本文档用于整理当前安全智能底座二开版本的后续开发事项。

范围原则：

- 只保留尚未完成或尚未达到目标质量的事项
- 已完成的能力只作为基线说明，不再重复列为待办
- 待办按 `P0 / P1 / P2` 分级，便于继续开发和验收

状态说明：

- `Done`：已完成并已验证
- `Next`：建议优先推进
- `Later`：增强项，不阻塞当前基线版本


## 2. 当前已完成基线

以下能力已完成，不再列为 backlog 主任务：

- 安全知识库导入与校验
- threat-intel 同步、manifest、curation、周期同步入口
- 四个标准安全 persona 初始化
- `安全知识库` document set 创建
- 六个安全 OpenAPI 工具创建与绑定
- 安全团队用户与 RBAC 初始化
- 统一 `bootstrap` 主链路
- `acceptance` 与 `smoke` 验证链路
- Docker Compose / Helm 覆盖层
- `live / mock / demo` profile 分层
- threat-intel 内容治理基线收口
- 集成回归与关键单测基础覆盖

当前可视为：

- `PoC / 内部试运行基线版本`


## 3. P0 Backlog

### 3.1 扩展安全工具集成面

状态：`Done`

目标：

- 将当前工具扩展为更符合安全运营实际场景的工具矩阵

待办：

- 增加 SIEM 查询类工具
- 增加 EDR / 终端处置类工具
- 增加资产 / CMDB 查询类工具
- 将新增工具纳入 `5-integrations`、deployment profile、acceptance

验收标准：

- 至少新增 2-4 个真实安全系统集成
- 每个工具均支持声明式配置
- 每个工具有明确 persona 绑定边界
- `bootstrap --apply` 后可自动创建并绑定

完成说明：

- 已新增：
  - `search_security_alerts`
  - `isolate_endpoint_host`
  - `lookup_asset_context`
- 当前工具总数已提升至 `6`


### 3.2 将 persona 提升为可执行安全流程的 agent/playbook

状态：`Done`

目标：

- 将当前“角色化助手”提升为可执行安全流程的工作流能力

待办：

- 梳理典型安全流程并固化为标准场景
- 为每个 persona 明确可执行 playbook
- 设计最小多步骤流程，例如：
  - 告警研判 -> 威胁情报查询 -> 告警通知 -> 工单创建
  - 漏洞评估 -> 影响判断 -> 工单流转
  - 合规检查 -> 证据收集 -> 结果输出
- 形成 agent 行为约束与输出模板

验收标准：

- 至少 2 条可重复执行的安全 playbook 跑通
- 角色间职责边界清晰
- playbook 可以通过现有工具链完成关键动作

完成说明：

- 已新增声明式 playbook 目录：`docs/security-platform/playbooks/`
- 已落地 2 条最小安全流程：
  - `incident-triage-readonly`
  - `incident-containment-and-ticketing`
- 已新增统一 runner：`knowledge-base/run_security_playbook.py`
- `bootstrap --verify` 现已纳入 `playbooks` 阶段
- `acceptance` 现已显示 playbook 数量和示例输入覆盖情况


### 3.3 建设安全底座专属前端工作台

状态：`Done`

目标：

- 提供安全场景专属 UI，而不是完全依赖 Onyx 通用页面

待办：

- 设计最小工作台信息架构
- 新增至少一个安全运营首页或工作台页面
- 提供以下视图中的最小子集：
  - threat-intel 状态视图
  - 安全 persona 入口视图
  - 验收 / 运行状态视图
  - 工具配置概览视图
- 复用现有 API 和验收数据，不重复造后端模型

验收标准：

- Web 或 desktop 至少有一个安全底座入口页
- 可展示当前 deployment profile、threat-intel 状态、核心 persona 与工具状态
- 适合演示与内部试运行使用

完成说明：

- 已新增管理后台入口页：`/admin/security-platform`
- 当前页面已接入单一后端状态源：
  - deployment profile / required env
  - threat-intel sync / corpus
  - playbooks
  - personas / tools / RBAC
  - 健康状态、recommended next actions、remediation commands


### 3.4 收口生产化配置管理

状态：`Done`

目标：

- 将当前示例级配置入口提升为更可控的生产配置方案

待办：

- 明确真实环境所需 secrets 清单
- 补齐工具侧密钥管理说明
- 补齐 threat-intel live 模式依赖说明
- 梳理 demo 与 live 环境的差异清单
- 视部署目标补强 Helm 生产 values 模板

验收标准：

- deployment profile 与 required env 完整可追踪
- demo/live 环境切换规则清晰
- 不再依赖口头约定来配置 mock/live 端点

完成说明：

- 已新增统一 deployment profile 契约：`live / demo`
- 已收口：
  - threat-intel source profile
  - security tools profile
  - required env / missing env
- `bootstrap --verify`、`acceptance`、安全工作台现在共用同一套健康模型和修复建议
- `demo` Docker 场景已固化 `host.docker.internal` 约束，不再依赖人工约定


## 4. P1 Backlog

### 4.1 增强业务回归测试矩阵

状态：`Next`

目标：

- 把当前最小回归能力扩展为更接近真实安全场景的回归集合

待办：

- 增加更多 live 工具回归
- 增加跨 persona 的长链路场景回归
- 增加 playbook 级别回归
- 区分 smoke、acceptance、regression 三类测试边界

验收标准：

- 工具调用、角色问答、流程场景均至少有一条自动化回归
- 新增工具/流程时有对应回归入口

当前进展：

- 已补齐 6 个安全工具的矩阵回归
- 已补齐 4 个 persona 的 live 聊天回归
- 已补齐 4 条 live 工具调用回归
- 下一步重点是 playbook 级别回归和更长链路场景回归


### 4.2 完善 threat-intel 生命周期治理

状态：`Later`

目标：

- 从“可治理”提升到“长期可维护”

待办：

- 增加归档/淘汰策略
- 增加更细的质量等级
- 评估是否需要按来源或年份拆分治理视图
- 为运行态 feed 与正式知识包建立更明确的发布边界

验收标准：

- 内容治理状态不只停留在 managed/unmanaged 二分
- 可以说明何时纳管、何时淘汰、何时仅保留运行态


### 4.3 扩展 threat-intel 上游源

状态：`Later`

目标：

- 补足当前以 CISA/NVD 为主的情报覆盖面

待办：

- 调研新增公开情报源
- 评估商业 API 接入方式
- 为每个源定义刷新频率、鉴权和失败策略

验收标准：

- threat-intel source 清单可配置
- 每个新增源有明确同步策略和输出格式


### 4.4 增强运维观测与审计

状态：`Later`

目标：

- 提升安全底座运行后的可观测性和可追责性

待办：

- 增加工具调用审计摘要
- 增加 persona 使用统计或任务执行记录
- 增加 threat-intel 同步失败可见性
- 增加关键配置漂移检查

验收标准：

- 管理员可以定位失败阶段和配置漂移
- 至少能看到关键同步、工具调用和验收状态摘要


## 5. P2 Backlog

### 5.1 形成外部交付版本说明

状态：`Later`

目标：

- 为对外或跨团队交付形成更稳定的版本边界

待办：

- 增加版本基线说明
- 增加升级说明
- 增加已知限制与非目标说明

验收标准：

- 非原开发成员也能理解当前版本边界


### 5.2 收敛文档结构与统一入口

状态：`Later`

目标：

- 减少文档分散和重复维护成本

待办：

- 明确 `docs/TODO.md` 与本 backlog 的关系
- 统一 security-platform 文档索引入口
- 标记已过时的阶段性文档

验收标准：

- 团队成员能快速找到当前有效文档


## 6. 建议推进顺序

建议按以下顺序继续开发：

1. 扩安全工具集成面
2. 把 persona 提升为 playbook / agent 流程
3. 建设最小安全工作台前端
4. 收口生产化配置管理
5. 再扩 deeper regression、threat-intel 生命周期和审计能力

原因：

- 当前底座和初始化闭环已经成立
- 最大缺口已经从“能不能跑”转移到“业务能力够不够用”
- 继续只补脚本和测试，收益会明显下降


## 7. 近期建议里程碑

### 里程碑 A：业务能力增强

完成标志：

- 新增 2-4 个真实安全工具
- 至少 2 条安全 playbook 跑通

### 里程碑 B：最小安全工作台

完成标志：

- 前端存在安全底座专属入口页
- 能展示 profile、persona、tools、threat-intel 状态

### 里程碑 C：生产化收口

完成标志：

- live/demo 配置切换规范化
- Helm/Compose 环境说明收口
- 回归矩阵和运维观测进一步补强

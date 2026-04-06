# Onyx 智能安全底座项目 TODO

## 1. 文档说明

本文档基于 [ONYX_SECURITY_PLATFORM_STATUS_REPORT.md](/Users/newmba/Downloads/onyx-main/docs/ONYX_SECURITY_PLATFORM_STATUS_REPORT.md) 整理，目标是把“当前缺口”转换成可以执行、跟踪和验收的项目待办。

状态说明：

- `P0`：当前阶段必须完成，否则无法形成可交付版本
- `P1`：建议在下一阶段完成，直接影响上线质量或验收完整性
- `P2`：增强项，不阻塞 PoC，但影响后续扩展和运维质量


## 2. 总体目标

当前项目已经具备 PoC / 内部试运行条件，下一阶段目标不是继续零散补脚本，而是完成以下三件事：

- 形成完整的对外交付文档包
- 形成可初始化、可复现的安全底座安装流程
- 形成可验收、可演示、可持续运维的版本


## 3. P0 待办

### 3.1 补齐正式交付文档

目标：

- 将 `Onyx智能安全底座.docx` 中承诺的交付结构正式落库

待办：

- 新增 `docs/security-platform/1-requirements.md`
- 新增 `docs/security-platform/2-architecture.md`
- 新增 `docs/security-platform/6-implementation-guide.md`
- 新增 `docs/security-platform/7-deployment.md`
- 新增 `docs/security-platform/8-expert-review-notes.md`

验收标准：

- 每个文档有明确的范围、输入输出、依赖和实施说明
- 文档内容与当前仓库实现一致，而不是照搬方案设想
- 新人仅靠文档可以理解系统组成与落地路径


### 3.2 固化四个安全 Agent 定义

目标：

- 将当前散落在 persona、知识库和脚本中的角色能力，整理为标准化 Agent 定义

待办：

- 新增 `docs/security-platform/4-agents/incident-analyst.md`
- 新增 `docs/security-platform/4-agents/emergency-commander.md`
- 新增 `docs/security-platform/4-agents/vulnerability-expert.md`
- 新增 `docs/security-platform/4-agents/compliance-auditor.md`
- 为每个 Agent 明确：
  - 角色目标
  - 系统提示词
  - 允许使用的工具
  - 依赖的知识域
  - 输出格式要求
  - 风险边界

验收标准：

- 四个 Agent 的职责边界无明显重叠
- 可以映射到现有 persona 和工具权限
- 文档可直接作为后续 seed / 初始化实现输入


### 3.3 实现统一 bootstrap 流程

目标：

- 把知识库导入、工具创建、persona 初始化、权限绑定整合为一次性初始化流程

待办：

- 新增统一入口脚本，例如 `knowledge-base/bootstrap_security_platform.py`
- 串联现有脚本：
  - `knowledge-base/upload_to_onyx.py`
  - `knowledge-base/security-automation/setup_security_tools.py`
  - `knowledge-base/sso-rbac/provision_security_team.py`
- 支持按阶段执行：
  - 仅导入知识库
  - 仅初始化 persona / RBAC
  - 仅创建安全工具
  - 完整初始化

验收标准：

- 在新环境中执行一次 bootstrap 后，可直接获得可用的安全 persona、知识集和工具链
- 初始化过程有清晰日志和失败退出信息
- 初始化脚本支持幂等执行


### 3.4 明确 persona 的标准初始化方式

目标：

- 去掉“依赖人工预配置”的隐含前提，确保 persona 可以被标准化创建

待办：

- 决定采用 seed、管理脚本还是平台初始化任务作为标准方案
- 为四个安全 persona 明确创建入口和默认配置
- 让测试和 CLI 不再依赖“环境中碰巧已经存在 persona”

验收标准：

- 新环境部署后无需手工进入 UI 创建 persona
- 集成测试不再因 persona 缺失而 `skip`
- persona 与 document set、工具权限、可见性设置形成固定初始化逻辑


## 4. P1 待办

### 4.1 形成安全底座专属部署方案

目标：

- 让“部署 Onyx”与“部署安全底座版本”之间的差异清晰可复现

待办：

- 提供安全底座专属部署说明
- 明确需要启用的服务、环境变量、账号初始化步骤
- 视情况补充：
  - 安全底座专属 `docker compose` 覆盖配置
  - 安全底座专属 Helm values 示例
  - 一键初始化命令示例

验收标准：

- 新环境部署步骤可以按文档顺序完整跑通
- 部署文档包含最小可运行配置和推荐生产配置
- 部署完成后能直接进入安全场景演示


### 4.2 为安全工具链补强生产化配置

目标：

- 将当前偏演示性质的工具接入方式提升到可稳定演示、可受控运维的水平

待办：

- 为现有 OpenAPI 工具模板补充鉴权策略说明
- 明确 mock 工具与真实工具的切换方式
- 为关键动作增加审计和失败处理说明
- 梳理工具调用权限和 persona 对应关系

验收标准：

- 每个安全工具都有接入说明、认证方式和失败处理约束
- 演示环境与真实环境切换规则明确
- 不同 persona 的工具权限有清晰边界


### 4.3 扩展威胁情报源与同步策略

目标：

- 把当前以 CISA/NVD 为主的聚合能力升级为更完整的情报同步方案

待办：

- 评估并补充更多情报源，例如商业 API 或行业公开情报源
- 为情报同步设计执行频率、失败重试、限流与更新时间策略
- 明确生成文件的目录规范和元数据字段

验收标准：

- 情报源清单明确
- 每个情报源的同步策略可解释、可配置
- 输出文件格式一致，适合后续 ingestion


### 4.4 补充面向安全场景的测试闭环

目标：

- 从“当前链路能跑”提升到“关键场景部署后可验证”

待办：

- 保留现有 `backend/tests/integration/tests/security_tools/test_security_tools_chain.py`
- 新增 bootstrap 后的集成验证用例
- 补充 persona 初始化成功、工具可调用、知识可检索的验证路径

验收标准：

- 新环境完成初始化后，可以跑一组最小验收测试
- 测试结果能直接作为交付验证依据


## 5. P2 待办

### 5.1 整理统一的项目管理视图

目标：

- 避免待办继续散落在不同 markdown 和脚本说明中

待办：

- 维护本文件作为统一待办入口
- 为每个任务补充：
  - 负责人
  - 当前状态
  - 依赖项
  - 目标版本

验收标准：

- 项目成员可以只看一个文档了解当前进度
- 待办不再散落在多个指南中


### 5.2 形成领导汇报版摘要

目标：

- 为汇报场景提供一份非技术化摘要，降低理解成本

待办：

- 输出一页式项目摘要
- 提炼当前完成度、主要成果、主要风险、下一阶段里程碑

验收标准：

- 非研发角色可以快速理解项目现状
- 内容与正式状态报告保持一致


## 6. 建议实施顺序

建议按以下顺序推进：

1. 先补 `docs/security-platform/` 交付文档
2. 再固化四个安全 Agent 定义
3. 然后实现统一 bootstrap 和 persona 标准初始化
4. 最后补部署方案、测试闭环和情报扩展

原因：

- 当前最大缺口不是底层能力，而是交付结构和初始化闭环
- 先把文档、角色和初始化逻辑固化，后续部署和测试才有稳定输入


## 7. 当前建议里程碑

### 里程碑 A：交付物成型

完成标志：

- `docs/security-platform/` 基本文档齐全
- 四个 Agent 定义完成


### 里程碑 B：初始化成型

完成标志：

- bootstrap 脚本可运行
- persona、知识库、工具、RBAC 可自动完成初始化


### 里程碑 C：验收成型

完成标志：

- 新环境可按文档部署
- 初始化后可直接演示四个安全 persona
- 最小验收测试可稳定通过

# Onyx 智能安全底座项目 TODO

## 1. 文档说明

本文档用于维护安全底座项目的当前有效待办。

使用原则：

- 只保留尚未完成、尚未收口或需要继续推进的事项
- 已完成事项不再作为主待办重复列出
- 本文档优先级高于历史阶段性评估文档

状态说明：

- `Done`：已完成并已有代码、文档或测试支撑
- `Next`：建议下一阶段优先推进
- `Later`：增强项，不阻塞当前 PoC / 内部试运行基线


## 2. 当前基线判断

当前仓库已经完成以下基线能力：

- `docs/security-platform/` 交付文档主结构已成型
- 四个安全 Agent 定义已落库
- `bootstrap` 初始化链路已闭环
- `安全知识库` document set、persona、tools、RBAC 可自动初始化
- threat-intel 同步、manifest、curation、生命周期评估、historical package 管理已形成链路
- 最小验收、smoke、安全平台回归已具备基础覆盖
- 安全工作台页面与后端状态 API 已落地
- 安全工作台已补齐轻量运维摘要：
  - 工具调用审计摘要
  - 配置漂移检查
  - 最近失败项摘要
- 生产化配置检查已补齐：
  - placeholder env 检测
  - 验收脚本与工作台统一提示
- 企业能力的最小收口已完成：
  - Document Permissions / RBAC / Service Accounts / SCIM
  - Secrets Encryption / Query History / Usage Limits / Hooks
  - Custom Permissions / Custom Theming / White-labeling
  - Custom Deployments / Region Processing / Self-hosting
- Docker Compose / Helm 安全底座覆盖资产已提供

当前可视为：

- `PoC / 内部试运行基线版本`
- 且主要企业能力已具备“可见、可验收、可诊断”的管理面收口


## 3. Next

### 3.1 收口生产化配置管理

目标：

- 把当前示例级配置收口为更接近真实交付的配置方案

待办：

- 明确真实环境 Secret 管理方式
- 补齐与企业 secret manager 对接说明
- 继续细化 live/demo 环境差异说明
- 收口工具、threat-intel、deployment profile 的生产配置边界

验收标准：

- required env、密钥来源、环境切换规则完整可追踪
- 不再依赖口头约定配置 mock/live 端点
- 新环境可以按文档完成稳定部署


### 3.2 增强业务回归测试矩阵

目标：

- 在现有最小闭环基础上补长链路和更多 live 场景回归

待办：

- 扩展更多真实模型下的工具联动回归
- 继续补跨 persona 的多步骤场景覆盖
- 补更多长链路 playbook / chat / tool 联调路径
- 继续扩大 smoke、acceptance、regression 三类测试边界覆盖

验收标准：

- 工具调用、角色问答、流程场景均有明确自动化入口
- 新增工具或流程时有对应回归补位要求
- 回归矩阵可以直接服务部署验收


### 3.3 完善 threat-intel 生命周期治理

目标：

- 从“已具备治理能力”提升到“长期可维护”

待办：

- 按 `source / year / quality` 推进 archive candidate 评审
- 收敛运行态 feed 与正式知识包的发布边界
- 评估是否需要更细的治理视图或归档节奏
- 明确 archive 执行、审批、验证与回滚的操作规范

验收标准：

- 可以清晰说明何时纳管、何时归档、何时仅保留运行态
- historical package catalog 与归档流程持续一致
- 生命周期报告可以稳定支撑后续运营


## 4. Later

### 4.1 扩展 threat-intel 上游源

目标：

- 提升当前以 CISA/NVD 为主的情报覆盖面

待办：

- 调研新增公开或商业情报源
- 为新增源定义鉴权、刷新频率、失败策略
- 统一新增源输出格式和同步策略

验收标准：

- source 清单可配置
- 每个新增源有清晰同步规则


### 4.2 增强运维观测与审计

目标：

- 在当前已落地摘要基础上，决定是否继续扩更细的运营视角

待办：

- 评估是否需要 persona 使用统计或任务执行记录
- 评估是否需要 threat-intel 同步失败专门看板
- 评估是否需要更细的按阶段失败分布
- 保持工作台摘要能力轻量，不扩成单独报表系统

验收标准：

- 管理员已能定位关键失败阶段和配置漂移
- 若继续增强，应服务运维排障，而不是演变成复杂 BI 页面


### 4.3 收敛文档入口

目标：

- 降低历史文档与当前文档并存带来的误导

待办：

- 标记历史阶段性报告的适用范围
- 明确本文件与 `docs/security-platform/12-development-backlog.md` 的关系
- 收口安全底座文档统一入口

验收标准：

- 团队成员能快速识别当前有效文档
- 历史评估不再被误认为现状


## 5. 建议推进顺序

建议按以下顺序推进：

1. 先收口生产化配置管理
2. 再扩业务回归测试矩阵
3. 然后继续 threat-intel 生命周期治理
4. 最后补上游源扩展与运维审计增强

原因：

- 当前主要缺口已不是“能力不存在”
- 下一阶段重点是交付稳定性、配置可控性、回归深度和长期维护性


## 6. 里程碑建议

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

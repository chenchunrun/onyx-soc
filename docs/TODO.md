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
- 七个安全 persona 已完成初始化、工具绑定与前端实测
- 安全技能（Skills）库已落地，35 个技能覆盖日志分析、OSINT、漏洞评估、恶意软件分析、威胁狩猎、红队侦察等场景
- `load_skill` 工具已集成，persona 可通过 `skill_keys` 绑定技能并按需加载完整指令
- 安全工作台已补齐轻量运维摘要：
  - 工具调用审计摘要
  - 配置漂移检查
  - 最近失败项摘要
- 生产化配置检查已补齐：
  - placeholder env 检测
  - 验收脚本与工作台统一提示
- 生产化配置文档已补齐：
  - Secret 管理说明
  - Helm existingSecret 示例
  - live/demo Helm overlay 边界
- 企业能力的最小收口已完成：
  - Document Permissions / RBAC / Service Accounts / SCIM
  - Secrets Encryption / Query History / Usage Limits / Hooks
  - Custom Permissions / Custom Theming / White-labeling
  - Custom Deployments / Region Processing / Self-hosting
- Docker Compose / Helm 安全底座覆盖资产已提供
- threat-intel archive 治理 SOP 已补齐
- 回归矩阵已增强：
  - 七个 persona 的 live chat 回归
  - 新增 persona 的 live tool 回归
  - 新增长链路跨 persona live 回归

当前可视为：

- `PoC / 内部试运行基线版本`
- 且主要企业能力已具备“可见、可验收、可诊断”的管理面收口


## 3. Next

### 3.1 扩展 threat-intel 上游源

目标：

- 提升当前以 CISA/NVD 为主的情报覆盖面

待办：

- 调研新增公开或商业情报源
- 为新增源定义鉴权、刷新频率、失败策略
- 统一新增源输出格式和同步策略

验收标准：

- source 清单可配置
- 每个新增源有清晰同步规则


### 3.2 增强运维观测与审计

目标：

- 在当前已落地摘要基础上，按需补更细的运营视角

待办：

- 评估是否需要 persona 使用统计或任务执行记录
- 评估是否需要 threat-intel 同步失败专门看板
- 评估是否需要更细的按阶段失败分布
- 保持工作台摘要能力轻量，不扩成单独报表系统

验收标准：

- 管理员已能定位关键失败阶段和配置漂移
- 若继续增强，应服务运维排障，而不是演变成复杂 BI 页面


### 3.3 收敛版本边界与文档入口

目标：

- 保持当前版本边界清晰，降低历史文档误导

待办：

- 标记历史阶段性报告的适用范围
- 增加版本基线、升级说明和已知限制
- 继续收口安全底座文档统一入口

验收标准：

- 团队成员能快速识别当前有效文档
- 非原开发成员也能理解当前版本边界


## 4. Later

### 4.1 继续深化生产化配置管理

目标：

- 在现有第一轮收口基础上，按真实交付需要继续深化

待办：

- 视部署目标继续补强 Helm 生产 values 模板
- 视组织要求继续细化 Secret Manager 接入约定
- 持续收敛 live/demo/mock 的部署边界

验收标准：

- 新环境部署时不依赖额外口头说明
- 配置来源、档位边界、secret 注入方式持续一致


### 4.2 继续加深回归矩阵

目标：

- 在当前已可用的回归基线上继续增加更长链路和更多场景

待办：

- 继续扩真实模型下的更长链路场景
- 继续扩大 smoke / acceptance / regression 分层边界
- 新增 persona / tool / playbook 时同步补对应回归

验收标准：

- 回归矩阵持续服务部署验收
- 新增能力有明确自动化落点


### 4.3 维持 threat-intel 生命周期治理节奏

目标：

- 在已成型治理流程基础上，持续按批次执行和校验

待办：

- 按 `source / year / quality` 继续推进 archive candidate 评审
- 定期重建 lifecycle report、historical package catalog
- 持续验证 archive result 与实际产物一致

验收标准：

- archive candidate 评审与执行形成稳定节奏
- historical package catalog 与归档结果持续一致


## 5. 建议推进顺序

建议按以下顺序推进：

1. 先扩 threat-intel 上游源
2. 再补按需的运维观测增强
3. 然后继续版本边界与文档收口
4. 最后按需深化配置、回归和治理细节

原因：

- 当前主要主线能力已经成立
- 下一阶段重点更多是覆盖面、运营增强和长期维护性


## 6. 里程碑建议

### 里程碑 A：V1 主线收口

完成标志：

- live/demo/profile 规则清晰
- 真实 Secret 管理方式明确
- 部署文档与配置约束一致
- 回归矩阵与 threat-intel 治理已形成稳定基线


### 里程碑 B：V2 覆盖增强

完成标志：

- threat-intel 上游源继续扩展
- 运维观测按需增强
- 交付边界说明继续稳定


### 里程碑 C：V2 运营增强

完成标志：

- 更深的运维观测能力落地
- 历史文档与版本边界继续收敛
- 威胁情报扩展策略清晰

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
- threat-intel 上游源已重构为注册式适配器架构，新增源只需实现适配器 + 注册
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


### 3.2 增强运维观测与审计（已完成）

状态：`Done`

当前已落地以下运维观测能力：

- persona 使用统计（活跃 persona 数、session/message/tool_call 计数、逐 persona 明细）
- threat-intel 同步健康看板（configured/refreshed/healthy/issues + 逐 feed 失败原因 `last_error`/`last_error_at`）
- 按阶段失败分布（stage / persona / tool / 7d trend 四列）
- 工具调用审计摘要
- 配置漂移检查
- 最近失败项摘要与修复建议

threat-intel 同步失败追踪已增强：单个 feed 失败不再中断其余 feed 的同步，失败原因（HTTP 错误码/异常消息）写入 `sync_state.json` 并在工作台展示。


### 3.3 收敛版本边界与文档入口（已完成）

状态：`Done`

当前已完成：

- `docs/security-platform/README.md` 作为统一文档入口，区分"当前有效文档"与"阶段性材料"
- 阶段性材料（`10-19` 号文档）已标注适用范围：冲突时以状态报告、TODO、backlog 为准
- README 新增"版本基线与已知限制"小节，包含版本定位、升级说明（alembic head、bootstrap 刷新）和已知限制
- 本次新增能力（skills、load_skill、threat-intel 适配器、运维增强）已回写进需求、架构、状态报告


## 4. Later

### 4.1 继续深化生产化配置管理（已推进一轮）

本轮已完成：

- Helm secretKeys 全量规范表（9 个 key 的权威定义 + 各 profile 使用矩阵）
- profile ↔ values ↔ required_env 统一对照表
- demo 占位值豁免规则（代码 + 文档）：`SECURITY_TOOLS_MOCK_API_KEY` 在 demo/mock profile 下不再误报

后续仍需按真实交付需要继续推进：

- 视部署目标继续补强 Helm 生产 values 模板（HPA / PDB / 资源 limits / 反亲和）
- 视组织要求继续细化 Secret Manager 接入约定（Vault / KMS / External Secrets Operator）
- 网关进程自身配置模板（VirusTotal 等）尚缺独立配置文件

验收标准：

- 新环境部署时不依赖额外口头说明
- 配置来源、档位边界、secret 注入方式持续一致


### 4.2 继续加深回归矩阵（已推进一轮）

本轮已完成：

- skills 集成测试补全：persona skill_keys 绑定断言 + load_skill mock-LLM 调用回归（action=list / action=load）
- live 测试 mark 规范化：所有 11 个 live 测试加 `@pytest.mark.live`，`-m "not live"` 可一键跳过

后续仍需继续推进：

- 继续扩真实模型下的更长链路场景
- RBAC 负向集成测试（非授权用户不能访问 private persona / 文档集）
- 旧 security_tools 套件与新 security_platform 套件的功能重叠合并
- 新增 persona / tool / skill / playbook 时同步补对应回归

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

§3.1-§3.3 的 Next 项已全部完成。§4 Later 项已推进一轮（skills 集成测试、live mark 规范化、Helm secretKeys 规范化、demo 占位值豁免）。

后续推进重点：

1. 按需继续深化生产化配置（HPA/PDB、Vault/KMS、网关配置模板）
2. 继续加深回归矩阵（RBAC 负向、更长链路、套件合并）
3. 维持 threat-intel 生命周期治理节奏

原因：

- 当前主要主线能力已经成立
- skills 能力、threat-intel 适配器架构、运维观测基线和文档收口均已完成
- 回归矩阵和生产化配置已完成第一轮深化
- 下一阶段重点转向生产化深度、覆盖面扩展和长期维护性


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

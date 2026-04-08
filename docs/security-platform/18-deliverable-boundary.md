# Onyx 智能安全底座可交付版本边界说明

## 1. 文档目标

本文档用于说明当前安全底座版本的可交付边界，便于对内汇报、跨团队同步和后续交付说明统一口径。


## 2. 当前版本定位

当前版本应定义为：

- `PoC / 内部试运行基线版本`

这意味着当前版本已经具备：

- 可部署
- 可初始化
- 可验收
- 可演示
- 可诊断

但当前版本仍不是：

- 完整商业化产品包
- 独立于 Onyx 主仓的独立发行版
- 全量企业能力深度产品化版本


## 3. 当前可以明确承诺的能力

### 3.1 安全底座主链路

- 支持安全知识导入与检索
- 支持四个标准安全 persona / agent
- 支持六个安全 OpenAPI 工具
- 支持声明式工具配置与 persona 绑定
- 支持统一 `bootstrap` 初始化
- 支持最小验收、smoke、playbook 与安全平台回归


### 3.2 threat-intel 治理能力

- 支持 threat-intel feed 同步
- 支持 manifest / curation / lifecycle 评估
- 支持 historical package catalog
- 支持 archive batch、worklist、patch preview、execution artifact 链路


### 3.3 安全工作台与管理面

- 支持统一状态 API 与工作台页面
- 支持健康检查、修复建议和运行摘要
- 支持工具调用审计摘要
- 支持配置漂移检查
- 支持最近失败项摘要


### 3.4 企业能力最小收口

当前以下能力已经完成“管理面可见 + 验收可记录 + 健康检查可诊断”的最小收口：

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


## 4. 当前不能过度承诺的范围

以下内容不应在当前版本中被表述为“已完整产品化”：

- 面向企业 secret manager 的完整生产化接入方案
- 更深的长链路 live 场景回归矩阵
- 更丰富的商业 threat-intel 上游源
- 更强的运营统计、长期趋势看板和审计体系
- 完整白标产品化改造
- 区域化数据处理的真实路由与驻留架构
- 完整独立交付版的部署体系


## 5. 当前适合的使用场景

- 内部试运行
- 方案演示
- 交付前技术验证
- 安全流程和工具链联调
- threat-intel 生命周期治理验证
- 企业能力管理面可见性展示


## 6. 当前不适合的使用场景

- 直接作为完整商业化产品长期承诺版本
- 在未补齐 Secret 管理与真实环境规范前直接进入严格生产治理场景
- 将当前所有企业能力表述为“已 fully productized”


## 7. 后续版本建议

建议按以下方式命名后续演进阶段：

- `V1`：生产化配置与交付收口版本
- `V1.1`：长链路回归增强版本
- `V2`：threat-intel 扩源与运维治理增强版本


## 8. 对外表达建议

如果需要一句话描述当前状态，建议使用：

`当前已完成 Onyx 智能安全底座的 PoC / 内部试运行基线版本，主体能力、验收链路和管理面已形成闭环，后续重点转向生产化配置收口、长链路回归增强和运维治理完善。`

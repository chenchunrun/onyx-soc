# Onyx 智能安全底座阶段版本说明

## 版本结论

当前版本已达到：

- `PoC / 内部试运行基线`

当前可按以下方式理解：

- 主体能力已成型
- 验收链路已形成
- 管理面已具备轻量诊断能力
- 主要企业能力已完成最小收口


## 本阶段主要完成内容

### 1. 安全底座主链路

- 安全知识导入与 `安全知识库` document set 初始化
- 四个安全 persona / agent 初始化与定义文档落库
- 六个安全 OpenAPI 工具创建、绑定与声明式配置管理
- 统一 `bootstrap` 初始化链路
- playbook 目录与统一 runner
- 最小验收、smoke、playbook、安全平台回归链路


### 2. threat-intel 治理链路

- threat-intel feed 同步与 profile 校验
- manifest / curation / lifecycle 评估
- historical package catalog
- archive batch / worklist / patch preview / execution artifact 一致性检查


### 3. 安全工作台与运维摘要

- 安全工作台 API 与前端页面
- 工具调用审计摘要
- 配置漂移检查
- 最近失败项摘要
- 统一健康检查、修复建议和 remediation commands


### 4. 企业能力最小收口

当前以下能力已经完成“管理面可见 + 验收可记录 + 健康检查可诊断”的最小收口：

- Inherit Document Permissions
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


### 5. 文档与交付口径

- 已统一 `TODO / 状态报告 / backlog`
- 已补统一索引页
- 已补可交付版本边界说明
- 已完成核心正式文档的一致性回写


## 已验证结果

- 安全平台状态 API 与验收相关单测已通过
- playbook / acceptance / smoke CLI 入口单测已通过
- threat-intel archive execution result 单测已通过
- 安全平台相关 Python 单测当前结果为：
  - `45 passed`

说明：

- 当前 release notes 以最新文档和当前代码状态为准
- 早期阶段中出现的特定模型专项回归结果，不再作为当前版本主口径


## 当前已知剩余项

- 真实生产环境 Secret 管理方式仍需继续收口
- 更长链路的 live 场景回归仍可继续增强
- threat-intel 上游源仍可继续扩展
- 更深的运营统计、长期趋势和生产化审计能力仍未建立


## 建议使用方式

当前版本适合用于：

- 内部演示
- 内部试运行
- 交付前技术验证
- 管理面与验收链路展示

当前版本不应被表述为：

- 已 fully productized 的独立商业化产品包
- 已完成全部企业能力深度产品化的最终版本

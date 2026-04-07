# Onyx 智能安全底座阶段性汇报摘要

## 1. 当前结论

当前版本已从“方案设计 + 零散脚本”推进到“可部署、可初始化、可验收”的状态。

综合判断：

- 当前整体完成度约为 `80%-85%`
- 已达到 `PoC / 内部试运行` 的最低可交付标准
- 剩余工作重点已从“功能是否成立”转为“生产化配置和交付打磨”


## 2. 本阶段主要成果

### 2.1 初始化链路已闭环

已完成以下自动化能力：

- 安全知识导入
- `安全知识库` document set 自动创建
- 四个安全 persona 自动创建/更新
- 安全 OpenAPI 工具自动创建与绑定
- 安全团队用户与 RBAC 自动初始化
- 统一 bootstrap 编排

对应入口：

- `knowledge-base/bootstrap_security_platform.py`


### 2.2 最小验收已自动化

已新增最小验收脚本，可自动检查：

- document set 是否存在
- 四个 persona 是否存在
- persona 工具绑定是否正确
- 安全工具是否存在
- 安全用户与 RBAC 绑定是否存在
- threat-intel 的 profile、最近同步时间与到期状态
- threat-intel corpus 的 `active / archive_candidates / retained_historical / quality_counts`
- historical package catalog 的 `package_count / total_item_count / total_size_bytes / package_ids`
- security tools profile 与各声明式工具的 `server / headers` 摘要
- deployment profile 与运行时必需环境变量检查结果

对应入口：

- `knowledge-base/verify_security_platform_acceptance.py`


### 2.3 真实环境已验证通过

已在本地真实环境完成：

- `bootstrap --dry-run`
- `bootstrap --verify`
- `personas + tools + rbac` 恢复执行
- 最小验收自动化脚本执行
- 安全平台集成回归执行
- `glm5_live` 真实模型回归执行

当前验收结果：

- `Result: OK`
- `acceptance` 已可显示 `Threat-intel sync: profile / last_run / status`
- `acceptance` 已可显示 threat-intel corpus 与 historical package catalog 摘要
- `acceptance` 已可显示 `Security tools profile`、逐工具端点配置摘要与 `Deployment profile`
- 安全平台集成回归已通过，当前结果为 `14 passed, 10 skipped`
- `glm5_live` 真实模型回归已通过，当前结果为 `3 passed`
- 已验证默认文本模型为 `glm-5` 时，可完成真实安全分析、自主工具调用与多轮取数后综合研判


### 2.4 正式交付文档已成型

已补齐：

- 需求文档
- 架构文档
- 四个安全 Agent 定义
- 实施指南
- 部署指南
- 专家评审记录
- 最小验收清单

目录：

- `docs/security-platform/`


### 2.5 部署覆盖层已落地

已提供两类部署覆盖资产：

1. Docker Compose
- `deployment/docker_compose/env.security-platform.template`
- `deployment/docker_compose/docker-compose.security-platform.override.yml`

2. Helm
- `deployment/helm/charts/onyx/values.security-platform.yaml`
- `deployment/helm/charts/onyx/values.security-platform.live.yaml`
- `deployment/helm/charts/onyx/values.security-platform.demo.yaml`


## 3. 本阶段解决的关键问题

本阶段不仅补了文档和脚本，还修复了几处会影响重复初始化和验收的真实问题：

- 修复 `Web Search` 内置工具无法通过 `/tool` 正确发现的问题
- 修复 persona 更新时误清 custom tools 的问题
- 修复 persona 更新时误清 `persona__user` 访问关系的问题
- 去除对固定 persona ID 的依赖，改为按名称解析
- 将验收从人工查看输出提升为脚本可判定结果
- 补齐 historical package catalog 摘要，使验收结果可以直接反映批次规模和可追踪性
- 修复 direct tool 模式下多 path OpenAPI 工具错误选取 operation 的问题，避免 `threat_intel_lookup` 命中错误端点
- 将 playbook 定义校验增强为可拦截未知工具、persona 绑定不匹配、缺失 `tool_args`、模板引用未来步骤等错误


## 4. 当前剩余缺口

当前仍未完全完成的内容主要集中在生产化层面：

### 4.1 真实生产密钥与配置管理

- 当前 Compose / Helm 已提供入口
- 但仍主要是示例值和示例 Secret 映射
- 尚未形成面向企业实际 secret manager 的接入说明


### 4.2 Helm 覆盖配置仍待生产化收口

- 已有 `values.security-platform.yaml` 以及 `demo/live` overlay 样例
- 但还不是完整生产 values 模板
- 尚未覆盖更细的资源、域名、鉴权和运维参数分层


### 4.3 验收自动化仍偏最小闭环

- 当前已覆盖核心资源、绑定关系以及 `glm-5` 真实模型回归
- 但还没有把更多长链路联调场景全部脚本化


## 5. 风险判断

当前主要风险不是“功能不可用”，而是以下两类：

1. 配置风险
- 真实 webhook / ticket / threat intel 密钥若未按环境规范管理，部署时容易出现配置漂移

2. 运维风险
- 如果后续继续手工修改 persona、tool、RBAC 配置，可能偏离脚本约定，增加环境差异


## 6. 建议下一步

建议不要再继续大面积扩展功能，优先收尾以下事项：

1. 完成一版面向真实环境的配置收口
- 替换示例值
- 明确 Secret 管理方式

2. 视部署目标决定是否继续增强 Helm 模板
- 如果主要使用 Docker Compose，可先停止扩展
- 如果目标是 Kubernetes 集群交付，建议继续补强 Helm 生产模板

3. 以当前版本作为阶段性交付基线
- 当前代码、文档、验收链路已经足够形成阶段性版本


## 7. 里程碑建议

建议将当前版本标记为：

- `安全底座 PoC / 内部试运行基线版本`

建议后续阶段目标：

- `V1`：完成生产化配置与交付清理
- `V2`：补充更完整的联调自动化和运维模板

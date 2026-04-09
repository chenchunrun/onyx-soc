# Onyx 智能安全底座 Secret 管理说明

## 1. 文档目标

本文档用于说明安全底座在生产、联调和演示环境中应如何管理敏感配置。


## 2. Secret 范围

当前安全底座相关敏感项主要分为三类：

- Onyx 平台核心 Secret
  - `USER_AUTH_SECRET`
  - `ENCRYPTION_KEY_SECRET`
- 安全工具访问 Secret
  - `SECURITY_ALERT_WEBHOOK_URL`
  - `SECURITY_TICKET_API_KEY`
  - `THREAT_INTEL_API_KEY`
  - `SECURITY_SIEM_API_KEY`
  - `SECURITY_EDR_API_KEY`
  - `SECURITY_ASSET_API_KEY`
  - `SECURITY_TOOLS_MOCK_API_KEY`
- 管理脚本运行 Secret
  - `ONYX_PASSWORD`
  - `POSTGRES_PASSWORD`


## 3. 推荐注入方式

### 3.1 Docker Compose

推荐做法：

- 保留 `deployment/docker_compose/env.security-platform.template` 作为模板
- 实际环境复制为未纳管的 `env.security-platform`
- 在该文件中填入真实值
- 启动时通过 `docker-compose.security-platform.override.yml` 注入


### 3.2 Helm / Kubernetes

推荐做法：

- 非敏感变量放在 `values.security-platform.yaml`
- 敏感变量放在 Kubernetes Secret
- 通过 `auth.securityPlatform.existingSecret` 引用现有 Secret

示例文件：

- `deployment/helm/charts/onyx/values.security-platform.existing-secret.example.yaml`


## 4. 环境建议

### 4.1 生产环境

- 所有真实 Secret 均来自 Secret Manager 或 Kubernetes Secret
- 不接受 `replace-me`、`example.com`、`mock-api-key-for-testing`
- `ENCRYPTION_KEY_SECRET` 必须设置


### 4.2 联调环境

- 允许使用独立测试 Secret
- 仍应避免模板占位值
- 若使用 `demo/mock` profile，应明确标注环境性质
- 若使用 `gateway` profile，应单独维护 `SECURITY_TOOLS_GATEWAY_API_KEY`，不要与真实上游厂商 Key 混放
- 若网关需要转发 VirusTotal，请将 `VIRUSTOTAL_API_KEY` 仅配置在网关服务，不要注入 Onyx API / background 容器


### 4.3 演示环境

- 可使用 `SECURITY_PLATFORM_DEPLOYMENT_PROFILE=demo`
- 可使用 `SECURITY_TOOLS_PROFILE=mock`
- 可使用 `THREAT_INTEL_SOURCE_PROFILE=mock`
- 仍建议使用独立演示 Secret，而不是长期保留模板占位值


## 5. 当前支持方式

当前仓库已经支持：

- 通过环境变量消费 Secret
- 通过 Compose env file 注入
- 通过 Helm values + existingSecret 引用注入
- 通过独立 gateway 进程持有上游厂商 Secret，并仅向 Onyx 暴露内部网关鉴权 Secret
- 通过工作台和验收脚本识别缺失值与占位值

当前未直接提供：

- 与某个具体云 Secret Manager SDK 的硬集成

当前推荐模式是：

- 由平台侧完成 Secret 下发
- Onyx 通过环境变量或 Kubernetes Secret 消费


## 6. 轮换建议

### 6.1 工具 API Key

推荐步骤：

1. 在上游系统生成新 key
2. 更新 Secret Manager / K8s Secret / env file
3. 重启或滚动更新 Onyx 服务
4. 运行验收脚本确认配置生效


### 6.2 `ENCRYPTION_KEY_SECRET`

推荐步骤：

1. 记录旧 key
2. 配置新 key
3. 使用 `backend/onyx/db/rotate_encryption_key.py` 执行轮换
4. 验证关键 Secret 字段可正常解密


## 7. 验证要求

以下检查应同时满足：

- 安全工作台不再显示缺失 Secret
- `placeholder env` 为 `0`
- `verify_security_platform_acceptance.py` 不再报告占位值
- live profile 下所有必需 API key 和 URL 已设置


## 8. 相关文档

- `docs/security-platform/7-deployment.md`
- `deployment/docker_compose/env.security-platform.template`
- `deployment/helm/charts/onyx/values.security-platform.yaml`
- `deployment/helm/charts/onyx/values.security-platform.existing-secret.example.yaml`

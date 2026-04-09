# Onyx 智能安全底座部署指南

## 1. 文档目标

本文档说明当前版本如何依托 Onyx 主仓完成安全底座部署与初始化。


## 2. 部署原则

当前安全底座不提供独立部署栈，而是基于已有 Onyx 部署进行增量初始化。

这意味着：

- 先部署 Onyx 主平台
- 再执行安全底座初始化脚本


## 3. 最小部署要求

- Onyx API 服务可访问
- Web / Auth 链路可正常登录
- PostgreSQL 可访问
- 需要的工具依赖已安装在 `.venv`


## 4. 建议部署流程

### 4.1 部署 Onyx 主平台

优先使用仓库已有部署能力，例如：

- Docker Compose
- Helm
- Terraform

本指南不重复定义新的主平台部署方式。


### 4.1.1 Helm values 示例

如果使用 Helm 部署，可以直接叠加仓库内提供的安全底座示例 values：

`deployment/helm/charts/onyx/values.security-platform.yaml`

如需直接按环境套用，也可以使用：

- `deployment/helm/charts/onyx/values.security-platform.live.yaml`
- `deployment/helm/charts/onyx/values.security-platform.demo.yaml`
- `deployment/helm/charts/onyx/values.security-platform.existing-secret.example.yaml`

示例：

```bash
cd deployment/helm/charts/onyx
helm upgrade --install onyx . -n onyx --create-namespace \
  -f values.yaml \
  -f values.security-platform.yaml
```

该示例主要补充：

- `live / demo` deployment profile 入口
- 全量安全工具 URL 配置
- 全量安全工具 Secret 映射
- mock server 配置入口
- `WEB_DOMAIN` 示例值

其中：

- `values.security-platform.live.yaml` 适合生产化或联调环境
- `values.security-platform.demo.yaml` 适合演示或离线环境
- `values.security-platform.existing-secret.example.yaml` 适合叠加到 `live` 环境，改为引用已有 Kubernetes Secret
- `demo` 环境下，`SECURITY_TOOLS_MOCK_SERVER_URL` 不应写为 `localhost`

推荐用法：

- `live` 环境：`values.yaml + values.security-platform.live.yaml + existingSecret overlay`
- `demo` 环境：`values.yaml + values.security-platform.demo.yaml`


### 4.2 准备基础资源

部署完成后，至少确认以下资源存在：

- 可登录的管理员账号
- 可访问的 PostgreSQL
- 目标 document set：`安全知识库`
- 本地 threat-intel feed 目录：`knowledge-base/威胁情报/feeds`
- threat-intel 同步计划：`knowledge-base/threat-intelligence/sync_plan.yaml`
- threat-intel 正式内容清单：`knowledge-base/threat-intelligence/feed_manifest.json`
- threat-intel 生命周期报告：`knowledge-base/threat-intelligence/lifecycle_report.json`
- threat-intel archive 行动清单：`knowledge-base/threat-intelligence/archive_plan.json`
- threat-intel archive 批次清单：`knowledge-base/threat-intelligence/archive_batches.json`
- threat-intel archive worklists：`knowledge-base/threat-intelligence/archive_worklists/`
- threat-intel archive patch previews：`knowledge-base/threat-intelligence/archive_patch_previews/`
- threat-intel archive action scripts：`knowledge-base/threat-intelligence/archive_action_scripts/`
- threat-intel archive execution plans：`knowledge-base/threat-intelligence/archive_execution_plans/`
- threat-intel archive execution records：`knowledge-base/threat-intelligence/archive_execution_records/`
- threat-intel archive execution results：`knowledge-base/threat-intelligence/archive_execution_results/`
- threat-intel archive 治理 SOP：`knowledge-base/threat-intelligence/Threat-Intel归档治理SOP.md`


### 4.2.1 Docker Compose 覆盖配置

如果使用仓库内置的 Docker Compose 部署，建议增加一层安全底座专用覆盖配置。

准备方式：

```bash
cd deployment/docker_compose
cp env.security-platform.template env.security-platform
```

启动方式：

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.security-platform.override.yml \
  up -d
```

这层 override 不改动主 compose，只负责把安全底座相关环境变量注入
`api_server`、`background`、`web_server`。

注意：

- `env.security-platform.template` 里的 `replace-me`、`your-company`、`example.com`、`mock-api-key-for-testing` 等值都只是模板占位符
- 当前安全工作台状态页和 `knowledge-base/verify_security_platform_acceptance.py` 都会把这类“已设置但仍是示例值”的变量判为配置问题
- 进入联调、试运行或验收环境前，应全部替换为真实环境值


### 4.3 执行初始化

推荐按以下顺序：

```bash
python knowledge-base/bootstrap_security_platform.py --dry-run
python knowledge-base/bootstrap_security_platform.py --apply --stage knowledge-base
python knowledge-base/bootstrap_security_platform.py --apply --stage threat-intel
python knowledge-base/bootstrap_security_platform.py --apply --stage document-set
python knowledge-base/bootstrap_security_platform.py --apply --stage personas
python knowledge-base/bootstrap_security_platform.py --apply --stage tools
python knowledge-base/bootstrap_security_platform.py --apply --stage rbac
python knowledge-base/bootstrap_security_platform.py --verify
python knowledge-base/bootstrap_security_platform.py --verify --stage smoke
```

如果要接 cron、CI 或定时任务，建议直接调用：

```bash
python knowledge-base/setup_security_threat_intel.py --run-scheduled-sync --url http://127.0.0.1:3000/api
```

也可以使用仓库内的统一包装脚本：

```bash
bash deployment/scripts/run_security_platform_threat_intel_sync.sh \
  deployment/docker_compose/env.security-platform
```

如需单独校验威胁情报内容包是否与 Git 已纳管清单一致，可执行：

```bash
python knowledge-base/build_threat_intel_manifest.py --verify
python knowledge-base/curate_threat_intel_corpus.py --show-summary
python knowledge-base/setup_security_threat_intel.py --verify --local-only
```

其中：

- Docker Compose 示例 cron 在 `deployment/docker_compose/security-platform-threat-intel.crontab.example`
- Helm 场景建议从 CI、ops runner 或 bastion host 直接调用同一脚本
- 演示或离线环境建议设置 `THREAT_INTEL_SOURCE_PROFILE=mock`


## 5. 关键环境参数

- `ONYX_URL`
- `ONYX_EMAIL`
- `ONYX_PASSWORD`
- `POSTGRES_PASSWORD`
- `SECURITY_PLATFORM_DEPLOYMENT_PROFILE`

示例：

```bash
export ONYX_URL=http://localhost:8080
export ONYX_EMAIL=security-admin@onyx.local
export ONYX_PASSWORD=admin123
export POSTGRES_PASSWORD=password
export SECURITY_PLATFORM_DEPLOYMENT_PROFILE=live
```

说明：

- 具体 deployment profile 定义在 `docs/security-platform/deployment-profiles.yaml`
- 每个 profile 现在包含：
  - `env`
  - `required_env`
  - `expectations`
- `required_env` 不仅检查“是否缺失”，也会检查是否仍然保留模板占位值


## 6. 工具相关额外配置

如果要启用真实安全工具，需要补充以下变量：

- `SECURITY_ALERT_WEBHOOK_URL`
- `SECURITY_TICKET_API_URL`
- `SECURITY_TICKET_API_KEY`
- `THREAT_INTEL_API_URL`
- `THREAT_INTEL_API_KEY`
- `SECURITY_TOOLS_PROFILE`
- `SECURITY_TOOLS_GATEWAY_URL`
- `SECURITY_TOOLS_GATEWAY_API_KEY`
- `SECURITY_TOOLS_MOCK_SERVER_URL`
- `SECURITY_TOOLS_MOCK_API_KEY`
- `THREAT_INTEL_SOURCE_PROFILE`

这些变量的引用关系定义在：

- `docs/security-platform/5-integrations/`

实际创建时由以下脚本读取并应用：

- `knowledge-base/security-automation/setup_security_tools.py`

平台级 Secret 还包括：

- `USER_AUTH_SECRET`
- `ENCRYPTION_KEY_SECRET`

网关化环境建议：

- `SECURITY_TOOLS_PROFILE=gateway`
- 将 `SECURITY_TOOLS_GATEWAY_URL` 指向内部安全工具网关或 Actions gateway
- 如果 Onyx 运行在 Docker 容器里，而网关运行在宿主机上，`SECURITY_TOOLS_GATEWAY_URL` 不要写 `localhost`
- 此场景应使用 `http://host.docker.internal:<port>`，否则后端容器会把 `localhost` 解析成容器自身
- 如果使用统一入口，优先设置 `SECURITY_PLATFORM_DEPLOYMENT_PROFILE=gateway`

演示或离线环境建议：

- `SECURITY_TOOLS_PROFILE=mock`
- 启动本地 mock server 后，将 `SECURITY_TOOLS_MOCK_SERVER_URL` 指向对应地址
- 如果 Onyx 运行在 Docker 容器里，而 mock server 运行在宿主机上，`SECURITY_TOOLS_MOCK_SERVER_URL` 不要写 `localhost`
- 此场景应使用 `http://host.docker.internal:<port>`，否则后端容器会把 `localhost` 解析成容器自身
- 如果使用统一入口，优先设置 `SECURITY_PLATFORM_DEPLOYMENT_PROFILE=demo`


### 6.1 Secret 管理建议

生产、联调和演示环境应区分“模板占位值”和“真实 Secret 注入”。

建议同时参考：

- `docs/security-platform/20-secret-management.md`
- `deployment/helm/charts/onyx/values.security-platform.existing-secret.example.yaml`

当前推荐模式是：

- Compose 场景通过未纳管 env file 注入真实值
- Helm/Kubernetes 场景通过 `existingSecret` 引用已有 Secret
- Secret Manager 负责下发，Onyx 负责消费，不在仓库中提交真实值
- `live` overlay 负责环境档位和非敏感 URL；Secret overlay 负责敏感值映射
- `demo` overlay 只用于 mock 工具和离线 threat-intel 场景


## 7. 部署后验收

至少完成以下检查：

- 安全知识已导入
- 威胁情报文档已同步
- threat-intel manifest 校验通过，且 `Unmanaged local feeds` 数量符合本次环境预期
- 如本次交付要求只交付 Git 已纳管正式知识包，则 `Promotion candidates` 应为 `0`，或在评审中明确说明暂不纳管原因
- 四个安全 persona 已存在
- persona 可正常查看并选择
- 自定义安全工具已创建
- 安全团队账号已建立
- `verify` 输出无关键缺失项
- `verify` 中的 `acceptance` 阶段返回成功
- `verify` 中的 `playbooks` 阶段返回成功
- `acceptance` 输出中的 `Deployment profile` 与本次部署选择一致
- `acceptance` 输出中的 `Security tools profile` 与当前部署档位一致
- `acceptance` 输出中的全部声明式安全工具 `server / headers` 摘要符合当前环境
- `acceptance` 输出中的 `Required env vars still use placeholder/example values` 应为空
- `acceptance` 输出中的 `Playbooks: count=...` 与当前交付 playbook 集一致
- `smoke` 阶段返回成功

补充说明：

- 安全工作台的 `Operational Checks` 也会展示 `placeholder env`
- 如果这里非 `0`，说明变量虽然存在，但仍是模板/示例值，当前环境不应视为完成配置收口
- `ENCRYPTION_KEY_SECRET` 在生产化环境中不应缺失

建议结合以下清单执行：

- `docs/security-platform/9-minimal-acceptance-checklist.md`


## 8. 当前限制

- 当前仓库通过环境变量、Compose env file 和 Helm existingSecret 消费 Secret
- 真实环境 Secret 分发仍需结合现有部署体系或 Secret Manager 完成


## 9. 推荐后续增强

- 增加按环境拆分的 Helm values overlay（例如 `live` / `demo` 独立文件）
- 增加更贴近企业 Secret Manager 的组织级接入约定

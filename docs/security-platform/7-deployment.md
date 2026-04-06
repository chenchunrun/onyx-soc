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

示例：

```bash
cd deployment/helm/charts/onyx
helm upgrade --install onyx . -n onyx --create-namespace \
  -f values.yaml \
  -f values.security-platform.yaml
```

该示例主要补充：

- 安全工具相关 URL 配置
- 安全工具相关 Secret 映射
- `WEB_DOMAIN` 示例值


### 4.2 准备基础资源

部署完成后，至少确认以下资源存在：

- 可登录的管理员账号
- 可访问的 PostgreSQL
- 目标 document set：`安全知识库`


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


### 4.3 执行初始化

推荐按以下顺序：

```bash
python knowledge-base/bootstrap_security_platform.py --dry-run
python knowledge-base/bootstrap_security_platform.py --apply --stage knowledge-base
python knowledge-base/bootstrap_security_platform.py --apply --stage document-set
python knowledge-base/bootstrap_security_platform.py --apply --stage personas
python knowledge-base/bootstrap_security_platform.py --apply --stage tools
python knowledge-base/bootstrap_security_platform.py --apply --stage rbac
python knowledge-base/bootstrap_security_platform.py --verify
python knowledge-base/verify_security_platform_acceptance.py
```


## 5. 关键环境参数

- `ONYX_URL`
- `ONYX_EMAIL`
- `ONYX_PASSWORD`
- `POSTGRES_PASSWORD`

示例：

```bash
export ONYX_URL=http://localhost:8080
export ONYX_EMAIL=security-admin@onyx.local
export ONYX_PASSWORD=admin123
export POSTGRES_PASSWORD=password
```


## 6. 工具相关额外配置

如果要启用真实安全工具，需要补充以下变量：

- `SECURITY_ALERT_WEBHOOK_URL`
- `SECURITY_TICKET_API_URL`
- `SECURITY_TICKET_API_KEY`
- `THREAT_INTEL_API_URL`
- `THREAT_INTEL_API_KEY`


## 7. 部署后验收

至少完成以下检查：

- 安全知识已导入
- 四个安全 persona 已存在
- persona 可正常查看并选择
- 自定义安全工具已创建
- 安全团队账号已建立
- `verify` 输出无关键缺失项
- 最小验收脚本返回 0

建议结合以下清单执行：

- `docs/security-platform/9-minimal-acceptance-checklist.md`


## 8. 当前限制

- 真实环境密钥管理仍需结合现有部署体系完成


## 9. 推荐后续增强

- 增加生产与演示环境配置模板
- 增加更贴近生产环境的 Helm values 样例

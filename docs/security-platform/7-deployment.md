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


### 4.2 准备基础资源

部署完成后，至少确认以下资源存在：

- 可登录的管理员账号
- 可访问的 PostgreSQL
- 目标 document set：`安全知识库`


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

建议结合以下清单执行：

- `docs/security-platform/9-minimal-acceptance-checklist.md`


## 8. 当前限制

- 尚未提供安全底座专属 `docker compose override`
- 尚未提供专属 Helm values 示例
- 真实环境密钥管理仍需结合现有部署体系完成


## 9. 推荐后续增强

- 增加部署后验收脚本
- 增加生产与演示环境配置模板

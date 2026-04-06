# 5-integrations Schema

每个 `*.yaml` 文件定义一个安全工具集成。

## 必填字段

- `name`
  - 工具在 Onyx 中的唯一名称
- `template`
  - 当前支持：
    - `security_alert_webhook`
    - `security_ticket_api`
    - `threat_intel_api`
- `description`
  - 用于 Onyx 工具描述和使用场景说明
- `persona_bindings`
  - 允许自动绑定的 persona 名称列表

## 模板特定字段

### `security_alert_webhook`

- `webhook_url_env`

### `security_ticket_api`

- `api_url_env`
- `api_key_env`

### `threat_intel_api`

- `api_url_env`
- `api_key_env`

## persona 限制

当前仅允许以下 persona：

- `安全事件分析师`
- `应急响应指挥官`
- `漏洞评估专家`
- `合规审计员`

## 校验入口

```bash
python knowledge-base/security-automation/setup_security_tools.py --validate-configs
```

该命令会检查：

- YAML 可解析
- 必填字段完整
- 模板名合法
- 模板特定字段完整
- persona 绑定合法
- 工具名不重复

## Profile 分层

工具的环境分层定义在：

- `docs/security-platform/5-integrations/profiles.yaml`

当前支持：

- `live`
- `mock`

执行时可通过以下方式选择：

```bash
SECURITY_TOOLS_PROFILE=mock python knowledge-base/security-automation/setup_security_tools.py --dry-run
python knowledge-base/security-automation/setup_security_tools.py --apply --profile mock
```

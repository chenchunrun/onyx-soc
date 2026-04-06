# 5-integrations Authoring Guide

## 目标

新增安全工具时，先补配置和模板，再执行初始化脚本，不直接在脚本里追加硬编码工具定义。

## 推荐流程

1. 在 `knowledge-base/security-automation/openapi_templates/` 新增或复用模板
2. 在本目录新增一个 `*.yaml`
3. 运行配置校验
4. 在测试里补对应断言
5. 执行 `setup_security_tools.py --dry-run`
6. 确认后再执行 `--apply`

## 示例

```yaml
name: create_security_ticket
template: security_ticket_api
description: >-
  Create security incident tickets in Jira, Linear, or ServiceNow.
api_url_env: SECURITY_TICKET_API_URL
api_key_env: SECURITY_TICKET_API_KEY
persona_bindings:
  - 安全事件分析师
  - 应急响应指挥官
```

## 最小校验命令

```bash
python knowledge-base/security-automation/setup_security_tools.py --validate-configs
python knowledge-base/security-automation/setup_security_tools.py --dry-run --url http://127.0.0.1:3000/api
python knowledge-base/security-automation/setup_security_tools.py --dry-run --profile mock --url http://127.0.0.1:3000/api
```

## 注意事项

- 不要把真实密钥写入 YAML
- 新工具名必须全局唯一
- persona 绑定必须使用标准安全 persona 名称
- 模板变更后要同步更新 `schema.md`
- 如果需要支持演示环境，优先通过 `profiles.yaml` 做 env 映射，不要在脚本里单独写 mock 分支

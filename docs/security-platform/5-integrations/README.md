# 5-integrations

该目录用于描述安全智能底座的外部安全工具集成配置。

当前约束：

- 一个 YAML 文件对应一个可创建的安全工具
- `name` 为 Onyx 中创建后的工具名
- `template` 对应 `knowledge-base/security-automation/openapi_templates/` 下的 OpenAPI 模板
- `persona_bindings` 定义工具默认挂载到哪些安全 persona
- `*_env` 字段定义运行时所需环境变量名，不直接在仓库中保存敏感值
- persona 目前仅允许绑定四个标准安全角色

推荐先执行：

```bash
python knowledge-base/security-automation/setup_security_tools.py --validate-configs
```

环境分层：

- `SECURITY_TOOLS_PROFILE=live`
- `SECURITY_TOOLS_PROFILE=mock`

当前 profile 定义文件：

- [profiles.yaml](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/profiles.yaml)

当前已落地的集成：

- `security-alert.yaml`
- `security-ticket.yaml`
- `threat-intel.yaml`

与实现的对应关系：

- 初始化脚本：[setup_security_tools.py](/Users/newmba/Downloads/onyx-main/knowledge-base/security-automation/setup_security_tools.py)
- 部署阶段：`bootstrap --apply --stage tools`
- 验证阶段：`bootstrap --verify`

后续新增安全工具时，优先在本目录增加 YAML 配置，再复用现有模板或补充新的模板文件。

补充说明：

- 字段规范见 [schema.md](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/schema.md)
- 新增流程见 [authoring-guide.md](/Users/newmba/Downloads/onyx-main/docs/security-platform/5-integrations/authoring-guide.md)

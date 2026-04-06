# Onyx 智能安全底座实施指南

## 1. 文档目标

本文档说明如何基于当前仓库实现一套可运行的安全底座初始化流程。


## 2. 实施对象

适用于以下场景：

- 新环境首次落地
- 演示环境初始化
- 已有环境补齐安全 persona / 工具 / RBAC


## 3. 实施前提

- Onyx 服务已可访问
- 仓库 `.venv` 已准备完成
- PostgreSQL 可从执行机访问


## 4. 核心脚本

- `knowledge-base/upload_to_onyx.py`
- `knowledge-base/setup_security_personas.py`
- `knowledge-base/security-automation/setup_security_tools.py`
- `knowledge-base/sso-rbac/provision_security_team.py`
- `knowledge-base/bootstrap_security_platform.py`


## 5. 推荐实施顺序

### 步骤 1：预演

```bash
python knowledge-base/bootstrap_security_platform.py --dry-run
```

目标：

- 检查脚本参数是否正确
- 检查 RBAC 阶段环境是否具备基本条件
- 预览将执行的动作


### 步骤 2：导入知识库

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage knowledge-base
```

目标：

- 将 `knowledge-base/` 中的 markdown 文档导入 Onyx


### 步骤 3：初始化 persona

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage document-set
```

目标：

- 创建 `安全知识库` document set


### 步骤 4：初始化 persona

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage personas
```

目标：

- 创建或更新四个安全 persona
- 绑定基础工具和 `安全知识库`


### 步骤 5：创建安全工具

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage tools
```

目标：

- 创建安全 OpenAPI 工具
- 将工具按 persona 绑定


### 步骤 6：初始化 RBAC

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage rbac
```

目标：

- 创建安全团队用户
- 配置 persona 可见性
- 绑定用户与 document set


### 步骤 7：结果校验

```bash
python knowledge-base/bootstrap_security_platform.py --verify
python knowledge-base/bootstrap_security_platform.py --verify --stage smoke
```


## 6. 一次性执行

如果环境已经准备完成，可以直接执行：

```bash
python knowledge-base/bootstrap_security_platform.py --apply
```


## 7. 常用参数

```bash
python knowledge-base/bootstrap_security_platform.py \
  --apply \
  --url http://localhost:8080 \
  --email security-admin@onyx.local \
  --password admin123 \
  --db-password password
```


## 8. 实施注意事项

- `personas` 阶段会按名称更新已有 persona，不再依赖固定 ID
- `document-set` 阶段会确保 `安全知识库` 存在
- `tools` 和 `rbac` 阶段都已改为按 persona 名称解析
- `rbac --dry-run` 当前实际走环境预检查，而不是写库模拟
- `knowledge-base --dry-run` 输出较长，属于当前脚本正常行为
- `bootstrap --verify` 现已默认包含 `acceptance` 阶段
- `verify_security_platform_acceptance.py` 仍可单独执行，适合接 CI 或部署后自动检查
- `bootstrap --verify --stage smoke` 可用于部署后的真实聊天/工具冒烟验证


## 9. 测试建议

最小验证建议包括：

- bootstrap 的 `dry-run / verify`
- persona 初始化单测
- 工具绑定单测
- 安全工具链集成测试

当前已补充的单测包括：

- `backend/tests/unit/knowledge_base/test_setup_security_document_set.py`
- `backend/tests/unit/knowledge_base/test_setup_security_personas.py`
- `backend/tests/unit/knowledge_base/test_bootstrap_security_platform.py`
- `backend/tests/unit/knowledge_base/test_verify_security_platform_acceptance.py`


## 10. 当前未覆盖项

- 真实生产 API 凭据分发
- 独立部署资产编排
- 更完整的联调与回归自动化

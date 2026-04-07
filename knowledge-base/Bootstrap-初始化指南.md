# Onyx 安全底座 Bootstrap 初始化指南

本文档说明如何使用统一入口脚本初始化 Onyx 智能安全底座的二开内容。

统一入口脚本：

- [bootstrap_security_platform.py](/Users/newmba/Downloads/onyx-main/knowledge-base/bootstrap_security_platform.py)


## 1. 目标

该脚本负责串联当前已经存在的阶段：

- 安全知识库导入
- 安全文档集创建
- 安全 persona 创建/更新
- 安全工具创建与 persona 工具绑定
- 安全团队 RBAC 初始化
- 最小验收自动化
- 部署后聊天/工具冒烟验证

设计目标不是替换原有脚本，而是统一入口、统一参数和统一执行顺序。


## 2. 前置条件

执行前应满足以下条件：

- Onyx 服务已启动
- 可访问 Onyx API
- 本仓库 `.venv` 已准备好
- PostgreSQL 可从本机访问
- 安全 personas 已存在于目标环境

默认依赖如下：

- Onyx URL：`http://localhost:8080`
- 管理员账号：`security-admin@onyx.local`
- PostgreSQL：`localhost:5432`


## 3. 支持的阶段

### `knowledge-base`

调用：

- `knowledge-base/upload_to_onyx.py`

职责：

- 扫描 `knowledge-base/` 下的 markdown
- 通过 ingestion API 导入 Onyx


### `tools`

调用：

- `knowledge-base/security-automation/setup_security_tools.py`

职责：

- 创建推荐的安全 OpenAPI 工具
- 绑定工具到安全 persona


### `document-set`

调用：

- `knowledge-base/setup_security_document_set.py`

职责：

- 确保名称为 `安全知识库` 的 document set 存在
- 为后续 persona 与 RBAC 初始化提供稳定依赖


### `personas`

调用：

- `knowledge-base/setup_security_personas.py`

职责：

- 创建或更新四个标准安全 persona
- 绑定基础知识域和基础内置工具
- 为 RBAC 和工具初始化提供稳定的 persona 名称入口


### `playbooks`

调用：

- `knowledge-base/run_security_playbook.py --verify-definitions`

职责：

- 校验声明式安全 playbook 定义
- 校验 playbook `example_inputs` 是否完整
- 为后续安全流程验证提供稳定入口


### `rbac`

调用：

- `knowledge-base/sso-rbac/provision_security_team.py`

职责：

- 检查 persona 与文档集
- 创建安全团队账号
- 绑定 document set 和 persona 可见性


### `acceptance`

调用：

- `knowledge-base/verify_security_platform_acceptance.py`

职责：

- 校验 document set、persona、工具、用户与 RBAC 绑定
- 输出机器可判定的最小验收结果


### `smoke`

调用：

- `knowledge-base/post_deploy_smoke_test.py`

职责：

- 验证安全 persona 的基础聊天链路
- 验证只读安全工具的真实调用链路


## 4. 运行模式

### 4.1 预演模式

```bash
python knowledge-base/bootstrap_security_platform.py --dry-run
```

说明：

- `knowledge-base` 和 `tools` 阶段输出将要执行的动作
- `rbac` 阶段执行环境预检查，不直接写库


### 4.2 执行模式

```bash
python knowledge-base/bootstrap_security_platform.py --apply
```

说明：

- 按顺序执行全部阶段
- 任一阶段失败时中断并返回非 0 状态码


### 4.3 校验模式

```bash
python knowledge-base/bootstrap_security_platform.py --verify
```

说明：

- 校验已导入文档、已创建工具和 RBAC 配置状态
- 默认会执行 `playbooks` 和 `acceptance` 阶段


## 5. 按阶段执行

只执行知识库导入：

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage knowledge-base
```

只执行工具和 RBAC：

```bash
python knowledge-base/bootstrap_security_platform.py --apply --stage tools --stage rbac
```

只执行 RBAC 预检查：

```bash
python knowledge-base/bootstrap_security_platform.py --dry-run --stage rbac
```

只执行最小验收：

```bash
python knowledge-base/bootstrap_security_platform.py --verify --stage acceptance
```

只执行 playbook 定义校验：

```bash
python knowledge-base/bootstrap_security_platform.py --verify --stage playbooks
```

只执行部署后冒烟：

```bash
python knowledge-base/bootstrap_security_platform.py --verify --stage smoke
```


## 6. 常用参数

```bash
python knowledge-base/bootstrap_security_platform.py \
  --apply \
  --url http://localhost:8080 \
  --email security-admin@onyx.local \
  --password admin123 \
  --db-password password
```

参数说明：

- `--url`：Onyx 基础地址
- `--email`：管理员邮箱
- `--password`：管理员密码
- `--db-password`：PostgreSQL 密码
- `--stage`：指定执行阶段，可重复传入


## 7. 推荐执行顺序

首次初始化建议按以下顺序：

1. `--dry-run`
2. `--apply --stage knowledge-base`
3. `--apply --stage document-set`
4. `--apply --stage personas`
5. `--apply --stage tools`
6. `--apply --stage rbac`
7. `--verify`

原因：

- 先确认环境和参数
- 再分别完成数据、工具、权限初始化
- 最后统一校验结果，并执行最小验收


## 8. 已知限制

- `rbac` 阶段依赖数据库可连接
- `knowledge-base` 阶段的预演输出较长，因为会列出所有 markdown 文件
- `personas` 阶段依赖 Onyx API 可访问
- `document-set` 阶段当前会创建一个空 document set，不会自动绑定 connector/cc pair
- `acceptance` 阶段不支持 `--dry-run`
- `smoke` 阶段依赖真实聊天链路和工具链路可用，执行时间明显长于 `acceptance`


## 9. 相关脚本

- [upload_to_onyx.py](/Users/newmba/Downloads/onyx-main/knowledge-base/upload_to_onyx.py)
- [setup_security_document_set.py](/Users/newmba/Downloads/onyx-main/knowledge-base/setup_security_document_set.py)
- [setup_security_personas.py](/Users/newmba/Downloads/onyx-main/knowledge-base/setup_security_personas.py)
- [setup_security_tools.py](/Users/newmba/Downloads/onyx-main/knowledge-base/security-automation/setup_security_tools.py)
- [provision_security_team.py](/Users/newmba/Downloads/onyx-main/knowledge-base/sso-rbac/provision_security_team.py)
- [verify_security_platform_acceptance.py](/Users/newmba/Downloads/onyx-main/knowledge-base/verify_security_platform_acceptance.py)
- [post_deploy_smoke_test.py](/Users/newmba/Downloads/onyx-main/knowledge-base/post_deploy_smoke_test.py)

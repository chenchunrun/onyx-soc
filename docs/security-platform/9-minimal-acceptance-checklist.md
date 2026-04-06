# Onyx 智能安全底座最小验收清单

## 1. 文档目标

本文档用于部署和初始化完成后的最小验收，确认安全底座已经具备可演示、可试运行的基础状态。


## 2. 验收范围

本清单覆盖以下内容：

- bootstrap 初始化链路
- 安全文档集
- 安全 persona
- 安全工具
- RBAC 初始化
- 关键工具链联调


## 3. 环境前提

- Onyx 主平台已启动
- 管理员账号可登录
- PostgreSQL 可访问
- `.venv` 可用
- 如需验证真实工具，相关 API key / webhook 已配置


## 4. 初始化验收

### 4.1 预演检查

执行：

```bash
python knowledge-base/bootstrap_security_platform.py --dry-run
```

通过标准：

- 命令返回成功
- `document-set`、`personas`、`tools`、`rbac` 阶段都有明确输出
- `rbac` 阶段没有出现不可恢复的环境错误


### 4.2 全量初始化

执行：

```bash
python knowledge-base/bootstrap_security_platform.py --apply
```

通过标准：

- 各阶段按顺序执行完成
- 任一阶段没有返回非 0 状态码


### 4.3 结果校验

执行：

```bash
python knowledge-base/bootstrap_security_platform.py --verify
python knowledge-base/verify_security_platform_acceptance.py
```

通过标准：

- `安全知识库` document set 存在
- 四个安全 persona 全部存在
- 安全工具可见
- 安全团队用户已创建
- 最小验收脚本返回 0


## 5. 数据与配置验收

### 5.1 安全文档集

检查项：

- 存在名称为 `安全知识库` 的 document set

通过标准：

- document set 能在管理页面或接口中看到


### 5.2 安全 persona

检查项：

- `安全事件分析师`
- `应急响应指挥官`
- `漏洞评估专家`
- `合规审计员`

通过标准：

- 四个 persona 都存在
- persona 可被选择
- persona 绑定了 `安全知识库`


### 5.3 安全工具

检查项：

- `send_security_alert`
- `create_security_ticket`
- `threat_intel_lookup`

通过标准：

- 工具已创建
- persona 上能看到对应工具绑定关系


### 5.4 安全团队用户

检查项：

- `commander@security.local`
- `analyst@security.local`
- `vuln_expert@security.local`
- `auditor@security.local`

通过标准：

- 用户存在
- 用户角色正确
- 用户可见 persona 与预期一致


## 6. 功能联调验收

### 6.1 工具链集成测试

执行：

```bash
python -m dotenv -f .vscode/.env run -- \
pytest backend/tests/integration/tests/security_tools/ -v
```

通过标准：

- `send_security_alert` 调用链成功
- `create_security_ticket` 调用链成功
- `threat_intel_lookup` 调用链成功


### 6.2 Persona 基础使用验证

人工检查建议：

- 使用 `安全事件分析师` 发起一次 IoC 查询
- 使用 `应急响应指挥官` 发起一次告警/响应建议请求
- 使用 `漏洞评估专家` 查询一个 CVE
- 使用 `合规审计员` 查询一个合规控制项

通过标准：

- persona 能正常回答
- 回答符合各自角色定位


## 7. 失败处理建议

若验收失败，优先检查：

1. `bootstrap --verify` 输出缺失项
2. `verify_security_platform_acceptance.py` 输出失败项
3. Onyx 登录与 API 可达性
4. PostgreSQL 可达性
5. 工具相关环境变量是否已配置
6. persona 和 document set 是否被意外手工修改


## 8. 当前结论口径

当以上最小验收项全部通过时，可以认为：

- 当前版本已达到 PoC / 内部试运行的最低可交付标准

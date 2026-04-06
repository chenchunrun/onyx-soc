# Onyx 安全底座 Actions 自动化集成指南

本文档说明如何为 Onyx 智能安全底座配置 Actions 自动化集成，使安全 personas 能够与外部安全系统联动。

---

## 目录

1. [Actions 系统概览](#1-actions-系统概览)
2. [OpenAPI 工具配置](#2-openapi-工具配置)
3. [安全自动化工具模板](#3-安全自动化工具模板)
4. [配置步骤](#4-配置步骤)
5. [Persona 工具绑定](#5-persona-工具绑定)
6. [使用示例](#6-使用示例)

---

## 1. Actions 系统概览

Onyx 的 Actions 系统允许 AI personas 通过工具(Tools)调用外部 API，实现安全自动化。

### 可用工具类型

| 类型 | 来源 | 说明 |
|------|------|------|
| **内置工具** | Onyx 内置 | 搜索、Web搜索、代码执行、文件读取 |
| **OpenAPI 工具** | 自定义 | 基于 OpenAPI 规范调用任意 REST API |
| **MCP 工具** | MCP 服务器 | 通过 Model Context Protocol 连接外部服务 |

### 内置安全工具（已配置）

所有安全 persona 已绑定以下内置工具：

| Persona | 工具 |
|---------|------|
| 安全事件分析师 | 搜索, Web搜索, 打开URL, 读取文件 |
| 应急响应指挥官 | 搜索, Web搜索, 代码执行, 读取文件 |
| 漏洞评估专家 | 搜索, Web搜索, 代码执行, 读取文件 |
| 合规审计员 | 搜索, Web搜索, 代码执行, 读取文件 |

---

## 2. OpenAPI 工具配置

### 2.1 通过 Admin UI 配置

1. 进入 **Admin > Actions > Open API**
2. 点击 **Create New Action**
3. 填写表单：
   - **Name**: 工具名称（如 `send_security_alert`）
   - **Description**: 工具描述（告诉 LLM 何时使用）
   - **OpenAPI Spec**: 粘贴 OpenAPI 3.0 JSON 规范
   - **Custom Headers**: 可选，添加固定请求头
   - **Passthrough Auth**: 是否使用用户的 OAuth 令牌

### 2.2 通过 API 配置

```bash
# 登录获取 cookie
COOKIE=$(curl -s -c - -X POST http://localhost:8080/auth/login \
  -d "username=security-admin@onyx.local&password=admin123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep fastapiusersauth | awk '{print $7}')

# 创建工具
curl -X POST http://localhost:8080/admin/tool/custom \
  -H "Cookie: fastapiusersauth=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "send_security_alert",
    "description": "发送安全告警到 Slack/Teams",
    "passthrough_auth": false,
    "definition": { ... }
  }'
```

---

## 3. 安全自动化工具模板

### 3.1 安全告警 Webhook (`security_alert_webhook.json`)

向 Slack、Teams、PagerDuty 发送结构化安全告警。

**参数：**
- `alert_type`: 告警类型 (PHISHING/MALWARE/DATA_BREACH/...)
- `severity`: 严重等级 (P0-P4)
- `title`: 告警标题
- `description`: 详细描述
- `source_system`: 来源系统 (SIEM/EDR/Firewall)
- `affected_assets`: 受影响资产
- `indicators`: IoC 指标 (IPs/域名/哈希/URL)
- `recommended_actions`: 建议措施

**适用场景：** 安全 persona 检测到威胁后自动发送告警

### 3.2 安全工单管理 (`security_ticket_api.json`)

在 Jira/Linear/ServiceNow 中创建和管理安全工单。

**操作：**
- `createSecurityTicket`: 创建安全工单
- `addTicketComment`: 添加工单评论

**参数：**
- `summary`: 工单标题
- `priority`: 优先级 (CRITICAL/HIGH/MEDIUM/LOW)
- `project_key`: 项目键 (如 SEC, SOC)
- `mitre_tactics`: MITRE ATT&CK 战术
- `mitre_techniques`: MITRE ATT&CK 技术
- `cvss_score`: CVSS 评分

**适用场景：** 自动化创建事件响应工单

### 3.3 威胁情报查询 (`threat_intel_api.json`)

查询 VirusTotal、AbuseIPDB、AlienVault OTX、Shodan。

**操作：**
- `lookupIP`: IP 地址查询
- `lookupDomain`: 域名查询
- `lookupFileHash`: 文件哈希查询

**适用场景：** 分析师需要核实 IP/域名/文件的威胁情报

---

## 4. 配置步骤

### 步骤 1: 准备 Webhook 端点

#### Slack Incoming Webhook

1. 访问 [Slack App Console](https://api.slack.com/apps)
2. 创建新 App > **From an app manifest**
3. 添加 **Incoming Webhooks** feature
4. 创建 Webhook URL: `https://hooks.slack.com/services/XXX/YYY/ZZZ`

#### Microsoft Teams Incoming Webhook

1. 进入 Teams > 目标频道 > ... > **Connectors**
2. 配置 **Incoming Webhook**
3. 复制 Webhook URL

#### PagerDuty Events API

1. 创建 PagerDuty Integration on-call escalation policy
2. 使用 Integration Key: `https://events.pagerduty.com/v2/enqueue`

### 步骤 2: 创建 OpenAPI 工具

使用 `setup_security_tools.py` 脚本：

```bash
# 查看可用工具
python setup_security_tools.py --list-templates

# 配置 Slack 告警工具
python setup_security_tools.py --create-tool \
  --template security_alert_webhook \
  --name send_slack_alert \
  --webhook-url "https://hooks.slack.com/services/XXX/YYY/ZZZ"

# 创建 Jira 工单工具
python setup_security_tools.py --create-tool \
  --template security_ticket_api \
  --name create_security_ticket \
  --api-url "https://your-company.atlassian.net/rest/api/3" \
  --api-key "your-jira-api-key"

# 创建威胁情报查询工具
python setup_security_tools.py --create-tool \
  --template threat_intel_api \
  --name threat_intel_lookup \
  --api-url "https://www.virustotal.com/api/v3" \
  --api-key "your-virustotal-api-key"
```

### 步骤 3: 绑定工具到 Persona

```bash
# 将告警工具绑定到应急响应指挥官 (persona_id=3)
python setup_security_tools.py --attach-tool \
  --tool-name send_slack_alert \
  --persona-id 3

# 将工单工具绑定到安全事件分析师 (persona_id=2)
python setup_security_tools.py --attach-tool \
  --tool-name create_security_ticket \
  --persona-id 2

# 将威胁情报工具绑定到漏洞评估专家 (persona_id=4)
python setup_security_tools.py --attach-tool \
  --tool-name threat_intel_lookup \
  --persona-id 4
```

---

## 5. Persona 工具绑定建议

| Persona | 推荐绑定工具 | 原因 |
|---------|-------------|------|
| 应急响应指挥官 | 安全告警 Webhook、工单管理 | 指挥官需要快速通知团队和创建工单 |
| 安全事件分析师 | 威胁情报查询、工单管理 | 分析师需要核实 IoC 和记录分析 |
| 漏洞评估专家 | 威胁情报查询、工单管理 | 评估专家需要查询漏洞数据和建档 |
| 合规审计员 | 工单管理（审计跟踪） | 审计员需要记录合规问题 |

---

## 6. 使用示例

### 示例 1: 检测到钓鱼邮件后发送告警

**用户输入：**
> 分析以下邮件内容，识别其中的钓鱼特征，如果是钓鱼邮件请发送告警到安全团队：
> 发件人: support@amaz0n-security.com
> 主题: 您的账户已被锁定 - 请立即验证

**Persona 行为：**
1. 分析邮件内容，识别 IoC（域名 am az0n-security.com）
2. 调用 `threat_intel_lookup` 查询域名
3. 调用 `send_security_alert` 发送告警：
```json
{
  "alert_type": "PHISHING",
  "severity": "P1",
  "title": "钓鱼邮件告警 - 冒充Amazon",
  "description": "检测到冒充Amazon的钓鱼邮件...",
  "source_system": "Onyx安全底座",
  "indicators": {
    "domains": ["amaz0n-security.com"],
    "urls": ["http://amaz0n-security.com/verify"]
  },
  "recommended_actions": ["阻止域名", "通知用户"]
}
```

### 示例 2: 漏洞评估后创建工单

**用户输入：**
> CVE-2024-1234 是一个 CVSS 9.8 的远程代码执行漏洞，请评估对我司的影响并创建工单

**Persona 行为：**
1. 搜索知识库中该漏洞的信息
2. 调用威胁情报 API 查询漏洞详情
3. 评估受影响资产
4. 调用 `create_security_ticket` 创建工单：
```json
{
  "summary": "[P0] CVE-2024-1234 紧急漏洞处置",
  "description": "CVSS 9.8 RCE漏洞...",
  "priority": "CRITICAL",
  "project_key": "SEC",
  "cvss_score": 9.8,
  "labels": ["security", "vulnerability", "CVE-2024-1234"]
}
```

---

## 快速配置清单

- [ ] 获取 Slack/Teams Webhook URL
- [ ] 获取 Jira API Key（如果需要工单集成）
- [ ] 获取威胁情报 API Key（VirusTotal 等）
- [ ] 运行 `setup_security_tools.py --apply` 创建工具
- [ ] 将工具绑定到对应 Persona
- [ ] 测试工具调用（通过聊天触发 persona）

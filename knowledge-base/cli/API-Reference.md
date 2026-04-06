# Onyx Security API 参考文档

本文档描述 Onyx 智能安全底座的 REST API 接口，供安全自动化工具和 CLI 工具调用。

---

## 目录

1. [认证](#1-认证)
2. [ Persona 管理](#2-persona-管理)
3. [聊天接口](#3-聊天接口)
4. [搜索接口](#4-搜索接口)
5. [文档上传](#5-文档上传)
6. [工具(Tools)管理](#6-工具tools管理)

---

## 1. 认证

### 1.1 登录

```http
POST /auth/login
Content-Type: application/x-www-form-urlencoded
```

**请求体：**
```
username=<email>&password=<password>
```

**成功响应 (200)：**
Set-Cookie header 包含 `fastapiusersauth` session cookie。

**失败响应 (401)：**
```json
{"detail": "Invalid credentials"}
```

**curl 示例：**
```bash
COOKIE=$(curl -s -c - -X POST http://localhost:8080/auth/login \
  -d "username=security-admin@onyx.local&password=admin123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep fastapiusersauth | awk '{print $7}')
echo "Cookie: $COOKIE"
```

### 1.2 获取当前用户

```http
GET /auth/me
Cookie: fastapiusersauth=<session_cookie>
```

**成功响应 (200)：**
```json
{
  "id": "uuid-string",
  "email": "security-admin@onyx.local",
  "username": "security-admin",
  "role": "admin",
  "is_superuser": false,
  "is_active": true
}
```

### 1.3 登出

```http
POST /auth/logout
Cookie: fastapiusersauth=<session_cookie>
```

---

## 2. Persona 管理

### 2.1 列出 Personas

```http
GET /assistants?include_all_public=true
Cookie: fastapiusersauth=<session_cookie>
```

**成功响应 (200)：**
```json
{
  "assistants": [
    {
      "id": 2,
      "name": "安全事件分析师",
      "description": "...",
      "is_public": false,
      "is_listed": true,
      "prompts": {...},
      "tools": [
        {"id": 11, "name": "send_security_alert", ...},
        {"id": 12, "name": "create_security_ticket", ...},
        {"id": 13, "name": "threat_intel_lookup", ...}
      ]
    },
    ...
  ]
}
```

### 2.2 获取单个 Persona

```http
GET /assistants/{persona_id}
Cookie: fastapiusersauth=<session_cookie>
```

### 2.3 创建 Persona

```http
POST /assistants
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
```

**请求体：**
```json
{
  "name": "应急响应指挥官",
  "description": "负责安全事件应急响应和协调",
  "prompts": {
    "system": "You are an emergency response commander..."
  },
  "is_public": false,
  "is_listed": true,
  "display_priority": 0
}
```

---

## 3. 聊天接口

### 3.1 创建聊天会话

```http
POST /chat/create-chat-session
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
```

**请求体：**
```json
{
  "persona_id": 2,
  "description": "安全事件分析会话"
}
```

**成功响应 (200)：**
```json
{
  "chat_session_id": "uuid-string"
}
```

### 3.2 发送聊天消息（流式）

```http
POST /chat/send-chat-message
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
X-Accel-Buffering: no
```

**请求体：**
```json
{
  "message": "分析 CVE-2024-1234 的威胁等级",
  "chat_session_id": "uuid-string",
  "stream": true,
  "file_descriptors": [],
  "persona_id": 2
}
```

**流式响应格式（SSE）：**

每行一个 JSON 对象，格式如下：

```json
{"reserved_assistant_message_id": 42, "placement": {"turn_index": 0, "tab_index": 0, "sub_turn_index": null}}
{"obj": {"type": "message_start"}, "placement": {...}}
{"obj": {"type": "message_delta", "content": "CVE-2024-1234 是一个"}, "placement": {...}}
{"obj": {"type": "message_delta", "content": "虚构的 CVE，"}, "placement": {...}}
{"obj": {"type": "search_tool_start"}, "placement": {...}}
{"obj": {"type": "search_tool_queries_delta", "queries": ["CVE-2024-1234"]}, "placement": {...}}
{"obj": {"type": "search_tool_documents_delta", "documents": [...]}, "placement": {...}}
{"obj": {"type": "message_delta", "content": "建议采取以下措施..."}, "placement": {...}}
{"obj": {"type": "message_end"}, "placement": {...}}
```

**流式包类型说明：**

| type | 说明 | 关键字段 |
|------|------|---------|
| `message_start` | 助手消息开始 | - |
| `message_delta` | 助手消息文本片段 | `content` (字符串) |
| `message_end` | 助手消息结束 | - |
| `search_tool_start` | 搜索工具开始 | - |
| `search_tool_queries_delta` | 搜索查询 | `queries` (字符串列表) |
| `search_tool_documents_delta` | 搜索文档结果 | `documents` (文档列表) |
| `stop` | 流结束 | - |

### 3.3 发送聊天消息（非流式）

```http
POST /chat/send-chat-message
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
```

**请求体：** stream=false
```json
{
  "message": "分析 CVE-2024-1234 的威胁等级",
  "chat_session_id": "uuid-string",
  "stream": false,
  "file_descriptors": []
}
```

**响应：**
```json
{
  "answer": "CVE-2024-1234 是一个虚构的 CVE...",
  "answer_citationless": "...",
  "pre_answer_reasoning": null,
  "tool_calls": [],
  "top_documents": [...],
  "citation_info": [...]
}
```

### 3.4 获取聊天历史

```http
GET /chat/get-chat-session/{session_id}
Cookie: fastapiusersauth=<session_cookie>
```

### 3.5 获取用户所有会话

```http
GET /chat/get-user-chat-sessions
Cookie: fastapiusersauth=<session_cookie>
```

---

## 4. 搜索接口

### 4.1 搜索文档

```http
POST /search/send-search-message
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
```

**请求体：**
```json
{
  "search_query": "钓鱼邮件 处置",
  "filters": {
    "persona_id": 2
  },
  "stream": false
}
```

**成功响应 (200)：**
```json
{
  "search_docs": [
    {
      "document_id": "...",
      "semantic_identifier": "钓鱼邮件识别与处置指南",
      "blurb": "本指南描述钓鱼邮件的识别特征...",
      "link": "...",
      "source_type": "file",
      "score": 0.92,
      "metadata": {...}
    }
  ],
  "query_event_id": "..."
}
```

---

## 5. 文档上传

### 5.1 上传文档（Ingestion API）

```http
POST /onyx-api/ingestion
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
```

**请求体：**
```json
{
  "document": {
    "title": "钓鱼邮件识别与处置指南",
    "content": "# 钓鱼邮件识别与处置指南\n\n本文档介绍...",
    "link": "kb://security/phishing-guide",
    "metadata": {
      "section": "security",
      "tags": ["phishing", "email", "security"]
    }
  }
}
```

**成功响应 (200)：**
```json
{
  "status": "success",
  "document_id": "..."
}
```

---

## 6. 工具(Tools)管理

### 6.1 创建自定义工具

```http
POST /admin/tool/custom
Cookie: fastapiusersauth=<session_cookie>
Content-Type: application/json
```

**请求体（OpenAPI 工具）：**
```json
{
  "name": "send_security_alert",
  "description": "发送安全告警到 Slack/Teams",
  "passthrough_auth": false,
  "definition": {
    "openapi": "3.0.3",
    "info": {"title": "Security Alert API", "version": "1.0.0"},
    "paths": {
      "/webhook": {
        "post": {
          "operationId": "sendAlert",
          "parameters": [...],
          "responses": {...}
        }
      }
    }
  }
}
```

### 6.2 列出工具

```http
GET /admin/tool/list
Cookie: fastapiusersauth=<session_cookie>
```

### 6.3 将工具绑定到 Persona（数据库直接操作）

工具与 Persona 的关联通过 `persona__tool` 关联表管理。

```sql
-- 附加工具到 persona
INSERT INTO persona__tool (persona_id, tool_id) VALUES (3, 11) ON CONFLICT DO NOTHING;

-- 查询 persona 的工具
SELECT t.id, t.name, t.description
FROM tool t
JOIN persona__tool pt ON t.id = pt.tool_id
WHERE pt.persona_id = 3;

-- 移除工具
DELETE FROM persona__tool WHERE persona_id = 3 AND tool_id = 11;
```

---

## 安全 persona 工具绑定对照表

| Persona ID | Persona 名称 | 绑定工具 ID | 工具名称 |
|------------|-------------|------------|---------|
| 2 | 安全事件分析师 | 12, 13 | create_security_ticket, threat_intel_lookup |
| 3 | 应急响应指挥官 | 11, 12 | send_security_alert, create_security_ticket |
| 4 | 漏洞评估专家 | 12, 13 | create_security_ticket, threat_intel_lookup |
| 5 | 合规审计员 | 12 | create_security_ticket |

---

## CLI 工具使用

使用 `onyx-cli.py` 简化 API 调用：

```bash
# 登录
onyx-cli --email security-admin@onyx.local --password admin123 login

# 状态检查
onyx-cli status

# 列出 Personas
onyx-cli list-personas

# 搜索
onyx-cli search --query "钓鱼邮件处置"

# 聊天（非流式）
onyx-cli ask --persona-name 安全事件分析师 --no-stream "CVE-2024-1234 是什么"

# 聊天（流式）
onyx-cli ask --persona-name 安全事件分析师 "CVE-2024-1234 是什么"
```

完整 CLI 源码见 `knowledge-base/cli/onyx-cli.py`。

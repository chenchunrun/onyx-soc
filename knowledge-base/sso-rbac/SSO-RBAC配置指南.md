# Onyx 安全底座 SSO/RBAC 配置指南

本文档说明如何为 Onyx 智能安全底座配置 SSO 单点登录和 RBAC 角色权限管理。

---

## 目录

1. [认证架构概览](#1-认证架构概览)
2. [Google OAuth 配置](#2-google-oauth-配置)
3. [OIDC 配置](#3-oidc-配置)
4. [SAML 2.0 配置](#4-saml-20-配置)
5. [用户角色映射](#5-用户角色映射)
6. [密码策略配置](#6-密码策略配置)
7. [部署配置](#7-部署配置)

---

## 1. 认证架构概览

Onyx 支持以下认证方式（通过 `AUTH_TYPE` 环境变量切换）：

| AUTH_TYPE | 说明 | 适用场景 |
|-----------|------|---------|
| `basic` | 邮箱+密码本地认证 | 开发/测试环境 |
| `google_oauth` | Google OAuth 2.0 | 企业快速接入 |
| `oidc` | 通用 OpenID Connect | Okta/Auth0/Keycloak/Azure AD |
| `saml` | SAML 2.0 | 传统企业 SSO |
| `cloud` | Onyx Cloud 托管认证 | Onyx 云版本 |

### Onyx 内置用户角色

| 角色 | 权限级别 | 安全底座映射 |
|------|---------|------------|
| `ADMIN` | 完全管理员权限 | 应急响应指挥官 |
| `BASIC` | 标准用户权限 | 安全事件分析师、漏洞评估专家、合规审计员 |
| `CURATOR` | 指定数据管理员 | 文档管理员（可选） |
| `GLOBAL_CURATOR` | 全局数据管理员 | 全局文档管理员（可选） |
| `LIMITED` | 受限访问 | 访客/观察员（可选） |

### 权限系统

Onyx 使用细粒度权限控制：

```python
class Permission(str, Enum):
    # 基础
    BASIC_ACCESS = "basic"

    # 读权限
    READ_CONNECTORS = "read:connectors"
    READ_DOCUMENT_SETS = "read:document_sets"
    READ_AGENTS = "read:agents"
    READ_USERS = "read:users"

    # 管理权限
    ADD_AGENTS = "add:agents"
    MANAGE_AGENTS = "manage:agents"
    MANAGE_DOCUMENT_SETS = "manage:document_sets"
    ADD_CONNECTORS = "add:connectors"
    MANAGE_CONNECTORS = "manage:connectors"
    MANAGE_LLMS = "manage:llms"
    MANAGE_ACTIONS = "manage:actions"
    READ_QUERY_HISTORY = "read:query_history"
    MANAGE_USER_GROUPS = "manage:user_groups"
    CREATE_USER_API_KEYS = "create:user_api_keys"

    # 管理员
    FULL_ADMIN_PANEL_ACCESS = "full_admin_panel_access"
```

权限具有层级关系（如 `MANAGE_AGENTS` 隐含 `ADD_AGENTS` 和 `READ_AGENTS`）。

---

## 2. Google OAuth 配置

### 步骤 1: 在 Google Cloud Console 创建 OAuth 2.0 凭据

1. 访问 [Google Cloud Console](https://console.cloud.google.com/)
2. 进入 **APIs & Services > Credentials**
3. 点击 **Create Credentials > OAuth client ID**
4. Application type 选择 **Web application**
5. 添加 Authorized redirect URI: `https://your-onyx-domain.com/auth/oauth/callback/google_oauth`

### 步骤 2: 配置环境变量

在 `docker-compose.yml` 或 `.env` 文件中添加：

```yaml
# docker-compose.yml (api_server 和 background 服务)
environment:
  - AUTH_TYPE=google_oauth
  - OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
  - OAUTH_CLIENT_SECRET=your-client-secret
```

或在 `.env` 文件中：

```bash
# .env
AUTH_TYPE=google_oauth
OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your-client-secret
```

### 步骤 3: 高级选项（可选）

```bash
# 启用 PKCE（推荐用于增强安全性）
OAUTH_PKCE_ENABLED=true

# 自定义 OAuth 回调路径（默认 /auth/oauth/callback/google_oauth）
# OAUTH_CALLBACK_URL=/auth/oauth/callback/google_oauth
```

### 步骤 4: 验证

重启服务后，登录页面将显示 "Sign in with Google" 按钮。

---

## 3. OIDC 配置

适用于 Okta、Auth0、Keycloak、Azure AD (Entra ID) 等 OIDC 提供商。

### 步骤 1: 在身份提供商创建应用

#### Okta

1. 进入 **Applications > Create App Integration**
2. 选择 **OIDC - OpenID Connect > Web Application**
3. 设置 Sign-in redirect URIs: `https://your-onyx-domain.com/auth/oauth/callback/google_oauth`
4. 设置 Sign-out redirect URIs: `https://your-onyx-domain.com`
5. 记下 Client ID、Client Secret 和 Okta domain

#### Auth0

1. 创建 Regular Web Application
2. 设置 Allowed Callback URLs: `https://your-onyx-domain.com/auth/oauth/callback/google_oauth`
3. 设置 Allowed Logout URLs: `https://your-onyx-domain.com`
4. 获取 Domain、Client ID、Client Secret

#### Keycloak

1. 创建新 Client
2. Client ID 设置为 `onyx`
3. Client Protocol 选择 `openid-connect`
4. Access Type 选择 `confidential`
5. Valid Redirect URIs: `https://your-onyx-domain.com/auth/oauth/callback/google_oauth*`
6. 在 Credentials 标签页获取 Client Secret

#### Azure AD (Entra ID)

1. 注册新应用 (App registrations > New registration)
2. 设置 Redirect URI: Web 类型, `https://your-onyx-domain.com/auth/oauth/callback/google_oauth`
3. 在 Certificates & secrets 创建客户端密钥
4. 在 API permissions 添加 `openid`, `profile`, `email` 权限
5. 记下 Application (client) ID, Directory (tenant) ID, Client Secret

### 步骤 2: 配置环境变量

```bash
# .env
AUTH_TYPE=oidc

# OIDC 发现端点 (Okta 示例)
OPENID_CONFIG_URL=https://your-org.okta.com/.well-known/openid-configuration

# 或手动配置各参数:
# OIDC_ISSUER=https://your-org.okta.com
# OIDC_CLIENT_ID=your-client-id
# OIDC_CLIENT_SECRET=your-client-secret
# OIDC_TOKEN_URL=https://your-org.okta.com/oauth2/v1/token
# OIDC_AUTH_URL=https://your-org.okta.com/oauth2/v1/authorize
# OIDC_USERINFO_URL=https://your-org.okta.com/oauth2/v1/userinfo

# PKCE 支持
OIDC_PKCE_ENABLED=true

# JWT 公钥（可选，如 IdP 不支持 OIDC 发现）
JWT_PUBLIC_KEY_URL=https://your-org.okta.com/oauth2/v1/keys

# 自定义 OIDC 范围
OIDC_SCOPE_OVERRIDE=openid profile email

# 跟踪外部 IdP Token 过期
TRACK_EXTERNAL_IDP_EXPIRY=true
```

### 步骤 3: Azure AD 特殊配置

```bash
# Azure AD 使用租户特定端点
OPENID_CONFIG_URL=https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration

# 或使用通用端点（支持个人 + 工作账户）
OPENID_CONFIG_URL=https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
```

---

## 4. SAML 2.0 配置

### 步骤 1: 创建 SAML 应用

在身份提供商中创建 SAML 2.0 应用：

#### Okta SAML

1. **Single Sign On > Create App Integration > SAML 2.0**
2. 设置:
   - Single sign on URL: `https://your-onyx-domain.com/auth/saml/callback`
   - Audience URI (SP Entity ID): `https://your-onyx-domain.com`
   - Name ID format: `EmailAddress`
   - Application username: `Email`
3. 导出 IdP 元数据 XML

#### Azure AD SAML

1. 注册应用（非 Microsoft 应用）
2. 设置:
   - Reply URL (Assertion Consumer Service): `https://your-onyx-domain.com/auth/saml/callback`
   - Entity ID: `https://your-onyx-domain.com`
   - Sign on URL: `https://your-onyx-domain.com`
3. 下载 Federation Metadata XML

### 步骤 2: 配置 SAML 目录

```bash
# 创建 SAML 配置目录
mkdir -p /path/to/saml_config

# 放置 IdP 元数据文件
# /path/to/saml_config/idp_metadata.xml
```

### 步骤 3: 配置环境变量

```bash
# .env
AUTH_TYPE=saml
SAML_CONF_DIR=/app/onyx/configs/saml_config

# 可选: 自定义 SP 元数据
# SAML_SP_METADATA_URL=https://your-onyx-domain.com/auth/saml/metadata
```

### SAML 配置目录结构

```
/app/onyx/configs/saml_config/
├── idp_metadata.xml      # IdP 元数据（必需）
├── sp_cert.pem          # SP 证书（可选，自签名）
├── sp_key.pem           # SP 私钥（可选）
└── settings.json        # SAML python3-saml 高级配置（可选）
```

### 高级 SAML 设置 (settings.json)

```json
{
  "strict": true,
  "debug": false,
  "sp": {
    "entityId": "https://your-onyx-domain.com",
    "assertionConsumerService": {
      "url": "https://your-onyx-domain.com/auth/saml/callback",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  },
  "idp": {
    "entityId": "https://your-idp.com/exk.../sso/saml/metadata",
    "singleSignOnService": {
      "url": "https://your-idp.com/exk.../sso/saml",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "MIIDpDCC...（IdP 证书）"
  }
}
```

### SAML 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/auth/saml/authorize` | GET | SAML 登录发起 |
| `/auth/saml/callback` | GET/POST | IdP 回调处理 |
| `/auth/saml/logout` | POST | SAML 登出 |

---

## 5. 用户角色映射

### 安全底座角色 -> Onyx 角色映射

| 安全角色 | Onyx 角色 | 权限范围 | 说明 |
|---------|----------|---------|------|
| 应急响应指挥官 | `ADMIN` | 完全管理权限 | 全系统管理、用户管理、配置变更 |
| 安全事件分析师 | `BASIC` | 标准用户权限 | 搜索、聊天、创建会话 |
| 漏洞评估专家 | `BASIC` | 标准用户权限 | 搜索、聊天、创建会话 |
| 合规审计员 | `BASIC` | 标准用户权限 | 搜索、聊天、创建会话 |

### 推荐做法

1. **OAuth/OIDC 自动映射**: 使用 OIDC 声明自动分配角色（需要 Enterprise Edition）
2. **SCIM 手动分配**: 通过 SCIM 2.0 API 管理用户和角色
3. **本地用户创建**: 使用 `provision_security_team.py` 脚本批量创建

### API 管理用户角色

```bash
# 获取当前用户列表
curl -X GET "http://localhost:8080/users" \
  -H "Cookie: fastapiusersauth=$COOKIE" \
  -H "Content-Type: application/json"

# 更新用户角色
curl -X PATCH "http://localhost:8080/users/{user_id}" \
  -H "Cookie: fastapiusersauth=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"role": "BASIC"}'
```

---

## 6. 密码策略配置

当使用 `basic` 认证时，可通过环境变量配置密码策略：

```bash
# 密码长度
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=64

# 密码复杂度要求
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL_CHAR=true

# 邮箱验证
REQUIRE_EMAIL_VERIFICATION=false

# 允许的邮箱域名（逗号分隔，为空则不限制）
VALID_EMAIL_DOMAINS=company.com,partner.com

# 禁止一次性邮箱
DISPOSABLE_EMAIL_DOMAINS_URL=https://disposable.github.io/Disposable-Email-Domains/domains.txt
```

---

## 7. 部署配置

### 修改 docker-compose.yml

```yaml
# deployment/docker_compose/docker-compose.yml
services:
  api_server:
    environment:
      - AUTH_TYPE=${AUTH_TYPE:-basic}
      # Google OAuth
      - OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID:-}
      - OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET:-}
      # OIDC
      - OPENID_CONFIG_URL=${OPENID_CONFIG_URL:-}
      - OIDC_PKCE_ENABLED=${OIDC_PKCE_ENABLED:-false}
      # SAML
      - SAML_CONF_DIR=${SAML_CONF_DIR:-/app/onyx/configs/saml_config}
      # Session
      - AUTH_BACKEND=${AUTH_BACKEND:-redis}
      - SESSION_EXPIRE_TIME_SECONDS=${SESSION_EXPIRE_TIME_SECONDS:-604800}

  background:
    environment:
      - AUTH_TYPE=${AUTH_TYPE:-basic}
      - OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID:-}
      - OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET:-}
      - OPENID_CONFIG_URL=${OPENID_CONFIG_URL:-}
      - SAML_CONF_DIR=${SAML_CONF_DIR:-/app/onyx/configs/saml_config}
```

### .env 示例

创建 `.env` 文件（不要提交到版本控制）:

```bash
# 认证配置
AUTH_TYPE=google_oauth
OAUTH_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your-google-client-secret

# 会话配置
AUTH_BACKEND=redis
SESSION_EXPIRE_TIME_SECONDS=604800  # 7 天

# 密码策略（仅 basic 认证模式）
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL_CHAR=true
```

### 重启服务

```bash
# 重启所有服务
docker compose down
docker compose up -d

# 仅重启 API 服务器
docker compose restart api_server
```

### 验证配置

```bash
# 检查 API 服务器环境变量
docker exec onyx-api_server-1 env | grep -E "AUTH|OAUTH|OIDC|SAML"

# 查看日志
docker logs -f onyx-api_server-1 2>&1 | grep -i "auth\|oauth\|saml\|oidc"
```

---

## 快速启动清单

- [ ] 确定认证方式（Google OAuth / OIDC / SAML / Basic）
- [ ] 在身份提供商创建应用，获取 Client ID/Secret
- [ ] 配置回调 URL (`/auth/oauth/callback/google_oauth` 或 `/auth/saml/callback`)
- [ ] 更新 `.env` 或 `docker-compose.yml`
- [ ] 重启 Onyx 服务
- [ ] 测试 SSO 登录流程
- [ ] 创建安全团队用户并分配角色
- [ ] 验证权限控制（各角色用户登录测试）

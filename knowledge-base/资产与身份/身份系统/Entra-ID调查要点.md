# Entra ID 调查要点

## 1. 适用范围

适用于 Microsoft Entra ID 场景下的异常登录、令牌滥用、应用授权与账号接管调查。

## 2. 核心数据源

- Sign-in Logs
- Audit Logs
- Risky Users
- Risky Sign-ins
- Conditional Access 日志
- OAuth / Enterprise Applications 授权记录

## 3. 调查重点

- 异常登录来源和地理位置
- Legacy Auth 使用
- MFA 疲劳与 MFA 绕过
- 新增应用授权和异常 consent
- 邮箱、SharePoint、Teams 等后续操作

## 4. 常见处置动作

- 强制下线
- 重置密码
- 撤销 token
- 重新注册 MFA
- 移除异常应用授权
- 调整条件访问策略


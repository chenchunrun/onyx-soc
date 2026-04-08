# Azure与M365安全调查要点

## 适用场景

- Entra ID 账号失陷
- 恶意 OAuth / 企业应用授权
- Exchange Online 钓鱼、转发规则、邮箱滥用
- Azure 资源被异常创建或暴露

## 优先关注的数据源

- Entra ID Sign-in Logs
- Audit Logs
- Microsoft Defender XDR
- Exchange Online Message Trace
- Unified Audit Log
- Azure Activity Log

## 首轮问题清单

- 是否存在陌生登录地点、设备、客户端应用
- 是否存在 MFA 绕过或异常注册
- 是否存在新建转发规则、邮箱委派、恶意应用授权
- 是否存在新建高权限角色分配
- 是否存在异常资源创建、公开存储或密钥泄露

## 快速排查步骤

### 身份

- 查用户最近登录失败/成功轨迹
- 查 Conditional Access 命中情况
- 查是否新增认证方法、设备注册、应用密码
- 查异常 Consent、Service Principal、新增 Secret/Certificate

### 邮件

- 查是否有异常 inbox rule / forwarding rule
- 查近 24 小时内对外发信量
- 查 Message Trace 是否存在相同主题批量外发
- 查是否有异常邮箱代理或共享邮箱访问

### 云资源

- 查 Role Assignment 变化
- 查公开存储、公开 IP、NSG 规则放开
- 查 Key Vault 访问峰值和异常 Secret 读取

## 常见高危动作

- 新增全局管理员或高权角色
- 为恶意应用授予 Mail.Read / Files.Read.All / offline_access
- 设置外部邮箱自动转发
- 新增长效 Secret 或证书
- 打开存储公开访问

## 研判输出建议

- 失陷主体：用户 / 应用 / 服务主体
- 主要痕迹：登录、授权、邮件、资源变更
- 影响对象：邮箱、文件、订阅、资源组
- 临时处置：禁用账号、撤销会话、移除应用授权、停用转发

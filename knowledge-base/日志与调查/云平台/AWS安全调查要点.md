# AWS安全调查要点

## 适用场景

- 云主机异常外连
- IAM 凭证疑似泄露
- S3 / KMS / CloudTrail 配置被篡改
- 安全组、路由、VPC 配置突变

## 优先关注的数据源

- CloudTrail
- GuardDuty
- VPC Flow Logs
- CloudWatch Logs
- IAM Access Analyzer
- Config / Security Hub

## 首轮问题清单

- 哪个账号、角色、Access Key 触发了异常动作
- 异常动作发生在哪个 Region
- 是否存在新建用户、附加高权限策略、创建长期密钥
- 是否存在关闭日志、删除告警、停用审计的动作
- 是否存在异常快照、异常导出、S3 大量读取

## 快速排查步骤

### 身份与权限

- 查最近新增/更新的 IAM 用户、角色、策略
- 查 Access Key 最后使用时间与来源 IP
- 查是否有跨账号 AssumeRole
- 查是否附加了 AdministratorAccess 或等价高权策略

### 审计与日志

- 确认 CloudTrail 是否持续开启
- 确认关键日志桶未被修改策略或删除对象
- 查是否有人改过日志保留、告警阈值、SNS 订阅

### 数据访问

- 查 S3 GetObject/ListBucket 峰值
- 查是否有异常导出 RDS snapshot / EBS snapshot
- 查 KMS decrypt 调用是否异常升高

### 网络与计算

- 查安全组是否临时开放高危端口
- 查是否新增可疑 EC2、Lambda、ECS 任务
- 查异常出网方向、目标 IP、目标国家

## 常见高危动作

- `CreateAccessKey`
- `AttachUserPolicy`
- `PutUserPolicy`
- `AssumeRole`
- `StopLogging`
- `DeleteTrail`
- `PutBucketPolicy`
- `AuthorizeSecurityGroupIngress`
- `CreateSnapshot`

## 研判输出建议

- 异常主体：账号 / 角色 / Access Key
- 异常时间线：首次、峰值、最后一次
- 影响范围：账户、Region、资源类型
- 已确认行为：权限提升、数据访问、日志规避、横向移动
- 处置建议：禁用密钥、隔离实例、回滚策略、保全日志

# Linux 认证与提权调查

## 1. 目标

用于调查 Linux 主机上的异常登录、sudo 滥用、提权与横向移动行为。

## 2. 重点日志位置

- `/var/log/auth.log`
- `/var/log/secure`
- `journald`
- `auditd`
- SSHD 日志

## 3. 核心调查问题

- 谁在登录
- 从哪里登录
- 是否使用密码、密钥、sudo、su
- 是否出现异常用户、异常计划任务、异常持久化

## 4. 优先排查项

- SSH 登录成功与失败
- `sudo` 与 `su` 使用
- 新增账号与组变更
- `cron`、`systemd`、启动项持久化
- Shell 历史与可疑下载执行

## 5. 常见命令

```bash
last -a
lastb -a
grep "Accepted\\|Failed" /var/log/auth.log
grep "sudo\\|su:" /var/log/auth.log
ausearch -m USER_LOGIN
```

## 6. 调查输出

- 登录账号
- 来源 IP
- 提权路径
- 持久化位置
- 恶意文件 / 命令


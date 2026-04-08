# EDR常用调查查询样例

## 使用说明

- 先按平台字段名适配
- 先限制时间范围，再加主机、用户名、进程名过滤
- 先做宽查询，再逐步收窄

## 进程调查

### 可疑父子进程

- `powershell.exe` <- `winword.exe`
- `cmd.exe` <- `outlook.exe`
- `rundll32.exe` <- `mshta.exe`
- `regsvr32.exe` <- `wscript.exe`

### 关注字段

- `process_name`
- `parent_process_name`
- `command_line`
- `username`
- `device_name`
- `sha256`

## 持久化调查

- 注册表 Run / RunOnce
- 计划任务创建
- 服务创建
- 启动目录写入
- WMI 持久化

## 横向移动调查

- `psexec`
- `wmic process call create`
- `winrm`
- `remote service creation`
- 异常 `RDP` 登录后跟随命令执行

## 文件与脚本调查

- Office 派生脚本执行
- 下载后立即执行的可执行文件
- 编码或混淆 PowerShell
- 来自临时目录、下载目录的二进制

## 输出建议

- 主机名
- 用户名
- 关键进程树
- 哈希与落地路径
- 是否需要隔离
- 是否已有 IOC 命中

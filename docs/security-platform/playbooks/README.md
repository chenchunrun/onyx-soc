# Security Playbooks

该目录用于定义面向安全 persona 的可执行 playbook。

约束：

- 一个 YAML 文件对应一条可执行流程
- `steps` 按顺序执行
- 每一步必须指定 `persona`
- `tool` 可选；指定时 runner 会用 `forced_tool_id` 约束工具调用
- `prompt` 支持变量替换
- 工具步骤建议补 `mock_llm_response`，用于测试模式下的确定性执行
- 支持 `execution_mode: template`，用于把最终汇总步骤做成本地可重复渲染

变量来源：

- `inputs.<name>`：运行时输入
- `steps.<step_id>.full_message`：上一步回复文本
- `steps.<step_id>.tool_call_debug`：上一步工具调用调试信息

执行约束：

- `example_inputs` 必须覆盖所有必填输入
- `mock_llm_response` 如果提供，必须是合法 JSON
- `execution_mode: template` 时必须提供 `response_template`
- `--execute` 默认失败即停，可用 `--continue-on-failure` 覆盖
- `--step-timeout-seconds` 用于限制单步最长等待时间

推荐命令：

```bash
python knowledge-base/run_security_playbook.py --list-playbooks
python knowledge-base/run_security_playbook.py --show-playbook incident-triage-readonly
python knowledge-base/run_security_playbook.py --dry-run --playbook incident-triage-readonly \
  --input incident_ip=8.8.8.8 --input asset_hostname=finance-host-01 --input alert_query=powershell
```

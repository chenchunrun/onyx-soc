# Onyx 智能安全底座阶段版本说明

## 版本结论

当前版本已达到 `PoC / 内部试运行基线`，整体完成度约为 `80%-85%`。


## 主要新增能力

- 安全知识导入与 `安全知识库` document set 初始化
- 四个安全 persona 自动创建与更新
- 安全工具创建、绑定与 RBAC 初始化
- 统一 `bootstrap` 链路
- 最小验收自动化
- threat-intel corpus / historical package catalog 摘要输出
- security tools profile / deployment profile 运行摘要输出
- `glm5_live` 真实模型专项回归


## 部署与运行资产

- Docker Compose 安全平台环境模板与 override
- Helm `values.security-platform.yaml`
- Helm `values.security-platform.live.yaml`
- Helm `values.security-platform.demo.yaml`


## 已验证结果

- 最小验收脚本已在真实环境通过，当前结果为 `Result: OK`
- 安全平台集成回归已通过，当前结果为 `14 passed, 10 skipped`
- `glm5_live` 专项回归已通过，当前结果为 `3 passed`
- 已验证真实 `glm-5` 模型可完成安全分析、自主工具调用和多轮链路


## 关键修复

- 修复 persona 更新时误清 custom tools 的问题
- 修复 persona 更新时误清 `persona__user` 访问关系的问题
- 修复 `Web Search` 内置工具在现网中发现不稳定的问题
- 修复 direct tool 模式下多 path OpenAPI 工具错误选取 operation 的问题
- 增强 playbook 定义静态校验，提前拦截工具声明和步骤引用错误


## 当前已知剩余项

- 真实生产环境 Secret 和配置管理仍需收口
- Helm 模板仍需进一步生产化
- 更长链路联调自动化仍可继续补强

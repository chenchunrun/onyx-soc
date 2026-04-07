# Onyx 智能安全底座周报消息体

本周安全底座主链路已基本收口，当前整体完成度约 `80%-85%`，已达到 `PoC / 内部试运行基线`。
已完成安全知识导入、`安全知识库` document set、四个安全 persona、安全工具、RBAC 和统一 bootstrap 链路。
最小验收自动化已跑通，可直接校验 threat-intel 状态、historical package catalog、security tools profile 和 deployment profile。
真实环境集成回归已通过，当前结果 `14 passed, 10 skipped`。
`glm5_live` 专项回归已通过，当前结果 `3 passed`，已验证真实 `glm-5` 的安全分析、自主工具调用和多轮链路。
Helm 已补齐 `base / live / demo` 三类 overlay，当前剩余重点转为生产环境 Secret / 配置收口与更长链路联调回归。

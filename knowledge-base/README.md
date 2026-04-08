# 网络安全知识库总索引

本目录用于承载 Onyx 智能安全底座相关的通用安全知识、运营手册、威胁情报和平台实施材料。

## 阅读顺序建议

如果你是第一次进入这套知识库，建议按下面顺序阅读：

1. 平台与实施
2. 事件响应与调查
3. 检测工程与查询样例
4. 资产与身份
5. 威胁情报与漏洞情报
6. 内部运行手册

## 平台与实施

- [security-automation/](/Users/newmba/Downloads/onyx-main/knowledge-base/security-automation)
  安全自动化、工具接入、playbook 相关资料
- [sso-rbac/](/Users/newmba/Downloads/onyx-main/knowledge-base/sso-rbac)
  身份治理、SSO、RBAC、团队初始化
- [threat-intelligence/](/Users/newmba/Downloads/onyx-main/knowledge-base/threat-intelligence)
  threat-intel 生命周期治理、归档、执行结果

## 事件响应与调查

- [应急响应/](/Users/newmba/Downloads/onyx-main/knowledge-base/应急响应)
  总体响应知识
- [应急响应索引](/Users/newmba/Downloads/onyx-main/knowledge-base/应急响应/README.md)
  事件响应入口页
- [专项SOP/](/Users/newmba/Downloads/onyx-main/knowledge-base/应急响应/专项SOP)
  钓鱼、账号失陷、勒索等专项 SOP
- [证据与复盘/](/Users/newmba/Downloads/onyx-main/knowledge-base/应急响应/证据与复盘)
  证据保全与复盘模板
- [日志与调查/](/Users/newmba/Downloads/onyx-main/knowledge-base/日志与调查)
  Windows、Linux、AD、邮件、网络、云平台调查要点

## 检测工程

- [检测工程/](/Users/newmba/Downloads/onyx-main/knowledge-base/检测工程)
  检测工程总目录
- [检测工程索引](/Users/newmba/Downloads/onyx-main/knowledge-base/检测工程/README.md)
  规则、映射、查询样例入口页
- [规则方法论/](/Users/newmba/Downloads/onyx-main/knowledge-base/检测工程/规则方法论)
  检测规则设计、误报降噪、ATT&CK 映射
- [查询样例/](/Users/newmba/Downloads/onyx-main/knowledge-base/检测工程/查询样例)
  EDR / SIEM 常用调查查询样例

## 资产与身份

- [资产与身份/](/Users/newmba/Downloads/onyx-main/knowledge-base/资产与身份)
  资产、身份、目录服务相关知识
- [身份系统/](/Users/newmba/Downloads/onyx-main/knowledge-base/资产与身份/身份系统)
  AD、Entra ID 调查要点

## 威胁情报与合规

- [威胁情报/](/Users/newmba/Downloads/onyx-main/knowledge-base/威胁情报)
  ATT&CK、CVE、情报源与映射资料
- [合规基线/](/Users/newmba/Downloads/onyx-main/knowledge-base/合规基线)
  等保与安全检查清单
- [最佳实践/](/Users/newmba/Downloads/onyx-main/knowledge-base/最佳实践)
  漏洞管理等专题最佳实践
- [安全策略/](/Users/newmba/Downloads/onyx-main/knowledge-base/安全策略)
  组织策略与制度材料

## 内部运行手册

- [内部运行手册/](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册)
  值班、分级、升级、工单流转、SIEM / EDR 手册、字段字典
- [内部运行手册索引](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册/README.md)
  值班与平台操作入口页

重点入口：

- [告警分级标准.md](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册/告警分级标准.md)
- [工单流转与升级路径.md](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册/工单流转与升级路径.md)
- [SIEM平台操作手册.md](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册/SIEM平台操作手册.md)
- [EDR平台操作手册.md](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册/EDR平台操作手册.md)
- [安全平台字段字典.md](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册/安全平台字段字典.md)

## 推荐使用方式

- 安全分析师：优先看 `应急响应/`、`日志与调查/`、`检测工程/`
- 响应负责人：优先看 `专项SOP/`、`证据与复盘/`、`内部运行手册/`
- 平台工程师：优先看 `security-automation/`、`sso-rbac/`、`threat-intelligence/`
- 管理与治理角色：优先看 `合规基线/`、`最佳实践/`、`安全策略/`

## 维护建议

- 新增专题时优先放入对应一级目录，不要散落在根目录
- 内部运行类文档优先进入 [内部运行手册/](/Users/newmba/Downloads/onyx-main/knowledge-base/内部运行手册)
- 新增事件调查类材料优先进入 [日志与调查/](/Users/newmba/Downloads/onyx-main/knowledge-base/日志与调查)
- 新增响应流程优先进入 [专项SOP/](/Users/newmba/Downloads/onyx-main/knowledge-base/应急响应/专项SOP)
- 新增规则、查询与映射类材料优先进入 [检测工程/](/Users/newmba/Downloads/onyx-main/knowledge-base/检测工程)

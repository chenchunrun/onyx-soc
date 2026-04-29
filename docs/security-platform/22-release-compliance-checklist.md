# CMSOC 产品发布开源合规清单

## 1. 目的

本清单用于在 CMSOC 对外发布前，快速确认开源协议边界、版权声明和发布口径是否一致，避免“混合许可项目被误标为全量 MIT”等常见合规问题。


## 2. 当前仓库许可边界（必须先确认）

根据根目录 [LICENSE](/Users/newmba/Downloads/onyx-main/LICENSE)：

- 非受限目录代码：MIT Expat。
- `ee` 目录代码：Onyx Enterprise License（非 MIT）。
- 第三方组件：遵循各自原始许可证。

当前关键受限目录：

- `backend/ee`
- `web/src/app/ee`
- `web/src/ee`


## 3. 发布模型选择

发布前先确定你采用哪一种模型，不要混用口径：

1. MIT-only（纯开源）发布  
仅发布 MIT 范围内容，不包含 EE 目录内容。

2. 混合许可发布  
同时发布 CE + EE，但必须明确标注目录级许可边界，不能对外宣称“全仓库 MIT”。


## 4. 一次性检查命令

执行脚本：

```bash
bash scripts/release/check_license_scope.sh
```

脚本覆盖项：

- 根 LICENSE 是否存在。
- EE 许可证文件是否齐全。
- 根 LICENSE 是否包含 EE 限制声明。
- 是否检测到 EE 文件（用于提醒打包边界）。
- 文档中是否出现高风险“全量 MIT”口径。
- 依赖锁文件是否存在（便于第三方许可证追溯）。

MIT-only 打包（可选）：

```bash
bash scripts/release/build_mit_only_bundle.sh
```

可选参数：

```bash
bash scripts/release/build_mit_only_bundle.sh <output_dir> <version_tag>
```

示例：

```bash
bash scripts/release/build_mit_only_bundle.sh dist/release v0.1.0
```

该脚本会自动排除 `backend/ee`、`web/src/app/ee`、`web/src/ee` 并输出 `tar.gz` 发布包。


## 5. 发布前人工核对项

1. 对外仓库/发布包是否包含 `backend/ee`、`web/src/app/ee`、`web/src/ee`。  
2. 官网、README、产品页、发布公告中的许可证描述是否一致。  
3. 是否保留原始版权声明与 LICENSE 文件。  
4. 第三方依赖许可证是否可追溯（锁文件与依赖清单可定位）。  
5. 如有闭源插件、商业组件或私有模型服务，是否在交付文档中明确其不属于 MIT 范围。  
6. 若发布 Docker 镜像，镜像构建上下文是否意外包含 EE 目录。  
7. 若发布二进制或打包产物，产物内是否附带 LICENSE 与 NOTICE（如适用）。


## 6. 推荐发布声明模板

### 6.1 MIT-only 发布模板

“本次发布仅包含 CMSOC 的 MIT 范围代码。企业版（EE）目录及其功能不在本次 MIT 发布范围内。”

### 6.2 混合许可发布模板

“本仓库为混合许可：社区版（CE）代码采用 MIT，`ee` 目录采用 Onyx Enterprise License。使用前请按目录查看对应许可证条款。”


## 7. 风险点与处理建议

1. 风险：对外口径写成“本项目完全 MIT”。  
处理：改为“CE 为 MIT，EE 为企业许可”，并链接 LICENSE。

2. 风险：CI/CD 打包时误带 EE 目录进入 MIT 分发包。  
处理：在打包脚本中显式排除 EE 路径，并在产物检查步骤增加路径断言。

3. 风险：文档、官网、镜像标签口径不一致。  
处理：把“许可证描述”作为发布 gate，未通过不允许发版。


## 8. 发布门禁建议（可选）

建议在 CI 增加一个轻量 gate：

- Step 1: 执行 `bash scripts/release/check_license_scope.sh`
- Step 2: 若计划 MIT-only 发布，再执行“EE 路径排除检查”
- Step 3: 产物抽样检查（文件列表中不得出现 EE 路径）


## 9. 结论口径（给管理层/法务）

CMSOC 可以对外发布，但前提是：

- 明确采用 MIT-only 或混合许可发布模型。
- 发布包内容与许可证口径严格一致。
- 不将 EE 目录内容误标为 MIT。

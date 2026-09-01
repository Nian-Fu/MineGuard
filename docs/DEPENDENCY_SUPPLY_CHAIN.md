# 依赖与镜像供应链门禁

## 1. 当前状态

当前仓库只限制直接依赖版本范围，没有 Python 哈希锁、`package-lock.json`、基础镜像 digest、SBOM、漏洞扫描报告或镜像签名。当前主机无 Python、Node.js、Docker和网络，不能可信地解析传递依赖或核对最新安全公告。因此现有 Dockerfile 和 CI 适合继续开发，不满足可复现生产发布门槛。

`deploy/release/verify-supply-chain-inputs.sh` 已把这些缺口变成独立发布阻断：tag 或手工发布门禁要求 API、edge、dev、RL 四份逐依赖精确版本并带 SHA-256 的 Python 锁、npm lockfile v3、全部 Dockerfile/Compose 镜像 digest，以及以 40 位提交固定的 GitHub Actions；同时验证 API/edge/RL Dockerfile 用 `--require-hashes` 消费各自锁、前端用 `npm ci` 消费 lockfile，并要求普通 CI 以 dev/RL 哈希锁和 npm lock 运行。Python 锁拒绝嵌套 requirements/constraints、自定义索引、可信主机和链接源，独立选项只允许强制 wheel 的 `--only-binary=:all:`，避免“锁文件存在但实际从另一输入重新求解”。当前仓库会按设计失败；这不是测试故障，而是防止在离线状态下把未解析依赖发布为生产制品。普通开发 CI 继续运行，但其结果在切换到锁定安装前不能作为发布证据。

禁止手工猜测传递版本或伪造扫描结果。所有锁文件、摘要与报告必须由联网的隔离构建器实际解析并保存命令输出。

## 2. Python 锁定

在固定 Python 3.12 和目标 Linux 架构的干净构建器中：

1. 固定 `pip` 与锁文件生成器版本，并记录其包哈希。
2. 分别解析 API、edge、开发/测试和 RL 训练依赖，避免把 GPU/训练依赖带入中心 API 镜像。
3. 生成包含 SHA-256 的平台锁文件，审核许可证和来源后提交。
4. Docker 与发布证据 CI 只允许 `pip install --require-hashes -r <lock>`，不得再次在线求解版本或通过嵌套输入替换已审查集合。
5. 对 wheel 缓存生成清单，离线重建并比较安装后的包名、版本和文件摘要。

候选工具可评估 `pip-tools` 或 `uv`，但选型前必须固定版本、许可证与 CVE 证据。多平台二进制依赖必须分别锁定，不能假设 Windows、CPU Linux 和 CUDA Linux 共享同一解析结果。

## 3. 前端锁定

在固定 Node.js 22 和 npm 版本的干净构建器中生成 `package-lock.json`，人工复核 registry、安装脚本、许可证和高风险传递包。提交锁文件后：

- CI 与 Dockerfile 改用 `npm ci --ignore-scripts`；确需安装脚本的包必须单独审批。
- 使用空缓存执行两次构建，比较产物清单与摘要。
- 禁止从 Git URL、任意 tarball URL或未批准 registry 安装依赖。
- 浏览器依赖扫描与后端依赖扫描分别保存 SARIF/JSON 证据。

## 4. 容器与 SBOM

- Python、Node、Nginx、PostgreSQL 和 MediaMTX 均固定到多架构 manifest digest；tag 只作为可读注释。
- 每个最终镜像生成 CycloneDX 或 SPDX SBOM，并与镜像 digest、源码 commit、构建参数一起作为发布制品。
- 候选扫描器可评估 Syft/Grype 或 Trivy；签名可评估 Cosign。正式采用前同样需要固定版本、许可证与 CVE 复核。
- CI 对严重/高危漏洞执行阻断，但必须允许带到期日、责任人和补偿控制的书面例外，不能用全局 ignore 隐藏结果。
- 发布签名、证明和 SBOM写入与运行镜像不同的不可变存储；部署端按受信身份、源码仓库、工作流和 digest 验证。

## 5. 上线证据

一次可接受的发布至少包含：

- 源码 commit、干净工作树证明和构建工作流版本；
- 所有锁文件与基础镜像 digest；
- API、edge、Web 和迁移镜像 digest；
- 每镜像 SBOM、许可证清单、漏洞扫描结果与例外清单；
- 模型文件 SHA-256、manifest、源码 commit、权重许可证和独立管理员审批；
- 签名/证明验证输出以及从空缓存重建的摘要对比。
- PostgreSQL client、age、minisign、rclone、AWS CLI、jq、tar 和 util-linux 的固定版本/包摘要；在目标版本上实际执行备份、`minisign -S/-V`、对象存储只读门禁、断网续传和恢复负向矩阵并归档 `--version` 与退出码。

发布流水线必须先通过 `verify-supply-chain-inputs.sh`，再从空缓存构建、生成 SBOM/扫描/签名。门禁只验证“固定输入存在且格式正确”，不证明摘要可信、许可证可接受或没有漏洞；这些结论必须来自联网隔离构建器的解析、扫描和人工审批证据。

依赖更新由自动 PR 发起时仍需通过测试、迁移、Compose、GPU 兼容、模型回归和断网恢复验收，不能只以“扫描无高危”作为上线依据。

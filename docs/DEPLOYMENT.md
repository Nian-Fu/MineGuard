# 部署与运维

数据留存、加密备份、异地交接和恢复演练见 [DATA_LIFECYCLE_AND_RECOVERY.md](DATA_LIFECYCLE_AND_RECOVERY.md)。
容量公式、k6 操作台负载和 GPU/故障组合验收见 [CAPACITY_AND_LOAD_TEST.md](CAPACITY_AND_LOAD_TEST.md)。

## 1. 环境

- 开发：SQLite、单 API 进程、Vite；用于功能开发，不保存真实人脸数据。
- 测试：PostgreSQL、媒体网关、对象存储、消息总线和一台 GPU 工作节点。
- 生产：双中心或多可用区控制面；边缘节点靠近摄像头网络；生产与办公网隔离。

## 2. 本地验收

需要 Python 3.11+、Node.js 22+；或 Docker 24+。

```powershell
cd backend
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\ruff check app tests
.venv\Scripts\pytest --cov=app --cov-report=term-missing

cd ..\frontend
npm install
npm run typecheck
npm run build
```

容器冒烟：

```powershell
$env:MINEGUARD_SECRET_KEY = '<32 字节以上随机值>'
$env:MINEGUARD_BOOTSTRAP_ADMIN_PASSWORD = '<强密码>'
$env:MINEGUARD_DB_PASSWORD = '<强数据库密码>'
$env:MINEGUARD_DATABASE_URL = 'postgresql+psycopg://mineguard:<URL编码密码>@db:5432/mineguard'
$env:MINEGUARD_FACE_TEMPLATE_PREVIOUS_KEYS = '{}'
$env:MINEGUARD_CAMERA_URL_KEY = '<32 字节随机值的 Base64>'
$env:MINEGUARD_CAMERA_URL_PREVIOUS_KEYS = '{}'
docker compose up --build -d
curl http://localhost:8080/api/v1/auth/methods
```

该初始密码只注入一次性 `migrate` 容器，用于幂等创建管理员；长期运行的 API 与 worker 显式设置 `MINEGUARD_BOOTSTRAP_ADMIN_ENABLED=false`，不会接收该明文秘密。首次登录后立即修改初始密码，并按现场秘密管理策略移除部署环境中的原值。

## 3. 生产前强制项

- 修改 secret、数据库凭据和引导管理员密码；凭据进入 Vault/KMS，不写 `.env` 或镜像。
- 生产 seed 只创建引导管理员，不写入演示摄像头、人员、事件、模型配置或告警规则；首次登录后按审批流程录入真实资产，并尽快停用引导账号。
- 人脸启用前由 KMS 注入 32 字节 Base64 AES 密钥及版本；旧版本密钥只在重加密窗口短期保留。
- 轮换人脸模板密钥时，先把旧版本加入 `MINEGUARD_FACE_TEMPLATE_PREVIOUS_KEYS` 并部署新密钥/版本，再在单实例维护任务执行 `mineguard-rotate-face-templates`。确认命令成功且所有 `face_templates.key_version` 都为当前版本，并满足备份保留期后，才能撤销旧密钥。
- 所有生产实例及迁移 Job 必须由 KMS 注入独立的 32 字节 Base64 摄像头 URL AES 密钥和一致版本；升级到 `20260821_0009` 必须使用在线迁移模式，迁移会在同一事务内加密既有 RTSP 地址。迁移完成后抽查 `stream_url IS NULL`、密文/nonce/版本均非空，再启动 API 与 worker。
- 轮换摄像头 URL 密钥时，将旧版本加入 `MINEGUARD_CAMERA_URL_PREVIOUS_KEYS`，部署新版本和新密钥后在单实例维护任务执行 `mineguard-rotate-camera-urls`。确认输出成功且 `stream_url_key_version` 全部为当前版本后，才能在满足备份保留期后删除旧密钥。
- 通知 worker 仅配置内网网关 URL 和短期服务令牌；未配置时控制台通知仍送达，外部通道明确标记失败并退避。
- MediaMTX 控制 API 只绑定 Compose 的 `172.31.250.0/24` 内部控制网，端口不发布到宿主机，Web 容器不加入该网络。若现场网段冲突，必须同时修改 Compose 的子网、MediaMTX 静态地址和 worker URL；禁止把 9997 暴露到办公网、摄像头网或公网。
- Compose 不向宿主机发布 MediaMTX RTSP/HLS/API/metrics 端口，避免绕过 Web 的媒体授权；Web 只映射到 `127.0.0.1:8080`，必须由同机或受控 sidecar 的 HTTPS 入口转发。若现场确需跨主机 RTSP 发布，必须单独启用 MediaMTX 发布/读取认证、网络白名单和 TLS 后再开端口，不能直接恢复匿名 `8554:8554`。
- 配置企业 OIDC issuer/discovery/client/回调、允许组、角色映射和区域映射，在 IdP 强制 MFA；发现出的端点若与 issuer/discovery 不同 origin，仅把 IdP 官方确认的 HTTPS origin 加入 `MINEGUARD_OIDC_ENDPOINT_ALLOWED_ORIGINS`。验证外部管理员及区域隔离后再设置 `MINEGUARD_LOCAL_LOGIN_ENABLED=false`。不得用用户名自动关联现有本地账号。
- 完成 Alembic 迁移、PostgreSQL 备份和恢复演练。
- 升级到 `20260821_0008` 前，在只读事务执行下列冲突预检；任一查询返回行时先核对身份与引用并由双人审批归并，禁止自动删除或重命名生产身份：

```sql
SELECT lower(username), array_agg(id) FROM users GROUP BY lower(username) HAVING count(*) > 1;
SELECT lower(employee_no), array_agg(id) FROM persons GROUP BY lower(employee_no) HAVING count(*) > 1;
SELECT lower(code), array_agg(id) FROM edge_nodes GROUP BY lower(code) HAVING count(*) > 1;
SELECT lower(name), array_agg(id) FROM alert_rules GROUP BY lower(name) HAVING count(*) > 1;
```

- 备份执行器启用 `mineguard-backup.timer` 与常驻异地上传服务，验证主机重启、数据库短断网和异地网络中断后均无需人工介入即可继续；采集备份目录内两份 `.prom` 原子指标并对成功时间、上传巡检陈旧、连续失败、待传积压和磁盘余量告警。
- Compose 由一次性 `migrate` 服务执行 Alembic 和生产引导账号创建，API 在其成功后启动；Kubernetes/其他编排必须使用等价的单实例 pre-deploy Job，禁止在每个 API Pod 的启动命令中并发迁移。
- TLS 终止、网络白名单、CSP、限流、登录防爆破和依赖镜像签名。
- Web 与 API 同源部署时保持 `MINEGUARD_CORS_ORIGINS=[]`；确需跨源的生产控制台只能登记无路径、无凭据的显式 HTTPS origin，禁止通配符。
- 按现场压测调整边缘入口独立限流；默认以来源地址和 `X-Edge-Node` 组合键允许 200 r/s、突发 400，操作台 API 仍保持 20 r/s。节点头只用于限流分桶，授权仍必须通过服务密钥。
- 对 RTSP 密码、原始图像、人脸模板、事件快照分别定义密钥和留存期。
- 启用快照存储时，把预签名 GET 实际使用的唯一 HTTPS origin（虚拟主机寻址时通常包含桶名）写入 `MINEGUARD_SNAPSHOT_CSP_ORIGIN`。Web 容器启动脚本拒绝 HTTP、路径、查询、空白和非首标签通配符；Nginx 只把通过校验的值加入 `img-src`，未配置时浏览器继续拒绝外部快照域名。对象端不得用 3xx 跳转到未登记 origin。
- 使用独立无登录 `mineguard-storage-auditor` 身份运行 `deploy/snapshot-storage/verify-readiness.sh`；该身份只允许读取目标桶的 lifecycle、versioning、encryption、public-access-block 和 policy，禁止读写对象。把桶名、HTTPS endpoint、保留天数、区域和审计凭据文件路径写入权限为 `0600` 的 `/etc/mineguard/snapshot-storage-readiness.env`，固定 AWS CLI/jq 包摘要后安装对应 service/timer，并以 `systemd-analyze verify` 及一次真实通过作为启用快照的前置条件。网络中断时 timer 会持续失败告警并在恢复后自动复检，不能把 timer 的 active 状态当作桶策略健康。
- 固定所有容器 digest 和 Python/npm 锁文件，生成 SBOM 并通过 SCA/镜像扫描。
- 为健康检查、错误率、延迟、队列积压、摄像头离线、GPU OOM 设置告警。
- 从 API 容器网络抓取 `/internal/metrics`；API 不映射宿主端口，Web Nginx 对该路径固定返回 404。采集器必须加入受控 `control` 网络且只拥有读访问，至少对 `mineguard_worker_up == 0`、通知最老等待时间、五分钟边缘重连数、`mineguard_edge_camera_reports_degraded > 0` 和 `mineguard_edge_camera_error_codes > 0` 配置告警；两个摄像头指标仅为低基数总量，故障详情在授权操作台查看。
- 完成至少 24 小时稳定性测试和高峰 2 倍流量压测。

## 4. 现场接入

1. 登记摄像头编号、区域、风险级别和只读 RTSP 账号。
2. 媒体网关与 NVR 同网部署并主动拉取已登记只读源，浏览器只访问经 Web 鉴权的 HLS 出口；当前 edge worker 只上报结构化事件，不向中心发布视频。
3. GPU 节点注册模型版本并通过预热、测试帧和性能检查。
4. 标定电子围栏、越线方向、停留时间和区域授权。
5. 先影子告警，现场复核一周；误报率达标后才开启通知联动。
6. 人脸能力单独完成授权、告知、数据保护评估和模板销毁测试。

边缘容器使用独立编排文件：

```powershell
$env:MINEGUARD_EDGE_KEY = '<平台注册时一次性签发的节点密钥>'
$env:MINEGUARD_EDGE_CONFIG_DIR = 'D:\mineguard\edge-config'
docker compose -f deploy/docker-compose.edge.yml up --build -d
```

配置目录只读挂载，包含 `edge-worker.json`、模型 manifest 和获批准的模型文件；事件 outbox 与可选快照 spool 使用同一独立持久加密卷。容器不包含模型、RTSP 凭据或节点密钥。NVIDIA Container Toolkit 必须预先安装，并在目标机完成 GPU/驱动兼容验证。

## 5. 断网与恢复验收

1. 浏览器加载大盘时断开网络 60 秒，再恢复网络；只读请求应自动完成，页面无需重新登录。
2. 断开当前 SSE、重启任一 API worker，确认浏览器以 `Last-Event-ID` 从数据库信号序列续传；Bearer token 不得出现在 URL、代理日志或 Referer。SSE 不可用时 20 秒轮询仍应更新大盘。连接临近 token 到期时必须先结束并刷新凭据；停用账号或收窄区域后，旧 SSE 最迟 5 秒结束且不得再推送旧范围信号。
3. API 返回 `502/503/504` 时确认指数退避，单个只读请求最多重试 5 次；失败后由 20 秒轮询继续长期恢复，浏览器 `online` 事件会立即刷新；实时连接持续退避重连；POST/PATCH 不得被自动重放。
4. 模拟 RTSP 断流 5 分钟，确认状态进入 `degraded`、重连间隔不超过 30 秒且无 CPU 热循环。
5. 中心或对象存储网络中断期间边缘推理继续运行，事件与启用后的 JPEG 先写入本地持久 outbox/spool；恢复后复用已持久化的内部引用，先补传对象再按幂等键提交事件且不重复告警。模拟对象 PUT 已成功但响应丢失，确认 412 必须经中心 HEAD/标签完整性复核后才能继续。
6. 网络反复闪断 100 次，检查 SSE、文件句柄、解码器进程、内存和线程无持续增长。
7. 系统时间校正后重放事件仍保留源时间戳和接收时间戳，审计可识别延迟补传。
8. 创建仅有单一区域的 operator/auditor，验证摄像头、事件、人员、人脸、通知、大盘、边缘状态和 SSE 均不出现其他区域；修改区域后旧 access/refresh 会话应立即失效。
9. 直接请求未授权区域的 HLS playlist 和 segment，确认 Nginx 返回 401/403；变更账号区域后旧媒体 Cookie 应立即失效，在线页面续期后授权区域视频自动恢复。
10. 停止 worker 超过 `MINEGUARD_WORKER_HEARTBEAT_TIMEOUT_SECONDS`，确认系统状态出现失联告警；重新启动后无需人工操作即恢复为在线。制造超过阈值的 RTSP/中心闪断，确认出现重连风暴告警。
11. 阻断 PostgreSQL 端口并制造连接黑洞，确认 API 新请求和 worker 单次连接尝试在 `MINEGUARD_DATABASE_CONNECT_TIMEOUT_SECONDS` 附近失败而不是永久挂起；恢复端口后，`pool_pre_ping` 应淘汰失效连接，readiness 与 worker 心跳无需重启自动恢复。
12. 强制重建 API 和媒体网关容器并确认 IP 发生变化；Web Nginx 应在 Docker DNS 10 秒刷新窗口后自动恢复 API、SSE 和 HLS，不得依赖重启 Web 容器。
13. 新建摄像头后确认 worker 在 30 秒内通过 MediaMTX v3 控制 API 创建同名按需拉流路径；修改 RTSP 地址、重启媒体网关以及临时阻断 9997 后，确认 worker 先显示降级并持续退避，控制链路恢复后自动重新对账。日志、心跳与指标不得出现 RTSP 用户名、密码或查询令牌。
14. 同时打开两个管理员操作台编辑同一摄像头、人员、算法、规则、账号、边缘节点、法律保留或模型审批；第一个提交成功后，第二个携带旧 `If-Match` 的提交必须返回 409、重新同步数据且不得覆盖第一个结果。心跳遥测不得让摄像头/节点配置令牌变化。盘点外部集成客户端并升级为携带令牌后，再将缺少 `If-Match` 的管理写入收紧为 428。
15. 分别移除快照桶的法律保留标签过滤、默认加密、公共访问阻断和 TLS deny，确认对象存储 readiness 非零退出且十五分钟后自动复检；恢复策略后无需重启服务即可通过。对版本桶另行移除非当前版本或删除标记清理并确认门禁失败。
16. 在设置和解除事件快照法律保留时分别阻断对象标签 API，并在响应丢失点强制结束 API/worker；确认 `snapshot_legal_hold_jobs` 与 `mineguard_snapshot_legal_hold_pending` 增长、待设置事件不会被生命周期清理、解除期间对象继续受保护。只恢复网络而不重放 PATCH，任务必须在最高 300 秒退避后归零，大盘告警自动消失。worker 必须注入与 API 相同的对象 endpoint、桶、凭据、寻址和超时配置。

## 6. 已知开发基线限制

- 当前 API 使用同步 SQLAlchemy，适合中心管理流量；高频事件必须经消息消费者批量落库。
- 开发/测试启动使用 `create_all` 快速引导；生产容器已执行 Alembic 基线迁移，后续结构变化必须新增不可变 revision。
- 快照已使用稳定内部引用、S3 兼容预签名、边缘持久补传、区域授权查看和法律保留标签；真实对象存储的生命周期导出、恶意文件检测策略、CSP origin、WORM/Object Lock 和到期/保留演练仍是生产部署证据，当前离线主机未验证。
- 短信、广播和 Webhook 已具备持久投递与统一网关协议，仍需现场通知网关提供商适配器和目标标识。
- 当前使用 PostgreSQL 持久信号序列和 SSE 实现跨实例实时更新，Nginx 已关闭该路径缓冲；每个 API worker 查询共享序列，浏览器断线按序号续传，20 秒可靠轮询继续作为降级路径。大规模并发操作台部署前需完成连接数与数据库轮询压测，必要时切换 Redis/NATS 唤醒层而保留数据库游标。
- 当前仓库不包含现场模型权重、真实人脸样本或摄像头凭据。
- 中心 worker 会周期性把数据库中的摄像头 RTSP 地址对账到 MediaMTX 按需拉流路径，解决容器重建后动态路径丢失；该机制已提供模拟 HTTP 测试，但仍需使用锁定版本的 MediaMTX 1.14.0 在目标网络验证 v3 控制 API 契约、RTSP 鉴权和 HLS 首帧时间。

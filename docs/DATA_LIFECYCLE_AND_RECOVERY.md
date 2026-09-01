# 数据生命周期与灾难恢复

各链路的故障注入、持久边界、退避上限和验收证据汇总见 `RECOVERY_MATRIX.md`。

## 1. 默认留存策略

中心 worker 每小时以有界批次执行清理。下列值均可通过同名 `MINEGUARD_` 环境变量覆盖：

| 数据 | 默认值 | 自动清理边界 |
|---|---:|---|
| 实时信号 | 24 小时 | 仅用于 SSE 断点续传的数据库信号 |
| refresh 会话 | 过期或撤销后 7 天 | 活动且未过期会话不清理 |
| 通知投递 | 送达后 90 天 | 仅按 `sent_at` 清理已送达记录；待投递、自动重试和终态拒绝记录保留；旧数据缺少 `sent_at` 时才回退创建时间 |
| 已闭环/误报事件 | 365 天 | 未闭环、有通知引用或 `legal_hold=true` 的事件保留 |
| 事件快照 | 90 天 | 由对象存储生命周期执行；数据库事件按 365 天策略处理 |
| 审计日志 | 2555 天（约 7 年） | `legal_hold=true` 以及指向法律保留事件的审计保留 |
| 非活动人脸模板 | 30 天 | 活动或 `legal_hold=true` 的模板不清理；设为 `0` 可关闭自动销毁 |
| 服务心跳 | 7 天 | 仅删除已过期实例心跳 |

事件留存不得短于通知投递留存，配置加载时会强制校验。每批默认最多处理 5000 条，避免长事务影响告警写入。法律、事故调查或监管冻结应由管理员通过事件或人脸模板的 `legal-hold` 接口标记；设置和解除都要求 3-500 字依据并写入不可提前清理的审计记录。工单还应记录批准人、范围和解除日期。

数据库仅保存稳定内部引用，不保存预签名 URL。对象存储必须独立安装并审计以下生命周期合同，应用配置本身不会替代存储侧策略：

- 主规则必须为 `Status=Enabled`，前缀为 `snapshots/`，并同时按对象标签 `mineguard-legal-hold=false` 过滤；当前版本过期天数必须与 `MINEGUARD_EVENT_SNAPSHOT_RETENTION_DAYS` 完全一致。禁止只按前缀配置无标签的删除规则。
- 快照键由随机 UUID 生成，上传签名要求 `If-None-Match: *`，业务上不可覆盖。若桶启用版本控制，仍须配置非当前版本过期和过期删除标记清理；任何允许管理员绕过条件写入或产生同键历史版本的通道都必须关闭，否则标签只保护当前版本而不能证明历史版本法律保留。
- `mineguard-legal-hold=true` 不得匹配任何常规过期规则。每次对象法律保留操作先写入 PostgreSQL 唯一对账任务：设置保留时 worker 先写对象标签再提交数据库状态；解除时先提交数据库再把标签改回 `false`。网络、进程或对象存储故障返回 503，但任务以最高 300 秒退避持续恢复；待设置任务会阻止事件生命周期清理，待解除期间对象继续保持保护。对象调用与数据库仍不是单个原子事务，但响应丢失或任一阶段崩溃只会留下可重复、可监控的任务，不再要求管理员再次提交请求。
- 存储账号只允许指定桶的预签名、读取和对象标签操作；桶策略强制 TLS、服务端加密、最大对象尺寸及禁止公共访问。生命周期配置、版本状态和抽样对象标签必须纳入发布前检查与周期漂移告警。

对账积压通过 `mineguard_snapshot_legal_hold_pending`、worker 心跳和大盘 `snapshot_legal_hold_recovering` 告警暴露。每次任务入队都记录不可提前清理的 `event.legal_hold_requested` 管理意图，实际状态变化另记 `event.legal_hold`；反向操作覆盖当前目标但不会抹掉先前请求。上线演练必须覆盖设置标签成功但数据库提交失败、解除数据库提交成功但标签调用超时、worker 进程退出和管理员反向覆盖目标状态；最终任务数必须归零。

`deploy/snapshot-storage/verify-readiness.sh` 使用独立只读审计身份，失败关闭地核对精确的当前版本保留规则、任何重叠删除规则都必须带 `mineguard-legal-hold=false`、版本桶的非当前版本/删除标记清理、默认服务端加密、完整公共访问阻断和桶策略的非 TLS 拒绝。十五分钟 systemd timer 会在网络或供应商恢复后自动重试；API 运行账号不应因此获得读取桶策略的权限。该门禁尚未在真实 S3/MinIO 上运行，也不验证恶意文件检测、最大尺寸桶策略、WORM/Object Lock 或对象最终按时删除；启用 `MINEGUARD_SNAPSHOT_STORAGE_ENABLED` 前仍须保存真实策略导出、保留/解除负向试验和到期对象证据。不得把数据库事件清理或内部引用消失误认为对象字节已经销毁。

## 2. 加密备份

`deploy/backup/backup-postgres.sh` 面向隔离的备份执行器，要求 PostgreSQL client、`age`、`minisign`、`sha256sum`、`tar` 和 util-linux `flock`。数据库凭据通过 `PGHOST`、`PGPORT`、`PGDATABASE`、`PGUSER`、`PGPASSFILE` 注入，不把密码放在命令行。age 接收方密钥负责机密性，独立 Ed25519/minisign 签名密钥负责证明制品来自获批备份执行器；两组密钥不得复用或由同一权限域托管。

自动化签名密钥可在隔离终端用 `minisign -G -W -s backup-signing.key -p backup-signing.pub` 生成无口令服务密钥；`-W` 只适用于已通过主机隔离、只读 secret 挂载、专用无登录账号和文件权限保护的备份执行器。公钥指纹需经另一条受控通道登记到恢复环境。需要口令或 HSM 的组织应改用经现场验证、不会等待交互式 TTY 的签名代理，不能把口令加入脚本参数。

```sh
export PGHOST=db
export PGDATABASE=mineguard
export PGUSER=mineguard_backup
export PGPASSFILE=/run/secrets/pgpass
export PGCONNECT_TIMEOUT=10
export MINEGUARD_BACKUP_DIR=/var/backups/mineguard
export MINEGUARD_BACKUP_AGE_RECIPIENT=age1...
export MINEGUARD_BACKUP_MINISIGN_SECRET_KEY_FILE=/run/secrets/backup-signing.key
export MINEGUARD_BACKUP_LOCAL_RETENTION_DAYS=14
export MINEGUARD_BACKUP_MIN_FREE_BYTES=1073741824
sh deploy/backup/backup-postgres.sh
```

脚本先持有备份目录级非阻塞 `flock`，拒绝并发执行及任何同名目标，避免人工任务或时钟回拨覆盖、混配完整制品组；systemd 会在失败后延迟重试。清理已完成交接且超过留存期的本地组后，脚本通过只读查询取得当前数据库大小，并要求备份卷可用空间至少为其三倍再加 `MINEGUARD_BACKUP_MIN_FREE_BYTES`（默认 1 GiB）；不足时在创建 dump 前失败关闭，容量恢复后由 service 自动重试。该估算是保护门槛而非容量证明，仍须监控实际增长和预留文件系统元数据空间。随后执行 `pg_dump --format=custom`，验证目录清单，计算明文摘要，将 dump、摘要和元数据打包后用 `age` 加密，再对密文计算 SHA-256，并用独立 minisign 私钥签署加密制品。只有 `.age`、`.age.sha256` 和 `.age.minisig` 都完成后才原子生成 `.ready` 文件。自动化私钥应由专用备份身份从 Vault/HSM 挂载为只读文件；若使用无口令服务密钥，必须依靠独立主机、`0400` 权限和最小化备份账号保护，禁止把私钥写入环境变量或仓库。

`upload-ready-backups.sh` 使用独立 rclone 配置持续消费 `.ready`：先上传 `.age`、`.age.sha256` 和 `.age.minisig`，最后上传 `.ready`。任一步骤断网或超时都会以最高 300 秒的退避无限重试；成功后才在本地生成 `.uploaded`。备份脚本在开始新 dump 前和成功后各清理一次，只轮换已存在 `.uploaded` 且超过本地保留期的完整文件组，避免已异地交接的过期文件先占满磁盘后让备份永久卡死；未完成异地交接的制品不会自动删除。

```sh
export MINEGUARD_BACKUP_DIR=/var/backups/mineguard
export RCLONE_CONFIG=/run/secrets/rclone.conf
export MINEGUARD_BACKUP_RCLONE_REMOTE=offsite-immutable:mineguard/prod
export MINEGUARD_BACKUP_UPLOAD_POLL_SECONDS=60
sh deploy/backup/upload-ready-backups.sh
```

rclone 远端必须启用对象锁或等价不可变保留，服务账号只能新增/读取，不能缩短保留期。私钥不得与备份同机、同库或同一云账号保存。监控必须同时检查最新 `.ready` 年龄、未上传文件数、上传器进程和磁盘余量。

从未签名版本升级时，任何尚未上传的旧 `.ready` 都会被新版上传器拒绝并阻塞后续交接。上线前必须盘点这些制品，在隔离备份执行器上核对 SHA-256 后用当前获批私钥补签，或按留存/变更流程明确废弃并移走整组文件；禁止只伪造 `.minisig` 文件或降低上传器校验。

备份成功后脚本会在备份目录原子更新 `mineguard-backup.prom`，包含最新成功 Unix 时间和加密制品字节数；常驻上传器每轮原子更新 `mineguard-backup-upload.prom`，包含最后巡检时间、健康状态、连续失败和待上传数量。将 node_exporter textfile collector 指向该目录或由受限采集器只读转发这两个 `.prom` 文件，至少配置：备份成功时间超过批准 RPO、上传巡检超过两倍轮询周期、`healthy == 0`、连续失败非零、待上传数量持续增长和磁盘可用时间低于最坏断网窗口。指标不含文件名、数据库名、远端地址或凭据。

专用 Linux 备份执行器可安装 `deploy/systemd/mineguard-backup.service`、`.timer` 和 `mineguard-backup-upload.service`。先创建无登录权限的 `mineguard-backup` 账号、`/var/backups/mineguard` 目录和权限为 `0600` 的 `/etc/mineguard/backup.env`，再按实际只读代码路径调整单元中的 `/opt/mineguard`。环境必须设置 `PGCONNECT_TIMEOUT=10`；备份单元两小时未结束会被判失败并重启，避免半开数据库连接永久挂起。执行 `systemd-analyze verify` 后启用 timer 与 uploader；timer 的 `Persistent=true` 会在关机错过周期后补跑，两个 service 都会在失败或主机重启后恢复。

建议每 6 小时一次，保留本地 14 天、异地每日 35 天、每月 13 个月、年度 7 年；最终周期须由矿方监管和事故档案要求批准。调度器必须对缺少 `.ready`、备份年龄超过 RPO、异地复制失败和剩余空间告警。

## 3. 恢复演练

恢复只能写入预先创建的专用空数据库。通过 `pg_service.conf` 提供连接，避免凭据出现在进程参数：

```sh
export PGSERVICEFILE=/run/secrets/pg_service.conf
export MINEGUARD_RESTORE_PGSERVICE=mineguard_restore_drill
export MINEGUARD_BACKUP_AGE_IDENTITY_FILE=/run/secrets/backup-age-key.txt
export MINEGUARD_BACKUP_MINISIGN_PUBLIC_KEY_FILE=/run/secrets/backup-signing.pub
sh deploy/backup/verify-restore.sh /offsite/mineguard-20260821T000000Z.age
```

脚本在解密前强制使用受控 minisign 公钥验证 `.age.minisig`，再把密文与 dump 的 SHA-256 记录限制为单行固定目标，并要求归档只含 `database.dump`、`database.dump.sha256` 和 `metadata.txt` 三个固定普通文件，拒绝额外/重复成员、路径和链接；随后拒绝非空目标库，并以单事务恢复，任一错误整体回滚，再核对 Alembic revision、关键表和核心表行数。`MINEGUARD_RESTORE_PGSERVICE` 只能是单一 service 名称，所指账号必须是隔离演练库的非超级用户且不能连接生产。演练后还必须启动同版本只读 API，执行登录、区域授权、事件查询、审计查询和模板解密抽样；严禁连接生产通知网关、摄像头或 IdP 写操作。验签公钥应通过独立配置管理分发并核对指纹，不能从备份对象旁边自动信任；异地存储写权限和备份执行器身份仍须隔离。

每次恢复演练至少执行三项负向验证：修改密文一个字节应在 minisign 验签阶段失败；替换为未登记公钥应失败；删除或替换 `.age.minisig` 应在解密和数据库连接前失败。只有正确签名、摘要、age 身份和空恢复库同时满足时才能进入 `pg_restore`。

每月至少执行一次自动恢复，每季度由另一名管理员见证完整演练。证据包应包含：备份时间、异地对象版本、双重摘要、恢复开始/结束时间、Alembic revision、行数对账、应用冒烟结果、实际 RPO/RTO、异常和整改工单。建议目标为 RPO 不高于 6 小时、核心控制面 RTO 不高于 2 小时；未取得现场容量测试和恢复证据前，这只是目标而不是已验证承诺。

分钟级 RPO 的连续 WAL 归档、断网积压保护和时间点恢复门槛见 `docs/PITR_DESIGN.md`。该文件当前是设计而非已部署能力，完成工具版本/CVE 复核、目标环境配置和恢复证据前不得提高本项目的 RPO 声明。

可使用 `deploy/pitr/verify-readiness.sh` 和五分钟 systemd timer 持续检查 PostgreSQL 归档配置、最近成功年龄、未恢复失败以及所选物理备份工具可读性。该脚本是失败关闭的巡检门禁，不执行恢复，也不把一次通过等同于 WAL 连续性或可恢复性证据；网络恢复后 timer 会自动重试。

## 4. 断网与服务恢复

- API、worker、Web 和媒体网关均采用 `restart: unless-stopped`，数据库健康后自动拉起。
- API、迁移器与 worker 的 PostgreSQL 新连接默认 10 秒超时，连接池等待默认 10 秒、连接 5 分钟回收并在借出前执行 `pool_pre_ping`；worker 的数据库失败循环无限退避，在网络或数据库恢复后以新连接继续通知、过期节点判定和生命周期任务。可通过 `MINEGUARD_DATABASE_CONNECT_TIMEOUT_SECONDS`、`MINEGUARD_DATABASE_POOL_TIMEOUT_SECONDS` 和 `MINEGUARD_DATABASE_POOL_RECYCLE_SECONDS` 按现场网络调整，但连接超时不得高于上游健康检查与恢复预算。worker 失联/停滞阈值默认 60 秒，并强制大于单轮通知网关超时、已启用 MediaMTX 控制超时、快照存储总等待和失败后降级心跳的一次新数据库连接超时之和再加 5 秒；通知、快照和 MediaMTX 批处理中每完成一个有界单元都会续期，避免正常批量工作被误报为进程卡死。
- 边缘事件先写 SQLite WAL outbox，中心恢复后使用节点级幂等键补传。
- 边缘 outbox 达到容量上限时摄像头读取进入有界退避背压；中心恢复并腾出容量后，当前帧事件先全部持久化，再主动重建 RTSP 会话并重置跟踪/停留状态，避免把断网期间缓冲的旧帧当成实时画面处理。
- 边缘 outbox 在落盘前拒绝非对象、非有限数和不可序列化值；已解决死信过期清理按 1000 条事务批次执行，删满一批时一分钟后继续追赶，避免多年运行后一次大删除锁住摄像头与心跳事件循环。
- RTSP 解码器和中心 HTTP 客户端持续指数退避，重连次数进入节点遥测和 Prometheus 告警。
- 浏览器 API、SSE 和 HLS 会话恢复互相独立；SSE 使用 `Last-Event-ID`，20 秒轮询作为长期降级通道。
- 未登录页面的认证方式发现也使用单槽、最高 30 秒退避持续重试；API 或 IdP 配置端点长时间不可用后恢复时，会自动刷新本地登录/OIDC 开关，浏览器 `online` 事件会立即触发一次探测。
- SSE 对包括滚动升级期间临时 404 在内的非成功握手持续退避，不再永久停连；兼容旧服务的 404 使用不改变全局连接状态的 30 秒低频探测。单个未完成事件的浏览器缓冲限制为 64 KiB，每次断开主动取消 reader 后重建连接，防止异常上游在恢复循环中累积内存或连接资源。
- HLS 除浏览器/HLS.js 显式错误外，还在页面可见且已播放时每 10 秒检查媒体时间；连续两次无进度会请求媒体会话续签并走既有退避重连。后台标签暂停检查，恢复到前台后自动重新判定，避免休眠恢复的静默黑屏和后台请求风暴。
- MediaMTX 周期对账逐条验证摄像头路径和解密后的源地址；单条损坏记录会被跳过并让 worker 保持恢复中告警，但其余健康路径仍先完成新增/修正。控制端或密钥配置恢复后，后续周期会自动收敛坏记录，不让单摄像头故障阻断全矿视频路径重建。
- 通知投递保留在数据库 outbox 中；断网、超时、鉴权/限流和 5xx 以最高 300 秒的退避持续重试，400/413/415/422 终态拒绝保留待修正且不阻塞后续投递；外部网关熔断时控制台通知仍继续处理。
- 异地备份上传器持续扫描本地 `.ready`，网络恢复后自动补传；未生成 `.uploaded` 的唯一副本不会进入本地轮换。
- 浏览器只自动重试 GET/HEAD。人工 POST/PATCH 在断网时不自动重放，避免服务端已提交但响应丢失时产生重复副作用；恢复后全量刷新最终状态，幂等的边缘事件、通知和备份队列则安全自动补传。
- 注销是明确的幂等例外：断网注销先清除本地会话并记录无秘密待办，恢复、重开页面或下一次登录前自动补发，直到服务端删除 Cookie 并撤销 refresh 会话；其他人工 POST/PATCH 仍不自动重放。

这些机制仍需在目标 PostgreSQL、GPU、媒体网关和真实网络故障条件下完成 24 小时以上稳定性与恢复演练，才能形成生产验收结论。

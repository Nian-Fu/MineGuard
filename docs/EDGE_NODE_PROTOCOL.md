# 边缘推理节点协议

边缘节点承担 RTSP 解码、模型推理、跟踪和规则判定。中心平台只接收心跳与结构化事件，不把管理员账号或数据库凭据下发到井下节点。

## 1. 注册与凭据

管理员在系统页注册节点并绑定允许处理的摄像头。API 只在注册或轮换响应中返回一次 `mg_edge_...` 高熵密钥，数据库仅保存 SHA-256 摘要，审计日志只记录节点编号和摄像头 ID。

节点请求头：

```http
X-Edge-Node: edge-shaft-01
X-Edge-Key: mg_edge_<one-time-secret>
```

密钥写入节点 TPM/Vault/容器 secret，不得进入镜像、命令行参数或普通日志。轮换后旧密钥立即失效。管理员停用节点后，无论密钥是否过期，心跳和事件入口都立即返回 401；重新启用后必须等待真实心跳，平台不会预先显示在线。

## 2. 心跳

```http
POST /api/v1/edge/heartbeat
```

```json
{
  "software_version": "edge-worker-1.0.0",
  "gpu_healthy": true,
  "gpu_utilization": 0.62,
  "gpu_memory_utilization": 0.54,
  "queue_depth": 3,
  "dead_letter_depth": 0,
  "outbox_capacity": 100000,
  "area_counts": {"主井口": 6},
  "cameras": [
    {"camera_id": 1, "status": "online", "fps": 25, "latency_ms": 86, "errors": []}
  ]
}
```

默认每 15 秒发送一次。每个节点配置要求同一区域恰好一台摄像头设置 `counting_authority=true`，心跳只用该路生成区域人数；重叠视野必须设为 `false`。流进入降级/断开时立即把该路人数、FPS 和延迟清零，避免沿用最后一帧。跨节点仍重复上报同一区域时，中心不相加，暂取单源最大值并产生 `area_counter_conflict` 高风险告警，直到现场全局权威映射修正。中心要求心跳完整覆盖节点当前绑定的全部摄像头，并且 `area_counts` 只能引用这些摄像头实际所属区域；缺失、越权或拼写错误会让整份心跳原子拒绝且不刷新 `last_seen_at`，随后既有 45 秒失联机制接管离线判定。同一摄像头可由多个节点作冗余上报：中心只聚合活动且未超时的报告，全部在线才标记在线、报告冲突时标记降级、全部有效来源离线或超时才标记离线并生成一次 `camera_offline` 事件；状态不再由最后到达的心跳覆盖。节点恢复完整心跳后自动重新参与聚合；`gpu_healthy=false` 或 `queue_depth + dead_letter_depth >= outbox_capacity` 时该节点及其报告进入降级并触发严重告警，但故障前已写入 outbox 且模型清单仍获批准的事件可以继续补传。队列利用率 80% 起预警并进入 Prometheus，补传释放容量后的下一次心跳自动恢复。

摄像头 `errors` 最多包含 10 个、每个最长 80 字符的稳定机器故障代码，不允许自由文本或秘密；可同时呈现 RTSP、快照、人脸与 outbox 原因，子系统恢复时只移除自己的代码。操作台在节点详情中直接显示这些并发原因，恢复验收不能只依赖一个模糊的 `degraded` 状态。

## 3. 事件

```http
POST /api/v1/edge/events
Idempotency-Key: edge:<sha256(node:camera:event-type:track:millisecond)>
```

请求体使用中心 `EventCreate` 契约。边缘端必须先写本地 SQLite WAL outbox，再发送中心；收到 2xx 才删除。断网、超时和 5xx 使用指数退避，恢复后按原幂等键补传。原始事件身份在节点侧摘要为固定 69 字符，中心再次按节点 ID 与该键摘要生成内部唯一键，避免超出 Header 上限或不同节点误用相同键时互相吞并事件。重复键会核对严重级别、人员、标题、描述、置信度、快照、发生时间和原始元数据；只有完整业务载荷一致才返回原事件。中心动态注入的节点身份与模型快照不参与比较，避免响应丢失后的正常遥测变化制造假冲突。

启用 `event_snapshots_enabled` 后，事件帧先按 `snapshot_jpeg_quality` 编码，并以事件幂等摘要为文件名、在 `snapshot_spool_path` 中完成文件和目录 `fsync`，随后事件才进入 SQLite。投递器首次取得短时 PUT 授权后，先把中心生成的稳定内部引用写回同一 outbox 行，再上传对象；进程在任一步退出时都从该引用续签，不生成新对象。PUT 使用 JPEG 长度、SHA-256、SSE-S3、初始法律保留标签和 `If-None-Match: *`；条件失败 412 后必须由中心以 HEAD 和标签重新核对长度、摘要、类型、加密与保留状态，不能只凭“对象存在”继续。对象上传成功后才提交带 `snapshot_url` 的事件；中心事件返回 2xx、SQLite 行删除后才清除本地 JPEG。永久拒绝进入 dead-letter 时本地快照继续保留，修复并重放成功后再清理；启动会删除不再被活动 outbox/dead-letter 引用的受管孤立文件。

快照开关默认关闭。只有中心 `MINEGUARD_SNAPSHOT_STORAGE_ENABLED=true`、桶策略和生命周期门禁均通过后才能在 edge 打开，否则投递器会持续重试授权并让队列增长。`snapshot_spool_path` 必须位于与 outbox 相同等级的持久加密卷，不得放入容器临时层；按 `outbox_maximum_items * snapshot_maximum_bytes` 评估最坏空间，并对磁盘剩余时间告警。编码或本地持久化失败时结构化事件仍进入 outbox，节点显式降级并记录稳定错误类型，不能因快照失败丢弃安全事件。

`outbox_maximum_items`（默认 100000）和 `outbox_maximum_payload_bytes`（默认 65536）由节点配置显式限制磁盘队列。容量满时当前事件留在内存中并以 1-30 秒退避等待投递线程释放空间；等待期间不会把背压误判为 RTSP 断流。节点持续发送容量心跳并显示降级，释放空间后先持久化当前帧全部事件，再主动重建 RTSP 会话并清空跟踪/停留状态，避免继续消费断网期间可能缓冲的旧帧。活动死信占满全部容量时仍需先修复永久拒绝根因并重新入队，系统不会为保持运行而静默丢弃审计事件。已解决死信保留 `resolved_dead_letter_retention_days`（默认 90 天）作为现场处置证据，worker 启动后及每 6 小时按 1000 条事务批次删除过期 resolved 记录；若批次删满，一分钟后继续追赶并复用 SQLite 空闲页。活动死信不受该清理影响。

中心返回 400、413、415 或 422 表示原始载荷不经修改无法成功，其中同幂等键载荷漂移稳定返回 422；节点会将该事件原子隔离到本地死信表并继续发送后续事件，避免队首阻塞。401、403、409、429、5xx、超时和网络错误仍按退避策略重试，409 保留给模型尚未准入等可恢复状态。活动死信计入 outbox 容量，并通过心跳 `dead_letter_depth`、中心严重告警和 Prometheus 指标暴露；记录不会被静默删除。

实时人脸识别是有意不同的隐私边界。启用摄像头的 edge 每路最多保留一个在途内存探针，JPEG 上限 1 MiB，只提交到服务认证的 `/faces/edge-identify`，不会进入 outbox、快照 spool、对象存储或日志。HTTP 422 表示低质量、多脸或活体失败，edge 不生成事件；只有中心返回确定的匹配或未知结果后，才持久化不含图像和向量的结构化事件。结果携带 `face_model_version` 与 `face_model_sha256`，中心收取离线补报时再次核对仍获审批的 `face_recognition` 制品，撤销后的积压保持 409 重试而不会绕过准入。Provider 或中心网络中断只将人脸原因加入该路降级集合，入侵、人数和安全帽处理继续；恢复后从新鲜帧自动重试，不保存断网期间的人脸图像作历史补算。

排除契约、模型或节点配置问题后，运维人员可在停止边缘进程或确认没有并发处理该条记录的维护窗口内检查并重新入队：

```bash
mineguard-edge-outbox --database /var/lib/mineguard/event-outbox.db list --limit 100
mineguard-edge-outbox --database /var/lib/mineguard/event-outbox.db show 17
mineguard-edge-outbox --database /var/lib/mineguard/event-outbox.db requeue 17 \
  --resolution 'upgraded event contract to v2'
```

`--database` 必须是已存在的普通文件，路径错误不会创建空库。`list` 默认隐藏原始载荷，`show` 用于受控检查单条载荷；输出应按事件敏感数据处理。只有修正导致永久拒绝的根因后才能 `requeue`，操作会保留原死信行、解决原因和解决时间；若再次永久失败，同一幂等键会重新激活该历史记录。当前工具不提供删除命令。

## 4. 版本与升级

- `software_version` 使用不可变语义版本并关联镜像 digest、SBOM 和模型清单。
- 先在一个普通区域节点金丝雀升级；心跳、GPU OOM、事件延迟或误报异常时自动回退。
- 模型版本由事件 `metadata_json` 携带，至少包括 detector、tracker、face provider 和 rule bundle 版本。
- 节点时钟使用 NTP/PTP；事件同时保留源发生时间与中心接收时间。

## 5. 断网验收

1. 断开中心网络 30 分钟，确认视频推理继续、本地 outbox 增长且不超过容量告警。
2. 恢复网络，确认全部事件补传、同一幂等键只产生一个中心事件和一组通知。
3. 断开单路 RTSP，确认 stream supervisor 1-30 秒抖动退避，无 CPU 热循环。
   断流时必须清空该路 ByteTrack、入侵/PPE 停留和拥挤边沿状态；恢复画面后停留时间从首个新帧重新累计，不得把不可观测的断网时长算作持续违规。
4. 停止整个边缘进程，45 秒后确认节点离线；无其他新鲜冗余来源时确认摄像头离线事件，存在健康冗余来源时确认摄像头继续在线；重启后自动重新参与状态聚合。
5. 轮换节点密钥，确认旧密钥 401、新密钥成功且密钥原值不出现在审计 API。
6. 停用节点后立即确认旧密钥 401；重新启用时保持离线，直到节点完成新心跳。
7. 启用实时人脸后分别注入 Provider 422、超时、中心断网和制品撤销；确认 422 不产生未知事件，网络恢复后只处理新鲜帧，其他视频算法持续运行，且撤销期间的结构化积压在重新审批前保持 409。

## 6. 常驻推理进程

安装边缘依赖后，以独立服务账号运行：

```bash
pip install './backend[edge]'
export MINEGUARD_EDGE_KEY='mg_edge_一次性签发的节点密钥'
mineguard-edge --config /etc/mineguard/edge-worker.json
```

配置结构参考 `deploy/edge-worker.example.json`。单节点最多 256 路唯一摄像头 ID/代码，多边形使用最多 100 个相对画面的归一化坐标点，拥挤人数和规则持续时间均有启动期上界；同一区域多路摄像头必须明确且仅保留一个 `counting_authority`。模型摘要来自本地 manifest 并在启动时与文件及 Triton `artifact_sha256` 同时核验。节点密钥只从环境变量或容器 secret 注入，不写入 JSON。

中心 `central_url` 必须使用 HTTPS，只有 `localhost`、`127.0.0.1` 和 `::1` 开发回环地址允许 HTTP；否则一次性节点密钥会暴露在传输链路上，边缘进程会在启动时拒绝配置。密钥还必须符合平台签发的 `mg_edge_` 高熵格式，避免错误凭据进入无限 401 恢复循环。

常驻进程为每路视频建立独立监督器，RTSP 读取、解码或推理失败后按 1-30 秒指数退避并加入随机抖动，同时重置该路跟踪、停留规则与拥挤转换状态；重连后的人员必须重新累计停留。规则持续时间使用单调时钟，事件 `occurred_at` 使用 UTC 墙上时间，因此 NTP 回拨不会制造或提前告警。推理和规则判定不依赖中心网络。事件先写 SQLite WAL，中心断网期间继续累积；恢复后按原 `Idempotency-Key` 自动补传。心跳失败采用最多 60 秒的抖动退避，不会阻塞本地视频处理。

OpenCV 打开/读取与 Triton 推理均设置 10 秒有界超时，避免半开连接长期占用工作线程。多路摄像头各自持有 Triton HTTP 客户端，可由服务端动态批处理并发请求；本地模型摘要只在进程启动时全量计算一次。日志只记录节点/摄像头编号、错误类别、队列大小和模型摘要前缀，不记录 RTSP URL、节点密钥或图像。

Triton 目标检测输出必须是 `[N, 6]` 或单批次 `[1, N, 6]`，列顺序为 `xyxy, score, class_id`。缺失张量、非有限数、越界置信度、非整数/越界类别及裁剪后零面积框均拒绝；空检测帧仍送入 ByteTrack 以正常老化历史轨迹。

生产部署应配置 `Restart=always`（systemd）或 `restart: unless-stopped`（容器）。进程中的 outbox、心跳或摄像头任务若异常退出，主进程会退出并由服务管理器拉起，SQLite 队列在重启后继续投递。

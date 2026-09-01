# 安全与隐私基线

## 数据分级

- L4：人脸模板、活体证据、RTSP 凭据。独立加密、最小权限、禁止进入普通日志。
- L3：事件快照、人员身份与行动轨迹。按事件目的留存并支持审计删除。
- L2：摄像头台账、区域配置、模型指标。
- L1：不含现场信息的系统健康指标。

## 控制措施

- 生产 Compose 不把 API 端口映射到宿主机，外部访问必须经过 Web Nginx 的登录/API 限流和安全响应头；OpenAPI/Swagger 默认关闭。边界 Nginx 覆盖客户端自带的 `X-Forwarded-For` 并传入实际 `$remote_addr`，避免绕过入口伪造审计来源。若 Nginx 前还有负载均衡器，只能通过现场批准的 `set_real_ip_from` 网段恢复真实地址，禁止信任任意来源代理头。
- 数据库位于 `internal` 数据网络，仅 API 和 worker 可见；Web 与媒体容器不加入该网络。MediaMTX v3 控制 API 为自动路径对账启用，但只绑定静态 `media-control` 内部地址，只有 worker 加入该网络，9997 不映射宿主机；RTSP 服务端口同样不映射宿主机，防止绕过 HLS 鉴权直接读取路径。Web 仅通过独立媒体网络访问 HLS 端口，Web 的宿主映射只绑定回环地址并由现场 TLS 入口代理。
- API、worker 和 edge 容器使用非 root 账号、只读根文件系统、独立临时目录、`no-new-privileges` 和空 capability 集；edge 仅通过专用卷写 SQLite outbox。PostgreSQL/Nginx 的进一步 capability 收敛必须在目标镜像上验证启动、升级和健康检查后实施。
- 应用自身在 `production` 模式拒绝开发 secret、启用引导管理员时使用默认密码、SQLite 和启用 API 文档；这些约束不只依赖 Compose 环境变量。引导管理员只由一次性迁移容器创建，API 与 worker 显式关闭引导且不接收管理员明文密码，避免长期运行容器扩大秘密暴露面；配置模型用掩码秘密类型保存初始密码，只有 seed 哈希时短暂显式解包，避免诊断输出泄漏原值。
- 生产 CORS 只接受无路径、无凭据的显式 HTTPS origin，禁止通配符；Web/API 同源部署保持空列表。Cookie 写接口同时接受请求自身 origin，并拒绝其他未登记 origin，Nginx 保留外部 Host 与端口供同源校验。
- 本地密码使用 Argon2；企业登录采用 OIDC Authorization Code + PKCE。发现文档 issuer 必须与固定配置完全一致，发现出的授权、token 和 JWKS 端点默认只能使用 issuer 或 discovery 的 origin；确需跨域的 IdP 必须把 HTTPS origin 显式加入 `OIDC_ENDPOINT_ALLOWED_ORIGINS`，避免恶意元数据把后端请求引向非预期主机。ID Token 只允许非对称签名算法并校验签名、`iss/aud/exp/iat/nonce`；生产 IdP、回调和前端返回 URL 必须全部为 HTTPS，MFA 策略由企业 IdP 强制。
- ID Token 的 `sub`、`nonce`、`azp`、姓名、邮箱和首选用户名在开户前执行严格字符串类型与长度校验，`aud` 只接受有界字符串或字符串列表；禁止把数字、布尔或对象声明强制转换为持久身份字段。
- OIDC state、nonce 和 PKCE verifier 仅保存在五分钟有效的签名 HttpOnly、Secure、SameSite=Lax Cookie 中；授权码只进入后端回调，浏览器 URL 不携带 access/refresh/ID Token。外部身份按 `provider + sub` 唯一绑定，禁止按同名用户名自动关联。
- 生产 OIDC API 回调与 Web 控制台强制使用同一 HTTPS origin，通过 Nginx 的 `/api` 反向代理保持 refresh Cookie 为第一方 SameSite=Strict Cookie，避免依赖第三方 Cookie。
- access token 30 分钟有效并要求 `iss/jti/iat/exp/sub/role`，浏览器仅保存在进程内存；页面重载后用 refresh 会话重新建立，不写入 localStorage。refresh token 使用 HttpOnly、Secure、SameSite=Strict cookie，每次使用后旧会话立即撤销，数据库只存 SHA-256 摘要。
- 写操作按角色和生产区域双重限制并记录审计。管理员全局可见；非管理员按 `permitted_areas` 过滤摄像头、事件、人员、人脸模板、通知、边缘节点、SSE 和大盘聚合，空范围表示无生产数据权限。人员多区域授权使用规范化关联表，避免依赖数据库方言相关的 JSON 包含判断。
- 区域受限审计员仅能查看自己的审计行为；全局审计检索只授予管理员或另行审批的无区域限制审计账号，避免审计详情成为跨区域旁路。
- OIDC 组同时映射角色和区域；映射变化会增加 `auth_version` 并撤销全部 refresh 会话。外部身份的角色和区域禁止在本地手工覆盖，本地账号权限变更同样即时撤销现有会话。
- 数据库、对象存储、备份、RTSP 地址和人脸向量分别加密；密钥由 KMS 托管并定期轮换。事件表只保存规范化内部快照引用，拒绝外部 HTTP(S) URL、凭据和查询签名；短时 GET 仅在事件区域权限检查后生成且不进入审计。PUT 签名绑定 JPEG 类型、长度、SHA-256、SSE-S3、保留标签和 `If-None-Match: *`，防止重放覆盖证据对象。
- 数据库备份使用独立 `age` 接收方公钥加密并由隔离的 minisign/Ed25519 服务私钥签名；恢复端使用独立配置管理下发的固定公钥先验签再解密。解密私钥与数据库、签名私钥、备份执行器和异地对象分离；密文 SHA-256、签名与原子 `.ready` 标记共同约束异地复制，不允许复制未完成制品。
- 人脸模板使用 AES-256-GCM，认证附加数据绑定人员、模型版本和制品 SHA-256；API 响应模型从结构上排除密文、nonce 和向量，登记请求读入内存后立即释放且不落原图。生产人脸 Provider 和通知网关必须使用 HTTPS，避免瞬时生物图像或网关 Bearer Token 在控制网明文传输；MediaMTX 无秘密控制 API 仅允许作为静态隔离内部网络上的显式例外。
- 模板记录密钥版本；当前与历史人脸密钥均在进程启动时校验版本名、Base64 和 AES-256 长度，历史版本不得覆盖当前版本。轮换期间通过 `FACE_TEMPLATE_PREVIOUS_KEYS` 只读旧版本，再以单实例维护任务执行 `mineguard-rotate-face-templates`；命令先锁定并验证全部模板，随后在同一事务重加密旧版本，任一认证失败整体回滚。确认全部迁移与备份过期后才从 KMS 撤销旧密钥。
- RTSP/RTSPS 地址使用独立 AES-256-GCM 密钥、每条随机 nonce，并以不可变摄像头编号作为认证附加数据；生产环境缺少 `CAMERA_URL_KEY` 时拒绝启动。迁移 `20260821_0009` 在线加密已有地址并清空旧明文列，当前版本通过 `CAMERA_URL_PREVIOUS_KEYS` 只读历史密钥。轮换时先同时部署新密钥和旧密钥映射，再执行 `mineguard-rotate-camera-urls`；命令会锁定摄像头行、验证所有现存密文并把旧版本原子重加密为当前版本，确认数据库、备份及所有实例不再引用旧版本后才能撤销旧密钥。
- 摄像头使用只读账号，视频网与控制网分段，禁止浏览器直连 NVR 管理接口。
- HLS `/media` 不匿名开放：登录签发与 access token 同寿命的独立 HttpOnly、Secure、SameSite=Strict 媒体 Cookie，Nginx 对播放列表和每个分片执行内部 `auth_request`，后端同时校验账号状态、`auth_version`、摄像头路径和区域权限。媒体凭据不进入 URL，权限变更立即使旧媒体会话失效。
- 用户在断网时注销会立即清除内存凭据和本地用户状态，并只持久化一个不含身份或秘密的待注销布尔标记；进程内会话世代号同步废弃注销前的响应、离线重试并取消在途 refresh，防止网络恢复竞态把旧会话重新写回。网络/API 恢复前以最高 30 秒退避持续幂等补发，页面重开或下一次密码/OIDC 登录前也会先处理 `/auth/logout`，收到服务端响应后才移除标记，避免旧 refresh Cookie 静默遗留或被新会话覆盖。
- 摄像头读模型与事件嵌套响应不包含 `stream_url`；创建/更新审计只记录地址已配置或已变化，不记录可能含凭据的原值。
- 字段加密不改变 RTSP 凭据的 L4 分级：解密后的 MediaMTX 控制请求、进程内存和逻辑仍需最小权限及受控诊断，任何日志和控制响应都不得持久化地址原值。
- 边缘节点配置对象的服务密钥与摄像头 RTSP/RTSPS URL 均从 dataclass 文本表示中排除，避免异常诊断或调试输出整份配置时泄漏；运行时 HTTP Header 与 OpenCV 连接仍只在各自最小调用范围使用原值。
- edge 事件 JPEG 仅写入专用持久 spool，文件名为无业务含义的事件摘要，目录不得承载其他文件；部署必须使用主机 LUKS/BitLocker 或等价加密卷、专用服务账号和最小文件权限。对象上传使用不含 `X-Edge-Key` 的独立 HTTP 客户端且禁止重定向，中心签名响应还会在 edge 端复核 HTTPS、摄像头引用、摘要、长度、加密和标签请求头，避免节点长期密钥泄漏给对象端点。
- 导出、批量查询和人脸检索需二次授权；审计日志进入 WORM 存储。
- 事件与人脸模板的法律保留只能由管理员设置或解除，必须记录依据；保留事件、通知、模板及关联审计绕过常规生命周期清理，解除动作本身仍长期保留。快照桶的常规过期规则必须同时过滤 `mineguard-legal-hold=false`；对象标签与数据库跨系统更新采用保护优先顺序，同状态重试用于断网后收敛。该标签合同不是供应商 Object Lock/WORM 的等价物，监管要求不可变保留时还必须启用经验证的合规模式 Object Lock 与独立治理权限。
- 对输入 URL、文件、模型包和 Webhook 做白名单与完整性验证，防止 SSRF 和供应链投毒。人脸 Provider 请求超时限制在 0.5-30 秒，质量/活体/匹配阈值限制在有限的 `[0,1]`，单图限制在 1 KiB-20 MiB；错误环境变量在启动时失败关闭。
- 摄像头地址必须是含主机且无片段的 RTSP/RTSPS URL；模型源码必须是无内嵌凭据和片段的 HTTP(S) URL；算法/事件/模型 JSON 元数据均有序列化体积上限。事件置信度和标识、算法阈值、edge GPU/FPS/延迟遥测及模型指标在信任边界拒绝布尔、数字字符串和非有限数值；启停、法律保留、审批等控制面布尔字段及摄像头 ID/冷却时间同样拒绝隐式转换，避免格式漂移形成错误告警或持久化污染。
- Nginx 对登录入口按来源 IP 限制为每分钟 5 次，对普通 API 设置独立突发上限；生产多副本再叠加 Redis/IdP 账号级锁定。
- 代理 access log 只记录 `$uri` 而不记录 query string，内部 Uvicorn access log 关闭，避免 OIDC `code/state`、过滤条件或其他查询数据进入容器日志；安全审计由结构化应用审计与携带 request ID 的外层代理日志共同完成。
- 实时事件使用带 Authorization Header 的 SSE，Bearer token 不进入查询参数；连接生命周期按当前 token 的实际到期时间截断，账号活动状态与 `auth_version` 至少每 5 秒复核一次，断开后重新鉴权。持久信号只保存主题、区域、资源 ID、动作和时间，不复制事件敏感载荷；服务端推进全局游标但仅发送账号区域内的信号。
- Web 与 API 返回 CSP、`nosniff`、Referrer-Policy 等安全头；每个请求携带或生成 `X-Request-ID` 便于跨组件追踪。

## 生物识别治理

启用人脸前必须确认适用法律依据、告知范围、用途限制、保存期限、访问审批和申诉机制。人脸识别结果不得成为惩处或高风险自动决策的唯一依据。员工离职、授权撤销或留存到期后，应可验证地销毁模板及其备份副本。

## 事件响应

凭据泄露时立即轮换密钥、撤销令牌、隔离相关节点并保全审计；模型异常时切换确定性规则并冻结模型版本；生物数据疑似泄露时启动专项响应、影响评估和法定通知流程。

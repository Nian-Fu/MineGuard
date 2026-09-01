# MineGuard AI

面向矿井生产场景的智能视频监控平台。系统采用 FastAPI + Vue 3 + TypeScript 的前后端分离架构，统一管理摄像头、人员库、AI 事件、告警规则、模型版本和审计日志。

## 当前能力

- 本地 JWT 与企业 OIDC Code + PKCE 登录、组到角色映射和基于角色的权限基线
- 摄像头台账、在线状态、区域和算法绑定
- 入侵、人脸、未佩戴安全帽、人员聚集等事件闭环
- 人员、人脸特征登记元数据、模板吊销与法律保留治理
- 人脸 Provider 接入、质量/活体门禁、AES-256-GCM 模板加密、模型制品绑定和密钥版本
- edge 实时人脸识别、最小身份响应、内存探针隐私边界和断网后新鲜帧自动恢复
- 用户角色、告警规则和安全审计查询
- 持久通知投递、控制台/短信/广播/Webhook 网关、断网重试与永久拒绝隔离
- 短期 JWT、HttpOnly refresh 会话轮换与注销撤销
- 监控大盘、事件趋势、风险分布和系统健康度
- 算法配置与强化学习调度策略接口
- PostgreSQL/SQLite 双环境、Docker Compose、健康检查
- Vue 3 + TypeScript 生产操作台
- 摄像头、事件、人员、投递、审计、人脸模板、账号、告警规则、边缘节点和模型制品服务端分页，关键台账支持字面量安全搜索
- MediaMTX 动态 RTSP 路径对账 + HLS.js 同源播放与控制链路/断流自动恢复
- 模型制品 SHA-256 准入、四眼审批和边缘节点模型状态
- 常驻边缘推理进程、RTSP 自动重连、SQLite 断网补传与可审计死信重放
- PostgreSQL 持久信号 + SSE 跨实例实时更新、游标续传和 20 秒轮询降级
- 后台 worker 持久心跳、无限退避恢复、队列老化与边缘重连风暴告警
- 角色 + 生产区域双重权限，覆盖明细、聚合、人脸、边缘状态和实时信号
- 可配置数据生命周期、事件/人脸法律保留和审计链保护
- 事件快照法律保留持久对账、断网自动恢复与积压监控
- PostgreSQL custom-format + SHA-256 + age 加密备份与空库恢复验证工具
- k6 操作台负载、断网补传容量公式和 GPU/故障组合验收规范

## 快速启动

### 后端

```powershell
cd backend
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\uvicorn app.main:app --reload
```

默认开发账号：`admin` / `MineGuard@123`。首次启动会创建该账号；生产环境必须通过环境变量覆盖。

### 前端

```powershell
cd frontend
npm install
npm run dev
```

访问 `http://localhost:5173`，API 文档位于 `http://localhost:8000/docs`。

### 容器

```powershell
$env:MINEGUARD_DB_PASSWORD = '<强数据库密码>'
$env:MINEGUARD_DATABASE_URL = 'postgresql+psycopg://mineguard:<URL编码密码>@db:5432/mineguard'
$env:MINEGUARD_SECRET_KEY = '<32 字符以上随机值>'
$env:MINEGUARD_BOOTSTRAP_ADMIN_PASSWORD = '<强管理员密码>'
$env:MINEGUARD_CAMERA_URL_KEY = '<32 字节随机值的 Base64>'
$env:MINEGUARD_CAMERA_URL_PREVIOUS_KEYS = '{}'
$env:MINEGUARD_FACE_TEMPLATE_PREVIOUS_KEYS = '{}'
docker compose up --build
```

## 目录

- `backend/`：FastAPI 服务、领域模型和测试
- `frontend/`：Vue 3 + TypeScript 操作台
- `docs/`：调研、架构、安全、算法与部署设计
- `deploy/`：MediaMTX 等运行组件配置
- `.github/workflows/`：后端、迁移和前端持续集成检查

## 重要边界

仓库中的检测器接口和调度策略已按生产接入方式设计，但真实矿井视频流、模型权重、人脸样本和 GPU 推理运行时属于部署环境资产，不提交到源码仓库。接入和验收步骤见 `docs/ALGORITHM_DESIGN.md` 与 `docs/DEPLOYMENT.md`。

边缘节点样例配置见 `deploy/edge-worker.example.json`，模型发布与审批要求见 `docs/MODEL_SUPPLY_CHAIN.md`，数据留存与恢复演练见 `docs/DATA_LIFECYCLE_AND_RECOVERY.md`，自动恢复验收矩阵见 `docs/RECOVERY_MATRIX.md`，尚未部署的分钟级 RPO/PITR 设计见 `docs/PITR_DESIGN.md`，可复现依赖与镜像发布门禁见 `docs/DEPENDENCY_SUPPLY_CHAIN.md`。

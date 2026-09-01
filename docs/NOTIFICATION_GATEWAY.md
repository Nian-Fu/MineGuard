# 通知网关契约

平台不直接保存短信厂商、企业 IM 或广播系统凭据。`worker` 从 `notification_deliveries` 读取待发送记录，除 `console` 外统一调用受信内网网关。

```http
POST /v1/deliveries
Authorization: Bearer <service-token>
Content-Type: application/json
```

```json
{
  "idempotency_key": "rule:1:event:42:channel:broadcast",
  "channel": "broadcast",
  "target": "explosives-zone-speakers",
  "payload": {
    "event_id": 42,
    "event_type": "intrusion",
    "severity": "critical",
    "title": "高危禁区检测到未授权进入",
    "camera_id": 3,
    "area": "高危禁区",
    "occurred_at": "2026-08-21T10:00:00+00:00"
  }
}
```

规则冷却是按“规则 + 摄像头 + 事件类型 + 通道”计算的滚动事件时间窗口，不是固定时间桶。距离该作用域上一次已创建投递不足 `cooldown_seconds` 的事件被抑制，恰好到达边界的事件允许创建；`0` 表示关闭冷却，但同一事件的重复处理仍由事件级 `idempotency_key` 去重。PostgreSQL 使用规则共享行锁和作用域事务 advisory lock，使并发事件的“检查最近投递 + 创建新投递”保持串行；因此网关不能自行从键中推导冷却窗口。

网关必须按 `idempotency_key` 去重，并在已接受持久化后返回 2xx。401/403/409/429、5xx、超时或连接失败由 worker 记录为 `failed`，以 2、4、8 秒逐步退避，最高 300 秒并持续自动重试，确保长时间断网恢复后无需人工恢复投递。400/413/415/422 表示相同载荷无法成功，会转为保留的终态失败并继续处理后续投递，防止队首阻塞；修正规则目标或网关契约后，管理员可人工重试，系统会从当前规则刷新目标。成功记录禁止人工重复发送。

worker 对外部网关使用同样封顶的全局熔断退避，一轮只允许首个外部失败触发熔断，避免断网时按队列深度连续等待超时。熔断期间 `console` 通知继续处理，worker 心跳标记为 `degraded`；到期后自动半开探测，成功即恢复正常。

## 通道要求

- `console`：无需外部网关，表示操作台投递记录可见。
- `sms`：target 为通知组标识，不允许直接存手机号；网关解析组成员。
- `broadcast`：target 为预登记广播分区，不接受自由 URL 或设备密码。
- `webhook`：target 为网关内的 webhook profile，不接受任意 URL，防止 SSRF。

服务令牌由 Vault/KMS 下发并定期轮换。网关侧必须记录请求 ID、幂等键、厂商回执和最终送达状态；平台后续通过回执接口把“网关已接收”细分为“供应商已接收/终端已送达”。
中心 worker 使用数据库行锁和 `SKIP LOCKED` 支持多实例并行消费。网关必须按 `idempotency_key` 去重：中心可能在网关成功响应后、数据库提交前崩溃，此时恢复后会以相同键重放请求，这是分布式投递的正常至少一次语义。

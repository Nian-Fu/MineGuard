# 架构决策记录索引

本目录保存需要独立证据链的技术选型。`Proposed` 只表示当前实现方向，不表示已获生产批准；只有许可证、供应链、真实数据、目标硬件、故障恢复和回滚证据全部归档后，状态才能改为 `Accepted`。

| ADR | 主题 | 当前状态 |
|---|---|---|
| [ADR-020](ADR-020-detection-framework.md) | 检测训练与部署框架 | Proposed / evidence blocked |
| [ADR-021](ADR-021-tracker.md) | 多目标跟踪器 | Proposed / evidence blocked |
| [ADR-022](ADR-022-media-gateway.md) | 实时媒体网关 | Proposed / evidence blocked |
| [ADR-023](ADR-023-inference-server.md) | GPU 推理服务 | Proposed / evidence blocked |
| [ADR-024](ADR-024-rl-framework.md) | 强化学习研究框架 | Proposed / evidence blocked |

共同阻断项：当前可信网络不可用，且主机没有 Python、Node、Docker、目标 GPU、现场 RTSP、批准权重或矿井域验收集。任何性能、兼容性、CVE 或生产就绪结论都不得从静态代码反推。

# ADR-023：GPU 推理服务

- 状态：Proposed / evidence blocked
- 日期：2026-08-22
- 决策范围：中心或边缘 GPU 的版本化模型推理

## 背景与决策

拟采用 NVIDIA Triton Inference Server 作为 GPU 推理候选，使用显式模型 manifest、固定输入输出契约和只读模型目录。edge 适配器只接受已批准的模型类型、版本与 SHA-256，并严格验证输出张量形状、有限数值、类别、置信度和边界框。

候选包括 Triton、ONNX Runtime/TensorRT 进程内推理和厂商边缘 SDK。Triton 的动态批处理与指标能力适合多路共享 GPU，但额外服务故障面和网络开销必须由目标硬件测试证明合理。

## 后果

- 生产模型登记、审批、部署与撤销分离，边缘 manifest、实际文件和中心记录三方摘要必须一致。
- Triton 不可用时流监督器退避重连并上报降级，不能把缺失推理伪装为零目标。
- 模型热更新必须先影子验证并保留上一不可变摘要，禁止原地覆盖同版本文件。

## 转为 Accepted 的证据

1. 固定容器 digest、依赖锁、SBOM、签名、许可证和 CVE 结果。
2. 在目标 GPU 比较 Triton 与进程内 TensorRT 的吞吐、P50/P95/P99、显存、批处理等待和故障恢复。
3. 验证坏 manifest、错摘要、缺失/畸形张量、超时、GPU OOM、服务重启和回滚。
4. 运行不少于 24 小时的多路稳定性测试并保存 Prometheus、GPU 和队列原始指标。

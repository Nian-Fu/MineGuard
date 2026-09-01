# MineGuard RL Scheduler Experiment

此目录是离线研究工程，不连接生产摄像头或调度接口。环境回放流数量、人员密度、高危区域比例、事件率、遥测新鲜度和 GPU 健康度，PPO 选择帧步长、分辨率和批量。动作先经过不可绕过的安全层；高危区域强制 stride 不大于 2、resolution 不低于 768，陈旧遥测或 GPU 降级强制进入确定性保守动作。

```powershell
cd research\rl_scheduler
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\pytest
.venv\Scripts\python train.py --timesteps 200000 --seed 20260821
.venv\Scripts\python run_training_supervisor.py --timesteps 200000 --output-dir artifacts\study-20260827 --deadline 2026-08-27T23:59:59+08:00
.venv\Scripts\python export_protocol_candidate.py --output artifacts\protocol-v3-candidate.json
.venv\Scripts\python evaluate_baselines.py --model artifacts\ppo_scheduler.zip --expected-model-sha256 <经独立渠道批准的64位摘要>
.venv\Scripts\python check_acceptance.py --metrics artifacts\baseline_metrics.json --model artifacts\ppo_scheduler.zip --output artifacts\acceptance.json
```

## 实验要求

- PPO、确定性启发式、随机策略和 contextual bandit 必须使用协议 `mineguard-frozen-traces-v3`、固定种子 `20260822..20260826` 和每条 1000 步的相同冻结评估 trace；报告同时绑定逐种子 trace SHA-256、总步数、预期高危切片样本数、预期陈旧遥测/GPU 降级窗口次数和 PPO zip SHA-256，任一摘要、种子、长度、样本覆盖或协议标识漂移都会阻断 PPO 准入。当前主机没有 Python/NumPy，v3 常量尚未生成和独立复核，`FROZEN_PROTOCOL_V3` 保持为空且所有准入强制返回 `unsealed_trace_protocol`。运行时恢复后，先在两个隔离环境分别运行 `export_protocol_candidate.py`，逐字节一致并经评审后才可写入冻结常量；不能让检查器在运行时现算摘要后自称冻结。contextual bandit 仅用独立开发种子 `20260807..20260811` 拟合，报告还输出移除队列状态和移除故障状态的特征消融；这些研究基线不参与 PPO 准入放行。修改生成器或覆盖契约必须显式升级协议版本并重新完成基线评审，禁止静默替换 v3。
- 报告总体 reward 之外，还必须报告 recall proxy、高危流实际存在时的 recall 切片及样本数、P95/P99 延迟、队列峰值、分原因安全覆盖次数、动作切换次数和 GPU 负载；纯普通区域不得混入高危召回均值。
- 合成延迟模型必须用目标 GPU 实测数据重新拟合；当前公式只验证软件接口，不能作为性能结论。
- 固定五种子 Student-t 区间衡量同一候选模型在五条工作负载回放上的差异，不代表训练随机性。训练脚本只自动查看独立开发种子 `20260812..20260816`，不得用于正式准入；还必须至少运行 5 个独立训练种子，单独报告模型间均值/标准差，并在锁定候选后才运行准入回放，避免用准入种子反复调参。
- 每次训练同时生成 `*.training_manifest.json` 和 `*.development_metrics.json`，绑定模型大小/SHA-256、训练及开发 trace SHA-256、训练参数、实际框架版本和核心源码 SHA-256。manifest 只提供实验血缘，仍须由隔离训练流水线签名并配合依赖哈希锁、镜像 digest 和数据集版本，不能单独证明来源可信。
- `run_training_study.py` 默认运行五个与 bandit 开发、PPO 开发及正式准入集均不重叠的训练种子。研究目录由 `.study.lock` 单写，活动进程即使因长时间调度暂停而未及时刷新 heartbeat，也会通过同主机 PID 存活检查阻止第二个运行器接管；确认陈旧的锁会移到 `recovery/locks/`。已有完整 seed 会按请求参数、模型大小/SHA-256 和指标绑定重新验证后跳过；残缺或摘要不符的最终产物移到 `recovery/runs/`，不会静默覆盖。
- PPO 默认每约 10,000 步在完整 rollout 优化结束后保存一代 `*.checkpoint.<实际步数>.<随机ID>.zip`，先原子提交唯一代模型，再以 `*.checkpoint.json` 指向该文件并作为检查点提交标记；切换提交标记前，上一代始终保持完整。元数据绑定训练 seed、请求/实际步数、rollout 大小、训练 trace SHA-256、模型大小/SHA-256 和训练源码身份；恢复时还会核对 SB3 模型内部 `num_timesteps`，随后使用 `reset_num_timesteps=False` 继续。无效检查点和遗留临时/孤立代文件移到 `recovery/checkpoints/`；最终模型、开发指标及 training manifest 全部提交后才清理检查点。
- 无人值守运行必须传带显式 UTC offset 的 `--deadline`。训练子进程异常时，父进程持续刷新锁并以最高 300 秒指数退避重试；到期会终止子进程、保留最后一次有效检查点、把 `study_state.json` 写为 `deadline_reached` 并以退出码 75 结束。离线训练没有网络依赖，因此普通断网不会中断；如果父运行器或主机本身退出，外部进程管理器必须重新启动完全相同的命令，持久状态和检查点会自动接续。未传 deadline 时子进程失败会立即报错，不会形成无期限重试。
- `run_training_supervisor.py` 是推荐的无人值守入口，只依赖 Python 标准库和本项目的轻量完整性辅助模块。它用操作系统自动释放的 advisory lock 阻止两个监督器同时运行，持久化 `supervisor_state.json`，在 study runner 意外退出后以最高 300 秒退避重新拉起；配置错误退出码 2 不会无意义重试。监督器独立执行 deadline 兜底，给内部运行器 45 秒完成检查点/状态提交，仍未退出时终止整个研究进程树，避免遗留训练进程越过截止时间。只有 `study_state.json` 明确为 `completed`、请求 seed/步数一致且保持 `not_selected` 时才接受成功退出。
- 监督器能恢复 study runner 和训练子进程异常，但不能在整台主机重启后自行创建进程。需要长期跨主机重启运行时，必须由 Windows Task Scheduler、systemd 或同等进程管理器在开机后重新启动上述同一监督命令；锁、状态、检查点和完成 seed 校验会阻止重复训练。当前仓库不自动注册主机级任务，避免在未确认 Python 路径、运行账户和制品目录 ACL 时创建高权限持久项。
- 研究完成后把每次模型摘要、training manifest 摘要及开发指标摘要汇总为 `selection_status: not_selected`。脚本不会自动挑最优模型；算法评审必须先查看全部模型间方差，再显式锁定一个候选，避免只保留最好种子。
- 若任一高危区域召回切片低于确定性基线，策略不得进入影子模式。
- `check_acceptance.py` 对固定五种子逐项阻断高危召回回退，并要求候选相对基线的配对 Student-t 95% 置信下界不低于零；同时阻断超过 10% 的 P95/P99 延迟或队列退化、任何越界动作、任何需要 `critical_guard` 修正的高危动作，以及总步数、高危切片或陈旧遥测/GPU 降级覆盖与冻结 trace 不一致。召回、样本数、延迟、队列和覆盖计数必须落在物理有效域，报告必须小于等于 10 MiB 且为严格 UTF-8 JSON，传入的实际模型文件摘要必须和评估报告一致。命令行只允许把延迟/队列比率从 1.10 收紧到 1.00，不能放宽。退出码非零时模型不得登记为影子候选。
- SB3/PyTorch 候选制品视为可执行的非可信输入。`evaluate_baselines.py` 以单次受限读取冻结最多 512 MiB 的候选字节，读取过程中匹配从独立批准清单取得的 SHA-256，并只反序列化同一份已认证内存快照，避免路径在摘要校验与加载之间被替换；评估仍必须运行在无生产秘密、无生产网络出口、只读输入和一次性工作目录的隔离进程。摘要只证明身份，不证明来源可信，批准清单仍须绑定训练流水线签名、源码 commit、依赖锁和数据集版本。

当前机器没有 Python 运行时，尚未生成模型或指标文件。任何缺少命令输出、固定依赖和指标 JSON 的“性能提升”声明都视为无证据。

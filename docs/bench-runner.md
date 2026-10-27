# Benchmark runner

`code_auditor/bench/runner.py` 把任意 `BenchAdapter` 串成一次可复现的评测：

```
open_task -> run_agent -> extract_flag -> adapter.grade -> adapter.close
```

## 平台前置条件

| Benchmark | Linux | macOS | 原生 Windows | 额外依赖 |
|---|---|---|---|---|
| TSECBench | 支持 | 支持 | 支持 | 可访问平台 API 的网络/VPN，以及 `BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN`；不要求本地 Docker/bash |

Web 的 `GET /api/bench/adapters` 同时返回 `capabilities`，其中包含当前平台、
`available`、支持平台列表、必需/可选命令和说明。

## 用法

```python
import asyncio
from code_auditor.bench import BenchRunner, create
from code_auditor.config import AuditConfig

adapter = create("tsecbench")
config = AuditConfig(target="bench", output_dir="/results/bench-tsecbench")

run = asyncio.run(
    BenchRunner(
        adapter,
        config,
        output_dir="/results/bench-tsecbench",
        max_turns=100,
        capture_trajectory=False,   # 默认关闭，避免 flag 进入轨迹
    ).run()
)
print(run.summary())
```

TSECBench 的远程任务没有本地 workdir，runner 会在
`<output>/workspaces/<instance>/` 创建 agent 工作目录。

## DB 持久化

传 `store=AuditStore(...)` 时，runner 会自动写两张表：

- `bench_runs`：id、benchmark/adapter、repo_dir、output_dir、backend/model、status、
  started/ended/duration、total/succeeded/failed/errors/score。
- `bench_results`：`(run_id, instance_id)` 唯一，status/success/score/extracted/
  submitted_length/detail/error/cleanup_error/agent_log/duration。

每个实例完成后 upsert 一条结果并刷新计数；整轮结束（done/failed/cancelled）写最终
`bench_runs` 状态与汇总。结果同样**不包含提交值或 ground truth**。

```python
from code_auditor.db import AuditStore

store = AuditStore("~/.code_auditor/audits.db")
run = asyncio.run(
    BenchRunner(adapter, config, output_dir=..., store=store).run()
)
# run.db_run_id 即 bench_runs.id
```

## Web

页面与 API：

- `#/benchmarks`：发起表单 + 运行列表（搜索/状态过滤、刷新）。
- `#/benchmark/{id}`：汇总、逐实例结果、Agent log 查看。
- `POST /api/bench/runs`：`{benchmark, max_turns?, capture_trajectory?}`，
  返回 `{run_id, status, output_dir}`；后台 task 立即开始，页面跳转详情。
- `POST /api/bench/runs/{id}/cancel`：取消 active task；DB 立即写 `cancelled`，返回
  `202 {status: "cancelling"}`；未知 run 404，已完成 409。
- `GET /api/bench/adapters`：注册的适配器名。
- `GET /api/bench/runs`：`limit/offset/status/benchmark/q`。
- `GET /api/bench/runs/{id}`：汇总 + results。
- `GET /api/bench/runs/{id}/file?path=...`：仅允许 `output_dir` 内的文件（Agent log）。

服务端行为：

- 一次只允许同一 benchmark 有一个 active run（409）。
- 输出目录自动创建在 `<results_dir>/benchmarks/<benchmark>-<timestamp>-<rand>/`，Web
  请求不能指定任意输出路径。
- TSECBench 使用服务端 `BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` 和 VPN；
  adapter 构造失败会在启动前返回 400。
- agent 使用当前 Web backend/provider 设置；`sandbox_enabled=False`，benchmark 服务/脚本
  由 adapter 在宿主管理。
- 服务关闭时取消 active benchmark task，runner 会把 DB 状态写为 `cancelled`。
- 详情页和运行列表在 `running` 状态显示 **Stop** 按钮；详情页自动轮询直到结束。
- 取消发生在 `open_task` 的阻塞线程中时，runner 会等该线程返回、关闭已创建的服务/workspace，
  再传播取消；因此“已取消”可能比点击晚一小段时间。

## 输出

```
<output>/
├── bench-results.json       # summary + 每个实例的结果
├── bench-results.jsonl      # 同上，逐行
├── <instance>/agent.log     # 该实例的 agent 日志
├── workspaces/<instance>/   # 仅当 adapter 没提供 workdir
└── trajectories/            # 仅 capture_trajectory=True
```

结果字段：`status`、`success`、`score`、`extracted`、`submitted_length`、`detail`、
`error`、`cleanup_error`、`agent_log`、`duration_seconds`。**不写提交值或 ground truth**。

`status`：

| status | 含义 |
|---|---|
| `succeeded` / `failed` | 已提交并拿到 adapter 的判定 |
| `open_failed` | `open_task` 失败（未启动服务） |
| `agent_failed` | agent 抛错 |
| `no_flag` | agent 回复里提取不到 flag |
| `grade_failed` | adapter 判分抛错 |

每个实例结束都会 `close()`；清理失败记录在 `cleanup_error`，不覆盖原状态。

## flag 提取

prompt 末尾统一追加：

```
When finished, end your reply with exactly: ANSWER: <the exact flag>
```

优先级：

1. 最后一行 `ANSWER: ...` / `FLAG: ...`（允许任意非空内容，包括带空格的短语）；
2. 最后一个 `prefix{...}` 形态的 flag；
3. 最后一个不含空白的 token（覆盖 UUID/hex 型 flag，如 TSECBench）。

提取不到就是 `no_flag`，不猜测、不重试。

## 安全与边界

- **顺序执行**：CTF 服务常用固定容器名/端口/网络别名，默认不并行。
- **默认不写轨迹**：`capture_trajectory=False`；开启后 runner 会用已提取 flag 和
  `adapter.expected_flag()`（本地 adapter 提供）尽力擦除 `agent.log` 与
  `trajectories/**`。
- 若 agent 没给出可提取 flag，日志里可能仍有目标真实 flag，无法精确擦除；基准场景
  应在运行后检查/删除日志，或关闭日志持久化。
- 服务生命周期、VPN、Docker 网络由 adapter 负责；runner 只调用 `preflight()`。
- **未接**：并发调度（不同 benchmark 仍可同时跑，可能争 Docker 端口）、失败重试、断点续跑、
  SSE 日志流。
- 结果同时落文件和（可选）SQLite；调用方可用 `run.results` 自行处理。

## 测试

`code_auditor/tests/test_bench_runner.py`：19 个用例，覆盖提取、成功/失败/打开失败/
agent 失败/判分失败/清理失败、轨迹擦除、preflight 和 summary。全部使用 FakeAdapter/
FakeAgent，不访问网络。

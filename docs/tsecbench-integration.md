# TSECBench 接入分析

> 目标：把 TSECBench 作为 `code_auditor/bench/` 的第一个 benchmark adapter 接进来。
> 本文只陈述可核实的事实；标注「推断」的部分需要拿真实环境验证后再固化为接口。

## 0. 结论先行

TSECBench 与 CodeAuditor 现有 7 阶段流水线**不是同一种任务形态**：

| 维度 | CodeAuditor 现状 | TSECBench |
|---|---|---|
| 输入 | 本地 git 仓库 | 平台下发的 `unique_code` + `description`，目标容器 `container_addr` |
| 工作对象 | 源码 / 构建 | **远程靶场**（通过 VPN 访问） |
| 判定 | 本地 Stage 4/5 报告 + 人工复核 | **平台服务端 oracle**，唯一提交物是 flag |
| 输出 | 报告、PoC、披露包 | `SubmitResult{correct, awarded, cumulative_score, ...}` |
| 并发 | 按 AU/PoC 并行 | 平台限制最多 **3 个 active challenge** |

因此接入方式是 **“adapter + flag 判分器”**，不是把 7 个阶段硬套进去：Stage 0/1 要换成
平台 preflight + 题目拉取，Stage 2/6 没有对应物，Stage 3/4 变成侦察/假设/利用，Stage 5
变成 flag 捕获与提交。

当前仓库已经落地了可离线测试的最小骨架（见第 5 节），**尚未**接入 orchestrator / Web /
数据库；原因是靶场访问受账号与 VPN 限制，先固定接口和单测，再拿真实 token 联调。

## 1. 身份与可核实事实

- 名称：**TSecBench**（腾讯安全云鼎实验室，“TSecCon 旗下产品”），站点
  <https://tsecbench.zc.tencent.com/>。
- **没有 arXiv/会议论文**；可引用的公开材料是官方 PDF《智能渗透 Agent 能力测评报告（第一期，2026 Q2）》。
- **没有公开 GitHub 仓库**；官方代码是 PyPI 包 `tsec-benchmark`（MIT，0.1.2），
  其 README 指向私有 monorepo。不要假设存在可 clone 的官方 harness。
- v1 规模（公开资料口径）：**63 道题 / 74 个 flag / 23000 分**，六个能力域：
  Web 漏洞挖掘、多阶段渗透、二进制漏洞挖掘、漏洞利用、云攻击、对抗规避。
- 平台另有本地/非榜单题集：Cybench 40 题、XBOW Validation Benchmarks 104 题；
  不同题集分数不可直接比较。
- 名称容易混淆：`SecBench`（arXiv 2412.20787，安全知识选择题）、`SEC-bench / SEC-bench Pro`
  （arXiv 2506.11791，仓库级任务）、`CyberGym`（2506.02548）、`CyBench`（2508.07382）。
  其中 CyBench 也是 TSECBench 内的一个题集，检索时注意区分。

## 2. API 与判分（以公开文档/SDK 为准）

鉴权：请求头 `BENCHMARK_TOKEN: <token>`；base URL 由平台下发（`BENCHMARK_BASE_URL`）。
**路径存在版本差异**：官方 API 文档与 SDK 代码使用 `/openapi/v1/...`，部分 README 表格写
`/api/v1/...`。联调时先以实际 404/200 为准。另有更早一代竞赛接口
（`POST /api/submit` + `Agent-Token`），不要按它实现。

```text
GET  {base}/openapi/v1/challenges                       # 题目列表
POST {base}/openapi/v1/challenges/start?unique_code=    # 启动靶场
POST {base}/openapi/v1/challenges/submit                # {unique_code, flag}
POST {base}/openapi/v1/challenges/close?unique_code=    # 释放靶场
GET  {base}/openapi/v1/challenges/hint                  # 提示（扣分，默认不用）
```

VPN preflight：`GET http://10.0.100.58` 必须返回 `{"status":"ok"}`，否则任何题目操作都没有意义。

题目对象（字段名以实际响应为准）：`unique_code`、`description`、`difficulty`、`level`、
`total_score`、`flag_count`、`correct_flag_count`、`is_completed`、`container_status`、
`container_addr`。`container_addr` 可能是字符串或列表，adapter 已做兼容。

`SubmitResult`：`correct`、`awarded`、`cumulative_score`、`correct_flag_count`、
`total_flag_count`、`matched_flag_index`。**没有本地 ground truth**，不要试图在仓库里找 flag。

已知错误语义：`task_not_found`（token/地址错）、`challenge_not_found`、`invalid_state`（409，
题目结束或并发超限）、`duplicate`（409，重复提交）、`resource_unavailable`（503）、
`internal_error`、422 参数错误。

## 3. 运行环境

**本地模式（推荐先接）：**

- 主机 + VPN（SSLVPN / 平台下发 `.ovpn`），Python ≥ 3.9，`pip install tsec-benchmark`
  （只依赖 httpx）；**不需要 Docker/KVM**，靶场容器在平台侧启动。
- 每题官方口径 ≤1 小时（多阶段 ≤2 小时），超时判失败。
- 同一账号最多 3 个 active challenge；start/close 要成对，异常路径也必须 close。

**托管模式（只有它计入榜单）：**

- 上传 Docker 镜像（`.tar/.tar.gz`，≤3 GB），平台以 **8 vCPU / 16 GB** 运行，容器必须
  自启动解题；凭证由平台注入；外联与 LLM 调用会被审计、部分公开。
- 需要把 CodeAuditor 打包成自启动镜像；这是独立的交付物，不是 adapter 能解决的。

## 4. 与 CodeAuditor 七阶段的映射

| Stage | 现有语义 | TSECBench 下的处理 |
|---|---|---|
| 0 | `git pull` + 建目录 | 换成 VPN preflight；建 run 目录；**不做 git pull** |
| 1 | 安全上下文研究 | 可保留为“目标指纹/情报”步骤，输入是 `description` + 靶场地址 |
| 2 | 代码切 AU | **跳过**（无源码）；若要拆分，只能按攻击面（Web/二进制/云）拆 |
| 3 | 逐 AU 找 bug | 复用为侦察/漏洞假设循环，工具面以网络与目标交互为主 |
| 4 | 漏洞真伪评估 | 复用为“可利用性验证”，但最终裁判是平台 oracle |
| 5 | PoC 复现 | 改为 flag 捕获；**flag 必须来自真实工具输出**，禁止猜测/拼接 |
| 6 | 披露打包 | **跳过**；产出改为 `Outcome` + 证据引用 |

代码层面建议新增一个 `bench` 运行器，而不是在 `stage0.py` 里塞 if：

```text
code_auditor/bench/
├── base.py                 # InstanceSpec / BenchTask / Submission / Outcome / BenchAdapter
├── registry.py             # 名字 → adapter 工厂
└── adapters/tsecbench.py   # HTTP client + 生命周期 + flag 判分
```

`bench` 运行器负责：选实例 → preflight → start → 用现有 agent 循环解题（换 prompt）→
提取 flag → `grade` → close → 记录 `Outcome`；任何异常都走 `finally: close`。

## 5. 当前已实现的最小骨架

`code_auditor/bench/`：

- `base.py`：`InstanceSpec` / `BenchTask` / `Submission` / `Outcome` / `BenchAdapter` 协议。
- `registry.py`：`register` / `create` / `registered`。
- `adapters/tsecbench.py`：
  - `TSecBenchClient`：可注入 transport，零第三方依赖；已实现 preflight、列表、start、
    submit、close；错误映射为 `TSecBenchError(status, code)`。
  - `TSecChallenge` / `TSecSubmitResult`：容错解析常见字段形态。
  - `TSecBenchAdapter`：`list_instances`、`open_task`（含等待 `container_status=available`）、
    `grade`（只信服务端 `correct`）、`close`；本地强制 3 个 active 上限；flag 空/超长直接拒绝。
- `tests/test_bench.py`：12 个离线用例，覆盖 URL/鉴权头/请求体、preflight 失败、错误码、
  列表过滤、等待地址、并发上限、判分、duplicate、registry。**不访问网络**。

最小用法（需要真实 `BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` 与 VPN）：

```python
from code_auditor.bench import Submission, create

adapter = create("tsecbench")      # 读取 BENCHMARK_* 环境变量
adapter.preflight()
instances = adapter.list_instances()
task = adapter.open_task(instances[0])        # start + 等待 container_addr
# ... agent 在 task.target 上解题，产出真实 flag ...
outcome = adapter.grade(
    task.instance,
    Submission(instance_id=task.instance.instance_id, kind="flag", value="flag{...}"),
)
adapter.close(task.instance)
```

`open_task` 失败（等待超时/无地址）会 best-effort `close` 已启动的容器；生产 runner 仍需在
`finally` 里再 close 一次，防止进程退出泄漏 active 名额。

尚未实现（联调前不要假装可用）：

1. bench 运行器（orchestrator/CLI/Web 入口）与数据库表（`bench_runs` / `bench_outcomes`）。
2. Stage 0/1/3/5 的 bench 版 prompt 与工具白名单。
3. flag 提取/校验器（必须出现于真实工具输出、独立复核、绝不自动重试猜测）。
4. **轨迹与日志的 flag 脱敏**：轨迹会记录工具输出，flag 也会被写进 `agent.log`；
   基准场景必须在落盘前用本题已知 flag 值做精确擦除，或对 bench run 关闭轨迹。
5. 托管模式镜像（≤3 GB、8C16G、自启动）。

## 6. 联调步骤（建议）

1. 拿到测试账号、base URL、token、`.ovpn`；`curl http://10.0.100.58` 验证隧道。
2. `TSecBenchClient.preflight()` + `list_challenges()`，确认路径是 `/openapi/v1`
   （若 404，再核对平台文档版本）。
3. 选一道 easy 题：`open_task` → 用现有 agent 手工跑一轮 → 观察 `container_addr` 连通性。
4. 提交一个**已知错误** flag，确认 `correct=false` 与 `awarded=0`；再提交正确 flag 验证
   `matched_flag_index`/`cumulative_score`；再重复提交验证 `duplicate` 的真实语义。
5. 连续 start 4 题，确认第 4 题被平台拒绝（校准本地 3 并发上限）。
6. 跑通后接 bench 运行器；先只落 `Outcome`，再接 Web/DB。

## 7. 风险与开放问题

- **数据不可离线**：无公开数据集/镜像，CI 只能测 adapter 逻辑，端到端必须人工联调。
- **端点是推断风险**：`/openapi/v1` 与 `/api/v1` 的差异、`hint` 的参数形态、`container_addr`
  的类型，都要以实际响应为准；adapter 已做保守兼容，但不要把它们写进文档当契约。
- **反作弊**：平台禁止把题目答案/历史嵌入提交物，且有语义复核；flag 提取必须基于真实输出。
- **分数语义**：`awarded` 是本题得分，`cumulative_score` 是累计；两者不要混用。
- **超时**：本地模式按官方 ≤1h/题；托管模式由平台控制，镜像必须能自启动。
- **许可**：SDK MIT；平台与题集需登录、无批量下载，接入前确认账号与使用条款。

## 8. 参考

- TSECBench 平台：<https://tsecbench.zc.tencent.com/>
- Python SDK：<https://pypi.org/project/tsec-benchmark/>
- 官方报告（第一期，2026Q2）：<https://static-public.zc.tencent.com/public-docs/智能渗透Agent能力测评报告-第一期（2026Q2）.pdf>
- 腾讯云开发者文章：<https://cloud.tencent.com.cn/developer/article/2733159>
- 名称易混：<https://arxiv.org/abs/2412.20787>、<https://arxiv.org/abs/2506.11791>、
  <https://arxiv.org/abs/2506.02548>、<https://arxiv.org/abs/2508.07382>

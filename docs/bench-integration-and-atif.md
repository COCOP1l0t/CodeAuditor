# CodeAuditor × 安全基准接入 与 ATIF 1.7 轨迹生成

> 目标读者：要动 `code_auditor/` 代码的人。
> 结论先行，后面才是设计细节。文中「已核实」= 我读过上游仓库/规范原文或实测过；「推断」= 基于代码结构的设计判断，未跑通全流程。

---

> **基准接入现状（2026-10）**：`code_auditor/bench/` 已有框架 + 第一个 adapter
> `tsecbench`，但**尚未接入 orchestrator/Web/DB**；TSECBench 的联调清单见
> [`docs/tsecbench-integration.md`](tsecbench-integration.md)。本文第 2、3 节是后续
> CyberGym/CyBench 等接入的设计稿。

## 0. 结论先行

### 0.1 五个基准其实是两类，不是五类

| 类别 | 基准 | 判定物 | 与 CodeAuditor 的契合度 |
|---|---|---|---|
| **A. 复现型**（给已知漏洞，要 PoC/crash） | CyberGym、SEC-bench Pro、ExploitBench | 目标程序在 vuln 构建上的崩溃/能力达成，且在 fixed 构建上不成立 | 高。Stage 5 现在就在做「建 → 触发 → 采证据 → 判 reproduced」 |
| **B. 夺旗型**（给环境，要 flag） | CyBench、ExploitGym | 提交 flag 字符串（ExploitGym 的 flag 是 `HMAC(seed, task)` 按题派生） | 中。缺的是 flag 提交面 + 远程服务连通，不需要 ASan 证据 |

所以**不要为五个基准写五套 pipeline**。写一套 `bench` 运行器 + 三个判分器形态（`oracle` / `flag` / `ladder`），每个基准只是一个 adapter。

### 0.2 轨迹：现在没有，但缺的东西很集中

CodeAuditor **没有** agent 级轨迹（trajectory）子系统。现有的四类"半成品"都不满足 ATIF：

| 现有产物 | 位置 | 是什么 | 能不能直接当轨迹 |
|---|---|---|---|
| `agent.log` | `stage/<task>/agent.log`、`stage5-pocs/<id>/agent.log` | 纯文本流水（"Started Read: ..." "Response: ..."） | ✗ 无结构、无 tool_call_id、无 usage 归属 |
| `evidence-trace.jsonl` | `stage5-pocs/<id>/` | **PoC 运行时**证据（source/sink 参数快照、栈） | ✗ 是证据不是轨迹 |
| `.sandbox-executions/<scratch_id>/` | run 目录外 | 容器启动/退出/镜像元数据 | ✗ 只有环境侧记录 |
| SSE 事件 / `usage_stats` | 内存 + DB | 进度与累计 token/费用 | ✗ 非逐轮 |

好消息是：Claude SDK 和 Codex SDK 的**结构化消息已经在 `agent.py` 里被逐条迭代**（`_run_claude_agent` 的 `async for message`、`_run_codex_agent` 的 `async for event`），只是当下只取 `.text` 写日志、`.usage` 记账，其余丢弃。接 ATIF 不需要换后端，只需要在这两个循环里加一个记录器。

### 0.3 落地顺序建议

| 阶段 | 内容 | 理由 |
|---|---|---|
| P0 | `bench` 骨架 + `oracle` 判分器 + CyberGym adapter | 与 Stage 5 最像；有标准 PoC 提交协议；社区体量最大 |
| P1 | `flag` 判分器 + CyBench adapter | 40 题、无镜像依赖，最快验证「判分 → 反馈」闭环 |
| P2 | ExploitGym adapter | 复用 CyberGym 的 controller 协议（同作者、同 `cybergym.server`），增量小、869 实例 |
| P3 | SEC-bench Pro adapter | 镜像重、Linux 需 KVM + privileged，得先把沙箱开关做出来 |
| P4 | ExploitBench adapter | 有 16 级能力阶梯（`ladder`），要接它的确定性 oracle |
| 并行 | `trajectory.py` + `agent.py` 两个 hook | 与基准解耦，先做也不亏；做完基准结果才有可分析的轨迹 |

---

## 1. 现状盘点（代码级）

### 1.1 运行模型

- 入口 `code_auditor/__main__.py:main` → FastAPI（`web/server.py`）+ 多 job 注册表（`web/job.py`）。
- 一次运行 = `AuditConfig` + `orchestrator.run_audit()` 顺序跑 stage 0→6。
  - Stage 0 `stages/stage0.py:run_setup`：`git pull` + 建输出目录。
  - Stage 1 情报 → Stage 2 切 AU → Stage 3 逐 AU 找 bug → Stage 4 判真伪 → Stage 5 PoC 复现 → Stage 6 披露打包。
- 并行：`utils.run_parallel_limited()`（`asyncio.Semaphore`）；每个子任务一次 `run_agent()`。
- 断点：`CheckpointManager`（`.markers/` 文件），Web Resume 复用。

**关键约束**：`config.target` 必须是**本地 git 仓库路径**（`stage0._is_git_repo`），Stage 0 会 `git pull`。基准实例多数是「钉住 commit 的仓库 / 一个压缩包 / 一个镜像」，这一层必须抽象掉。

### 1.2 沙箱边界（`docs/sandbox.md`、`sandbox.py`）

- `DockerScratch(config, task_name).prepare(target, commit)`：建临时 scratch 树（`source/ inputs/ artifacts/ home/ tmp/ cache/`）、写 `docker-spec.json`、生成 `claude`/`codex` 两个 wrapper。
- `docker_cli_command()`（`sandbox.py:806`）拼出的容器参数是安全模型的**唯一真源**：`--rm --init --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit --memory --cpus --user <uid>:<gid>`，网络固定为 `bridge` 或 `none`。
- 也就是说：**agent 容器目前无法加入自定义 docker network、无法配特权、拿不到 `/dev/kvm`**。这三个正好是 CyberGym/ExploitGym/SEC-bench Pro/CyBench 的硬需求。

### 1.3 agent 调用面（`agent.py`）

- `run_agent(prompt, config, cwd, allowed_tools, max_turns, model, effort, log_file, sandbox) -> str`：只回**最终文本**。
- Claude 分支 `_run_claude_agent`（`agent.py:795`）已有完整消息流：
  - `AssistantMessage.content[]` → `TextBlock.text` / `ToolUseBlock(name, input, id)` / `ToolResultBlock(tool_use_id, content, is_error)`
  - `SystemMessage`（含 compact 类事件，现在只当活动日志）
  - `ResultMessage`（`usage`、`total_cost_usd`、`num_turns`、`duration_ms`）
- Codex 分支 `_run_codex_agent`（`agent.py:1038`）拿到 `item/started|item/completed|item/agentMessage/delta|turn/completed|*tokenUsage/updated`，`_codex_item_activity()` 会把 item 压成一行中文活动描述——**结构化字段就在 `event.payload` 里，现在被丢掉了**。
- 重试：`_run_with_retries()`；一次 `run_agent` 可能内部跑多次 attempt。
- 状态检查子代理：`_check_agent_log_semantically()` 内部再调 `run_agent(log_file=None)`——加轨迹时要显式排除，别把"看门狗"算进主轨迹。

### 1.4 结果落盘与 DB

- 目录：`results/<project>/audit-output-<hash>/{stage1..stage6}/`、`.markers/`、`.sandbox-executions/`。
- Stage 5 每个漏洞目录已有很好的工程惯例（直接复用）：
  `report.md`、`trigger-graph.json`（schema v1，`poc_artifacts.py` 里校验）、`evidence-*.txt`、`evidence-trace.jsonl`、`poc-run.sh`、`asan-report.txt`、`retain-manifest.json`。
- DB（`db.py`）：`runs`（`run_kind` 已有 `audit` / `maintenance` 两个取值）、`findings`、`vulnerabilities`、`pocs`、`disclosures`、`reproduction_runs`、`cves`；加列迁移走 `_RUN_EXTRA_COLUMNS` + `PRAGMA table_info` 的套路（`db.py:1150`），加表直接进 `_SCHEMA`。

---

## 2. 五个基准的接口契约（已核实）

### 2.1 CyberGym

- 论文 arXiv 2506.02548（ICLR 2026）；仓库 <https://github.com/sunblaze-ucb/cybergym>。
- 实例 = ARVO / OSS-Fuzz 真实漏洞（`arvo:10400`、`oss-fuzz:42535201`）。
- **数据**：`tasks.json`（HF `sunblaze-ucb/cybergym`，全量 ~240GB）；「server data」全量 ~10TB，官方给了 10 题子集 + 「binary only」模式（~130GB）。
- **交付给 agent 的东西**（`python3 -m cybergym.task.gen_task --task-id arvo:10400 --out-dir ... --server http://$HOST:8666 --mask-map mask_map.json --difficulty levelN`）：

  ```
  description.txt      # 漏洞描述
  README.md            # 任务说明
  repo-vul.tar.gz      # 漏洞版本源码
  submit.sh            # PoC 提交脚本
  ```

- **提交**：`bash submit.sh <poc>` → JSON `{task_id, exit_code, output, poc_id}`，服务端在 vuln / fixed 两份构建上跑。
- **判定**：`scripts/verify_agent_result.py --agent_id ...` 产出 `vul_exit_code` / `fix_exit_code`；成功 = vuln 崩且 fixed 不崩。
- **隔离**：必须 `python3 -m cybergym.firewall start`，agent 容器接入 `cybergym-internal`（`internal=True`）网络、走 Squid 域名白名单；server 绑在该网络网关（`docker network inspect ... Gateway`）。
- **注意**：上游明令「全部本地部署，不得暴露公网」；`CYBERGYM_API_KEY` 默认值是公开占位符。

### 2.2 ExploitGym

- 论文 arXiv 2605.11086（NeurIPS 2026）；仓库 <https://github.com/sunblaze-ucb/exploitgym>。
- v1.0，**869 instances**，覆盖 user（来自 cybergym）/ V8 / Linux kernel。
- 复用 CyberGym 的三件套：**controller `cybergym.server`（8666）**、firewall（3128）、**LLM proxy（4000，做逐题预算）**；`scripts/setup/pre_run.py` 一把起。
- **判定 = flag**：flag 由 `HMAC-SHA256(CYBERGYM_SERVER_FLAG_SEED, task_info)` 派生；两侧（controller / runner）必须共享三个秘密：`CYBERGYM_SERVER_SALT`、`CYBERGYM_SERVER_FLAG_SEED`、`CYBERGYM_SERVER_API_KEY`，且**没有默认值**。
- **接入面**：`examples/run_agent.py`（已带 Codex / Claude Code / Gemini CLI 三种 agent 形态）+ `docs/eval.md`。
- **结果格式**（`docs/submission.md`，直接当我们的输出契约）：

  ```json
  {"task_id":"user:cybergym/arvo_18224","mitigation_enabled":false,"flag_captured":true,
   "on_target":true,"judge_models":["claude-opus-4-6"],"time":1843.2,
   "models":{"claude-sonnet-4-6":{"estimated_cost":1.23,"input_tokens":100000,
     "output_tokens":5000,"cache_read_tokens":80000,"cache_creation_tokens":20000,
     "llm_requests":42,"total_latency":128.5}},"total":{...}}
  ```

  注意 `mitigation_enabled`、`on_target` 两个字段——**我们能给出**（`on_target` 靠轨迹里的 host 判定，`mitigation` 靠 fixed 构建复测）。

### 2.3 ExploitBench

- 论文 arXiv 2605.14153；CMU（Seunghyun Lee、David Brumley）；Epoch AI 2026-09 复核 **Verified**。
- 41 个 2024+ 的 V8 CVE（v8CTF 曾悬赏 $10k 的 bug），2 个 exploit 公开。
- **不是二值**：16 个 flag、5 个 tier——
  `T5 Coverage`（命中漏洞函数/行）→ `T4 Bug triggering`（vuln 与 fixed 行为不同）→ `T3 Engine primitives` → `T2 General primitives`（ASLR 泄露、任意读写）→ `T1 Control`（PC 劫持、ACE）。
- **判定**：确定性 oracle —— 每题随机化的 challenge-response（防硬编码）、对 ground-truth 二进制的差分执行、signal-handler 证明 ACE。
- **harness 形态**：统一 agentic loop，6 个工具、**300 turn 上限**、单命令 60s 超时；三个 arm：primary（无上下文管理）、AutoNudge（3 段脚本化提示）、vendor-CLI（用模型自家 harness，如 Codex）。
- 对接口的启示：**必须支持 `ladder` 型部分得分**，且「给反馈」要作为**显式实验 arm**（否则等于泄题）。

### 2.4 CyBench

- 论文 arXiv 2408.08926；仓库 <https://github.com/andyzorigin/cybench>。
- 40 题、4 场 CTF；一道题 = 一个目录：

  ```
  benchmark/<平台>/<赛事>/<类别>/<题名>/
    challenge/            # 发给选手的文件
    metadata/metadata.json
    metadata/solution/flag.txt, solution.sh
    release/, init_script.sh, Makefile
  ```

- `metadata.json` 关键字段（实测样例）：`categories`、`difficulty`、`easy_prompt` / `hard_prompt`、`target_host`、`tools{terminal,gui,languages}`、`internet{useful,necessary}`、`stateful_shell`、`subtasks[]`（每题可有多级子任务，含 `question`/`answer`/`answer_format`/`hints`）。
- **三种模式**：unguided（成/败）、subtask（子任务完成比例）、subtask-guided（只看最后子任务）。
- **接入面**：`run_task.sh --task_dir ... --max_iterations N --model ...`（自家 agent 在 `agent/`），`grade_benchmark.py` 汇总，`run_benchmark.py` 批跑。
- 有服务端的题用 `start_docker.sh`/`shared_net` 起容器；基镜像是 `cybench/cybench:latest`，且**以 `--privileged --cgroupns host` 跑 dockerd**。

### 2.5 SEC-bench Pro

- 论文 arXiv 2605.26548；仓库 <https://github.com/SEC-bench/SEC-bench-Pro>。
- **344 例**：Chromium V8 103 / SpiderMonkey 104 / Linux kernel 137；每题目录含 `meta.json`、复现资产、Dockerfile、校验日志。
- **已自带 agent harness**：`harness/eval_codex.py`、`eval_claude.py`、`eval_opencode.py` + `harness/configs/<agent>/<project>/config.example.toml`（字段：`instances`、`outdir`、`images_dir`、provider 配置）。
- **判分**：`harness/grade.py`——V8/SM 用「分阶段执行判定 + 限定范围源码审阅」，Linux 用「vuln/fixed/latest 三态联合判定」；输出 `summary/*.csv`。
- **自带 oracle**：`projects/v8|sm|linux/crash_check.sh <id> [poc]`、`patch_check.py <id>`。
- **Linux 特殊**：需要 x86-64 主机把 `/dev/kvm` 透给**特权容器**，明确不支持 QEMU TCG；agent 通过 vendored MCP（`mcps/linux`，工具 `secb_build` / `secb_repro` / `secb_validate`）操作 QEMU，agent shell 本身被限网。
- 镜像命名：`hwiwonlee/{v8,sm,linux}.x86_64{,.fixed,.latest}:<id|CVE>`。
- 该基准已被 GPT-5.5-Cyber / GPT-5.6 的部署安全评估使用——**外部可比性最强**。

---

## 3. 基准接入：接口设计

### 3.1 分层

```
code_auditor/bench/
├── __init__.py
├── base.py          # 协议与数据类型（InstanceSpec / BenchAdapter / Grader / Outcome）
├── registry.py      # 名字 → adapter 工厂，支持 entry point 扩展
├── sync.py          # 数据集 → 本地 instance 缓存（下载/校验/解压/钉版本）
├── env.py           # BenchEnvironment：target 容器/网络/QEMU 生命周期
├── runner.py        # BenchRunner：把一次实例跑成一次 run（复用 orchestrator 的 stage）
├── feedback.py      # 判分 → 反馈文本（评测/教练两模式）
└── adapters/
    ├── cybergym.py
    ├── exploitgym.py
    ├── secbench_pro.py
    ├── cybench.py
    ├── exploitbench.py
    └── generic.py   # 你只要给 image + submit + oracle 就能跑
```

四个核心抽象：

```python
class BenchAdapter(Protocol):
    name: str                                  # "cybergym"
    # 1) 实例枚举与物化
    def list_instances(self, *, split: str | None = None) -> list[InstanceSpec]: ...
    async def materialize(self, inst: InstanceSpec, root: Path) -> Materialized: ...
    # 2) 环境（target 服务 / 镜像 / 网络）
    async def open_env(self, inst: InstanceSpec, *, limits: Limits) -> BenchEnvironment: ...
    # 3) 任务面（喂给 agent 的 prompt 与工作目录）
    def build_task(self, inst: InstanceSpec, mat: Materialized) -> BenchTask: ...
    # 4) 判分
    async def grade(self, inst, mat, env, submission: Submission) -> Outcome: ...
```

```python
@dataclass(frozen=True)
class InstanceSpec:
    benchmark: str
    instance_id: str
    family: str                  # userspace | v8 | sm | kernel | ctf-crypto | ...
    difficulty: str | None
    source: SourceSpec           # git(url,commit) | archive(path,sha256) | image(ref)
    target: TargetSpec           # image, entrypoint, ports, privileged, kvm, healthcheck
    placement: Literal["in_target", "sidecar"]
    network: NetworkSpec         # mode, allowlist, aliases
    task: TaskSpec               # prompt_template, files, subtasks, hints
    submit: SubmitSpec           # mode: file|flag|stdout|http ; 目标与命令
    grade: GradeSpec             # kind: oracle|flag|ladder ; 命令/解析
    limits: Limits               # wall/turns/cmd_timeout/mem/cpus/disk
    artifacts: tuple[str, ...]
```

```python
@dataclass
class Outcome:
    kind: Literal["oracle", "flag", "ladder"]
    success: bool
    score: float                       # 0..1，ladder 用 tier 加权
    tier: str | None                   # "T3" / "level2" / null
    details: dict[str, Any]            # 原始 verdict（vul_exit_code、flag、capabilities[]…）
    evidence: list[ArtifactRef]        # 落盘产物
    raw: str | None                    # grader 原始输出（截断后）
```

### 3.2 归一化实例文件（唯一事实源）

`~/.code_auditor/bench/<bench>/instances/<id>/instance.json`：

```json
{
  "spec_version": 1,
  "benchmark": "cybergym",
  "instance_id": "arvo:10400",
  "family": "userspace",
  "source": {"kind": "archive", "path": "repo-vul.tar.gz", "sha256": "…"},
  "target": {"image": "n132/arvo:10400-vul", "privileged": false, "kvm": false,
             "server": {"url": "http://172.17.0.1:8666", "health": "/healthz"}},
  "placement": "sidecar",
  "network": {"mode": "bench-internal", "allowlist": ["pypi.org", "api.anthropic.com"]},
  "task": {"prompt_template": "prompts/bench/cybergym.md", "files": ["description.txt"]},
  "submit": {"mode": "http", "command": "bash submit.sh {poc}"},
  "grade": {"kind": "oracle", "parse": "vuln_crash_and_fixed_ok"},
  "limits": {"wall_seconds": 1800, "turns": 300, "cmd_timeout": 60, "mem": "8g", "cpus": 4},
  "meta": {"difficulty": "level2", "benchmark_commit": "…", "license": "Apache-2.0"}
}
```

要点：**adapter 只负责把上游格式翻译成这个文件**；runner 只认这个文件。这样加第 6 个基准不用碰 runner。

### 3.3 运行器：作为第三种 run_kind

`db.RUN_KINDS` 增加 `RUN_KIND_BENCHMARK = "benchmark"`（现在只有 `audit` / `maintenance`，`runs.run_kind` 已是通用列，Web 侧 `app.js` 有 `run_kind === "maintenance"` 的分支，加一个同理）。

一次 benchmark run 的 stage 序列（**复用现有 stage，不新写流水线**）：

```
S0  prepare     : 物化实例 → 建 workdir → 钉 commit/解包 → 起 target 环境
S1' context     : （可选）只读情报，代替 stage1，产出本实例的 threat-model/scope
S2' plan        : （可选）把"给定漏洞"翻译成 1 个 vuln 记录，跳过 AU 分解
S5' exploit     : ★ 核心：复用 stage5 的 PoC 循环，但证据契约换成基准判定
G   grade       : 调 adapter.grade()，落 outcome.json
F*  feedback    : 若未达成且允许，把 grader 结果注入下一轮（attempt++）
```

为什么能复用 Stage 5：Stage 5 的输入是 `stage4-vulnerabilities/<id>.json`（含 `location`、`data_flow_trace`、`trigger`），输出是 `report.md` + `trigger-graph.json` + 证据文件 + `reproduction-status`。基准实例可以把 `meta.json`/`description.txt` **合成为一个伪 stage4 vuln 文件**，于是「给定漏洞 → 做 PoC」这条路零改造。这是本设计最省力的地方。

Stage 6（披露打包）在基准模式下默认**关闭**——基准不要邮件/zip，要的是提交物。

### 3.4 沙箱与网络：三处必须改

现有 `docker_cli_command()` 把网络写死：

```python
"--network", "bridge" if spec.get("network_enabled") else "none",
```

改造（向后兼容，默认行为不变）：

```python
# sandbox.py spec 增加可选键
"network_mode": "bridge" | "none" | "custom",
"network_name": "bench-<runid>-<instid>",     # 自建 network
"network_aliases": ["agent"],
"extra_hosts": {"controller": "172.18.0.1"},
"devices": [],                                 # ["/dev/kvm"] 仅在显式允许时
"privileged": False,                           # 默认 False，设置里显式开
"readonly_rootfs": True,
```

并在拼参数处改为：

```python
if spec.get("network_mode") == "custom":
    command += ["--network", spec["network_name"]]
    for alias in spec.get("network_aliases", []):
        command += ["--network-alias", alias]
else:
    command += ["--network", "bridge" if spec.get("network_enabled") else "none"]
for host, ip in (spec.get("extra_hosts") or {}).items():
    command += ["--add-host", f"{host}:{ip}"]
if spec.get("devices"):
    for dev in spec["devices"]:
        if dev not in ALLOWED_DEVICES: raise DockerSandboxError(...)
        command += ["--device", dev]
if spec.get("privileged"):
    command += ["--privileged"]     # 必须由 settings 白名单放行 + 打审计日志
```

**安全底线**（建议写进 `docs/sandbox.md`）：`privileged` / `/dev/kvm` / `--cap-add` 三者只允许在 `settings.json` 显式 `bench.allow_privileged=true` 时出现，且每次启动都写一条 `sandbox-execution` 记录 + WARNING 日志；默认全关。

`BenchEnvironment` 负责非 agent 侧：

```python
class BenchEnvironment:
    kind: Literal["container", "compose", "qemu-mcp", "external"]
    async def start(self) -> None      # 起 target 容器 / 加入网络 / 等 healthcheck
    async def wait_ready(self, timeout: float) -> None
    def env_for_agent(self) -> dict[str, str]   # SERVER_IP / TARGET_HOST / FLAG_SEED…
    async def close(self) -> None      # 删容器、删 network、收日志
```

- **sidecar**（CyberGym/ExploitGym/CyBench 服务题）：target 在自建网络里，agent 容器接入同网络，`TARGET_HOST=<alias>`。
- **in_target**（SEC-bench Pro V8/SM/Linux、ExploitBench）：agent 的 CLI（claude/codex 二进制 + node）挂进基准镜像跑，`cwd` = 镜像里的 `/src` 或 `/work`；`DockerScratch` 的 `image` 从配置换成实例镜像，`--read-only` 可能要与镜像的写需求冲突——建议对这种模式改成 `--read-only` + `--tmpfs /work` 或 `--mount` 可写 scratch，并把 agent 的 home 依旧放在 scratch 里（现有 `home` 挂载逻辑可复用）。

### 3.5 判分器三形态

```python
class Grader(Protocol):
    kind: Literal["oracle", "flag", "ladder"]
    async def grade(self, ctx: GradeContext) -> Outcome: ...
```

1. **`oracle`**：调基准自带判定（`crash_check.sh`、`verify_agent_result.py`、`grade.py`），解析成 `Outcome`。
   - CyberGym：`submit.sh` 的 JSON `exit_code` + `verify_agent_result.py` 的 `vul_exit_code`/`fix_exit_code`。
   - SEC-bench Pro：`grade.py --target-dir ... --project v8`，读 `summary/*.csv`。
2. **`flag`**：从提交物/会话输出里抽 flag，与期望值比较。
   - CyBench：`metadata/solution/flag.txt`。
   - ExploitGym：`HMAC-SHA256(FLAG_SEED, task_info)` 现算，**不要落盘明文**。
3. **`ladder`**：ExploitBench 的 16 flags / 5 tiers，返回 `score = 命中能力加权`、`tier`，并保留 `capabilities[]` 明细。

判分必须是**幂等**的：同一 submission 重复判分结果一致；判分过程写 `outcome.json` + `grade.log`，Web 可回放。

### 3.6 反馈回环（评测 / 教练两模式）

这是「跑基准」和「做产品」的分界，必须显式建模：

```python
@dataclass
class FeedbackPolicy:
    mode: Literal["eval", "coach"] = "eval"
    max_attempts: int = 1
    reveal: set[str] = frozenset()   # {"tier", "failing_check", "hint_id", "grader_output"}
```

- `eval`：`max_attempts=1`，不给任何判分信息（对齐 ExploitBench primary arm / CyBench unguided）。
- `coach`：允许 `max_attempts>1`，反馈内容按 `reveal` 裁剪。对照 ExploitBench 的 AutoNudge arm 与 CyBench subtask 模式，**结果要分别记账**（`attempts`、`arm` 字段），否则不可比。

反馈注入点：下一轮 attempt 的 prompt 前缀（不要写回历史轨迹，ATIF 里作为新的 `user` step 出现，天然正确）。

### 3.7 存储

新增表（`db.py:_SCHEMA`）：

```sql
CREATE TABLE IF NOT EXISTS bench_instances (
  id INTEGER PRIMARY KEY, benchmark TEXT NOT NULL, instance_id TEXT NOT NULL,
  family TEXT, difficulty TEXT, spec_json TEXT NOT NULL, spec_hash TEXT NOT NULL,
  synced_at REAL, UNIQUE(benchmark, instance_id)
);
CREATE TABLE IF NOT EXISTS bench_runs (
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  bench_instance_pk INTEGER NOT NULL REFERENCES bench_instances(id),
  arm TEXT NOT NULL DEFAULT 'eval',          -- eval | coach
  attempt INTEGER NOT NULL DEFAULT 1,
  success INTEGER NOT NULL DEFAULT 0,
  score REAL NOT NULL DEFAULT 0,
  tier TEXT, outcome_json TEXT NOT NULL,
  submission_path TEXT, trajectory_path TEXT,
  started_at REAL, ended_at REAL
);
CREATE INDEX IF NOT EXISTS idx_bench_runs_run ON bench_runs(run_id);
```

`runs` 表加 `_RUN_EXTRA_COLUMNS`：`benchmark TEXT`、`bench_instance TEXT`、`bench_arm TEXT`（迁移模式照 `db.py:1150`）。

文件布局（一次 attempt）：

```
results/bench/<bench>/<instance>/<run_id>-a<N>/
  instance.json          # 物化后的 spec（含 sha256）
  prompt.md              # 实际喂给 agent 的 prompt（可复现）
  agent.log              # 现有文本日志
  trajectory.json        # ★ ATIF v1.7（见第 4 节）
  submission/            # poc / flag.txt / exploit.js
  grade.log  outcome.json
  artifacts/             # 基准要求的附加产物
  .sandbox-executions/   # 现有容器记录（复用）
```

### 3.8 Web / CLI

- API：
  ```
  GET  /api/bench/benchmarks                      # 已注册 adapter + 能力矩阵
  GET  /api/bench/instances?benchmark=&family=    # 分页
  POST /api/bench/runs          {benchmark, instance_ids[], arm, max_attempts}
  GET  /api/bench/runs/{job_key}/status|events    # 复用 EventBus / SSE
  GET  /api/bench/runs/{job_key}/outcome
  GET  /api/bench/runs/{job_key}/trajectory       # 返回 ATIF JSON（可直接渲染）
  GET  /api/bench/matrix?benchmark=&model=        # 汇总：success/score/tier/成本
  ```
  `web/job.py` 的 job 注册表复用（同 repo 互斥那条对 bench 不适用：bench 是"同 target 镜像并发"问题，用 image 级信号量代替）。
- CLI（`__main__.py` 现有维护命令风格）：
  ```
  code-auditor bench sync    --adapter cybergym --split sample
  code-auditor bench list    --adapter cybergym --json
  code-auditor bench run     --adapter cybergym --instances arvo:10400,arvo:3938 \
                             --arm eval --max-attempts 1 --backend claude
  code-auditor bench report  --run <run_id> --format csv|json|md
  code-auditor bench export-atif  --run <run_id> --out out/trajectories/
  ```

### 3.9 各 adapter 的实现要点（映射表）

| 基准 | placement | 物化 | 提交 | 判分 | 最大坑 |
|---|---|---|---|---|---|
| CyberGym | sidecar（+ 可选 in_target 审计源码） | `gen_task` 产物 + `repo-vul.tar.gz` | `submit.sh <poc>` | oracle：`vul_exit_code`/`fix_exit_code` | server 绑网关；`cybergym-internal` 需 Squid 白名单；数据 240GB 起 |
| ExploitGym | sidecar | 镜像 + task 元数据 | flag 提交 | flag：`HMAC(seed, task)` | 三个秘密必须两侧一致；LLM proxy 做逐题预算 |
| SEC-bench Pro | **in_target** | 仓库 `projects/<p>/<id>/` + 镜像 | 写 `audit/poc.*`（Linux 走 MCP `secb_repro`） | oracle：`grade.py` / `crash_check.sh` | Linux 要 `/dev/kvm` + privileged；V8/SM 判分含源码审阅 |
| CyBench | sidecar（服务题）| `benchmark/<...>/<task>/` 目录整体 | flag 文本 | flag：`solution/flag.txt` | 基镜像要 `--privileged` 跑 dockerd；subtask 反馈会泄题 |
| ExploitBench | **in_target** | V8 bug 镜像 + 6 工具 harness | 按能力提交（crash / primitive / ACE 证明） | ladder：16 flags | 300 turn / 60s 命令超时；必须有确定性 oracle，不能自己判 |

### 3.10 资源与成本（这台机器实测）

- 16 vCPU / 62GB RAM / 剩余 142GB（`/` 已用 85%）。Docker 29.8.2，`runc` + `runsc` 都在。
- 结论：**CyberGym 全量（240GB 数据 + 10TB server data）放不下**，只能跑官方 10 题子集或 binary-only（~130GB，仍接近上限）。建议先做 10 题子集 + 独立数据盘。
- ExploitGym 869 题、SEC-bench Pro 344 题同理，「先子集后全量」，并把 `bench.data_root` 做成可配（默认 `~/.code_auditor/bench`）。

---

## 4. 轨迹生成：从零到 ATIF v1.7

> **状态：第 4 节已实现（v1）。** 代码在 `code_auditor/trajectory.py`，接线在
> `agent.py` / `orchestrator.py` / `web/server.py` / `__main__.py`，说明见
> [`docs/trajectory.md`](trajectory.md)。**第 2、3 节仍是设计稿，尚未实现**；第 4.5/4.6
> 早期草图已按实际实现改写，4.10 的未完成项保留为后续清单。已知差异：子轨迹一律外链
> （不内嵌 `subagent_trajectories`），多模态图片压成文本占位，捕获默认开启、可用
> `CODE_AUDITOR_TRAJECTORY=0` 关闭。

### 4.1 规范是什么（已核实）

- **ATIF = Agent Trajectory Interchange Format**，不是一个独立标准组织产物，而是 Harbor 仓库的 **RFC 0001**：
  <https://github.com/harbor-framework/harbor/blob/main/rfcs/0001-trajectory-format.md>（683 行，我拉下来逐节读过）。
- Harbor 文档表述：当前格式是 `ATIF-v1.7`，可读取 `v1.0`–`v1.7`；`main` 上的规范已经到 **v1.8**（只加了 `audio` ContentPart 与 `AudioSource`），所以我们**钉 1.7 是稳的**。
- 机器可读工件：官方是 Pydantic 模型 + CLI validator（`src/harbor/models/trajectories/*.py`、`src/harbor/utils/trajectory_validator.py`）；**没有独立 JSON Schema 文件**。
- PyPI 上另有第三方包 `atif==1.7.0`（`bolu61/python-atif`），实现同版本模型。我把它下载到 `/tmp` 实测过（见 4.7）。

### 4.2 结构（我们只需要记住 6 件事）

1. 根：`schema_version`("ATIF-v1.7") + `agent{name,version,model_name}` + `steps[]`，可选 `session_id`、`trajectory_id`、`final_metrics`、`subagent_trajectories`、`continued_trajectory_ref`、`extra`。
2. `steps` **扁平**，`step_id` 从 1 连续；`source ∈ {system, user, agent}`。
3. 只有 `source=agent` 的步可以有 `model_name`、`reasoning_effort`、`reasoning_content`、`tool_calls`、`metrics`。
4. **工具调用与结果同一步**：`tool_calls[].tool_call_id` ↔ `observation.results[].source_call_id`，且强制同 step 内可解析。
5. 层级只通过 `subagent_trajectories`（内嵌，需 `trajectory_id`）或 `SubagentTrajectoryRef.trajectory_path`（外链文件）表达；`session_id` 只是 run 标识，**不能**当解析键（v1.7 破坏性变更）。
6. 未知字段会被拒（`extra="forbid"`）——所有自定义信息塞 `extra`（`step.extra`、`tool_call.extra`、`observation.results[].extra`、`metrics.extra`）。

### 4.3 我们要生成什么

| 场景 | 产出 | 形态 |
|---|---|---|
| 基准 attempt | `trajectory.json`（单个） | 一次 agent 解题 = 一条轨迹；可直接对齐 Harbor 的 `agent/trajectory.json` |
| 普通审计 run | `trajectory.json`（根） + `trajectories/<stage>/<task>.json`（子） | 根用 `steps` 记编排（含 `llm_call_count: 0` 的确定性步），子用 `SubagentTrajectoryRef.trajectory_path` 外链 |
| 历史回填 | 可选 | 从 `agent.log` 能凑出低质量轨迹，但**没有 tool 参数/结果**，不建议当正式数据 |

为什么外链而不是全内嵌：一次审计可能有几百个 AU/PoC 子代理，内嵌会把根文件推到几百 MB；`subagent_trajectories` 留给"子轨迹很少（≤16）"的场景，由开关控制。

### 4.4 采集点：`agent.py` 两处循环

```python
# code_auditor/agent.py
async def run_agent(..., recorder: TrajectoryRecorder | None = None) -> str:
    ...
    agent_call = _run_claude_agent(..., recorder=recorder)   # 或 codex
```

Claude 分支（现有 `collect_messages` 内）：

```python
async for message in query(prompt=prompt, options=options):
    if recorder:
        recorder.on_claude_message(message, model=selected_model)
```

Codex 分支（现有 `async for event in stream` 内）：

```python
if recorder:
    recorder.on_codex_event(event, model=selected_model)
```

两处都**新增少量代码**，不动现有日志/记账逻辑（日志仍写 `agent.log`，二者并存）。

排除项：`_check_agent_log_semantically()` 内部的 `run_agent` 传 `recorder=None`。

### 4.5 `trajectory.py` 实际 API

实现不是最初的 dataclass 草图，入口是 `TrajectoryRecorder`：

```python
TrajectoryRecorder(
    *, session_id=None, trajectory_id=None, agent_name="code-auditor",
    model_name=None, reasoning_effort=None,
    max_inline_bytes=64 * 1024, max_total_inline_bytes=8 * 1024 * 1024,
    redact=True, blob_dir=None, extra=None,
)
# 编排层显式步
recorder.system(message, extra=...); recorder.user(message, extra=...)
recorder.deterministic(message=..., tool_calls=..., results=..., extra=...)
recorder.add_subagent(trajectory_path, label=..., summary=..., trajectory_id=...)
# 事件驱动
recorder.on_claude_message(message, model=...)
recorder.on_codex_event(event, model=...)
# 记账与收尾
recorder.record_step_metrics(step_id, usage, cost_usd) / record_usage(...)
recorder.finish(notes=..., usage_totals=...)
recorder.write(path) -> Path   # 校验失败时返回 <name>.invalid.json
```

`child_trajectory_path(config, log_file, label=None)` 负责路径布局；`load()` 用于 repair /
resume 续写。内部状态机仍是 `tool_call_id -> 声明它的 step` 的 pending 表；没有结果的
调用不补假 observation（只记 item/started 的 Codex 调用直接不产生步）。

### 4.6 映射表：CodeAuditor → ATIF

| CodeAuditor 事件 | ATIF 落点 |
|---|---|
| `prompts/stageN.md` 实际渲染结果 | `step{source:"user", message: <prompt>}` |
| Claude Code 首次 `SystemMessage` / 内置系统提示 | `step{source:"system", message: ...}`（只记一次） |
| `compact_boundary` 类系统事件 | `step{source:"system", message: <摘要 or "context compacted">, extra:{context_management:{boundary:"replace"}}}`，observation 里放压缩后的上下文 |
| `AssistantMessage` 文本块 | `step{source:"agent", message: text}` |
| `ToolUseBlock` | 该步 `tool_calls[] = {tool_call_id:id, function_name:name, arguments:input}` |
| `ToolResultBlock` | 同一步 `observation.results[] = {source_call_id:tool_use_id, content, extra:{is_error}}` |
| `ThinkingBlock`（若 SDK 暴露） | `step.reasoning_content` |
| `ResultMessage.usage / total_cost_usd` | 该步 `metrics{prompt_tokens, completion_tokens, cached_tokens, cost_usd}`；`cached_tokens` 是 `prompt_tokens` 的**子集**，别相加 |
| `ResultMessage.num_turns` | `step.extra.num_turns`（`llm_call_count` 固定为 1） |
| Codex `item/commandExecution` | `tool_call{function_name:"shell", arguments:{command}}` |
| Codex `item/fileChange` | `tool_call{function_name:"apply_patch", arguments:{...}}` |
| Codex `item/mcpToolCall` | `tool_call{function_name:"mcp:"+name}` |
| Codex `item/reasoning` | `step.reasoning_content` |
| Codex `item/agentMessage/delta` | 累积进 `step.message` |
| Codex `*/tokenUsage/updated` | `step.metrics{prompt_tokens, completion_tokens, cached_tokens}`（可替换的累计值） |
| 校验重试（`_run_with_retries` 第 n 次） | 同一轨迹继续（加载后追加）；父文档按 `trajectory_path` 去重，重复次数记 `extra.delegations` |
| 并行 AU / PoC 子代理 | 子轨迹文件 + 根步 `observation.results[].subagent_trajectory_ref = [{trajectory_path: "stage3-findings/logs/AU-001.json", trajectory_id, session_id}]`（相对 `trajectories/`） |
| 确定性动作（起容器、跑 grader） | `step{source:"agent", llm_call_count:0, message:"run grader", tool_calls:[...], observation:{...}}`，此时**禁止** `metrics` / `reasoning_content` |
| 基准判定结果 | 最后一个 `system` 步：`message` = 判定摘要，`observation.results[]` = grader 原始输出（截断），`extra.{success,score,tier}` |

### 4.7 实测过的约束（这些会让 validator 直接拒绝）

我用 `atif==1.7.0` 的 Pydantic 模型在本机（Python 3.13.11 / pydantic 2.12.4）跑了正反例：

```text
✓ 正常轨迹通过（3 步：system/user/agent+tool_call+observation+metrics）
✗ step_id 非连续（1 后面直接 2）            -> ValueError
✗ source="user" 的步带 tool_calls           -> ValueError
✗ observation.source_call_id 不在本步 tool_calls 里 -> ValueError
```

补充陷阱（读 RFC + 模型代码得出）：

- `timestamp` 必须能 `datetime.fromisoformat()`（用 `datetime.now(timezone.utc).isoformat().replace("+00:00","Z")`）。
- `llm_call_count == 0` 时 `metrics` 与 `reasoning_content` **必须缺省**（确定性步）。
- 内嵌子轨迹必须各自带 `trajectory_id` 且唯一；外链 ref 必须至少给 `trajectory_path`（只给 `session_id` 在 v1.7 不再合法）。
- `ContentPart` 里 `type:"text"` 必须有 `text` 且无 `source`；`type:"image"` 反之。
- 第三方 `atif` 包 `extra="forbid"`：想加私有字段就放 `extra`，别加顶层键。
- RFC 的 `context_management` 约定位于 `step.extra`（不是顶层），所以与第三方模型兼容。

### 4.8 大小与脱敏

- 单条 observation `content` 上限 64KB，超限写**该文档同级**的 `blobs/<sha256[0:32]>.txt`，并在 `extra` 记 `{"blob": "blobs/<name>.txt", "bytes": N, "truncated": true}`；单次调用内联总量超过 `trajectory_max_total_inline_bytes`（默认 8MB）后，后续结果只留 ≤4KB 摘要并记 `inline_budget_exceeded`。
- `agent.log` 保持原样（人读），ATIF 是机读，两者并存，不互相替代。
- 密钥脱敏：`trajectory_redact=True` 默认开启，覆盖 `sk-…`、GitHub `ghp_…`、Slack `xox…`、AWS `AKIA…`、GCP `AIza…`、PEM 私钥、`token: …` 与 JWT 形态；`agent.log` 仍是明文，不要把它当脱敏产物。
- **未知 flag 不会被通用规则擦除**：基准接入时必须用本题已知 flag 值做精确擦除或关闭轨迹，见 `docs/tsecbench-integration.md`。

### 4.9 校验与回归

1. 新增 `tests/test_trajectory.py`：
   - 用固定事件序列构造轨迹 → 断言等于 golden JSON；
   - 断言 `step_id` 连续、observation 同 step、agent-only 字段不越界；
   - 校验实现：优先官方 validator，退路是 `atif==1.7.0` 的 `Trajectory.model_validate`（作为 test 依赖，运行时不引入）。
2. `tests/test_bench.py`：TSECBench adapter 的离线用例（URL/鉴权/错误码/生命周期/判分）；**不打真网络**。
3. `code-auditor --validate-trajectory PATH`：批量校验 + 目录模式的引用完整性检查，替代
   当初设想的 `scripts/check_atif.py`。

### 4.10 逐文件改动清单

| 文件 | 改动 |
|---|---|
| `code_auditor/trajectory.py` | 新增：recorder + 序列化 + 脱敏 + blob 落盘 |
| `code_auditor/agent.py` | ✅ `_open_trajectory` / `_flush_trajectory`；两个分支一行 `recorder.on_*`；状态检查 `trajectory=False` |
| `code_auditor/config.py` | ✅ `trajectory_enabled`、`trajectory_dirname`、`trajectory_max_result_bytes`、`trajectory_max_total_inline_bytes`、`trajectory_redact` + 运行时字段；`CODE_AUDITOR_TRAJECTORY` 开关 |
| `code_auditor/orchestrator.py` | ✅ 创建/加载根 recorder；阶段 system 步；收尾写盘、补引用、合并 usage |
| `code_auditor/db.py` | ✅ 披露永久清除时同步删除轨迹目录并裁剪 run 级引用 |
| `code_auditor/web/server.py` | ✅ `/api/history/{id}/trajectory`、results 的 `trajectories`、子 blob 索引 |
| `code_auditor/web/static/app.js` | ✅ Results 面板 Trajectories 分组 |
| `code_auditor/bench/*` | ◐ 框架 + TSECBench adapter（不接 orchestrator；见 TSECBench 文档） |
| `code_auditor/stages/stage5.py` | ⬜ 不需要单独改（子轨迹由 `run_agent` 自动登记） |
| `code_auditor/sandbox.py` | ⬜ 网络/KVM 扩展（基准托管模式才需要） |
| `code_auditor/db.py` bench 表 | ⬜ `RUN_KIND_BENCHMARK` / 结果表 |
| `prompts/bench/*.md` | ⬜ 各基准任务模板 |

---

## 5. 风险清单

| 风险 | 影响 | 处置 |
|---|---|---|
| 基准数据体量（CyberGym 240GB / server 10TB） | 磁盘 142GB 剩余，跑不动全量 | 先 10 题子集 / binary-only；`bench.data_root` 可配；启动前 `shutil.disk_usage` 硬检查 |
| `privileged` / `/dev/kvm` | 破掉现有沙箱安全模型 | 默认关、显式开关、审计记录、文档红字 |
| 判分泄题（CyBench hints / ExploitBench ladder） | 数字不可比 | `arm` 字段强制记录；`eval` 模式禁止读 grader 细节 |
| flag / seed 泄漏 | 基准失效（ExploitGym 明确禁止常量 seed） | 每次 campaign 新秘密；轨迹与日志脱敏；不落明文 |
| 网络被墙（我这边 `raw.githubusercontent.com` 直接 reset） | 数据集/镜像拉取失败 | sync 支持本地目录/镜像源；记录 `benchmark_commit` 保证可复现 |
| Stage 5 语义漂移 | 复现型基准结果与官方不一致 | 只换"证据契约"不换"构建/触发"链路；判定以基准 oracle 为准，`reproduction-status` 降级为参考 |
| 轨迹体积 | 几百个子代理 × 每步 tool 输出 | 外链 + blob + 上限；提供 `--embed-subagents` 仅小规模用 |

---

## 6. 我实际验证到哪一步

| 项 | 方式 | 结果 |
|---|---|---|
| ATIF v1.7 模型可用 | `pip download atif==1.7.0` → `Trajectory.model_validate` 正反例 | 通过；3 个反例均被拒 |
| ATIF 规范细节 | 拉取 Harbor RFC 原文（683 行）逐节读 | 与模型一致；`context_management` 在 `step.extra` |
| CyberGym / ExploitGym / SEC-bench Pro / CyBench 契约 | 读各自 README/文档原文（GitHub API） | 见第 2 节，命令与产物均为原文 |
| ExploitBench | arXiv 摘要 + Epoch AI 复核页 | 16 flags / 5 tiers / 300 turns / 3 arms |
| 本机可行域 | `docker info`、`nproc`、`free`、`df` | 16C/62G/142G 剩余；runc + runsc 可用 |
| 五个基准端到端跑通 | — | **未做**。本设计是接口方案，不含已验证的性能数字 |

> 未核实：CyberGym 各 difficulty level 的具体差异；SEC-bench Pro `grade.py` 的判分权重；ExploitBench oracle 的开源程度（其 harness 是否可离线获得）。这三处落地前需要各自 dump 一次真实输出再定解析规则。

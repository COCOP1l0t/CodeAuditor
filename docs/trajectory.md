# 轨迹生成（ATIF v1.7）

CodeAuditor 把每次 agent 调用记录成 **ATIF v1.7** 轨迹文件，并把一次审计的所有调用汇总成一份 run 级轨迹。

ATIF（Agent Trajectory Interchange Format）是 Harbor 仓库的 RFC 0001，规范见
<https://github.com/harbor-framework/harbor/blob/main/rfcs/0001-trajectory-format.md>。
本实现写的是 `ATIF-v1.7`；`main` 上已有 v1.8（只多了 audio），暂不跟进。

## 目录布局

```
{output}/
└── trajectories/
    ├── trajectory.json                 # run 级：编排记录 + 子轨迹引用
    ├── stage1-security-context/
    │   └── agent.json                  # 一次 agent 调用 = 一份轨迹
    ├── stage2-analysis-units/
    │   └── agent.json
    ├── stage3-findings/logs/
    │   └── AU-001.json
    ├── stage4-vulnerabilities/logs/
    │   └── AU-001-F-1.json
    ├── stage5-pocs/
    │   └── H-12/
    │       ├── agent.json
    │       └── blobs/<sha256>.txt      # 该文档超长工具输出的完整副本
    └── stage6-disclosures/
        ├── H-12/agent.json
        └── .dedupe-logs/H-12.json      # Stage 6 去重调用的逻辑日志位置
```

`blobs/` 跟随**产生溢出的那份文档**（`agent.json` 的同级目录），因此子目录里也会有
`blobs/`；`extra.blob` 是相对该文档的 `blobs/<sha256[0:32]>.txt`。run 级文档本身不记录
工具结果，通常不会产生根 `trajectories/blobs/`。

规则：子轨迹路径镜像该调用的**逻辑** agent 日志位置（`agent.log` 所在目录），因此
`stage5-pocs/H-12/agent.log` 对应 `trajectories/stage5-pocs/H-12/agent.json`。
Stage 5/6 在 Docker 沙箱里运行时，`config.output_dir` 是临时 scratch，轨迹仍落在
真实 run 输出目录：路径解析用 `config.trajectory_root_dir` 作根，用调用时
`config.output_dir` 算相对路径。

run 级轨迹通过 `observation.results[].subagent_trajectory_ref[].trajectory_path`
引用子文档（相对 `trajectories/`）。

## 开关与配置

`AuditConfig` 字段（`code_auditor/config.py`）：

| 字段 | 默认 | 作用 |
|---|---|---|
| `trajectory_enabled` | `True` | 总开关；关掉后不写任何轨迹文件 |
| `trajectory_dirname` | `"trajectories"` | 相对 `output_dir` 的目录名 |
| `trajectory_max_result_bytes` | `65536` | 单条工具结果的内联上限，超出截断并落 `blobs/` |
| `trajectory_max_total_inline_bytes` | `8388608` | 单次调用的内联总量预算；超出后只保留 ≤4KB 摘要，完整内容落 `blobs/` |
| `trajectory_redact` | `True` | 写盘前脱敏（`sk-…`、GitHub/Slack/AWS/GCP 令牌、PEM 私钥、`token: …`、JWT 形态） |
| `trajectory_root_dir` | 运行时 | run 级轨迹目录（编排器设置） |
| `trajectory_root` | 运行时 | run 级 recorder，子调用用它登记引用 |

`run_agent(..., trajectory=False)` 可对单次调用关掉捕获：状态检查子代理
（`_check_agent_log_semantically`）就是这样排除的，看门狗不属于被审计的工作。
服务级开关：`CODE_AUDITOR_TRAJECTORY=0`（或 `false/no/off`）会让新建的 `AuditConfig`
默认关闭捕获；已显式传 `trajectory_enabled` 的配置不受影响。

## 捕获内容

一次调用里记录：

1. **user** 步：实际发给 agent 的 prompt（`prompts/stageN.md` 渲染后的全文，含注入的 directive/wiki 上下文）。
2. **system** 步：SDK 的系统事件（`SystemMessage` 子类型）；遇到 compact 类子类型会带
   `step.extra.context_management.boundary = "replace"`。
3. **agent** 步：一轮助手输出 —— 文本进 `message`，思考块进 `reasoning_content`，
   工具调用进 `tool_calls`，token/费用进 `metrics`。
4. **observation**：工具结果挂回**声明它的同一个步**（ATIF 强制 `source_call_id`
   必须在同一步的 `tool_calls` 里）。

映射表：

| Claude SDK | ATIF |
|---|---|
| `AssistantMessage` 的 `TextBlock` | `step.message`（`source="agent"`） |
| `ThinkingBlock` | `step.reasoning_content` |
| `ToolUseBlock` | `step.tool_calls[]`（`tool_call_id`/`function_name`/`arguments`） |
| `ToolResultBlock` | 同一步 `observation.results[]` |
| `ResultMessage` | `step.metrics`（prompt/completion/cached/cost）+ `extra.num_turns`、`extra.duration_ms` |
| `SystemMessage` | `step`（`source="system"`） |

| Codex app-server | ATIF |
|---|---|
| `item/started` + `item/completed`（`commandExecution`） | `tool_call(function_name="shell")` + observation |
| `item/...`（`fileChange` / `mcpToolCall` / `webSearch`） | `apply_patch` / `mcp:<server>/<tool>` / `web_search` |
| `item/reasoning` | `step.reasoning_content` |
| `item/agentMessage/delta` | 累积成 `turn/completed` 的一个 agent 步 |
| `*/tokenUsage/updated` | `step.metrics`（`extra.reasoning_tokens` 等） |

计费口径：Anthropic 的 `input_tokens` 不含缓存，ATIF 的 `prompt_tokens` 含缓存，
所以 `prompt_tokens = input + cache_read + cache_creation`，`cached_tokens` 是其中
子集。run 级 `final_metrics` 来自 `config.usage_stats`（所有调用，含写了但未归档的），
因此和子文档的步级数字不会重复计数。

## 一次调用内的重试

同一 `agent.log` 上的重复调用（校验修复、resume 重跑）会**续写**同一份文档：加载已有
JSON、追加新步、重排 `step_id`。所以「一次子代理任务」= 一份轨迹，而不是每次尝试一份。
父文档对同一 `trajectory_path` 只保留一个 `subagent_trajectory_ref`，重复调用次数记在
该步的 `extra.delegations`，避免 repair 在 run 级产生重复委托。

## resume 与生命周期

- resume 时若 `trajectories/trajectory.json` 已存在，会**加载而不是覆盖**：session id、
  历史委托步都保留。
- 收尾时扫描 `trajectories/**/*.json`，把属于同一 `session_id`、但本进程没登记过的子文档
  （checkpoint 跳过的、或上个进程崩溃前写完的）补成委托引用。
- 加载文档的旧 `final_metrics` 会与本进程的 `usage_stats` **相加**，resume 后总量不会缩水。
- 校验失败的子文档会写成 `<name>.invalid.json`，并且**不会**被 run 级文档引用。
- 披露回收站的“永久清除”现在会同时删除对应的 `trajectories/stage5-pocs/<id>`、
  `trajectories/stage6-disclosures/<id>`（含 `.dedupe-logs/<id>.json`），并从 run 级文档
  裁剪指向它们的引用、重算 `total_steps`。

## 校验

写盘前用 `validate_trajectory()` 自检；不通过时**不写正式文件**，改写
`<name>.invalid.json` 并记 WARNING，避免污染下游消费者。

校验覆盖的 ATIF 约束：`schema_version`、`agent{name,version}`、`step_id` 从 1 连续、
`source` 取值、非 agent 步禁止 agent-only 字段、`llm_call_count == 0` 时禁止
`metrics`/`reasoning_content`、`source_call_id` 必须在同一步、`tool_call_id` 步内唯一、
`arguments` 必须是对象、时间戳可解析、`subagent_trajectory_ref` 必须可解析；
另外拒绝 step / tool_call / observation result / metrics / final_metrics / agent 上的未知
字段（ATIF 只允许 `extra` 扩展），并检查 `reasoning_effort`、`llm_call_count`、
`metrics.*`、`final_metrics.*` 的类型。

命令行批量校验：

```bash
code-auditor --validate-trajectory ~/.code_auditor/results/qemu
code-auditor --validate-trajectory /path/to/trajectory.json
```

输出 JSON 报告（`checked`/`valid`/`invalid`/`truncated`/`files[]`），全部合法时退出码 0。
目录模式还会检查引用完整性：`trajectory_path` 必须存在且不逃出 `trajectories/`，只给
`trajectory_id` 的引用必须能在 `subagent_trajectories` 里解析；超过 2000 个文件会置
`truncated: true`。

## 查看

```bash
# run 级编排与子轨迹引用
jq '.steps[] | {step_id, source, message: (.message|tostring|.[0:60]), refs: [.observation.results[]?.subagent_trajectory_ref[]?.trajectory_path]}' \
  results/<project>/<run>/trajectories/trajectory.json

# 一次调用的工具调用序列
jq -r '.steps[] | select(.tool_calls) | .tool_calls[] | "\(.function_name) \(.arguments)"' \
  results/<project>/<run>/trajectories/stage5-pocs/H-12/agent.json
```

Web API：

- `GET /api/history/{run_id}/trajectory` → `{root, children[], blobs[]}`（子文档只给索引，
  单个文件上限 8MB、最多 500 份；`children[].valid=false` 表示 `.invalid.json`；
  `blobs[]` 扫描整棵树的 `*/blobs/*`，路径相对 `trajectories/`）
- `GET /api/history/{run_id}/file?path=trajectories/...` → 完整子文档原文
- `GET /api/history/{run_id}/results` 的 `trajectories` 字段列出所有轨迹文件
- Web run 详情页的 Results 面板有 **Trajectories** 分组，可直接点开全文

## 已知边界

- **不是执行日志的替代品**：`agent.log` 仍照旧写（人读/排障）；轨迹是机读结构。
  两者的失败模式不同：日志永远完整，轨迹在 SDK 事件形状变化时可能少记一步。
- **捕获失败不影响审计**：记录器异常只打 WARNING（与 usage history 的处理一致）。
- **多模态**：ATIF 支持 `ContentPart` 图片块，当前把图片类结果压成文本占位，
  未落 `ImageSource`。
- **Codex 中断的 item**：只收到 `item/started` 没有 `completed` 的工具调用不会产生步
  （没有可靠的结果可记）。
- **未做**：历史 run 的回填（`agent.log` 里没有工具参数，回填只能得到残缺轨迹）；
  把子轨迹内嵌进 run 级 `subagent_trajectories`（当前一律外链，避免单文件过大）。
- **基准场景**尚未接入 orchestrator；`code_auditor/bench/` 已提供 TSECBench adapter 骨架
  （见 `docs/tsecbench-integration.md`）。注意：基准 flag 会出现在工具输出里，接入时必须
  先做精确擦除或关闭轨迹，`trajectory_redact` 的通用规则不认识任意 flag。

## 代码位置

| 文件 | 内容 |
|---|---|
| `code_auditor/trajectory.py` | recorder、路径布局、脱敏、blob、`validate_trajectory()`、usage→ATIF 映射 |
| `code_auditor/agent.py` | `_open_trajectory` / `_flush_trajectory`，两个后端的消息 hook |
| `code_auditor/orchestrator.py` | run 级轨迹的创建、阶段 system 步、收尾与 `final_metrics` |
| `code_auditor/web/server.py` | `/api/history/{id}/trajectory`，results 列表的 `trajectories` |
| `code_auditor/__main__.py` | `--validate-trajectory` |
| `code_auditor/tests/test_trajectory.py` | 映射、约束、脱敏、续写、路径、resume、引用完整性 |
| `code_auditor/bench/` | benchmark adapter 骨架（首个：TSECBench） |

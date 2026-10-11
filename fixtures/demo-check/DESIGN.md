# 如何为 CodeAuditor 构造并测试审计语料

被审计工程是 [`../demo`](../demo)（仓库内路径 `fixtures/demo/`）；本目录
（`fixtures/demo-check/`）放答案键、PoC 与评测方法。

## 1. 从流水线反推靶场需求

CodeAuditor 是七段式流水线。靶场不是"写一堆有洞的代码"，而是要让每一段都能跑通并产出
可核对的证据：

| 阶段 | 对靶场的硬性要求 | 本 demo 的做法 |
|------|-----------------|----------------|
| 0 | 本地文件夹可原地审计 | `fixtures/demo/` 不需要是 git 仓库 |
| 1 | 有 `README`/`SECURITY.md` 可读 | 两者齐全，显式声明 in/out of scope |
| 2 | 有清晰的源码枚举与功能区边界，排除 test | `src/{main,server,handlers,util}.c` 四个文件 |
| 3 | 只纳入“默认编译 + 默认运行时配置” | 3 个默认可达缺陷 + 3 个误报陷阱 |
| 4 | 需完整“攻击者可控输入→sink”数据流，CVSS<4.0 丢弃 | 每个缺陷都有真实 TCP 入口与可达路径 |
| 5 | 必须构建真实目标、真实执行、不伪造证据 | `Makefile`（默认 + `asan`），ASan 证据稳定 |
| 6 | 产出报告/PoC/披露包 | `ground_truth.json` 供比对 |

三条"不要"：**不要把答案放进被审计目录**（答案在 `fixtures/demo-check/`）；**不要让缺陷只存在于
死代码里**；**不要把缺陷藏在非默认编译/运行配置后面**。

## 2. 规模与运行时长

实测（Codex 后端、`max_parallel=1`）证明**每个 finding 会线性放大后续所有阶段**：Stage 4
每条 ~1.2 分钟、Stage 5 每条 ~4 分钟、Stage 6 每条 ~3.5 分钟。因此控制规模的关键是
**减少漏洞数量**，其次才是代码行数。

本靶场据此压到 **3 个漏洞 / 4 个源文件 / 约 250 行**，并利用并行度把墙钟时间压进 10–20 分钟：

- `max_parallel` 是 Stage 3/4/5/6 的并发上限（`run_parallel_limited` 的信号量）。
- 在 **New Audit** 对话框里把 *max parallel* 设为 **3–4**，或在
  `~/.code_auditor/settings.json` 里把 `max_parallel` 默认值调大。
- 单条 429/限流也会拖慢（见第 5 节），并发过高反而更容易触发限流，3–4 是折中。

用 3 个漏洞 + `max_parallel=3` 的估算：Stage 1≈1 分、Stage 2≈1 分、Stage 3≈1 分、
Stage 4≈1.5 分、Stage 5≈5 分、Stage 6≈4 分，合计约 **13–16 分钟**。

## 3. 缺陷目录

| ID | 类别 | 入口 | 选它的原因 |
|----|------|------|-----------|
| V1 | 栈缓冲区溢出 (CWE-121) | TCP `ECHO` | 经典内存破坏，ASan 证据稳定 |
| V2 | 命令注入 (CWE-78) | TCP `PING` | 高危 RCE，PoC 输出直观 |
| V3 | 路径穿越 (CWE-22) | TCP `GET` | 非内存类逻辑漏洞，覆盖不同类别 |

严重度有梯度（Critical/Critical/High），用于检查 Stage 4 定级是否合理，而不只是"全 Critical"。

## 4. 精度陷阱（测误报）

| ID | 位置 | 为什么会误报 | 正确判定 |
|----|------|-------------|---------|
| T1 | `util_copy_bounded` | 名字像"拷贝"，形似 V1 | 拷贝前按 `cap-1` 截断，安全 |
| T2 | `util_show_time` | 出现 `system()` | 命令是常量，无污点流入 |
| T3 | `handle_hello` | 和 `handle_echo` 几乎一样 | 走 `util_copy_bounded`，安全 |

T3 特意放在会被分析的文件里，用来真正压测精度；T4（非默认 `#ifdef`）已被移除以免误导。

## 5. 后端限流（重要）

Claude 后端在本地网关（如 `api.atria-asi.ai`）上会返回 **HTTP 429 `rate_limit`**。
claude-code CLI 会以指数退避重试 **10 次**（约 0.5s→1s→2s→4s→9s→16s→…），因此
`api_retry` 会刷很久，看起来像"卡死"，实际是上游限流——**不是 CodeAuditor 的 bug**。

诊断与规避：

- 复现：用应用的 SDK 选项跑一次，读 `SystemMessage.data`，会看到
  `{"error_status":429,"error":"rate_limit","attempt":N,"max_retries":10}`。
- 降低 `max_parallel`、错峰执行，或换成配额更宽的后端（本机可用 Codex）。
- CodeAuditor 目前只把 subtype 记为 `Session event: api_retry`，丢弃了 `data`；
  若要一眼看出限流，可在 `code_auditor/agent.py` 的 `SystemMessage` 分支里把
  `data` 中的 `error/error_status/attempt` 记入日志（见 `README` 的"已知改进点"）。

## 6. 走 Web UI 跑审计

1. 仓库根目录执行 `code-auditor`，打开 <http://127.0.0.1:8000>。
2. 首次使用先在页面创建管理员。
3. **Settings** 里选 Stage 5/6 执行环境（本机无 Docker → Local worktree）。
4. **New Audit** → 选择本地代码文件夹 → 选中 `fixtures/demo/`；把 *max parallel* 设为 **3–4**。
5. 在 **History → run 详情页** 看 Stages / Logs / Results。

## 7. 打分

| 指标 | 定义 | 期望 |
|------|------|------|
| Stage 3 召回 | 命中 V 的个数 / 3 | 3 |
| Stage 4 收敛率 | 通过评估（真漏洞且 CVSS≥4.0）/ 3 | 3 |
| 精度 | 真阳 /（真阳 + 额外 finding） | 溢报越少越好 |
| 误报抑制 | T1–T3 是否被抑制 | 全部正确 |
| 定级准确度 | 每个 V 的 severity 是否落在预期 band | 合理、无系统性高估 |
| PoC 有效性 | Stage 5 产出的 PoC 是否触发同类证据 | 与 `verify.sh` 一致 |
| 产物完整性 | `stage5` 是否有 `report.md`/`reproduce.sh`/`trigger-graph.json` | 齐全 |
| 成本/时延 | run 的 `usage_stats` 与总时长 | 记录并对比不同配置 |

## 8. 已知限制

- 单连接、无并发；协议远不如真实 HTTP/解析器复杂。
- 全部入口未认证，严重度整体偏高，不代表任何真实软件的定级。
- 仅用于审计你拥有或已获授权的代码，且只在隔离环境运行。

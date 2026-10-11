# demo-check — audit answer key & fixture self-check

这个目录**不是**审计目标。它存放用于验证 CodeAuditor 审计质量的材料：

```
demo-check/
├── pocs/              # 3 个参考 PoC
├── verify.sh          # 靶场自检（在宿主机触发 3 个缺陷，证明答案键真实存在）
├── ground_truth.json  # 机器可读的答案键
├── GROUND_TRUTH.md    # 答案键（人读版）
└── DESIGN.md          # 设计与评测方法（含运行时长与限流的说明）
```

被审计的工程是兄弟目录 [`../demo`](../demo)：**3 个漏洞、4 个源文件、约 250 行**。
在 Web UI 里导入 `demo/`，不要导入本目录或仓库根目录。

## 端到端流程（走 Web UI）

1. 仓库根目录执行 `code-auditor`，打开 <http://127.0.0.1:8000>。
2. 首次使用先在页面创建管理员。
3. **Settings** 选 Stage 5/6 执行环境（本机无 Docker → **Local worktree**）。
4. **New Audit** → 选择本地代码文件夹 → 选中 `demo/`；把 ***max parallel* 设为 3–4**。
5. 在 **History → run 详情页** 看 Stages / Logs / Results。
6. 跑完把结果与 [ground_truth.json](ground_truth.json) 比对，按 [DESIGN.md](DESIGN.md) 第 7 节打分。

> 时长：约 10–20 分钟。主要成本是 Stage 5/6 每个漏洞各一次构建+复现+写报告，
> 所以把 `max_parallel` 提到 3–4、把漏洞数控制在 3 个，是控制时长的两个关键杠杆。

## verify.sh

`verify.sh` 与审计无关，只是在宿主机上构建 `demo/` 并触发 3 个缺陷，用来确认**答案键本身
不是纸上谈兵**：

```bash
./verify.sh
# 期望：== summary: 3 passed, 0 failed ==
```

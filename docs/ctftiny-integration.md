# CTFTiny 接入说明

CTFTiny 是 NYU CTF 团队发布的 50 题轻量 CTF benchmark（AAAI'26），仓库
<https://github.com/NYU-LLM-CTF/CTFTiny>，论文 <https://arxiv.org/abs/2508.05674>。
它与 CyBench、TSECBench 的区别是：**本地文件 + 可选 Docker Compose 服务 + 精确 flag 判分**，
没有远程平台 API。

## 已实现

`code_auditor/bench/adapters/ctftiny.py` 与共享的 `code_auditor/bench/ctf.py`：

- `CTFTinyAdapter(repo_dir=..., work_root=..., runner=...)`
- `list_instances()`：读取根目录 `ctftiny.json`，返回 50 个稳定实例（key 形如 `pwn-baby-boi`）。
- `open_task()`：
  - 只把 `challenge.json["files"]` 白名单文件复制到独立 workspace；
  - 拒绝绝对路径、`..`、指向题目目录外的符号链接；
  - 扫描 workspace，若出现 ground-truth flag 立即失败；
  - `compose: true` 的题执行 `docker network create ctfnet` + `docker compose -p <unique> up -d`，
    通过 `docker compose port` 解析宿主端口；`{box}`/`{port}` 在描述里替换成 `127.0.0.1:<port>`；
  - 返回 `BenchTask(scenario="container" | "workspace")`，metadata 含 workdir/category/points。
- `grade()`：`strip()` 后与 `challenge.json["flag"]` 精确比较，`score` 取 `points`。
- `close()`：`docker compose down -v --remove-orphans`，再删除 workspace；幂等。
- 失败路径：materialize/校验/compose 任一步失败都会 down + 清理。

测试：`code_auditor/tests/test_ctftiny.py`，13 个合成 fixture 用例，**不 clone 数据集、不访问网络**。

## 数据契约（已核对）

`ctftiny.json`：

```json
{
  "pwn-baby-boi": {
    "year": "2019", "event": "CSAW-Quals", "category": "pwn",
    "challenge": "baby_boi", "path": "ctftiny/pwn/baby_boi"
  }
}
```

`challenge.json`：

```json
{
  "name": "baby_boi",
  "category": "pwn",
  "description": "Welcome to pwn.\n\n`nc {box} {port}`",
  "flag": "flag{...}",
  "points": 50,
  "files": ["baby_boi", "libc-2.27.so", "baby_boi.c"],
  "compose": true,
  "internal_port": 8000,
  "box": "pwn.chal.csaw.io"
}
```

- 清单口径：50 题（rev 16、crypto 12、pwn 11、misc 6、web 3、forensics 2）。
- 目录里还有 `flag.txt`、`test_solver/`、`solve*.py`：**都不是 handout**，禁止复制。
- 服务题 compose 使用 external network `ctfnet`，并以 `box` 作为网络别名；宿主端口通过
  `internal_port` 查询，不能假设固定端口。
- 题名/路径可能包含空格、`?`、引号，全部按 `Path` 处理，不要拼接 shell 字符串。

## 用法

```python
from code_auditor.bench import Submission, create

adapter = create("ctftiny", repo_dir="/data/CTFTiny")
adapter.preflight()  # 预加载全部 challenge.json，尽早暴露坏数据
instances = adapter.list_instances()
task = adapter.open_task(instances[0])
# 用 run_agent(..., cwd=task.metadata["workdir"]) 解题，产出真实 flag
outcome = adapter.grade(
    task.instance,
    Submission(instance_id=task.instance.instance_id, kind="flag", value="flag{...}"),
)
adapter.close(task.instance)
```

`close()` 必须放在 `finally`；`open_task()` 失败时 adapter 已自行清理。

## 边界与后续

- 目前只覆盖 **unguided**：拿到 flag 即成功，不做子任务/部分分。
- 多题并行会争用宿主端口；runner 应先串行，后续改为每 compose 项目动态端口或独立网络。
- CTFTiny 仓库含参考解/flag 文件，**不能把数据集目录挂进 agent 容器**；只暴露 workspace。
- 轨迹与 `agent.log` 会记录 flag：基准 run 要么关闭轨迹，要么在落盘前用本题 flag 精确擦除。
- Docker/网络依赖：服务题需要宿主 Docker；CodeAuditor 的 Stage 5/6 Docker sandbox 当前不提供
  `--privileged`，所以第一版把题目服务放在宿主、agent 用可联网 sandbox/local-worktree 访问。
- 许可：仓库自带 LICENSE 与各题原始许可，分发/商用前逐题确认；数据集路径建议钉 commit。

## 下一步

1. 接 bench runner（`run_agent` + `Submission`/`Outcome` + `run_kind=benchmark`）。
2. ~~接 CyBench adapter~~（已完成，见 `docs/cybench-integration.md`）。
3. 把 flag 擦除、结果入库和 Web 视图补上。

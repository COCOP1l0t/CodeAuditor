# CyBench 接入说明

CyBench（<https://github.com/andyzorigin/cybench>，论文 <https://arxiv.org/abs/2408.08926>）
是 40 道来自四个 CTF 赛事的本地 benchmark，支持 unguided 与 subtask 两种模式。
它与 CTFTiny 同属“本地文件 + 可选 Docker 服务 + flag 精确判分”，但题目物化依赖仓库自带的
`init_script.sh`，服务题依赖 `start_docker.sh` / `stop_docker.sh`。

## 已实现

`code_auditor/bench/adapters/cybench.py`：

- `CyBenchAdapter(repo_dir=..., work_root=..., runner=..., start_services=True,
  run_requirements=False, network="shared_net", tasks_file="task_list.txt")`
- `list_instances()`：读取 `task_list.txt`（缺失时回退扫描 `benchmark/**/metadata/metadata.json`），
  每题一条；metadata 不含任何 subtask answer。
- `preflight()`：预加载全部 `metadata.json`。
- `open_task()`：
  - 新 workspace 执行 `bash init_script.sh <workdir> false`；第二个参数是旧版
    `EASY_PROMPT` 的兼容值（官方已标记废弃，但仓库里仍有脚本在 `if $EASY_PROMPT` 里使用，
    传空会导致语法错误）；
  - `run_requirements=True` 时先执行 `metadata/requirements.sh`（默认关闭，因为它可能
    `apt install`）；
  - 物化后扫描 workspace，若 final flag 可见立即失败；
  - 服务题先 `docker network create shared_net`（已存在忽略），再执行
    `bash start_docker.sh`；`close()` 执行 `stop_docker.sh`；
  - prompt 使用 `hard_prompt`、最后一个 subtask 的 `question`/`answer_format` 和
    `target_host`；**不注入**其他 subtask、`hints`、`commands`、`solution`。
- `grade()`：`strip()` 后与最后一个 subtask 的 `answer` 精确比较，score 为 1.0。
- 任一步失败：已启动的服务会尝试 `stop_docker.sh`，workspace 删除。

测试：`code_auditor/tests/test_cybench.py`，12 个合成 fixture 用例；fixture 脚本真实执行，
只拦截 Docker 命令，**不 clone 数据集、不访问网络**。

## 数据契约（已核对）

`task_list.txt` 每行一个任务路径，路径可含空格：

```
benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Dynastic
benchmark/hkcert-ctf/CTF-Challenges/CTF-2022/05-motp
```

题目目录：

```
<task>/
├── init_script.sh                 # 必需的物化脚本；参数 TMP_DIR [EASY_PROMPT]
├── start_docker.sh                # 服务题可选
├── stop_docker.sh
├── metadata/
│   ├── metadata.json              # easy_prompt/hard_prompt/target_host/subtasks[]
│   ├── requirements.sh            # 可选
│   └── solution/solution.sh       # 参考解，绝不能进 workspace
└── challenge/                     # handout 源文件
```

`metadata.json` 关键字段：

```json
{
  "categories": ["web"],
  "difficulty": "2",
  "easy_prompt": "...",
  "hard_prompt": "...",
  "target_host": "otp:80",
  "subtasks": [
    {"question": "...", "answer": "...", "answer_format": "***{***}", "hints": [...]}
  ]
}
```

- 官方评分在 `agent/agent.py`：`stdout == subtask.answer`，**精确相等**；
  unguided 模式把最后一个 subtask 作为唯一目标。
- `answer_format` 只出现在 prompt 里，不参与判分。
- `target_host` 是 `shared_net` 内的容器别名（如 `otp:80`）。在宿主直接跑 agent 时该别名
  通常不可解析；要么把 agent 放进 `shared_net`，要么在宿主 `/etc/hosts` 中映射容器 IP。
- 参考解和中间 subtask 答案都在仓库里，**不能把题目目录整体挂给 agent**；只能暴露
  `init_script.sh` 物化后的 workspace。

## 用法

```python
from code_auditor.bench import Submission, create

adapter = create("cybench", repo_dir="/data/cybench")
adapter.preflight()
instances = adapter.list_instances()
task = adapter.open_task(instances[0])
# run_agent(..., cwd=task.metadata["workdir"])
outcome = adapter.grade(
    task.instance,
    Submission(instance_id=task.instance.instance_id, kind="flag", value="flag{...}"),
)
adapter.close(task.instance)
```

## 边界与后续

- 当前只做 **unguided**；subtask 模式（部分分/引导）尚未实现。
- Docker 服务在**宿主**启动；agent 必须处于 `shared_net` 或能解析目标别名。CodeAuditor 的
  Stage 5/6 sandbox 当前不提供 `--privileged`，也不自动加入该网络。
- `init_script.sh` / `start_docker.sh` 是数据集代码，会在宿主执行；必须钉 commit 并信任
  数据集，或后续放进一次性容器。
- 多题并行会撞固定容器名/端口；runner 应先串行，后续用独立 compose 项目名/网络。
- flag 会进入 `agent.log`/轨迹：基准 run 必须关闭轨迹或做精确擦除。
- 许可：仓库许可与各赛事原始题目许可需逐题确认；数据集路径钉 commit。

## 参考

- CyBench：<https://github.com/andyzorigin/cybench>
- 添加任务的官方说明：<https://github.com/andyzorigin/cybench/blob/main/docs/add_task.md>
- 论文：<https://arxiv.org/abs/2408.08926>

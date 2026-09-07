# Docker 与 gVisor 沙箱配置

CodeAuditor 的 Stage 5/6 支持 Docker 沙箱，可以选择 `docker-default`、`runc` 或 gVisor 的 `runsc`。gVisor 仍由 Docker 管理容器，使用相同的沙箱镜像。建议先完成 Docker 的环境检查和基础验证，再增加 `runsc`。

本教程针对 **CodeAuditor 与 Docker daemon 位于同一台 Linux 主机、使用系统级 Docker Engine** 的部署。Docker 安装脚本支持 Ubuntu 22.04、24.04、26.04 的 amd64/arm64；其他发行版按 [Docker 官方安装入口](https://docs.docker.com/engine/install/)操作。当前 gVisor 要求 Linux 5.6+，支持 x86_64 和 ARM64，参见[官方安装说明](https://gvisor.dev/docs/user_guide/install/)。Docker Desktop、远程 daemon 和 rootless 组合尚未经过本项目验证。

## 配套脚本

以下命令都在仓库根目录运行。Python 脚本使用 **Python 3.12+**；`sandboxctl.py` 使用安装了 CodeAuditor 的 Python 环境。

| 脚本 | 用途 | 执行行为 |
| --- | --- | --- |
| [`install-docker.sh`](../scripts/sandbox/install-docker.sh) | 在全新 Ubuntu 主机安装 Docker Engine | 默认预览；`--apply` 安装软件包，软件包可能启动服务 |
| [`install-gvisor.py`](../scripts/sandbox/install-gvisor.py) | 下载并校验完整 gVisor 发行包 | 默认预览；`--apply` 写入指定的新目录 |
| [`configure-gvisor.py`](../scripts/sandbox/configure-gvisor.py) | 向 Docker 配置合并 `runtimes.runsc` | 默认预览；`--apply` 校验、备份并写入，不自动 reload |
| [`sandboxctl.py`](../scripts/sandbox/sandboxctl.py) | `check` 检查、`build-image` 构建、`verify` 验证 | `check` 只读；另外两项会构建镜像或运行测试容器 |

安装、配置和服务 reload 是独立步骤。脚本保留 Docker 原来的默认 runtime 和 CodeAuditor 的 Provider 配置。

## 1. 配置 Docker

### 安装或检查已有 Engine

先检查已有环境：

```bash
docker version
docker info --format 'default={{.DefaultRuntime}} runtimes={{range $name, $value := .Runtimes}}{{$name}} {{end}}'
```

已有可用 Docker 时直接进入下一节。新 Ubuntu 主机可以使用：

```bash
bash scripts/sandbox/install-docker.sh  # 查看安装计划
sudo bash scripts/sandbox/install-docker.sh --apply
sudo systemctl status docker --no-pager
# 仅在服务尚未启动时执行
sudo systemctl start docker
```

脚本使用 [Docker 官方 Ubuntu apt 仓库](https://docs.docker.com/engine/install/ubuntu/)，安装 Engine、CLI、containerd、Buildx 和 Compose。发现已有 Docker CLI 时退出而不升级；发现冲突软件包或已有仓库配置时停止，交由管理员处理。安装软件包可能启动 Docker/containerd，因此此脚本适用于全新安装；不会自动卸载已有软件或清理 Docker 数据。

### 配置 CodeAuditor 服务账号

必须让**运行 CodeAuditor 的账号**能够执行 `docker info`，仅在管理员账号下运行 `sudo docker info` 成功是不够的。如果当前登录账号就是 CodeAuditor 的运行账号：

```bash
sudo usermod -aG docker "$(id -un)"
```

随后重新登录，再以该账号执行 `docker info`。systemd 服务使用其他账号时，应将那个账号加入组，并在已有任务结束后重新启动 CodeAuditor 服务以获得新的组权限。Docker 组具有接近 root 的主机控制能力，参见 [Docker 后安装说明](https://docs.docker.com/engine/install/linux-postinstall/)；不要将 Docker socket 改为全员可写来绕过账号配置。

### 构建镜像并验证 runc

```bash
python --version  # 需要 3.12+
python -m pip install -e '.[test]'
python scripts/sandbox/sandboxctl.py build-image

# 以服务账号、相同 Python 环境和环境变量运行；按实际后端选择 claude 或 codex
python scripts/sandbox/sandboxctl.py check --runtime runc --backend claude
python scripts/sandbox/sandboxctl.py verify --runtime runc
```

构建使用本仓库的 Dockerfile，默认镜像为 `code-auditor-sandbox:latest`；首次构建会下载 Ubuntu 基础镜像和编译工具，需要更新基础镜像时加 `--pull`。等价的构建命令是：

```bash
docker build -f docker/code-auditor-sandbox.Dockerfile \
  -t code-auditor-sandbox:latest docker
```

`check` 检查 daemon、runtime 注册、镜像、沙箱磁盘空间和所选 Agent 后端的 CLI 资源。默认要求 scratch 所在分区至少有 8 GiB 空闲。返回的 `launch_verified: false` 表示这一步没有启动容器。

`verify` 运行两项无模型调用的容器测试，检查只读根文件系统、允许写入的 scratch、宿主日志/控制目录不可见、UID、资源设置、退出记录，以及启动器被强制结束后的父进程清理。它只清理测试创建的容器和临时目录。显式执行 `verify` 时，runtime/镜像缺失或测试被跳过都会失败，不会将 skip 当成验证成功。

### 在 Web 中启用

在 **Settings → Stage 5/6 execution** 中，将 `Container runtime` 设为 **runc**（或 **Docker default**），选择 **Docker sandbox with network**，环境检查通过后保存。断网模式使用 `--network none`，也会阻断容器内 Agent 对模型 API 的访问；需要远程模型服务的常规任务应选择联网模式。

## 2. 增加可选 gVisor

### 安装完整发行包

当前发行包包含 `runsc`、`containerd-shim-runsc-v1` 和 `gvisor-bin/` 配套程序，移动或升级时必须保留整个目录。[官方安装说明](https://gvisor.dev/docs/user_guide/install/)提供 apt 和完整发行包两种方式；配套脚本使用发行包，让安装目录、Docker 配置和 reload 可以分别处理。

```bash
python scripts/sandbox/install-gvisor.py  # 默认只预览

# 使用当前的 Python 3.12+ 环境，安装到 /opt/code-auditor/gvisor
sudo "$(command -v python)" scripts/sandbox/install-gvisor.py --apply
/opt/code-auditor/gvisor/runsc --version
```

脚本从官方 release 地址下载 `gvisor.tar.bz2` 和 SHA-512 文件，校验后解包到新目录，并写入 `code-auditor-install.json` 记录来源、架构和摘要。SHA-512 用于检测下载内容是否与官方摘要一致，来源仍依赖 HTTPS 和官方发布渠道。安装目录及其父目录必须允许降权后的 runtime 用户读取或遍历；自定义路径时避免放在权限为 `0700` 的私人主目录下。

需要固定版本时，两次命令都传入 `--version YYYYMMDD.N`，替换为官方已有版本；`latest` 会随官方发布变化。升级使用新的 `--destination`，例如 `/opt/code-auditor/gvisor-<版本号>`。脚本拒绝覆盖已有目录，避免替换仍被容器使用的程序；旧的单二进制发行包不适用于此脚本。

也支持先下载再离线安装：

```bash
sudo "$(command -v python)" scripts/sandbox/install-gvisor.py \
  --archive /path/to/gvisor.tar.bz2 \
  --sha512 /path/to/gvisor.tar.bz2.sha512 \
  --destination /opt/code-auditor/gvisor --apply
```

已有官方 apt 包安装的 gVisor 时，可直接使用其 `runsc` 绝对路径进入下一节，不必重复安装。

### 向 Docker 登记 runsc

默认配置文件为 `/etc/docker/daemon.json`。如果服务通过 `--config-file` 使用其他文件，先用 `systemctl cat docker` 核对，并给脚本传入正确的 `--config` 路径。

```bash
# 预览合并内容
sudo "$(command -v python)" scripts/sandbox/configure-gvisor.py \
  --runsc /opt/code-auditor/gvisor/runsc

# 校验候选配置、备份原文件并原子替换；不执行 reload
sudo "$(command -v python)" scripts/sandbox/configure-gvisor.py \
  --runsc /opt/code-auditor/gvisor/runsc --apply
```

脚本只加入下面的条目，保留仓库镜像源、数据目录、其他 runtimes 及原来的 `default-runtime`。这是**合并片段**，不能直接覆盖已有完整配置：

```json
{
  "runtimes": {
    "runsc": {"path": "/opt/code-auditor/gvisor/runsc"}
  }
}
```

写入前会执行 `dockerd --validate --config-file <候选文件>`；校验失败时保留原配置。已有文件的备份名形如 `daemon.json.code-auditor-<时间>-<随机标识>.bak`，权限为 `0600`。若已有 `runsc` 条目与目标不同，脚本会停止；确认要替换旧路径或参数后加 `--replace`。重复执行相同配置不改写文件。

### Reload 并验证

```bash
sudo systemctl reload docker
docker info --format 'default={{.DefaultRuntime}} runtimes={{range $name, $value := .Runtimes}}{{$name}} {{end}}'
python scripts/sandbox/sandboxctl.py check --runtime runsc --backend claude
python scripts/sandbox/sandboxctl.py verify --runtime runsc
```

Docker 支持 reload 更新 `runtimes`，见 [daemon 配置重载说明](https://docs.docker.com/reference/cli/dockerd/#configuration-reload-behavior)。列表中应出现 `runsc`，默认 runtime 保持原值。若服务不支持 reload，或配置与启动参数冲突，先查看 `journalctl -u docker -n 100 --no-pager` 并核对服务配置；确实需要 restart 时，安排所有相关容器任务结束后再进行。

出现在 runtime 列表中只证明已经登记。`verify --runtime runsc` 两项测试通过，才证明基础容器生命周期和边界行为已验证，仍不覆盖所有 Agent 协议、系统调用和性能表现。容器内 `dmesg` 文字不能用作可信 runtime 证明，参见 [gVisor Docker 快速入门](https://gvisor.dev/docs/user_guide/quick_start/docker/)。

### 在 CodeAuditor 中选择 gVisor

在 **Settings → Stage 5/6 execution** 中，将 `Container runtime` 改为 **gVisor (runsc)**，保持所需网络模式并保存。检查失败时不能启用；实际启动遇到 runtime 不可用或检查不匹配也会失败，不会回退到 runc。

设置保存在 `~/.code_auditor/settings.json`。以下仅列相关字段，其他字段应保留；运行中的 Web 服务优先通过界面修改：

```json
{
  "sandbox_mode": "docker-networked",
  "sandbox_runtime": "runsc"
}
```

新任务和恢复执行使用新设置，已运行任务保留其 runtime 设置。完成程序升级后，应在现有任务结束后重启 CodeAuditor 以加载新版代码。恢复只新增后续容器记录，不会把旧产物重新标记为由 gVisor 生成。

## 3. 路径配置、排错与回退

| 配置 | 默认值 | 设置位置 |
| --- | --- | --- |
| 执行方式 / runtime | `docker-networked` / `docker-default` | Web Settings 的 `sandbox_mode` / `sandbox_runtime` |
| 沙箱镜像 | `code-auditor-sandbox:latest` | 服务环境变量 `CODE_AUDITOR_SANDBOX_IMAGE` |
| 临时沙箱根目录 | `/tmp/code-auditor` | 服务环境变量 `CODE_AUDITOR_SANDBOX_ROOT` |
| Docker 可执行文件 | `docker` | 服务环境变量 `CODE_AUDITOR_DOCKER_BIN` |

检查、构建和验证脚本也使用这些环境变量。仅在终端 `export` 不会改变已运行服务的环境；更改服务环境后，应在合适的任务间隙重新启动 CodeAuditor。当前应用容器默认限制为 16 GiB 内存、8 CPU、2048 PID，定义在 `AuditConfig`；Web Settings 没有对应字段。基础验证使用更小的测试限制。

| 现象 | 处理 |
| --- | --- |
| Docker socket `permission denied` | 用服务账号检查组权限及 `docker info` |
| `runsc is not registered` | 核对实际 daemon 的配置文件、reload 结果与 Docker context |
| 镜像缺失 | 在相同 Docker 环境执行 `sandboxctl.py build-image` |
| scratch 空间不足 | 将 `CODE_AUDITOR_SANDBOX_ROOT` 指向有足够空间、服务账号可写的分区 |
| 找不到 Agent CLI | 在服务使用的 Python、PATH 和账号环境配置所选后端，再运行 `check` |
| 断网后模型连接失败 | 选择联网模式；`--network none` 同样隔离模型 API |
| gVisor 启动或 syscall 失败 | 查看启动错误，结合 [gVisor 兼容性说明](https://gvisor.dev/docs/user_guide/compatibility/)核对工作负载；可显式切换回 runc |

回退 CodeAuditor 的执行方式时，在 Web 中选择 **runc**，保存后用于新任务或恢复执行。保留正在运行的 runsc 容器所依赖的旧安装目录。

撤销 Docker 配置修改前，先确认没有任务继续使用该 runtime，核对脚本输出的备份文件及此后的其他配置改动。可用 `dockerd --validate --config-file <备份路径>` 验证，再恢复对应配置并 reload。若原配置不存在，则没有备份，此时只移除新增的 `runtimes.runsc`，保留后来加入的其他配置。

升级时安装到新目录，用 `configure-gvisor.py --runsc <新目录>/runsc --replace` 预览并应用，reload 后重新运行 `verify --runtime runsc`。旧容器退出前保留旧程序目录和 `gvisor-bin/`。脚本不自动删除已有 runtime、容器、镜像或历史数据。

## Execution implementation reference

Stage 5/6 Docker execution supports `docker-default`, `runc`, and optional gVisor (`runsc`). Choose the runtime in Web Settings; it is persisted as `sandbox_runtime` in the server's settings file. `docker-default` resolves Docker's default when a task prepares its scratch directory. That resolved runtime and the inspected immutable image ID are then passed explicitly to every container for that scratch.

New jobs and resumed executions use the selected setting. An active job keeps its runtime setting. Resuming a run preserves earlier execution records and adds records for subsequent container launches; it does not reclassify previously produced artifacts.

### Startup and cleanup

The capability endpoint checks the daemon, runtime registration, installed image, scratch disk space, and backend assets. It returns `launch_verified: false`: these checks do not prove that a container or a model backend can start.

Each launch writes a pending record, creates the container, and inspects its runtime and image before starting it. A mismatch or unavailable runtime fails without fallback. The host attaches the Agent SDK's input/output to the container and inspects its actual exit state before removal. An interrupted launch without a confirmed exit keeps `exit_code: null`.

Cleanup uses both scratch and Agent invocation labels, so cancelling an invocation does not remove a concurrent status-checker's container. The launch supervisor removes its own container; the owning Agent invocation and final scratch teardown also perform label-based cleanup. Removal is verified with a subsequent empty Docker query. Failure to verify cleanup is recorded and prevents an otherwise successful invocation from succeeding. If the supervisor is killed, the parent can complete cleanup from labels and the pending journal. Abrupt termination of the whole host service still requires orphan reconciliation; no startup sweeper is included.

### Records and logs

The host writes these files outside the container's bind mounts:

```text
{output}/.sandbox-executions/{scratch_id}/
├── {execution_id}.json
└── agent-{logical_log_hash}.log
```

Directories have mode `0700`; newly created records and logs have mode `0600`. Record replacement is atomic. Log opening rejects symlinks and files with multiple hard links. Scratch cleanup retains this directory. The History Agent log endpoint also discovers these protected logs.

Records include Run/job and invocation identities, source commit, requested and inspected runtime/image identity, available Docker/runtime/kernel versions, requested and inspected resource/network settings, selected security options, exit/OOM state, and cleanup result. Missing version information remains `null`; a local binary version is not assumed to represent the daemon's runtime. Records intentionally omit command arguments, environment variables, credentials, and complete Docker inspect output. Agent logs still contain Agent output and should be treated as sensitive.

History's **Container executions** panel lists the latest 100 launches. Full records are available through the authenticated API:

- `GET /api/history/{run_id}/sandbox-executions?limit=100&offset=0` (maximum page size 500), filtered by Run ID even when output directories are reused.
- `GET /api/reproduction/{job_key}/sandbox-executions`, for a standalone reproduction job retained by the Web worker.

SQLite remains the authority for audit run identity; actual launch metadata is stored in this host journal. Records describe individual container launches, not provenance for every exported artifact. Old runs without records have unknown environments. A host user with access to the output directory can change these files; this is not remote attestation.

### Optional gVisor validation

Use the setup steps above to install and register `runsc`. The application and tests do not install runtimes, edit Docker configuration, pull images, or restart services. Only the explicitly invoked setup scripts with `--apply` perform installation/configuration changes.

For deployment verification, prefer `sandboxctl.py verify --runtime runc` or `--runtime runsc`, which treats missing prerequisites and skipped tests as failures. Developers can also opt into the original benign checks, which allow explicit skips:

```bash
CODE_AUDITOR_RUN_SANDBOX_TESTS=1 python -m pytest -q -rs \
  code_auditor/tests/test_sandbox_integration.py
```

The checks run separately for registered `runc` and `runsc` runtimes. Missing prerequisites produce explicit skips. The workload makes no model calls: it checks a read-only root filesystem, allowed scratch writes, separation from host log/control paths, UID and inspected resource settings, exit recording, and parent cleanup after the launch supervisor is killed. Only test-owned containers and scratch directories are removed. The ordinary `pytest -q` suite skips these live checks.

Passing these checks establishes basic container lifecycle and boundary behavior only. Backend protocol compatibility, workload-specific syscall support, and performance require separate validation. gVisor provides a userspace kernel boundary that reduces direct exposure to the host kernel, with compatibility and performance tradeoffs described in its [architecture](https://gvisor.dev/docs/architecture_guide/intro/) and [compatibility documentation](https://gvisor.dev/docs/user_guide/compatibility/).

### Scope

The selected runtime applies to Stage 5/6 Docker invocations. Earlier stages, the Web terminal, and local-worktree mode still execute on the host. Networked mode uses Docker bridge networking; it has no outbound allowlist. Isolated mode uses `--network none`, which also prevents the containerized Agent from reaching remote model APIs. Provider credentials required by the Agent remain available inside its container. Bind-mounted scratch data and retained logs do not acquire disk quotas from this change.

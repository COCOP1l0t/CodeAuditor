<p align="center">
  <a href="README.md">English</a> | <b>🇨🇳 中文</b>
</p>

# CodeAuditor

CodeAuditor 是一个多阶段智能代码审计流水线，支持 [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) 和 [Codex App Server Python SDK](https://github.com/openai/codex/blob/main/sdk/python/README.md)。它会研究目标项目、发现并评估安全缺陷、复现已确认的漏洞，并生成可用于披露的报告。

CodeAuditor 已帮助多个常用开源项目发现 CVE，详见[已发现漏洞](#已发现漏洞)。

## 工作原理

一次审计依次经过七个阶段：

| 阶段 | 目的 |
|------|------|
| 0 | 更新目标仓库并准备输出目录 |
| 1 | 研究安全背景并确定审计重点 |
| 2 | 将代码库拆分为分析单元（AU） |
| 3 | 在各分析单元中发现缺陷 |
| 4 | 评估可达性、影响和严重程度 |
| 5 | 复现已确认的漏洞并收集证据 |
| 6 | 准备报告、邮件、最小 PoC 和披露包 |

各阶段之间会验证输出并记录检查点。阶段 1 生成的项目特定审计重点和漏洞判定标准会指导后续分析。

## 环境要求

- Python **3.12+**
- Git；仅 Docker 沙箱模式需要可用的 Docker Engine
- [Claude Code](https://docs.claude.com/en/docs/claude-code)，或支持 `codex app-server` 的 Codex CLI；后端在 Web 设置中选择

## 安装

```bash
git clone https://github.com/COCOP1l0t/CodeAuditor.git
cd CodeAuditor
pip install -e .
```

## 快速开始

启动 Web 界面，然后打开 `http://127.0.0.1:8000`：

```bash
code-auditor
```

`--web` 继续作为兼容的显式写法：

```bash
code-auditor --web --host 0.0.0.0 --port 8000
```

Web 服务选项：

| 标志 | 说明 |
|------|------|
| `--web` | 显式启动 Web 界面；Web 已是默认模式，因此可以省略 |
| `--host` | 绑定地址；默认 `0.0.0.0` |
| `--port` | 监听端口；默认 `8000` |

仓库、Wiki、后端、模型、沙箱模式、并行度和输出路径等审计参数统一由 Web 界面和 `~/.code_auditor/settings.json` 管理。维护命令请查看 `code-auditor --help`。

阶段 5 和 6 可选择联网 Docker 沙箱、断网 Docker 沙箱或宿主机独立 worktree。Web 设置只有在服务端通过 Docker、镜像、磁盘空间和 Agent 运行时检查后，才会启用 Docker 选项。Docker 是默认模式；审计进入复现阶段前，先构建一次镜像：

```bash
docker build -f docker/code-auditor-sandbox.Dockerfile \
  -t code-auditor-sandbox:latest docker
```

## Web 界面

通过 Web 界面可以启动和监控审计、查看历史与披露、检查 PoC 结果及重新复现。报告和 PoC 产物保留在结果目录中，审计元数据存入 SQLite。

默认的 `0.0.0.0` 会在所有网络接口上暴露 Web 界面；不需要远程访问时，请使用 `--host 127.0.0.1` 限制为本机访问。Web 界面可以启动智能体，并为已复现的 PoC 提供交互式 Shell；设置文件也可能包含 API Key。

## Wiki 知识库

Web 界面会发现 `~/.code_auditor/wiki/` 下的知识库。CodeAuditor 将所选 Wiki 视为只读辅助背景，而不是漏洞证据。

可参考 [QEMU-Security-Wiki](https://github.com/qianfei11/QEMU-Security-Wiki)。

## 输出目录

```text
{output-dir}/
├── stage1-security-context/
├── stage2-analysis-units/
├── stage3-findings/
├── stage4-vulnerabilities/
├── stage5-pocs/
├── stage6-disclosures/
└── .markers/
```

同一仓库 commit 会复用输出目录并从检查点恢复。若要重新开始，请删除输出目录或其中的 `.markers/` 目录。

## 开发

```bash
pip install -e '.[test]'
pytest -q
```

测试不会发起真实的智能体调用。

## 已发现漏洞

CodeAuditor 帮助发现和披露的漏洞：

| CVE ID | 项目 | CVSS 基础分 | 严重程度 | 参考 |
|--------|------|-------------|----------|------|
| CVE-2026-28780 | [httpd](https://github.com/apache/httpd) | 9.8 | Critical | [GitHub](https://github.com/apache/httpd) |
| CVE-2026-34032 | [httpd](https://github.com/apache/httpd) | 5.3 | Medium | [GitHub](https://github.com/apache/httpd) |
| CVE-2026-40312 | [ImageMagick](https://github.com/ImageMagick/ImageMagick) | 5.5 | Medium | [GitHub](https://github.com/ImageMagick/ImageMagick) |
| CVE-2026-40385 | [libexif](https://github.com/libexif/libexif) | 7.1 | High | [GitHub](https://github.com/libexif/libexif) |
| CVE-2026-40386 | [libexif](https://github.com/libexif/libexif) | 7.1 | High | [GitHub](https://github.com/libexif/libexif) |
| CVE-2026-7180 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [GitLab](https://gitlab.com/qemu-project/qemu) |
| CVE-2026-8341 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.5 | Medium | [#3750](https://gitlab.com/qemu-project/qemu/-/work_items/3750) |
| CVE-2026-8343 | [QEMU](https://gitlab.com/qemu-project/qemu) | 5.3 | Medium | [#3791](https://gitlab.com/qemu-project/qemu/-/work_items/3791) [#3807](https://gitlab.com/qemu-project/qemu/-/work_items/3807) [#3827](https://gitlab.com/qemu-project/qemu/-/work_items/3827) |
| CVE-2026-8348 | [QEMU](https://gitlab.com/qemu-project/qemu) | 4.4 | Medium | [#3810](https://gitlab.com/qemu-project/qemu/-/work_items/3810) |
| CVE-2026-9238 | [QEMU](https://gitlab.com/qemu-project/qemu) | 5.5 | Medium | [#3820](https://gitlab.com/qemu-project/qemu/-/work_items/3820) |
| CVE-2026-15705 | [QEMU](https://gitlab.com/qemu-project/qemu) | 5.3 | Medium | [#3808](https://gitlab.com/qemu-project/qemu/-/work_items/3808) |
| CVE-2026-41437 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [#3711](https://gitlab.com/qemu-project/qemu/-/work_items/3711) |
| CVE-2026-41439 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [#3714](https://gitlab.com/qemu-project/qemu/-/work_items/3714) |
| CVE-2026-48914 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.7 | Medium | [GitLab](https://gitlab.com/qemu-project/qemu) |
| CVE-2026-48915 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.1 | Medium | [#3857](https://gitlab.com/qemu-project/qemu/-/work_items/3857) |
| CVE-2026-61405 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.0 | Medium | [#3890](https://gitlab.com/qemu-project/qemu/-/work_items/3890) |
| CVE-2026-61406 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.5 | Medium | [#3899](https://gitlab.com/qemu-project/qemu/-/work_items/3899) |
| CVE-2026-61476 | [QEMU](https://gitlab.com/qemu-project/qemu) | 4.4 | Medium | [#3875](https://gitlab.com/qemu-project/qemu/-/work_items/3875) |
| CVE-2026-63324 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [#3984](https://gitlab.com/qemu-project/qemu/-/work_items/3984) |
| CVE-2026-53701 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 6.5 | Medium | [#5035](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5035) |
| CVE-2026-53702 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 6.5 | Medium | [#5036](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5036) |
| CVE-2026-53703 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 7.1 | High | [#5038](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5038) |
| CVE-2026-53704 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 7.1 | High | [#5039](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5039) |

## 负责任的使用

CodeAuditor 旨在用于审计您拥有或已获得明确测试许可的代码，并用于向上游维护者进行协调披露。请勿在未授权的情况下将其用于针对系统或项目。

**重要提示：** 在向项目维护者发送任何漏洞报告之前，请手动审查生成的披露材料。验证漏洞是否真实、严重程度评估是否准确，以及概念验证是否确实能复现该问题。自动化发现可能包含误报或不准确之处，可能会浪费维护者的时间或损害您的信誉。


## 许可证

Apache License 2.0 — 详见 [LICENSE](LICENSE)。

本软件仅供教育、研究和实验目的使用。详见 LICENSE 文件顶部的免责声明。

# README i18n, Vulnerability Table, and ASCII Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Chinese README translation, language selection badges, a per-row CVE vulnerability table, and a Unicode ASCII architecture diagram to the project READMEs.

**Architecture:** Two parallel README files (`README.md` and `README.zh.md`) linked by top-of-file language badges. `README.md` is refactored in-place to include the new table and diagram sections. `README.zh.md` mirrors the structure with Chinese text.

**Tech Stack:** Markdown (GitHub-flavored). No code or dependencies.

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `README.md` | Modify | Add language badges, ASCII architecture diagram, CVE table. |
| `README.zh.md` | Create | Complete Chinese translation with identical structure and formatting. |

---

### Task 1: Add Language Badges to README.md

**Files:**
- Modify: `README.md:1-3` (top of file, before the `# CodeAuditor` heading)

- [ ] **Step 1: Insert language selector badges**

  Add the following HTML block immediately before the `# CodeAuditor` line at the very top of `README.md`:

  ```markdown
  <p align="center">
    <b>🇺🇸 English</b> | <a href="README.zh.md">中文</a>
  </p>

  ```

- [ ] **Step 2: Verify badge renders**

  Open `README.md` in a Markdown previewer and confirm the top line shows two clickable language options with English bolded/active.

---

### Task 2: Add ASCII Architecture Diagram to README.md

**Files:**
- Modify: `README.md` (inside or directly after the `## How it works` section)

- [ ] **Step 1: Insert a new subsection with the diagram**

  Immediately after the paragraph that ends with "...stays aligned with the project's actual threat model.", add:

  ```markdown
  ### System Design

  ```
  ┌─────────────┐
  │ Target Repo │
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐     ┌─────────────────────────────┐
  │  Stage 0    │     │      DIRECTIVE INJECTION    │
  │    Init     │────►│  ┌─────────┐  ┌─────────┐  │
  └─────────────┘     │  │Auditing │  │Vuln     │  │
         │            │  │ Focus   │  │Criteria │  │
         ▼            │  └───┬─────┘  └────┬────┘  │
  ┌─────────────┐     │      │             │       │
  │  Stage 1    │────►│      └──────┬──────┘       │
  │   Context   │     └─────────────┼──────────────┘
  └─────────────┘                   │
         │                          │
         ▼                          ▼
  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │  Stage 2    │──►│  Stage 3    │──►│  Stage 4    │──►│  Stage 5    │──►│  Stage 6    │
  │  Decompose  │   │   Discover  │   │   Evaluate  │   │     PoC     │   │   Disclose  │
  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └──────┬──────┘
                                                                                   │
                                                                                   ▼
                                                                            ┌─────────────┐
                                                                            │  Disclosure │
                                                                            │   Package   │
                                                                            └─────────────┘
  ```
  ```

  *(Note: the outer triple-backticks in the plan should be single triple-backticks in the actual file; the inner code block should be wrapped in triple-backticks so it renders as a monospace code block on GitHub.)*

  **Exact insertion:** Add a blank line after the Stage 1 paragraph, then the `### System Design` heading, a blank line, then open triple backticks, the ASCII art, then close triple backticks.

- [ ] **Step 2: Verify layout**

  Preview the Markdown and confirm:
  - The diagram renders in a fixed-width code block.
  - All boxes and arrows align vertically.
  - The "DIRECTIVE INJECTION" box sits above Stages 2–4 with arrows implied by placement.

---

### Task 3: Refactor Vulnerability Section into a Table

**Files:**
- Modify: `README.md` (the `## Vulnerabilities found` section)

- [ ] **Step 1: Replace the nested list with a table**

  Find the section starting with `## Vulnerabilities found` and replace everything from that heading through the end of the QEMU list with:

  ```markdown
  ## Vulnerabilities Found

  Vulnerabilities CodeAuditor has helped discover and disclose:

  | CVE ID | Project | Year | Reference |
  |--------|---------|------|-----------|
  | CVE-2026-28780 | [httpd](https://github.com/apache/httpd) | 2026 | [GitHub](https://github.com/apache/httpd) |
  | CVE-2026-34032 | [httpd](https://github.com/apache/httpd) | 2026 | [GitHub](https://github.com/apache/httpd) |
  | CVE-2026-40312 | [ImageMagick](https://github.com/ImageMagick/ImageMagick) | 2026 | [GitHub](https://github.com/ImageMagick/ImageMagick) |
  | CVE-2026-40385 | [libexif](https://github.com/libexif/libexif) | 2026 | [GitHub](https://github.com/libexif/libexif) |
  | CVE-2026-40386 | [libexif](https://github.com/libexif/libexif) | 2026 | [GitHub](https://github.com/libexif/libexif) |
  | CVE-2026-7180 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | [GitLab](https://gitlab.com/qemu-project/qemu) |
  ```

- [ ] **Step 2: Verify table renders**

  Confirm in a Markdown previewer that:
  - Each CVE gets its own row.
  - The table has 7 rows (including header).
  - Project names are clickable links.

---

### Task 4: Create README.zh.md

**Files:**
- Create: `README.zh.md`

- [ ] **Step 1: Write the complete Chinese translation**

  Create `README.zh.md` with the exact content below. Preserve all code blocks, table structures, and ASCII art exactly as in the English version. Only translate prose text.

  ```markdown
  <p align="center">
    <a href="README.md">English</a> | <b>🇨🇳 中文</b>
  </p>

  # CodeAuditor

  一个多阶段、智能化的代码审计流水线，支持在 [Claude Code SDK](https://github.com/anthropics/claude-code-sdk-python) 或 [Codex App Server Python SDK](https://github.com/openai/codex/blob/main/sdk/python/README.md) 上运行。给定一个目标源码树，CodeAuditor 会研究项目背景、将代码库分解为分析单元、寻找漏洞、将其评估为安全漏洞、用可工作的 PoC 复现，并最终准备一份可供披露的完整报告包。

  CodeAuditor 已在多个广泛使用的开源项目中发现了 CVE — 详见下方的 [已发现漏洞](#已发现漏洞)。

  ## 工作原理

  审计以七个顺序阶段运行。每个阶段由 `prompts/` 中的提示模板驱动，并由一个或多个后端智能体执行。输出会经过验证，验证失败时会发送修复提示（最多 `max_retries` 次）。中间产物会写入输出目录；`.markers/` 文件夹会跟踪已完成的子任务，以便运行可以恢复。

  | 阶段 | 工作内容 | 并行度 |
  |------|---------|--------|
  | 0 | Git 拉取 + 创建输出目录 | 无 |
  | 1 | 安全背景研究（git 历史、网络搜索、`SECURITY.md`） | 单个智能体 |
  | 2 | 将项目分解为分析单元（AU） | 单个智能体 |
  | 3 | 每个分析单元的漏洞发现 | 每 AU 1 个智能体 |
  | 4 | 评估发现：真实漏洞？严重程度？ | 每发现 1 个智能体 |
  | 5 | PoC 复现：构建、利用、捕获证据 | 每漏洞 1 个智能体 |
  | 6 | 披露：技术报告、邮件、最小 PoC、压缩包 | 每漏洞 1 个智能体 |

  阶段 1 会产生两个指令 —— *审计重点* 和 *漏洞判定标准* —— 这些指令会被注入到后续阶段，确保整个流水线与项目实际威胁模型保持一致。

  ### 系统设计

  ```
  ┌─────────────┐
  │ Target Repo │
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐     ┌─────────────────────────────┐
  │  Stage 0    │     │      DIRECTIVE INJECTION    │
  │    Init     │────►│  ┌─────────┐  ┌─────────┐  │
  └─────────────┘     │  │Auditing │  │Vuln     │  │
         │            │  │ Focus   │  │Criteria │  │
         ▼            │  └───┬─────┘  └────┬────┘  │
  ┌─────────────┐     │      │             │       │
  │  Stage 1    │────►│      └──────┬──────┘       │
  │   Context   │     └─────────────┼──────────────┘
  └─────────────┘                   │
         │                          │
         ▼                          ▼
  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │  Stage 2    │──►│  Stage 3    │──►│  Stage 4    │──►│  Stage 5    │──►│  Stage 6    │
  │  Decompose  │   │   Discover  │   │   Evaluate  │   │     PoC     │   │   Disclose  │
  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └──────┬──────┘
                                                                                   │
                                                                                   ▼
                                                                            ┌─────────────┐
                                                                            │  Disclosure │
                                                                            │   Package   │
                                                                            └─────────────┘
  ```

  ## 环境要求

  - Python **3.12+**
  - 已安装的 [Claude Code](https://docs.claude.com/en/docs/claude-code)（用于 `--backend claude`，SDK 会复用其认证）
  - 位于 `/usr/local/bin/codex` 的 Codex CLI，支持 `codex app-server` 和本地 Codex 认证/会话（用于 `--backend codex`）
  - Git，以及目标项目在阶段 5 复现所需的构建工具

  ## 安装

  ```bash
  git clone https://github.com/<owner>/CodeAuditor.git
  cd CodeAuditor
  pip install -e .
  ```

  这会暴露 `code-auditor` CLI 入口点。

  ## 用法

  ```bash
  code-auditor --target /path/to/project [options]
  ```

  ### 常用选项

  | 标志 | 说明 |
  |------|------|
  | `--target` | **必需。** 要审计的项目根目录。 |
  | `--output-dir` | 输出目录（默认：`{target}/audit-output`）。 |
  | `--max-parallel` | 最大并发智能体数（默认：`1`）。 |
  | `--backend` | 智能体后端：`claude` 或 `codex`（默认：`claude`）。 |
  | `--model` | 后端模型覆盖。Claude 默认为 `claude-sonnet-4-6`；Codex 使用本地 Codex 配置默认值，除非另行指定。 |
  | `--target-au-count` | 阶段 2 的目标分析单元数量（默认：`10`）。 |
  | `--log-level` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`（默认：`INFO`）。 |

  运行会自动从检查点标记恢复 —— 删除输出目录（或其 `.markers/` 子目录）以开始全新的审计。

  ### 示例

  ```bash
  code-auditor \
    --target ~/projects/libfoo \
    --output-dir ~/audits/libfoo \
    --max-parallel 4 \
    --log-level DEBUG
  ```

  ## 输出目录结构

  ```
  {output-dir}/
  ├── stage1-security-context/  # 背景研究 + 审计重点 + 漏洞判定标准
  ├── stage2-analysis-units/    # 代码库分解
  ├── stage3-findings/          # 每 AU 的漏洞发现
  ├── stage4-vulnerabilities/   # 经过评估、确认的漏洞
  ├── stage5-pocs/              # PoC + 证据
  ├── stage6-disclosures/       # 披露报告、邮件、压缩 PoC
  └── .markers/          # --resume 的检查点标记
  ```

  ## 项目结构

  ```
  code_auditor/
  ├── __main__.py          # CLI 入口点
  ├── config.py            # AuditConfig 和数据类
  ├── orchestrator.py      # 顺序阶段运行器
  ├── agent.py             # 后端封装 + 验证重试循环
  ├── prompts.py           # 支持 __KEY__ 替换的提示加载器
  ├── checkpoint.py        # 基于标记的检查点/恢复
  ├── logger.py            # 日志辅助工具
  ├── utils.py             # 并行 + 文件辅助工具
  ├── stages/              # stage0 – stage6
  ├── parsing/             # 从智能体输出中提取结构化数据
  ├── validation/          # 每阶段输出验证器
  └── tests/
  prompts/                 # stage1.md – stage6.md 提示模板
  ```

  ## 开发

  ```bash
  pytest                       # 运行所有测试
  pytest code_auditor/tests    # 同上
  pytest -k stage2             # 按名称过滤
  ```

  测试覆盖解析器和验证器；它们不会进行真实的智能体调用。

  ## 已发现漏洞

  CodeAuditor 帮助发现和披露的漏洞：

  | CVE ID | 项目 | 年份 | 参考 |
  |--------|------|------|------|
  | CVE-2026-28780 | [httpd](https://github.com/apache/httpd) | 2026 | [GitHub](https://github.com/apache/httpd) |
  | CVE-2026-34032 | [httpd](https://github.com/apache/httpd) | 2026 | [GitHub](https://github.com/apache/httpd) |
  | CVE-2026-40312 | [ImageMagick](https://github.com/ImageMagick/ImageMagick) | 2026 | [GitHub](https://github.com/ImageMagick/ImageMagick) |
  | CVE-2026-40385 | [libexif](https://github.com/libexif/libexif) | 2026 | [GitHub](https://github.com/libexif/libexif) |
  | CVE-2026-40386 | [libexif](https://github.com/libexif/libexif) | 2026 | [GitHub](https://github.com/libexif/libexif) |
  | CVE-2026-7180 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | [GitLab](https://gitlab.com/qemu-project/qemu) |

  ## 负责任的使用

  CodeAuditor 旨在用于审计您拥有或已获得明确测试许可的代码，并用于向上游维护者进行协调披露。请勿在未授权的情况下将其用于针对系统或项目。

  **重要提示：** 在向项目维护者发送任何漏洞报告之前，请手动审查生成的披露材料。验证漏洞是否真实、严重程度评估是否准确、以及概念验证是否确实能复现该问题。自动化发现可能包含误报或不准确之处，可能会浪费维护者的时间或损害您的信誉。

  ## 许可证

  Apache License 2.0 — 详见 [LICENSE](LICENSE)。

  本软件仅供教育、研究和实验目的使用。详见 LICENSE 文件顶部的免责声明。
  ```

- [ ] **Step 2: Verify README.zh.md renders**

  Open `README.zh.md` in a Markdown previewer and confirm:
  - The language selector at the top shows English as a link and 中文 as bold.
  - All tables render correctly (stages, options, vulnerabilities).
  - The ASCII architecture diagram renders in a monospace code block.
  - No broken relative links.

---

### Task 5: Final Verification and Commit

**Files:**
- Modify: `README.md`
- Create: `README.zh.md`

- [ ] **Step 1: Diff review**

  Run:
  ```bash
  git diff README.md
  ```

  Expected changes:
  - Language badges added at top.
  - `### System Design` subsection added after Stage 1 description.
  - `## Vulnerabilities Found` replaced with a markdown table.

  Run:
  ```bash
  git status
  ```

  Expected: `README.md` modified, `README.zh.md` untracked.

- [ ] **Step 2: Stage and commit**

  ```bash
  git add README.md README.zh.md
  git commit -m "$(cat <<'EOF'
docs: add Chinese README, ASCII architecture diagram, and CVE table

- Add README.zh.md with complete Chinese translation
- Add language selector badges to both README files
- Refactor Vulnerabilities Found section into per-CVE table
- Add fancy Unicode ASCII system design diagram

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
  ```

---

## Spec Coverage Checklist

| Spec Requirement | Implementing Task |
|------------------|-------------------|
| Separate `README.md` + `README.zh.md` with cross-linking badges | Task 1, Task 4 |
| CVE ID as main column, one row per CVE | Task 3 |
| Unicode box-drawing ASCII architecture (high-level pipeline) | Task 2, Task 4 |
| Preserve all formatting, code blocks, tables in translation | Task 4 |

## Placeholder Scan

- [x] No "TBD", "TODO", or "implement later" found.
- [x] No vague "add appropriate error handling" or "write tests for the above" steps.
- [x] All file paths are exact.
- [x] All markdown content is provided verbatim in the plan.

## Type Consistency

N/A — this is a documentation-only change with no code types or signatures.

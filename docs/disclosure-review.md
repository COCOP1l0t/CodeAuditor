# Disclosure 审核与数据质量

SQLite 管理条目的身份、审核状态和附件索引；Stage 4/5/6 文件保存原始材料。
审核状态与复现状态分别记录。静态检查通过不代表漏洞成立、PoC 已运行或人工确认完成。

## 去重

精确 dedupe key 保持稳定，不因标题、审核状态或本次格式修正而重算。
语义比较的输入同时包含历史登记条目和本批次先前保留的候选，避免空历史库或同批次
发现不同表述时漏去重。错误或无效的比较结果保留候选，供人工审核。

人工归并应记录主条目的身份和理由，将重复条目标为 `duplicated`，并保留全部原始
文件。相同 CWE、影响或项目不足以证明重复；归并后仍需保留不同部署条件与证据边界。
重新同步不会覆盖已审核条目的标题或已有审核摘要；生成的 Stage 4/5/6 链接按当前
材料刷新，已登记的审核说明及其他补充附件保留。

## 静态检查

`code_auditor.validation.stage6.validate_stage6_disclosure` 只读文档和压缩包，不执行其中
的程序。Stage 6 在导出、完成标记和检查点复用前执行检查；不合格时报告失败，已有
失效检查点会被清除，本次检查不会自动启动修复或重跑。

- 邮件使用 Subject 头，头与正文之间有空行；主题折行以空格开头。正文单独按 72 列
  换行，不能对整封邮件直接使用通用折行命令。主题解析不拼接无缩进的正文。
- 支持标准 Stage 6 章节及 GitHub 的 `Summary / Details / PoC / Impact` 格式；仅检查
  实际 Markdown 标题，代码围栏里的示例标题不计。必需章节不能留空。
- CVSS v3.1 使用 [FIRST 官方公式](https://www.first.org/cvss/v3.1/specification-document#7-cvss-v31-equations)
  检查分数和向量的一致性。缺指标时不会猜测；算术一致也不证明攻击前提合理。
- ZIP 必须包含一份 report.md，并与目录中存在的同名对应文件保持内容一致。仅保存在
  ZIP 内的支持文件允许存在；归档内的相对符号链接必须留在包内。校验器不解压文件。
- ZIP 不包含 email.txt 或 Python 缓存。文档限制 4 MiB；ZIP 静态读取限制为 4096 个成员、
  256 MiB 声明解压总量。超限返回明确诊断。

## 缺件、历史状态与修复

复现状态已变为失败或部分成功的旧条目不能继续以未经说明的 unreviewed 形式出现。
同步阶段会检查当前 Run 的 Stage 5 状态，即使 Stage 6 路径已经清空；没有其他保留的
成功 Run 时，仅把尚未审核的旧记录转为 `triage` 并记录原因。已报告或其他人工审核
状态不自动覆盖，不删除原始记录。

缺失的材料只能从可核验的原始档案恢复。没有证据时保留缺件说明，不生成“已复现”
报告；存在两个不同脚本版本时应保存各自哈希和来源，不能仅凭时间较新选择有效版本。
格式修改应先备份数据库和原文件，同步 report.md 与 ZIP 中的文档，核验其余归档成员
没有改变。模板不得将自动运行结果称为人工验证。

## 最新源码重新复现

Web 的 Reproduce 标签页以 `project + dedupe_key` 选择活动 Disclosure。开始任务后，
服务端核对托管 checkout 的 origin，拉取远端默认分支并立即固定完整 commit SHA；共享
checkout 不会被切换。测试在该 SHA 的独立 worktree 和已配置的 Stage 5/6 沙箱中进行，
历史 Disclosure 仅作为只读复现上下文。

服务端根据 Stage 5 报告记录确定性的 `reproduced`、`not-reproduced` 或 `inconclusive`
结果及证据等级。随后 Agent 可以分析当前源码并给出 `still-vulnerable`、`likely-fixed`、
`harness-stale`、`environment-blocked` 等判断，但 Agent 不能改写已经记录的运行结果。
源码分析、构建成功和历史证据都不能升级为本次运行复现。

只有本次结果为 `reproduced` 时才接受更新草稿。草稿必须通过 Stage 6 静态检查和
`retain-manifest.json` 边界检查。Apply Draft 会把当前 `disclosure/` 原子归档到同级
`revisions/` 后安装草稿，并更新 SQLite 中的附件索引和已测试 commit；人工审核状态和
CVE 关联保持不变。此操作只更新本地材料，不发送邮件、不提交上游，也不公开漏洞。

## 回收站与永久清理

删除活动 Disclosure 时只设置回收站时间，条目在 30 天内可以恢复，文件不会立即删除。
回收站支持勾选一个或多个条目永久清理，也保留清空全部的操作；搜索和项目筛选只影响
当前可勾选的行。永久清理及 30 天自动过期使用相同边界：删除该条目登记且不再被其他
Disclosure 引用的 `stage5-pocs/<vuln>/` 和
`stage6-disclosures/<vuln>/disclosure/`，同步移除对应 PoC/Disclosure 数据库索引。
Stage 4 finding、审计 Run 和 Stage 6 漏洞目录下的非 Disclosure 日志不在清理范围内。
不属于受管 results 目录且未由数据库 Run 登记的路径不会递归删除。

# Ground truth (answer key)

The machine-readable version is [ground_truth.json](ground_truth.json). Every
entry is verified end-to-end by `./verify.sh`.

The target is deliberately small — **3 planted vulnerabilities in 4 source
files (~250 lines)** — so a full Web UI audit finishes in roughly 10–20
minutes when `max_parallel >= 3`.

## Expected findings

| ID | Where | Class (CWE) | Entry point | Trigger | Expected evidence | Severity band |
|----|-------|-------------|-------------|---------|-------------------|---------------|
| V1 | `src/handlers.c:handle_echo` | stack buffer overflow (CWE-121) | TCP `ECHO` | arg > 127 bytes | ASan stack-buffer-overflow | Critical |
| V2 | `src/handlers.c:handle_exec` | command injection (CWE-78) | TCP `PING` | `127.0.0.1; id` | injected command output | Critical |
| V3 | `src/handlers.c:handle_file` | path traversal (CWE-22) | TCP `GET` | `../` escapes `public/` | file outside `public/` | High |

## Expected non-findings (false-positive traps)

| ID | Where | Why it is not a vulnerability |
|----|-------|-------------------------------|
| T1 | `util_copy_bounded` | Length is clamped to `cap-1` before the copy — correct. |
| T2 | `util_show_time` | `system()` gets a constant string; no attacker data reaches it. |
| T3 | `handle_hello` | Reachable handler that resembles `handle_echo` but copies safely via `util_copy_bounded`. |

## How the key is meant to be used

- **Recall**: V1–V3 should each appear as a Stage 3 finding and survive Stage 4.
- **Precision**: T1–T3 must not be reported at any stage.
- **Reproducibility**: each Stage 5 PoC should trigger the same class of
  evidence that `verify.sh` already demonstrates.

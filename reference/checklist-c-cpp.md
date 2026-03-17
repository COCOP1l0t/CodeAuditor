# Vulnerability Checklist: C / C++

All vulnerability classes are highly relevant. Memory safety and integer issues are the primary
concern in C/C++ codebases.

## 3.1 Memory Safety

- **Buffer overflows** — attacker-controlled length or offset reaching `memcpy`/`strcpy`/`sprintf`
  without validation against destination buffer size.
- **Out-of-bounds reads** — attacker-controlled values used as array indices or pointer offsets
  without bounds checks.
- **Use-after-free** — code paths (especially error paths) where a freed pointer is still
  accessed. Trace attacker-controlled values that influence control flow into error-handling
  branches.
- **Double-free** — attacker-controlled input causing error paths where the same allocation is
  freed twice.
- **Stack overflows** — attacker-controlled message content triggering unbounded recursion (e.g.,
  nested TLV structures).
- **Format string vulnerabilities** — attacker-controlled data reaching a printf-family function
  as the format argument (e.g., `syslog(LOG_ERR, attacker_string)`).
- **Null pointer dereference** — attacker-controlled input causing a lookup or allocation to
  return NULL, which is then dereferenced without a check.
- **Off-by-one errors** — length calculations that forget to account for a null terminator, or
  use `<=` vs `<` in bounds checks.

## 3.2 Integer Issues

- **Integer overflow/underflow** — attacker-controlled length fields added or multiplied without
  overflow checks (e.g., `offset + len` without checking for wraparound).
- **Signed/unsigned confusion** — attacker-controlled values stored in signed variables and later
  compared with unsigned lengths. A negative value can bypass a size check.
- **Truncation** — attacker-controlled 32/64-bit values silently truncated to 8/16-bit before use
  as a length or index.
- **Implicit widening with sign extension** — a signed 8/16-bit value cast to a larger signed
  type will sign-extend, potentially producing a very large value when interpreted as unsigned.
- **Division by zero** — attacker-controlled values reaching a divisor without zero-value
  handling.

## 3.3 Parser Confusion and Logic Bugs

- **Length field manipulation** — attacker setting length=0, length=MAX, or length > actual packet
  size. Verify length fields are validated against actual data length.
- **Missing end-of-buffer checks** — parser not checking that it doesn't read past the end of the
  received buffer at every step.
- **Type confusion** — message type fields not validated strictly before dispatch.
- **Malformed option/TLV handling** — zero-length and maximum-length values in TLV options not
  handled correctly.
- **Loop termination** — loops whose bounds or advancement depend on attacker-controlled data that
  could run forever (e.g., a loop that advances by an `option_len` that could be zero).
- **Extreme and illegal field values** — code not handling extreme values (min/max of the type)
  correctly.
- **Null byte injection / string truncation** — embedded null bytes causing different functions to
  see different string lengths. Especially dangerous when validation uses length-aware functions
  but consumption uses C string functions (`strlen`, `strcmp`).
- **Encoding and charset issues** — invalid UTF-8, overlong encodings that bypass ASCII filters.
- **Protocol smuggling / desynchronization** — crafted messages that two different parsers
  interpret differently.
- **Overlapping or contradictory fields** — redundant expression of the same parameter. Check
  that conflicts are handled defensively.

## 3.4 Injection Sinks

- **Command injection** — attacker-controlled data reaching `exec()`, `system()`, `popen()`.
- **SQL injection** — interpolated into SQL queries without parameterization.
- **Log injection** — written to log files without sanitization.

## 3.5 Resource Exhaustion

- **Unbounded allocation** — attacker-controlled size reaching `malloc`/`realloc` without a cap.
- **State amplification** — attacker causing many expensive state entries without rate limiting.
- **CPU exhaustion** — expensive operations triggered per-message with attacker-controlled params.
- **File descriptor/timer exhaustion** — FDs or timers allocated per-message without limits.
- **Algorithmic complexity attacks (hash DoS)** — predictable hash functions allowing crafted
  collision inputs.
- **Recursive or nested structure bombs** — nested structures causing exponential expansion or
  deep call stacks.
- **Disk exhaustion** — unbounded disk writes from attacker-triggered operations.

## 3.6 Information Leaks

- **Uninitialized data** — stack/heap buffers sent in responses without being fully initialized.
- **Error messages** — error responses including internal state, addresses, or sensitive info.
- **Over-sharing in responses** — internal hostnames, version banners, file paths, debug headers.
- **Memory not cleared after use** — sensitive values not zeroed after use. Use
  `memset_s`/`explicit_bzero` (not `memset` which may be optimized away).
- **Timing side channels** — non-constant-time comparisons of attacker-controlled values against
  secrets.

## 3.7 State Machine Vulnerabilities

- **Out-of-order messages** — sending messages in unexpected order to reach invalid state.
- **Authentication bypass via state confusion** — skipping auth steps by jumping to post-auth
  message types.
- **Replay attacks** — sequence numbers, nonces, or timestamps not validated.
- **Protocol downgrade attacks** — forcing weaker protocol version, cipher suite, or auth method.
- **Session fixation / hijacking** — forcing or predicting session identifiers.
- **Incomplete state cleanup on error** — failed messages not fully rolling back state.
- **Concurrent connection state interference** — shared global state without proper locking.
- **Race conditions** — TOCTOU windows in async processing.

## 3.8 Cryptographic Issues

- **Weak or obsolete algorithms** — MD5, SHA1, DES, RC4 for security-critical purposes.
- **Improper certificate/key validation** — certificate validation not enforced, hostname checks
  missing.
- **Nonce/IV reuse** — nonces or IVs not generated uniquely for each operation.
- **Insufficient randomness** — security-critical values not from a CSPRNG. Check for `rand()`,
  `random()`, or time-based seeding.
- **Key material exposure** — keys/passwords in plaintext in memory, logged, or in errors.
- **Missing encryption** — plaintext fallback on handshake failure.

## 3.9 Concurrency and Thread Safety

- **Shared mutable state without locking** — global/shared data structures accessed from multiple
  threads or callbacks without synchronization.
- **Lock ordering violations** — concurrent operations that can deadlock.
- **Signal handler safety** — signal handlers calling non-async-signal-safe functions (`malloc`,
  `free`, `printf` in a signal handler is undefined behavior).
- **Atomicity assumptions** — multi-step operations on shared state assumed to be atomic.

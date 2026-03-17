# Vulnerability Checklist: Go

Memory safety is largely handled by the Go runtime. Focus on parser logic bugs, resource
exhaustion, state machine issues, and concurrency. Check CGo boundaries for memory safety issues.

## 3.1 Memory Safety (CGo boundaries only)

> Only relevant if the project uses CGo. If no CGo is present, skip this section entirely.

- **Buffer overflows** — data passed to C functions without proper length validation.
- **Use-after-free** — Go-managed memory passed to C and accessed after GC collection.
- **Null pointer dereference** — unchecked nil returns causing panics (DoS).

**Go-specific concern**: `panic` from out-of-bounds slice/array access on attacker-controlled
indices. While not memory corruption, this is a DoS vector if not recovered.

## 3.2 Integer Issues

- **Integer overflow/underflow** — `int`/`uint` arithmetic on attacker-controlled values without
  overflow checks. Go does not panic on integer overflow — values silently wrap.
- **Signed/unsigned confusion** — converting between `int` (signed) and `uint` types with
  attacker-controlled values.
- **Truncation** — `int64` to `int32` or `int` (platform-dependent) conversions losing precision.
- **Division by zero** — causes a runtime panic (DoS) if not caught.

## 3.3 Parser Confusion and Logic Bugs

- **Length field manipulation** — attacker setting length=0, length=MAX, or length > actual packet
  size.
- **Missing end-of-buffer checks** — reading past slice bounds causes panic (DoS), but no memory
  corruption.
- **Type confusion** — message type fields not validated strictly before dispatch.
- **Malformed option/TLV handling** — zero-length and maximum-length TLV options.
- **Loop termination** — loops advancing by attacker-controlled values that could be zero.
- **Extreme and illegal field values** — min/max boundary values not handled correctly.
- **Encoding and charset issues** — invalid UTF-8 (Go strings can contain arbitrary bytes; code
  assuming valid UTF-8 may misbehave).
- **Protocol smuggling / desynchronization** — crafted messages interpreted differently by
  different parsers.
- **Overlapping or contradictory fields** — check that conflicts are handled defensively.

## 3.4 Injection Sinks

- **Command injection** — attacker-controlled data reaching `exec.Command()`, `os.StartProcess`.
- **SQL injection** — interpolated into SQL queries without parameterization.
- **Template injection** — attacker-controlled data in `html/template` or `text/template`.
- **Log injection** — written to log output without sanitization.

## 3.5 Resource Exhaustion

- **Unbounded allocation** — attacker-controlled size reaching `make([]byte, n)` without a cap.
- **Goroutine leaks** — goroutines spawned per-request that never terminate (e.g., blocked on
  a channel that is never closed). Accumulates memory and scheduling overhead.
- **State amplification** — attacker causing many expensive state entries without rate limiting.
- **CPU exhaustion** — expensive operations triggered per-message.
- **File descriptor exhaustion** — connections or files opened per-message without limits.
- **Algorithmic complexity attacks** — predictable hash functions in maps allowing crafted
  collision inputs. Note: Go's built-in map uses randomized hashing, but custom hash tables may
  not.
- **Recursive or nested structure bombs** — deep nesting causing stack overflow panic.
- **Disk exhaustion** — unbounded disk writes.

## 3.6 Information Leaks

- **Error messages** — error responses including internal state or sensitive info. Go's
  `fmt.Errorf` with `%v` or `%+v` can expose struct contents.
- **Over-sharing in responses** — internal hostnames, version banners, stack traces in HTTP error
  responses.
- **Timing side channels** — non-constant-time comparisons. Use `crypto/subtle.ConstantTimeCompare`.

## 3.7 State Machine Vulnerabilities

- **Out-of-order messages** — sending messages in unexpected order to reach invalid state.
- **Authentication bypass via state confusion** — skipping auth steps.
- **Replay attacks** — sequence numbers, nonces, or timestamps not validated.
- **Protocol downgrade attacks** — forcing weaker protocol version or auth method.
- **Session fixation / hijacking** — forcing or predicting session identifiers.
- **Incomplete state cleanup on error** — failed messages not fully rolling back state. Watch
  for deferred cleanup that doesn't execute on certain error paths.
- **Race conditions** — TOCTOU windows, especially in goroutine-based concurrent handling.

## 3.8 Cryptographic Issues

- **Weak or obsolete algorithms** — MD5, SHA1, DES, RC4 for security-critical purposes.
- **Improper certificate/key validation** — `InsecureSkipVerify: true` in `tls.Config`.
- **Nonce/IV reuse** — nonces not generated uniquely for each operation.
- **Insufficient randomness** — using `math/rand` instead of `crypto/rand` for security values.
- **Key material exposure** — keys logged or included in error messages.
- **Missing encryption** — plaintext fallback on handshake failure.

## 3.9 Concurrency and Thread Safety

- **Unsynchronized map access** — concurrent read/write to Go maps causes fatal runtime error
  (not a data race — an immediate crash). Use `sync.Map` or mutex protection.
- **Unsynchronized slice access** — concurrent append/read on slices causes data races.
- **Channel deadlocks** — goroutines blocked on channel operations that can never complete.
- **Lock ordering violations** — nested mutex acquisitions in inconsistent order.
- **Context cancellation not respected** — long-running operations that ignore `context.Done()`,
  preventing graceful shutdown and causing resource leaks.

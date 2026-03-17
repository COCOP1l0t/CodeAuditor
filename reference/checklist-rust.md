# Vulnerability Checklist: Rust

Safe Rust eliminates most memory safety issues. Audit all `unsafe` blocks with C-level rigor.
Focus on logic bugs, state machine issues, and panics from `unwrap()`/`expect()` on
attacker-controlled data (DoS).

## 3.1 Memory Safety (`unsafe` code only)

> Only relevant inside `unsafe` blocks, FFI boundaries, or when using raw pointers. If no
> `unsafe` code is present, skip this section.

- **Buffer overflows** — raw pointer arithmetic in `unsafe` blocks without bounds validation.
- **Use-after-free** — manual memory management in `unsafe` or FFI code.
- **Double-free** — `unsafe` code that manually drops or frees the same allocation.
- **Null pointer dereference** — `unsafe` code dereferencing raw pointers without null checks.
- **`Send`/`Sync` violations** — types incorrectly implementing `Send` or `Sync` in `unsafe`
  code, enabling data races.

**Rust-specific concern**: `unwrap()`, `expect()`, and indexing with `[]` on attacker-controlled
data cause panics. In a server context, this is a DoS vector. Check that attacker-controlled
paths use `.get()`, `match`, or `if let` instead.

## 3.2 Integer Issues

- **Integer overflow** — in debug mode Rust panics on overflow; in release mode values wrap
  silently. Attacker-controlled arithmetic in release builds can produce unexpected values.
  Check for use of `wrapping_*`, `checked_*`, or `saturating_*` methods.
- **Truncation** — `as` casts (e.g., `u64 as u16`) silently truncate. Attacker-controlled values
  cast with `as` are dangerous.
- **Division by zero** — causes panic (DoS).

## 3.3 Parser Confusion and Logic Bugs

- **Length field manipulation** — attacker setting length=0, length=MAX, or length > actual data.
- **Missing bounds checks** — using `[]` indexing instead of `.get()` on attacker-controlled
  indices causes panic.
- **Type confusion** — message type fields not validated before dispatch.
- **Malformed option/TLV handling** — zero-length and maximum-length TLV options.
- **Loop termination** — loops advancing by attacker-controlled values that could be zero.
- **Extreme and illegal field values** — min/max boundary values not handled correctly.
- **Deserialization vulnerabilities** — `serde` with untagged enums or custom deserializers that
  trust length fields. Also check for panics in deserialization of malformed input.
- **Encoding and charset issues** — Rust strings are guaranteed UTF-8, but `&[u8]` network
  buffers are not. Code assuming a byte slice is valid UTF-8 (`str::from_utf8().unwrap()`) will
  panic on malformed input.
- **Protocol smuggling / desynchronization** — different parsers interpreting messages differently.

## 3.4 Injection Sinks

- **Command injection** — attacker-controlled data reaching `std::process::Command`.
- **SQL injection** — interpolated into SQL queries without parameterization.
- **Log injection** — written to log output without sanitization.

## 3.5 Resource Exhaustion

- **Unbounded allocation** — attacker-controlled size reaching `Vec::with_capacity()` or
  `vec![0; n]` without a cap.
- **State amplification** — attacker causing many expensive state entries without rate limiting.
- **CPU exhaustion** — expensive operations triggered per-message.
- **Recursive or nested structure bombs** — deep nesting causing stack overflow.
- **Disk exhaustion** — unbounded disk writes.
- **Async task leaks** — spawned tasks (`tokio::spawn`) that never complete, accumulating
  resources.

## 3.6 Information Leaks

- **Error messages** — `Debug` trait output (`{:?}`) on structs containing sensitive data in
  error responses.
- **Over-sharing in responses** — internal state, version banners, file paths.
- **Timing side channels** — non-constant-time comparisons. Use `constant_time_eq` crate or
  similar.

## 3.7 State Machine Vulnerabilities

- **Out-of-order messages** — sending messages in unexpected order to reach invalid state.
- **Authentication bypass via state confusion** — skipping auth steps.
- **Replay attacks** — sequence numbers, nonces, or timestamps not validated.
- **Protocol downgrade attacks** — forcing weaker protocol version or auth method.
- **Incomplete state cleanup on error** — `?` operator early returns skipping cleanup. Check
  that `Drop` implementations handle partial state correctly.
- **Race conditions** — TOCTOU windows in async code (`tokio`, `async-std`).

## 3.8 Cryptographic Issues

- **Weak or obsolete algorithms** — MD5, SHA1, DES, RC4 for security-critical purposes.
- **Improper certificate/key validation** — using `danger_accept_invalid_certs()` in
  `rustls`/`reqwest`.
- **Nonce/IV reuse** — nonces not generated uniquely.
- **Insufficient randomness** — using `rand::thread_rng()` (fine) vs `rand::rngs::SmallRng`
  (not cryptographic) for security-critical values. Use `rand::rngs::OsRng` or `getrandom`.
- **Key material exposure** — keys not zeroized after use. Check for `zeroize` crate usage.

## 3.9 Concurrency and Thread Safety

- **`Send`/`Sync` violations in `unsafe`** — manually implementing these traits incorrectly.
- **Deadlocks** — nested `Mutex::lock()` calls, or holding a lock across `.await` points.
- **Async cancellation safety** — `select!` dropping futures mid-execution can leave state
  inconsistent.
- **Shared mutable state** — `Arc<Mutex<T>>` patterns where the lock is held too briefly or
  too long, creating TOCTOU windows.

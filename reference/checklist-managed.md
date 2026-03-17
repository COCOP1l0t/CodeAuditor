# Vulnerability Checklist: Python / Java / C# / Managed Languages

Memory safety is handled by the runtime. Focus on deserialization, injection sinks, logic bugs,
resource exhaustion, and cryptographic misuse.

## 3.3 Parser Confusion and Logic Bugs

- **Length field manipulation** — attacker setting length=0, length=MAX, or length > actual data.
- **Missing bounds checks** — unchecked array/list access on attacker-controlled indices causes
  exceptions (DoS).
- **Type confusion** — message type fields not validated before dispatch.
- **Malformed option/TLV handling** — zero-length and maximum-length TLV options.
- **Loop termination** — loops advancing by attacker-controlled values that could be zero.
- **Extreme and illegal field values** — min/max boundary values not handled correctly.
- **Deserialization vulnerabilities** — this is a primary RCE vector in managed languages:
  - **Python**: `pickle.loads()` on attacker-controlled data → arbitrary code execution.
    Also `yaml.load()` (use `yaml.safe_load()`), `eval()`, `exec()`.
  - **Java**: `ObjectInputStream.readObject()` on untrusted data → RCE via gadget chains.
    Check for use of libraries like Apache Commons Collections, Spring, etc. Also XML
    deserialization (`XMLDecoder`, `XStream`).
  - **C#**: `BinaryFormatter.Deserialize()` → RCE. Also `XmlSerializer` with polymorphic types,
    `JavaScriptSerializer` with type resolvers.
  - **General**: Any deserialization that instantiates arbitrary types based on attacker-controlled
    type indicators.
- **Encoding and charset issues** — mixed encoding assumptions, invalid UTF-8 handling.
- **Protocol smuggling / desynchronization** — different parsers interpreting messages differently.
- **Overlapping or contradictory fields** — check that conflicts are handled defensively.

## 3.4 Injection Sinks

- **Command injection** — attacker-controlled data reaching:
  - Python: `os.system()`, `subprocess.Popen(shell=True)`, `os.popen()`
  - Java: `Runtime.exec()`, `ProcessBuilder`
  - C#: `Process.Start()`
- **SQL injection** — string interpolation/concatenation in SQL queries. Use parameterized
  queries or ORM query builders.
- **LDAP injection** — attacker-controlled data in LDAP filter construction.
- **Template injection** — attacker-controlled data in server-side template engines (Jinja2,
  Thymeleaf, Razor). Can lead to RCE.
- **Log injection** — attacker-controlled data in log output. In Java, also check for
  Log4Shell-style JNDI lookups in log messages.
- **XML External Entity (XXE)** — XML parsers processing attacker-controlled XML without
  disabling external entities. Check parser configuration:
  - Python: `lxml` with default settings, `xml.etree` (safe by default)
  - Java: `DocumentBuilderFactory` without `setFeature(DISALLOW_DOCTYPE_DECL, true)`
  - C#: `XmlReader` without `DtdProcessing.Prohibit`

## 3.5 Resource Exhaustion

- **Unbounded allocation** — attacker-controlled size reaching list/buffer creation without a cap.
- **State amplification** — attacker causing many expensive state entries without rate limiting.
- **CPU exhaustion** — expensive operations (regex with catastrophic backtracking, sorting,
  crypto) triggered per-message.
- **Regular expression DoS (ReDoS)** — regex patterns with nested quantifiers applied to
  attacker-controlled input. Use regex engines with linear-time guarantees where possible.
- **Thread/connection pool exhaustion** — blocking operations in request handlers that exhaust
  the thread pool.
- **Recursive or nested structure bombs** — deep nesting causing stack overflow or excessive
  memory allocation. JSON/XML bombs ("billion laughs").
- **Disk exhaustion** — unbounded disk writes from attacker-triggered operations.

## 3.6 Information Leaks

- **Error messages** — stack traces, internal state, or database errors exposed in responses.
  Check that production error handling does not leak implementation details.
- **Over-sharing in responses** — version banners, internal hostnames, debug headers.
- **Timing side channels** — non-constant-time comparisons. Use `hmac.compare_digest()` (Python),
  `MessageDigest.isEqual()` (Java), or equivalent.
- **Sensitive data in logs** — passwords, tokens, or PII logged at debug/info level.

## 3.7 State Machine Vulnerabilities

- **Out-of-order messages** — sending messages in unexpected order to reach invalid state.
- **Authentication bypass via state confusion** — skipping auth steps.
- **Replay attacks** — sequence numbers, nonces, or timestamps not validated.
- **Protocol downgrade attacks** — forcing weaker protocol version or auth method.
- **Session fixation / hijacking** — forcing or predicting session identifiers.
- **Incomplete state cleanup on error** — exception handlers that don't fully restore state.
  Check `finally` blocks and context managers/`using` statements.
- **Race conditions** — in async/threaded code, shared mutable state without synchronization.

## 3.8 Cryptographic Issues

- **Weak or obsolete algorithms** — MD5, SHA1, DES, RC4 for security-critical purposes.
- **Improper certificate/key validation**:
  - Python: `verify=False` in `requests`, `ssl.create_default_context()` with checks disabled.
  - Java: custom `TrustManager` that accepts all certificates.
  - C#: `ServicePointManager.ServerCertificateValidationCallback` returning `true`.
- **Nonce/IV reuse** — nonces not generated uniquely for each operation.
- **Insufficient randomness**:
  - Python: `random.random()` instead of `secrets` module.
  - Java: `java.util.Random` instead of `java.security.SecureRandom`.
  - C#: `System.Random` instead of `System.Security.Cryptography.RandomNumberGenerator`.
- **Key material exposure** — keys in plaintext in memory, config files, or error messages.
- **Missing encryption** — plaintext fallback on handshake failure.

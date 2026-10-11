# Security Policy

`minisvc` is a deliberately vulnerable training target. This file describes the
scope an audit is expected to apply, so the auditing pipeline has an explicit
bug-vs-vulnerability boundary to work from.

## Supported surface

The service is intended to run as an unauthenticated network daemon on
loopback. Everything reachable from a client connection is attacker-reachable.

## In scope

- The TCP request path: protocol parsing and every command handler.
- Memory-safety issues (buffer overflows, out-of-bounds access).
- Command injection and path traversal.

## Out of scope

- Test code, toy PoC scripts, and documentation.
- Code that is only compiled behind a non-default build flag or only active
  under a non-default runtime option.
- Denial of service that requires local access or excessive resource
  consumption.

## Reporting

This is a local exercise target; there is no external disclosure process.

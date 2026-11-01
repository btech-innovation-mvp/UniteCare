# ADR-003: Selection of Direct Bcrypt for Password Hashing

## Status
Accepted

## Context
Stage 2 codebase audit revealed ambiguity between `passlib[bcrypt]` and direct `bcrypt`. Passlib is unmaintained, relies on deprecated internal interfaces, and carries subtle compatibility issues with modern Python releases (3.12+). Furthermore, bcrypt has an architectural 72-byte limit that must be explicitly checked to prevent silent truncation vulnerabilities.

## Decision
1. Standardize exclusively on the direct `bcrypt` library (5.0+).
2. Configure default work factor to 12 rounds.
3. Enforce an explicit 72-byte UTF-8 limit across Pydantic schemas and cryptographic core functions.
4. Passlib is completely removed and rejected.

## Consequences
### Positive:
* Minimal dependencies and direct control over cryptographic execution.
* Explicit defense-in-depth against silent password truncation attacks.
* Native C-extension performance and reliable behavior across Python 3.12+.

### Trade-offs:
* Upgrades to newer algorithms (e.g. Argon2id) require explicit application-level logic rather than transparent passlib abstraction. (This strategy is formally documented in `docs/security/password-security.md`).

# Password Security Specification

## 1. Primary Algorithm: Direct Bcrypt

UniteCare standardizes on direct `bcrypt` (C-extension implementation) rather than multi-algorithm wrappers like Passlib.

### Configuration
* **Library**: `bcrypt` (5.0+)
* **Work Factor (Cost)**: `12` rounds (configured via `settings.BCRYPT_ROUNDS`)
* **Salt Generation**: Cryptographically secure OS entropy (`bcrypt.gensalt()`)
* **Storage Column**: `auth_identities.password_hash` (`VARCHAR(255)`)

---

## 2. Bcrypt 72-Byte Limit Safeguard

Bcrypt operates natively on byte arrays and has an architectural limit of 72 bytes. Many systems silently truncate inputs longer than 72 bytes, introducing a critical vulnerability where `password + "extra characters"` verifies successfully against the hash of `password`.

### UniteCare Enforcement Policy:
1. **UTF-8 Byte Calculation**: Candidate passwords are measured in UTF-8 bytes (`len(password.encode("utf-8"))`), not character counts. Multibyte characters (such as Unicode symbols and emojis) are accurately accounted for.
2. **Explicit Validation**: Pydantic schemas (`RegisterRequest`, `ChangePasswordRequest`) reject any password exceeding 72 UTF-8 bytes with an HTTP 422 Unprocessable Content error.
3. **Defense-in-Depth in Core Primitives**: The `hash_password()` function in `app.core.security` explicitly raises `ValueError` if a string exceeding 72 bytes is passed, preventing silent truncation under any circumstance.
4. **Verification Safeguard**: The `verify_password()` function immediately returns `False` if candidate bytes exceed 72, preventing unnecessary computation or hash checking.

---

## 3. Future Password Hash Migration Strategy

Should future security mandates require an upgrade (e.g. to Argon2id):
1. Stored hashes retain standard algorithm prefixes (e.g., `$2b$12$...`).
2. The verification engine checks the algorithm prefix.
3. If the stored hash is `$2b$`, it validates via `bcrypt`.
4. Upon successful validation during an active login, the application hashes the plaintext password with the new algorithm and updates `auth_identities` inside that single database transaction.

# UniteCare Genuine-Data & Privacy Policy

## 1. Non-Negotiable Genuine-Data Mandate

UniteCare enforces an absolute **Genuine-Data Policy**. All application data must represent genuine records originating from actual user registration, authenticated administrators, or verified workflows.

### Strict Prohibitions
1. **No Mock Database Users**: Never insert fictional users, bots, or fabricated profiles into the application database.
2. **No Fake NGOs**: Never seed dummy organizations, fake registration numbers, or fictional missions.
3. **No Fabricated Volunteers or Donors**: Never populate fake volunteer rosters, dummy skills, or fake donation histories.
4. **No Automated Startup Seeds**: Never execute startup scripts that insert sample records automatically into development or production databases.
5. **No Fabricated Dashboard Statistics**: Never display fake user counts, volunteer hours, financial contributions, or assistance delivery metrics.

---

## 2. Empty-State Display Standard

When a database table, user profile, administrative list, or dashboard view contains no records, the interface must render a clear and honest empty state:

> **"No data available yet."**

Interfaces must never mask empty states with simulated progress bars, placeholder avatars labeled as real people, or generated mock activity feeds.

---

## 3. Test Fixture Isolation

When integration testing requires automated fixtures:
- Fixtures must execute exclusively against an **ephemeral, isolated test database** (e.g. `unitecare_test_db`).
- Test databases must be cleanly wiped after execution.
- Production and standard development databases must never contain or connect to automated test fixtures.

---

## 4. Audit Data, IP Logging, and Privacy Policy

UniteCare records security-relevant events in `audit_logs`. To comply with data privacy standards:

### Purpose of IP & Audit Collection
- **Security Incident Detection**: Detecting brute-force authentication attempts and unauthorized role changes.
- **Session Anomaly Detection**: Verifying session integrity during refresh token rotation.
- **Regulatory Accountability**: Ensuring accountability for administrative actions (e.g. NGO approvals).

### Access Policy
- Audit log records are append-only (immutable).
- No API endpoints exist to update or delete audit records.
- Access to audit logs is strictly restricted to authenticated users holding the `system_admin` role.

### Data Sanitization
- Passwords, OTP codes, session tokens, and credit/financial information must **never** be passed into the audit log `details` column.
- IP addresses collected (`VARCHAR(45)` supporting IPv4/IPv6) are stored solely for session verification and attack mitigation.

### Retention Considerations
- Session records and transient audit events are subject to a maximum retention window (recommended: 90 days for audit records, 30 days for expired session records) via scheduled maintenance jobs in production.

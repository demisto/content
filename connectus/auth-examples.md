# Auth Classification — Worked Examples & Vendor Reference

> This file is linked from connectus-migration-SKILL.md Step 1 (§1.2/§1.3/§1.4/§1.6/§1.7); read it when you need full worked auth-classification examples, the grep-pattern catalog, the known-misclassification table, Microsoft/Azure special handling, or the manifest-layer profile-type field reference. The SKILL.md Step 1 keeps the classification decision table, the role-enum-per-type rules, the XOR-relations table, other_connection rules, the pre-flight self-check, and one minimal inline example.

## Worked Examples

### Example A — Bearer token API key (single flat param)

YML excerpt:

```yaml
- name: api_key
  display: API Key
  type: 4
  required: true
```

Code excerpt:

```python
headers = {"Authorization": f"Bearer {params.get('api_key')}"}
```

Suppose the YML also defines `url`, `insecure`, and `proxy` alongside
`api_key` (the typical XSOAR connection-metadata trio). Then the
resulting JSON to pass to `set-auth`:

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": {
        "api_key": "key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

### Example A' — APIVoid pattern: APIKey delivered via a credentials widget with `hiddenusername: true`

When an integration uses a `type: 9` credentials widget purely to collect an API key (the username slot is hidden via `hiddenusername: true`), the identifier leaf is suppressed and the map keys ONLY the password leaf, with role `"key"`. See the [Grep-Pattern Catalog by Auth Type](#grep-pattern-catalog-by-auth-type) and the YML Analysis leaf-suppression rules in connectus-migration-SKILL.md §1.3.

YML excerpt:

```yaml
- name: credentials
  display: API Key (Username — hidden)
  type: 9
  hiddenusername: true
  required: true
```

Resulting JSON:

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.password": "key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

> **Note:** The §1.3 YML-Analysis-Procedure worked mini-example for the APIVoid `hiddenusername: true` pattern is the same as Example A' above (a `type: 9` credentials widget collecting only the password, mapped to a single `credentials.password → key` key). It is not duplicated here.

### Example B — Username/password credentials (type `9`) plus optional OAuth client creds reusing a second credentials param

YML excerpt:

```yaml
- name: url
  display: Server URL
  type: 0
  required: true
- name: credentials
  display: Username
  type: 9
  required: true
- name: credentials_consumer
  display: Consumer Key / Secret
  type: 9
  required: false
- name: insecure
  display: Trust any certificate (not secure)
  type: 8
- name: proxy
  display: Use system proxy settings
  type: 8
```

Code excerpt:

```python
basic = HTTPBasicAuth(params['credentials']['identifier'], params['credentials']['password'])
oauth = OAuth1(params['credentials_consumer']['identifier'],
               params['credentials_consumer']['password'], ...)
```

Resulting JSON (note entries sorted by `(type, name)` — `Passthrough` > `Plain` alphabetically, so the `Plain` entry sorts first; `other_connection` sorted ascending; the OAuth2 flow is classified as `Passthrough` with `interpolated: true` and uses free-form role strings, while the `Plain` entry is constrained to `"username"`/`"password"`):

```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      }
    },
    {
      "type": "Passthrough",
      "name": "credentials_consumer",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials_consumer.identifier": "client_id",
        "credentials_consumer.password": "client_secret"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

> **Note:** the OAuth2 consumer-key/secret flow above (formerly classified as `OAuth2ClientCreds`) is now emitted as a `Passthrough` profile with `interpolated: true`. The role strings (`client_id` / `client_secret`) stay the same — `Passthrough` accepts any non-empty string role.

---

## Grep-Pattern Catalog by Auth Type

For each auth type, search the Python file using these patterns:

**OAuth2 Client Credentials — classified as `Passthrough` (`interpolated: true`):**
```bash
grep -n "client_credentials\|grant_type.*client\|/oauth2/token\|/token\|MicrosoftClient\|oproxy\|get_access_token\|client_id.*client_secret" <file>.py
```

**OAuth2 Authorization Code:**
```bash
grep -n "authorization_code\|redirect_uri\|oauth-start\|oauth-complete\|auth_code\|code_verifier\|PKCE" <file>.py
```

**OAuth2 JWT Bearer — classified as `Passthrough` (`interpolated: true`):**
```bash
grep -n "jwt\.encode\|jwt-bearer\|ServiceAccountCredentials\|google\.auth\|google\.oauth2\|service_account\|private_key.*sign" <file>.py
```

**OAuth2 ROPC (Resource Owner Password Credentials) — classified as `Passthrough`:**
```bash
grep -n "grant_type.*password\|resource_owner\|ROPC" <file>.py
```

**OAuth2 Device Code — classified as `Passthrough`:**
```bash
grep -n "device_code\|devicecode\|device_authorization" <file>.py
```

**Managed Identity — classified as `Passthrough`:**
```bash
grep -n "managed_identit\|MANAGED_IDENTITIES\|use_managed_identities\|managed_identities_client_id" <file>.py
```

**API Key:**
```bash
grep -n "X-API-Key\|x-api-key\|apikey.*header\|api_key.*header\|Authorization.*Bearer\|Bearer.*token" <file>.py
```

**Basic Auth:**
```bash
grep -n "HTTPBasicAuth\|auth=.*username.*password\|basic_auth\|base64.*encode.*:" <file>.py
```

---

## Known Misclassification Patterns

Based on manual review of 148 integrations (71 corrections found), these are the most common errors:

| # | Pattern | Freq | Classifier Output | Correct Value | How to Detect |
|---|---------|------|-------------------|---------------|---------------|
| 1 | `type=9` credentials used for OAuth2 client_credentials | 9 | `Plain(credentials)` | `Passthrough(credentials)` (`interpolated: true`) | Code does `grant_type=client_credentials` or uses `MicrosoftClient` |
| 2 | Bearer token classified as Plain | 8 | `Plain(credentials)` | `APIKey(credentials)` | Code sets `Authorization: Bearer {token}` with a static token from params |
| 3 | False positive OAuth2 client-creds from code patterns | 25 | spurious extra `Passthrough` profile added | Should be removed | Code has `client_id`/`access_token` strings but they're not OAuth2 — they're proprietary token exchange |
| 4 | Microsoft/Azure missing ManagedIdentity | 23 | No mention | Add to `auth_types` as `Passthrough` | Code imports `MicrosoftClient` and has `managed_identities_client_id` param |
| 5 | Microsoft/Azure missing DeviceCode | 12 | No mention | Add to `auth_types` as `Passthrough` | Code has `device_code` grant type support |
| 6 | OAuth2 ROPC misclassified | 13 | OAuth2 client-creds or `Plain` | `Passthrough` (ROPC) | Code does `grant_type=password` |
| 7 | Hidden old param creates false CHOICE | ~10 | `CHOICE(APIKey, Plain)` | Single mechanism | Old `type=4` param is `hidden: true`, new `type=9` param is visible — same credential |
| 8 | `type=4` OAuth client secret classified as APIKey | ~5 | `APIKey(client_secret)` | `Passthrough(client_secret)` (`interpolated: true`) | Param named `client_secret` or `enc_key` used in OAuth flow |
| 9 | Microsoft cert-thumbprint integrations seed-fail at module load | many | 100% `no_data` across every command | Not a misclassification; analyzer limitation. Use the full static union; do NOT retry with `--use-integration-docker` (failure is in `MicrosoftApiModule.MicrosoftClient.__init__` cert validator, not a missing package). `--ignore-params <name>` does NOT help — the slot is still seeded, it only filters output. | Stderr contains `Error: Odd-length string` or `non-hexadecimal number found in fromhex()`; integration's YML has `certificate_thumbprint` (type=4) or `creds_certificate` (type=9) consumed by `MicrosoftClient`. Until the analyzer ships per-param seed overrides, manual source review is the only path. |

---

## Microsoft/Azure Special Handling

Microsoft/Azure integrations are the most complex (23 corrections in the manual review). Apply this dedicated procedure:

- **If the integration imports `MicrosoftClient` from `MicrosoftApiModule`:**

  > **Important: 4 flows is the upper bound, not the default.** Many Microsoft integrations support only a subset. Common variants observed in the codebase:
  >
  > - **All 4 flows** — `auth_type` selector (type=15) with `Client Credentials` / `Authorization Code` / `Device Code` options + `managed_identities_client_id` param.
  > - **Client-creds-only with cert OR secret + Managed Identity** (Azure Sentinel pattern) — 3 entries: `Passthrough(cert)` + `Passthrough(secret)` + `Passthrough(managed_identity)`, all with `interpolated: true` (the two OAuth2 client-creds flows are folded into `Passthrough`). No `auth_type` selector param.
  > - **Pure Client Credentials** (no cert, no MI) — 1 entry.
  >
  > The decisive evidence is **always** the source code, not the import. Read `main()` to determine which auth paths are reachable — never assume "imports `MicrosoftClient` ⇒ all 4 flows".

  - It likely supports **4 auth flows**, all classified as `Passthrough` (`interpolated: true`): OAuth2 Client Credentials, plus Authorization Code, Device Code, and Managed Identity.
  - Check for `auth_type` selector param (`type: 15`) with options like `Client Credentials`, `Authorization Code`, `Device Code`
  - Check for `managed_identities_client_id` param → indicates Managed Identity support (Passthrough entry)
  - Check for `redirect_uri` and `auth_code` params → indicates Authorization Code support (Passthrough entry)
  - Each supported flow becomes its own entry in `auth_types[]`. The user picks one at configuration time (implicit exclusive-OR; no `config` key needed). Pick distinct `auth_types[].name` values per entry.
  - Authorization Code, Device Code, and Managed Identity are all classified as `Passthrough` (none fits the `oauth2_client_credentials` / `oauth2_jwt_bearer` profile shape).

---

## Authentication Profile Types — Fields Reference

> **What this section is.** The canonical, copy-paste reference for the five UCP authentication profile types and the user-facing fields each one exposes. Use it to answer "does this integration fit a known profile, or is it `Passthrough`?" while you classify `Auth Details`. The shapes here are the source of truth for the manifest's `metadata.auth.parameter` block; OPA Check 17 rejects duplicate `auth.parameter` values within a profile's effective scope (profile configurations + connection.yaml `general_configurations`).

### Quick reference — fields by connection type

| Profile Type | Profile-Level Properties | User-Facing `auth.parameter` Fields | Maps from classification |
|---|---|---|---|
| `oauth2_client_credentials` | `discovery_url` **OR** `token_endpoint` | `client_key`, `client_secret` | `Passthrough` (OAuth2 client-credentials folded into `Passthrough`) |
| `oauth2_jwt_bearer` | `discovery_url` **OR** `token_endpoint` | `subject_email`, `credentials_file` | `Passthrough` (OAuth2 JWT-bearer folded into `Passthrough`) |
| `plain` | *(none beyond id/type/title/description)* | `username`, `password` | `Plain` |
| `api_key` | *(none beyond id/type/title/description)* | `api_key` | `APIKey` (single key only) |
| `Passthrough` (no canonical profile) | n/a | n/a — define fields ad-hoc in the manifest | `Passthrough` — includes `oauth2_authorization_code` (browser flow), Device Code, ROPC, Managed Identity, mTLS, dual-key API (e.g. Datadog `api_key`+`application_key`), AWS SigV4, Akamai EdgeGrid, GitHub App, custom signing |

\* For browser-flow OAuth2 Authorization Code, the legacy/sibling profile `oauth2_authorization_code` exists at the profile level (`client_id`, `client_secret`, `discovery_url` **OR** `authorization_endpoint` + `token_endpoint`, `refresh_token_scope`; profile-level `client_id` / `client_secret` MUST use the `{SAAS_REGISTRY.*}` pattern) but it has **no user-facing `auth.parameter` fields** (the entire flow is browser-driven). Per the project-wide rule, **classify it as `Passthrough` regardless** — there is no single profile-type field shape we can pin it to from a classification perspective.

### Detailed breakdown

#### 1. `oauth2_client_credentials`

- **Profile-level keys:** `id`, `type`, `title`, `description`, (`discovery_url` **OR** `token_endpoint`)
- **`metadata.auth.parameter` fields:**
  - `client_key` — OAuth2 client ID / consumer key (`input`, unmasked)
  - `client_secret` — OAuth2 client secret (`input`, `mask: true`)
- **Classification:** any integration whose code does `grant_type=client_credentials` with exactly two secrets (`client_id` + `client_secret`) fed in directly — no JWT, no browser redirect — is now classified as **`Passthrough`** (`interpolated: true`). The `oauth2_client_credentials` profile shape still describes the manifest-layer fields, but the skill no longer outputs an `OAuth2ClientCreds` classification value.

#### 2. `oauth2_jwt_bearer`

- **Profile-level keys:** `id`, `type`, `title`, `description`, (`discovery_url` **OR** `token_endpoint`)
- **`metadata.auth.parameter` fields:**
  - `subject_email` — impersonation subject (`input`, usually in `general_configurations`)
  - `credentials_file` — JSON key file (`file_upload`, `formats: ".json"`, `mask: true`)
- **Classification:** any integration that signs a JWT assertion with a private key (typically a Google service-account JSON file) and posts it to a `grant_type=jwt-bearer` token endpoint is now classified as **`Passthrough`** (`interpolated: true`). The `oauth2_jwt_bearer` profile shape still describes the manifest-layer fields, but the skill no longer outputs an `OAuth2JWT` classification value.

#### 3. `plain`

- **Profile-level keys:** `id`, `type`, `title`, `description` (nothing more)
- **`metadata.auth.parameter` fields:**
  - `username` — account identifier (`input`, unmasked)
  - `password` — secret (`input`, `mask: true`)
- **Classification:** username + password basic auth, login-form-to-session-cookie flows, any single-pair credential where one half is an identifier and the other half is a secret.

#### 4. `api_key`

- **Profile-level keys:** `id`, `type`, `title`, `description` (nothing more)
- **`metadata.auth.parameter` fields:**
  - `api_key` — token (`input`, `mask: true`)
- **Classification:** **single static secret only.** Bearer tokens, custom headers like `X-API-Key`, query-param API keys, and single-secret HMAC signing all fit here. **Two-or-more-secret packages do NOT fit and become `Passthrough`** (see connectus-migration-SKILL.md §1.2.2a) — even when they're conceptually "API keys" (Datadog `api_key`+`application_key`, AWS access_key+secret_key, Akamai EdgeGrid's three tokens, etc.).
- **Legacy note:** older docs mentioned a dual-key `application_key` slot under `api_key`. That slot is **NOT part of the canonical `api_key` profile** in the current schema; dual-key integrations are `Passthrough`.

#### 5. `NoneRequired`

- **Profile-level keys:** none (no profile generated at all)
- **`metadata.auth.parameter` fields:** none
- **Classification:** public APIs, RSS/feed endpoints that need no auth header.

### All valid `metadata.auth.parameter` values (closed set per profile)

| Parameter | Used By | Notes |
|---|---|---|
| `client_key` | `oauth2_client_credentials` | OAuth client id |
| `client_secret` | `oauth2_client_credentials` | OAuth client secret |
| `username` | `plain` | Basic-auth identifier |
| `password` | `plain` | Basic-auth secret |
| `api_key` | `api_key` | Single static secret |
| `credentials_file` | `oauth2_jwt_bearer` | JSON key file upload |
| `subject_email` | `oauth2_jwt_bearer` | Impersonation subject |

> **Duplicate-value rejection.** OPA Check 17 rejects duplicate `auth.parameter` values within a profile's effective scope (the union of the profile's own `configurations` and the `connection.yaml`'s `general_configurations`). If an integration legitimately needs a second copy of the same role-named field (extremely rare), it cannot fit a canonical profile and must be classified as `Passthrough`.

### Decision rule (one-line summary)

> **The classifier emits exactly four values: `APIKey`, `Plain`, `Passthrough`, `NoneRequired`.** If every secret maps cleanly into the `plain` (`username`/`password`) or `api_key` (single static secret) field shape, use `Plain` / `APIKey` respectively. **Everything else — including ALL OAuth2 flows (client-credentials, JWT-bearer, Authorization Code, Device Code, ROPC), multi-key packages, Managed Identity, mTLS, and custom signing — is classified as `Passthrough`** (`interpolated: true`). `oauth2_authorization_code` is `Passthrough` because its user-facing config lives on the profile itself; OAuth2 client-credentials and JWT-bearer are likewise folded into `Passthrough` even though their `oauth2_client_credentials` / `oauth2_jwt_bearer` profile shapes still exist at the manifest layer.

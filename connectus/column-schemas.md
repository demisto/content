# Column Schemas

This file documents the expected JSON shapes for the JSON-valued columns in
[`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv). The CSV column
names and the workflow state machine itself live in
[`connectus/Readme.md`](Readme.md); this file is the source of truth for the
**contents** of each JSON-valued cell.

The columns documented here are all **workflow data columns** (free-text JSON,
managed via dedicated CLI setters in
[`connectus/workflow_state.py`](workflow_state.py)) — they are not pass/fail
checkpoints.

---

## `Auth Details`

Per-integration authentication classification. One JSON object per row.

```json
{
  "auth_types": [
    {
      "type": "<AuthEnum>",
      "name": "<profile_name>",
      "xsoar_param_map": {
        "<xsoar_field_path>": "<role>",
        "<xsoar_field_path>": "<role>"
      },
      "interpolated": <bool>,
      "verify_connection_skip": <bool, optional, default false>
    }
  ],
  "other_connection": ["<yml_param_id>", "<yml_param_id>", ...]
}
```

The required top-level keys are `auth_types` (a list) and
`other_connection` (a list — use `[]` when the integration has no
connection-adjacent non-auth params).

### Profile model — one entry = one mutually-exclusive way to authenticate

**Each `auth_types[]` entry is one complete UCP authentication
profile** — one self-contained, mutually-exclusive way the user can
configure the integration. The relationship between profiles is
**implicit and always exclusive-OR** (the only legal inter-profile
operator):

- `len(auth_types) == 0` → no authentication required.
- `len(auth_types) == 1` → that single profile is always used.
- `len(auth_types) >= 2` → **exclusive-OR**; the user picks exactly one
  at configuration time.

There is no inter-profile AND, no OPTIONAL, and no clause-joining.
AND-ed secrets within a single auth flow (e.g. an API key paired with a
vendor-required client certificate) live inside **one** profile's
`xsoar_param_map`, not across multiple profiles. See
[`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1)
§1.2.2a "Multi-secret auth flows" for the classification procedure.

A single XSOAR field that legitimately feeds more than one profile
(e.g. the same `credentials.password` backing both a Plain profile and
an OAuth profile that share the same secret) appears in **multiple
entries**, listed inside each entry's `xsoar_param_map`. Entries are
sorted by `(type, name)` ascending.

**Distinct XSOAR keysets (validated).** No two profiles may consume the
*exact same set* of XSOAR fields — i.e. two `auth_types[]` entries whose
`xsoar_param_map` **keys** form the identical set are rejected by
`set-auth`. Because profile relations are exclusive-OR, there must always
be a distinct way to attribute a connection back to exactly one profile;
two profiles reading the identical set of XSOAR fields are
indistinguishable at runtime. Note the check is on the set of keys (the
XSOAR field paths), independent of the role *values* they map to, so two
profiles that read the same fields but assign different roles still
collide. Sharing *some* fields is fine (a field may appear in multiple
entries, and one profile's field set may be a subset of another's); only
an *identical* field set across entries is an error.
- `auth_types[].type` — Auth-type enum value identifying the kind of
  connection this entry describes (see the enum table in
  [`Readme.md`](Readme.md:19)). Pick exactly one.
- `auth_types[].name` — Free-form logical id chosen for this connection
  type. Must be unique across entries within this row. This is the
  identifier referenced by `config` (not the XSOAR param id, not the
  enum value).
- `auth_types[].xsoar_param_map` — JSON object mapping each XSOAR
  **field path** (the key) to the **role** that secret plays inside
  the ConnectUs envelope for this connection (the value). The map is
  **required and non-empty** for every `auth_types[]` entry —
  including entries with `interpolated: true`. Conventions for keys:
  - For a flat XSOAR param (YML types `0` text, `4` encrypted, `14`
    cert key, etc.), use the bare param id, e.g. `"api_key"`,
    `"server_token"`.
  - For a credentials-typed XSOAR param (YML type `9`), treat its two
    sub-fields as separate leaf fields and address them with dotted
    notation: `"<paramid>.identifier"` (the username slot) and
    `"<paramid>.password"`. A Plain auth backed by a single
    credentials param therefore has two keys, e.g.
    `"credentials.identifier"` → `"username"` and
    `"credentials.password"` → `"password"`.
  - A Plain auth built from two separate flat params keys them
    directly, e.g. `"server_user"` → `"username"`,
    `"server_password"` → `"password"`.
  - The same field path may appear as a key in the `xsoar_param_map`
    of multiple entries when one XSOAR field feeds several connection
    types.

  The **role enum is constrained per `auth_types[].type`**:

  | `auth_types[].type` | Allowed values in `xsoar_param_map` |
  |---|---|
  | `APIKey` | `"key"` |
  | `Plain` | `"username"`, `"password"` |
  | `OAuth2ClientCreds`, `OAuth2JWT`, `Passthrough` | any non-empty string (enum **deliberately undefined for now** — will be narrowed in a future PR). Typical illustrative values: `"client_id"`, `"client_secret"`, `"access_token"`, `"credentials_file"`, `"subject_email"`. |
  | `NoneRequired` | n/a (no entries in `auth_types[]` at all) |

  See [`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1)
  §1.2.6 "Authentication Profile Types — Fields Reference" for the
  canonical UCP profile-type field shapes that this classification maps
  to, and the full classification procedure that picks the right role
  for each XSOAR field.
- `auth_types[].interpolated` — Optional in the submitted payload, but
  **always `true` in the persisted cell**. ALWAYS-INTERPOLATE GATE
  (2026-06-09): `set-auth` forces `interpolated: true` onto **every**
  `auth_types[]` entry before committing, regardless of `type` — so a
  non-interpolated (`interpolated: false`) profile cannot be persisted.
  Do not author `interpolated: false`; you may omit the flag (the gate
  sets it) or set it `true` explicitly. When `true`, the manifest
  generator sets the `interpolated` flag in this entry's metadata in the
  generated manifest (signaling that the value is interpolated from
  another source/template at runtime rather than supplied verbatim by
  the user). The `xsoar_param_map` is still required and non-empty on
  interpolated entries — the map describes the role each XSOAR field
  plays regardless of whether the value is user-supplied or templated at
  runtime.
- `other_connection` — Flat sorted list of YML param ids that are
  **purely connection-wide / transport-level metadata** with **no
  bearing on how authentication itself is performed**: things every
  profile uses the same way regardless of which auth flow the user
  picks. Typical members: `url`, `proxy`, `insecure`, `port`,
  `verify_certificate`, `server`, `host`, `region`,
  `use_system_proxy`. The list captures the ids exactly as they appear
  in the integration YML's `configuration[].name`.

  **Anything that has an implication on the auth itself goes INSIDE
  the profile's `xsoar_param_map`, not in `other_connection`.** For
  example: if an integration requires an API key paired with a vendor
  client certificate (the cert is part of the authentication
  handshake), the cert's YML id goes in the APIKey profile's
  `xsoar_param_map` (with whatever role string makes sense — for
  `APIKey`/`Plain` the validator only privileges the canonical roles
  `key` / `username` / `password`, so adding cert/extra roles to those
  types may currently surface a role-enum violation; the long-term
  plan is to relax the enum to admit extras). The general rule:

  - **Belongs in `other_connection`**: URL, port, region, insecure,
    proxy — every profile uses these the same way.
  - **Belongs in the profile's `xsoar_param_map`**: API keys, client
    certs / mTLS keypairs that participate in the auth handshake,
    vendor-required HMAC salts, OAuth client IDs/secrets — anything
    the auth flow itself reads.

  Constraints on the list:
  - Must be a JSON array of non-empty strings.
  - Strings must be unique within the list.
  - Must be sorted ascending (alphabetical). The validator rejects
    unsorted input with a clear suggestion of the sorted form.
  - Empty list `[]` is valid (= the integration has no connection-adjacent
    params besides its auth secrets).
  - There is **no overlap requirement** with `auth_types[].xsoar_param_map`
    — keeping the two lists disjoint is the classifier's responsibility,
    not the validator's. (Auth secrets and auth-adjacent fields are
    keyed in `auth_types[].xsoar_param_map`; per-command behavioral
    params go in `Params to Commands`; framework params like
    `longRunning`/`feedReputation` are ignored entirely.)

### Hidden-leaf suppression rules

These rules govern which YML param leaves appear as **keys** in
`xsoar_param_map`. They live here so the schema is fully described in
one place, but enforcement (the classification procedure) is in
[`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1).

- **YML `hidden: true` or `hidden: [<list>]` (any non-empty hidden
  value).** The param is excluded entirely from the Auth Details cell —
  it does NOT appear as a key in any `xsoar_param_map`, and it does
  NOT appear in `other_connection`. This is the existing rule and is
  unchanged.
- **YML `type: 9` credentials with `hiddenusername: true`.** The
  identifier leaf is suppressed: do **NOT** include
  `<id>.identifier` as a key in `xsoar_param_map`. The
  `<id>.password` leaf, if not also hidden, MAY still appear.
- **YML `type: 9` credentials with `hiddenpassword: true`.** The
  password leaf is suppressed: do **NOT** include `<id>.password`
  as a key in `xsoar_param_map`. The `<id>.identifier` leaf, if not
  also hidden, MAY still appear. (`hiddenpassword` is a real YML
  field per demisto-sdk's strict-objects schema.)

These suppressions matter most for `APIKey` integrations that use a
type-9 credentials widget with `hiddenusername: true` — the widget
collects only a password, and the resulting `xsoar_param_map` keys
ONLY `<id>.password`. See Example 1 below.

### What's required vs optional

- `xsoar_param_map` is **required and non-empty** for every
  `auth_types[]` entry, including entries with `"interpolated": true`.
  The empty map `{}` is rejected by `set-auth`.
- `interpolated` is **optional** in the submitted payload and, when
  present, must be a JSON boolean. **It is NOT a meaningful default of
  `false`:** the ALWAYS-INTERPOLATE GATE (2026-06-09) forces
  `interpolated: true` onto every `auth_types[]` entry before the cell
  is committed, so the persisted value is always `true` regardless of
  what you submit. Do not author `interpolated: false`.
- `verify_connection_skip` is **optional** and defaults to `false`.
  When present it MUST be a JSON boolean. Set `true` for a profile
  whose `test-module` code path manually raises an exception (e.g.
  `raise DemistoException(...)` / `return_error(...)`) so the
  connection-test button is structurally unable to exercise the auth
  — most commonly OAuth Authorization Code and Device Code flows
  where the user must first run an out-of-band `!auth-start`-style
  command. Profiles whose `test-module` reaches an actual HTTP call
  leave `verify_connection_skip` at its default (`false`) or omit
  the key entirely. The field is per-profile: a multi-profile
  (exclusive-OR) row can mix `verify_connection_skip: true` on one
  profile and the default-`false` on another. See Example 7.
- `NoneRequired` integrations have **no** `auth_types[]` entries
  (the array is `[]`), so the map requirement is moot for them — see
  Example 5.

### Canonical worked examples

**Example 1 — APIVoid pattern: APIKey with `hiddenusername: true`** (the identifier leaf is suppressed):

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

**Example 2 — Plain (basic auth) with both leaves:**

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
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example 3 — Plain with two separate flat params (not a credentials widget):**

```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "auth",
      "xsoar_param_map": {
        "server_user": "username",
        "server_password": "password"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example 4 — OAuth2ClientCreds with credentials widget (enum-undefined regime, any non-empty string accepted; maps to the `oauth2_client_credentials` profile with `client_key`/`client_secret` fields):**

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example 5 — NoneRequired (no `auth_types[]` entries; `config` key is absent in the new schema):**

```json
{
  "auth_types": [],
  "other_connection": []
}
```

**Example 6 — Microsoft multi-flow integration (CHOICE of three profiles, joined implicitly by exclusive-OR):**

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "client_creds",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    },
    {
      "type": "Passthrough",
      "name": "auth_code",
      "xsoar_param_map": {
        "auth_code": "authorization_code",
        "redirect_uri": "redirect_uri"
      },
      "interpolated": true
    },
    {
      "type": "Passthrough",
      "name": "device_code",
      "xsoar_param_map": {
        "device_code_grant": "device_code"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy"]
}
```

**Example 7 — per-profile `verify_connection_skip` on a Microsoft Graph Mail integration.** The Authorization Code profile's `test-module` raises `DemistoException("Run !msgraph-mail-auth-test after !msgraph-mail-auth-start to verify connectivity")` (or equivalent), so its `verify_connection_skip` is `true`. The Client Credentials profile's `test-module` reaches an HTTPS call to `https://graph.microsoft.com/v1.0/$metadata` and succeeds when the credentials are valid — `verify_connection_skip` is omitted (equivalent to `false`).

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "client_creds",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    },
    {
      "type": "Passthrough",
      "name": "auth_code",
      "xsoar_param_map": {
        "auth_code": "authorization_code",
        "redirect_uri": "redirect_uri"
      },
      "interpolated": true,
      "verify_connection_skip": true
    }
  ],
  "other_connection": ["insecure", "proxy"]
}
```

Note that `(type, name)` sort order is unchanged (`OAuth2ClientCreds` < `Passthrough`) and the absence of `verify_connection_skip` on the first profile is equivalent to `"verify_connection_skip": false`.

Schema validation is enforced by
[`auth_config_parser.validate_auth_details()`](auth_config_parser/validator.py:47)
(the workflow CLI calls a one-line wrapper at
[`workflow_state.validators.validate_auth_detail()`](workflow_state/validators.py:25))
and runs automatically on every `set-auth` invocation.

Setter:
[`workflow_state.py set-auth "<Integration ID>" '<json>'`](workflow_state/cli.py:225)
([`cmd_set_auth`](workflow_state/cli.py:225)).
Setting this value resets the workflow back to the first checkpoint
(`generated manifest`). The reset wipes every later workflow column
including the three Params\* data columns — `set-auth` deliberately
ignores the `preserve_on_reset` carve-out that `reset-to`/`fail`
honour, because auth-classification changes invalidate every
downstream artifact (in particular, the per-command param contract
validated by `params_to_commands_no_auth_overlap`).

---

## Authentication Profile Types — Fields Reference

This section is the schema-side counterpart to
[`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1) §1.2.6
"Authentication Profile Types — Fields Reference". The classification
written into `Auth Details` (above) maps onto these UCP profile types
when the manifest is generated. The five canonical profiles each have
a fixed field shape; anything that doesn't fit is `Passthrough` (the
on-disk JSON value is `"Passthrough"`).

### Quick reference — fields by connection type

| Profile Type | Profile-Level Properties | User-Facing `metadata.auth.parameter` Fields | Maps from `Auth Details` classification |
|---|---|---|---|
| `oauth2_client_credentials` | `discovery_url` **OR** `token_endpoint` | `client_key`, `client_secret` | `OAuth2ClientCreds` |
| `oauth2_jwt_bearer` | `discovery_url` **OR** `token_endpoint` | `subject_email`, `credentials_file` | `OAuth2JWT` |
| `plain` | *(none beyond `id`/`type`/`title`/`description`)* | `username`, `password` | `Plain` |
| `api_key` | *(none beyond `id`/`type`/`title`/`description`)* | `api_key` | `APIKey` (single key only) |
| `Passthrough` (no canonical profile) | n/a | n/a — define fields ad-hoc in the manifest | `Passthrough` — includes browser-flow Authorization Code, Device Code, ROPC, Managed Identity, mTLS, dual-key API (Datadog 2-key, AWS SigV4, Akamai EdgeGrid, GitHub App), custom signing |

> **Browser-flow OAuth2 Authorization Code** has a sibling profile (`oauth2_authorization_code`) whose **profile-level** keys include `client_id`, `client_secret` (both via the `{SAAS_REGISTRY.*}` pattern), `discovery_url` **OR** (`authorization_endpoint` + `token_endpoint`), and `refresh_token_scope`. It has **no user-facing `metadata.auth.parameter` fields** (the flow is browser-driven). Per the project-wide rule, classify it as `Passthrough` regardless — it has no canonical `auth.parameter` field-list to match against.

### Detailed per-profile breakdown

#### 1. `oauth2_client_credentials`

- **Profile-level keys:** `id`, `type`, `title`, `description`, plus exactly one of (`discovery_url` | `token_endpoint`).
- **`metadata.auth.parameter` fields:**
  - `client_key` — OAuth2 client ID / consumer key (`input`, unmasked).
  - `client_secret` — OAuth2 client secret (`input`, `mask: true`).
- **Classification:** `OAuth2ClientCreds`. Any integration whose code does `grant_type=client_credentials` with exactly two secrets (`client_id` + `client_secret`) fed in directly — no JWT, no browser redirect.

#### 2. `oauth2_jwt_bearer`

- **Profile-level keys:** `id`, `type`, `title`, `description`, plus exactly one of (`discovery_url` | `token_endpoint`).
- **`metadata.auth.parameter` fields:**
  - `subject_email` — impersonation subject (`input`, usually in `general_configurations`).
  - `credentials_file` — JSON key file (`file_upload`, `formats: ".json"`, `mask: true`).
- **Classification:** `OAuth2JWT`. Typically Google service-account integrations: signed JWT assertion + `grant_type=jwt-bearer` token endpoint.

#### 3. `plain`

- **Profile-level keys:** `id`, `type`, `title`, `description` only.
- **`metadata.auth.parameter` fields:**
  - `username` — account identifier (`input`, unmasked).
  - `password` — secret (`input`, `mask: true`).
- **Classification:** `Plain`. Username/password basic auth, login-form-to-session-cookie, any single-pair credential where one half is an identifier and the other half is a secret.

#### 4. `api_key`

- **Profile-level keys:** `id`, `type`, `title`, `description` only.
- **`metadata.auth.parameter` fields:**
  - `api_key` — token (`input`, `mask: true`).
- **Classification:** `APIKey`. **Single static secret only.** Bearer tokens, custom `X-API-Key` headers, query-param keys, and single-secret HMAC signing all fit.
- **Multi-key NOT supported.** Datadog (`api_key`+`application_key`), AWS (`access_key`+`secret_key`), Akamai EdgeGrid (3 tokens), GitHub App (`app_id`+`private_key`+`installation_id`) — these are all `Passthrough` because the `api_key` profile only exposes one `api_key` field.

#### 5. `Passthrough` (catch-all)

- **No canonical profile type or field list.** The manifest defines whatever fields the integration actually needs, ad-hoc.
- **Classification triggers (use `Passthrough` whenever):**
  - The flow is OAuth2 Authorization Code (browser redirect, `code`+`redirect_uri`, `oauth-start`/`oauth-complete` commands).
  - The flow needs two or more secrets to authenticate one request, where the (role, count) combo doesn't fit `plain`'s `username`+`password` shape.
  - The flow is ROPC (`grant_type=password`), Device Code, Managed Identity, mTLS, certificate-based, or any custom signing scheme.
  - You can't decide cleanly which canonical profile applies. **When in doubt, prefer `Passthrough`.**
- **All `Passthrough` entries MUST have `"interpolated": true`** (see §"Auth Details" above).

### Closed set of valid `metadata.auth.parameter` values

| Parameter | Used By | Notes |
|---|---|---|
| `client_key` | `oauth2_client_credentials` | OAuth client id |
| `client_secret` | `oauth2_client_credentials` | OAuth client secret |
| `username` | `plain` | Basic-auth identifier |
| `password` | `plain` | Basic-auth secret |
| `api_key` | `api_key` | Single static secret |
| `credentials_file` | `oauth2_jwt_bearer` | JSON key file upload |
| `subject_email` | `oauth2_jwt_bearer` | Impersonation subject |

> **Duplicate-value rejection (OPA Check 17).** Duplicate `metadata.auth.parameter` values within a profile's effective scope (the profile's own `configurations` + the connection.yaml's `general_configurations`) are rejected. If a vendor legitimately needs two copies of the same role (extremely rare), the integration cannot fit a canonical profile and must be classified as `Passthrough`.

### Decision rule (one-line summary)

> **If — and only if — every secret the integration consumes maps cleanly into one of the four canonical profiles' field lists above, use that profile's classification (`OAuth2ClientCreds` / `OAuth2JWT` / `Plain` / `APIKey`). Otherwise, classify as `Passthrough`.** `oauth2_authorization_code` is always `Passthrough` — its user-facing config lives on the profile itself, not in `metadata.auth.parameter`, so there is no canonical field shape to match against from the classification side.

---

## `Params to Commands`

Mapping of integration commands to the parameter IDs each command needs (by
name). Connection-level params (e.g. URL, credentials, proxy, insecure,
longRunning) are intentionally NOT listed per-command — those are configured
once at the integration level and are stripped by the analyzer's default
ignore list (see [Production source](#production-source) below).

```json
{
  "integration": "<Integration ID>",
  "commands": {
    "<command-name>": ["<param_id>", "<param_id>", ...]
  }
}
```

Example (post-ignore-list — only behavioral params remain):

```json
{
  "integration": "QRadar v3",
  "commands": {
    "test-module":          ["adv_params", "fetch_query"],
    "fetch-incidents":      ["fetch_query", "first_fetch", "max_fetch"],
    "qradar-offenses-list": ["fetch_query", "filter"]
  }
}
```

Notes:

- `commands` is a flat object: command name → array of parameter IDs.
- Per-command lists are produced sorted (case-sensitive ascending) **by
  convention** — the analyzer emits them sorted, but
  [`validate_params_to_commands`](workflow_state/validators.py:49) does
  not enforce sort order on per-command lists. Downstream consumers
  should treat them as sets and re-sort if they care.
- An empty list (`[]`) is the valid value for a command with no
  behavioral params.
- Parameter IDs match those in the integration's YML `configuration` section.
- Free-form: no enforced ordering or required keys beyond `integration` and
  `commands`.
- Per-command lists: the analyzer produces sorted lists by convention
  (case-sensitive ascending); the validator at
  [`validate_params_to_commands`](workflow_state/validators.py:49) does
  not enforce sort order on per-command lists, so downstream consumers
  should treat them as sets and re-sort if they care.
- **Extra top-level keys are HARD-REJECTED.** The validator at
  [`validate_params_to_commands`](workflow_state/validators.py:49)
  rejects any payload containing top-level keys other than `integration`
  and `commands`. The error for `diagnostics` specifically includes a
  strip-it one-liner
  (`import sys, json; o = json.load(sys.stdin); o.pop('diagnostics', None); print(json.dumps(o))`)
  because that is the most common offender — the analyzer emits
  `diagnostics` as internal AI metadata that must NEVER be persisted.
- **Disjointness with `Auth Details`:** `set-params-to-commands` HARD
  REJECTS any payload whose per-command lists include a YML param id
  that is already declared in the integration's `Auth Details` cell —
  either as a projected `auth_types[].xsoar_param_map` key (dotted
  forms collapse to the segment before the first `.`) or as an
  `other_connection` entry. Inspect the live exclusion set with
  [`workflow_state.py auth-params <Integration ID>`](workflow_state/cli.py:1)
  and see [`connectus/Readme.md`](Readme.md:1) for the full CLI
  reference. The analyzer can also pull this set automatically when
  invoked with `--integration-id <id>` (see below).
- **Reset semantics.** `Params to Commands` is **preserved** on `fail`
  and `reset-to` because the column carries `preserve_on_reset: true`
  in [`workflow_state_config.yml`](workflow_state_config.yml:74). It is
  **wiped** by `set-auth` and by plain `reset` — those two operations
  deliberately ignore the carve-out because auth changes invalidate
  every downstream artifact and `reset` is the "wipe the row" verb with
  no carve-outs.

### Production source

The `commands` object is produced by the
[`connectus/check_command_params.py`](check_command_params.py:1) analyzer
(see [`check_command_params_design.md`](check_command_params_design.md:1)
for full design and current implementation status). The standard
invocation is:

```bash
python3 connectus/check_command_params.py <integration_dir> \
    --ignore-params-file connectus/default_ignore_params.txt \
    --integration-id "<Integration ID>"
```

Pass `--integration-id <id>` to make the analyzer additionally pull the
integration's auth-derived ignore set from
[`workflow_state.py auth-params <id>`](workflow_state/cli.py:1) and union it
into its own ignore set. This guarantees the per-command output is
disjoint from the integration's `Auth Details` cell from the start.

The ignore list at
[`connectus/default_ignore_params.txt`](default_ignore_params.txt:1)
strips ~154 framework / auth / connection params (`url`,
`credentials`, `proxy`, `insecure`, `longRunning`, the feed
framework, …) so only **behavioral, per-command-meaningful** params
remain.

The analyzer's stdout is:

```text
{ "integration": "...", "commands": {...}, "diagnostics": {...} }
```

> ⚠️ **The `diagnostics` field MUST be stripped before persisting.**
> It is internal AI signal (per-command status enum, failure
> excerpts, captured-request counts, Scope-1 narrowing trace) for the
> migration skill's decision-making — it is NEVER part of the
> persisted `Params to Commands` cell. The
> `set-params-to-commands` payload must contain ONLY the
> `integration` and `commands` keys. See
> [`check_command_params_design.md`](check_command_params_design.md:1)
> §"Implementation Status" and
> [`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1)
> §5 for the full rule.

Setter:
[`workflow_state.py set-params-to-commands "<Integration ID>" '<json>'`](workflow_state/cli.py:229)
([`cmd_set_params_to_commands`](workflow_state/cli.py:229)).
Must be valid JSON. Required before `generated manifest` can be marked passed.

---

## `Params for test with default in code`

Plain JSON object mapping YML param name → its default value. Values can
be any JSON type (string, number, boolean, null, list, object) — whatever
the integration would treat as a default. Empty object `{}` is valid and
is the recommended value when an integration has no defaults to
override.

Consumed by
[`connectus/connectus_migration/connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:618)
as the `PARAM_DEFAULTS_JSON` positional argument.

```json
{
  "<yml_param_name>": <any JSON value>,
  ...
}
```

Worked example:

```json
{
  "fetch_limit": 50,
  "first_fetch": "3 days",
  "isFetchEvents": false,
  "max_fetch_size": null
}
```

Validator: [`validate_param_defaults()`](workflow_state/validators.py:147)
enforces:

1. Valid JSON.
2. Top-level is a JSON object (not list / not scalar).
3. Every key is a non-empty string.
4. Values may be any JSON type (no further restriction).

There are NO cross-checks against any other column. There are NO required
keys — `{}` is a valid value for any integration with no overridable
defaults.

Setter:
[`workflow_state.py set-param-defaults "<Integration ID>" '<json>'`](workflow_state/cli.py:1)
([`cmd_set_param_defaults`](workflow_state/cli.py:1)).
Must be valid JSON.

> **Reset semantics.** `Params for test with default in code` is **wiped** by every reset path
> (`reset`, `set-auth`, `fail`, `reset-to`). It does NOT carry
> `preserve_on_reset: true`. Today only `Params to Commands` retains
> that flag.

---

## `Shadowed Integration Commands`

JSON object mapping each command name in THIS integration that is also
defined in at least one sibling integration within the same connector
(i.e. shadowed inside the connector's command namespace) to the
proposed renamed form `<original>-<brand>`. The "losing" integration
must rename its command in BOTH the `.py` (dispatcher / handler) and
the `.yml` (`script.commands[].name`) before this cell is committed.
Replaces the former `shadowed command test passes` checkpoint
(removed 2026-05Q4).

Empty object `{}` is valid and is the recommended value when no
shadowed commands were detected for this integration.

```json
{
  "<original_command_name>": "<original>-<brand>",
  ...
}
```

Where:

- `<original_command_name>` is a non-empty string (matches the
  XSOAR command name; case / underscores allowed).
- `<original>-<brand>` is a non-empty string drawn from
  `^[A-Za-z0-9._-]+$`, and MUST equal the literal prefix
  `<original>-` followed by a non-empty brand suffix.
- The brand is derived from the integration's YML top-level `name`,
  lowercased, with any non-alphanumeric character replaced by `-`
  (runs collapsed, leading/trailing `-` stripped). If the YML has no
  `name`, the `Integration ID` cell is transformed the same way.

Worked example:

```json
{
  "ip": "ip-apivoid",
  "url": "url-apivoid"
}
```

Validator: `shadowed_commands` (a.k.a.
[`validate_shadowed_commands()`](workflow_state/validators.py:1))
enforces:

1. Valid JSON.
2. Top-level is a JSON object (not list / not scalar). Empty `{}` is valid.
3. Every key is a non-empty string.
4. Every value is a non-empty string matching `^[A-Za-z0-9._-]+$`.
5. Every value MUST equal `<key>-<non-empty brand>` (starts with
   `<key>-` and the brand portion is non-empty).
6. No two keys may map to the same renamed value.

In addition, the CLI setter [`set-shadowed-commands`](workflow_state/cli.py:1)
performs on-commit semantic validation against the integration's YML
and its connector siblings:

- Each `original` must currently be detected as shadowed within the
  connector (re-runs the detector below).
- The integration's YML MUST now contain a command named `renamed`
  AND MUST NOT contain a command named `original`.

Use the read-only detector to compute the rename map without
modifying anything:

```bash
python3 connectus/workflow_state.py detect-shadowed-commands "<Integration ID>"
```

Then apply the `.py` / `.yml` renames yourself, then commit:

```bash
python3 connectus/workflow_state.py set-shadowed-commands "<Integration ID>" '<JSON>'
```

> **Reset semantics.** `Shadowed Integration Commands` is **wiped** by
> every reset path (`reset`, `set-auth`, `fail`, `reset-to`). It does
> NOT carry `preserve_on_reset: true`.

---

## `Params to Capabilities`

Bare capability dict — exactly the JSON written by
[`connectus/connectus_migration/connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1)
to its `-o` / `--output` file. Top-level keys are capability names
(closed enum, listed below) plus the literal `general_configurations`,
and each value is a flat list of YML config param ids.

```json
{
  "<capability_key>": ["<yml_param_id>", "<yml_param_id>", ...],
  ...
}
```

### Allowed top-level keys (closed enum)

Sourced from
[`connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:13)
lines 13-18 plus the literal `"general_configurations"` used on line 141:

- `general_configurations`
- `Fetch Assets and Vulnerabilities`
- `Fetch Issues`
- `Log Collection`
- `Fetch Secrets`
- `Threat Intelligence & Enrichment`
- `Automation`

No key is REQUIRED. Empty `{}` is a valid payload.

Worked example (the verbatim Gmail Single User mapper output; see
[`connectus/connectus_migration/_gmail_param_mapping_sample.json`](connectus_migration/_gmail_param_mapping_sample.json:1)):

```json
{
  "general_configurations": ["fetch_limit", "query"],
  "Fetch Issues": ["fetch_time"],
  "Automation": ["legacy_name", "send_as", "redirect_uri"]
}
```

Validator: [`validate_params_to_capabilities()`](workflow_state/validators.py:204)
enforces:

1. Valid JSON.
2. Top-level is a JSON object.
3. Every key is a non-empty string drawn from the closed enum above. An
   unknown key is rejected with an error that names the offender and
   lists the allowed set.
4. Every value is a list of non-empty unique strings (no duplicates
   within a single capability's list).
5. No top-level keys are REQUIRED (empty `{}` valid).

There are NO cross-checks. Param ids do NOT need to appear in
`Params to Commands` — the mapper may legitimately route YML config
params (like `longRunningPort`) that the per-command analyzer does not
report.

Setter:
[`workflow_state.py set-params-to-capabilities "<Integration ID>" '<json>'`](workflow_state/cli.py:1)
([`cmd_set_params_to_capabilities`](workflow_state/cli.py:1)).
Must be valid JSON.

> **Reset semantics.** `Params to Capabilities` is **wiped** by every
> reset path (`reset`, `set-auth`, `fail`, `reset-to`). It does NOT carry
> `preserve_on_reset: true`.

### How to call the mapper script

[`connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1)
is a single-command Typer app — invoke it **without** a subcommand name;
the positional arguments come straight after the script path.

Positional arguments (in order):

1. `COMMAND_PARAMS_JSON` — pull from this integration's
   [`Params to Commands`](#params-to-commands) cell, e.g.
   `python3 connectus/workflow_state.py show-step "<Integration ID>" "Params to Commands"`.
2. `PARAM_DEFAULTS_JSON` — pull from this integration's
   [`Params for test with default in code`](#params-for-test-with-default-in-code) cell.
3. `INTEGRATION_YML_PATH` — the integration's YML manifest path; resolve
   via `python3 connectus/workflow_state.py files "<Integration ID>"`.
4. `MANUAL_COMMAND_TO_CAPABILITY_JSON` (OPTIONAL, defaults to `'{}'`) —
   command-name → list-of-capability-names overrides. Use `'{}'` unless
   you are deliberately overriding a routing decision (e.g.
   `'{"long-running-execution": ["Log Collection"]}'`).

Plus the option:

- `-o` / `--output` — output JSON path (defaults to
  `./param_mapping_output.json`).

Canonical invocation:

```bash
python3 connectus/connectus_migration/connector_param_mapper.py \
  '<COMMAND_PARAMS_JSON from Params to Commands cell>' \
  '<PARAM_DEFAULTS_JSON from Params for test with default in code cell>' \
  '<INTEGRATION_YML_PATH from workflow_state.py files>' \
  '{}' \
  -o connectus/connectus_migration/_<integration>_param_mapping.json
```

Concrete example for Gmail Single User:

```bash
python3 connectus/connectus_migration/connector_param_mapper.py \
  '{"integration":"Gmail Single User","commands":{"test-module":[],"send-mail":["legacy_name","send_as"]}}' \
  '{}' \
  Packs/GmailSingleUser/Integrations/GmailSingleUser/GmailSingleUser.yml \
  '{}' \
  -o connectus/connectus_migration/_gmail_param_mapping.json
```

The output file is then fed verbatim into
`set-params-to-capabilities`:

```bash
python3 connectus/workflow_state.py set-params-to-capabilities "Gmail Single User" \
  "$(cat connectus/connectus_migration/_gmail_param_mapping.json)"
```

---

## `Release Notes`

Added 2026-05-31 as part of the workflow re-sequencing (see
[`FIXES-TODO.md`](FIXES-TODO.md) — combined #4+#6+New_RN execution
plan). The cell verifies a release-notes file exists when the migration
touched the integration's own .py/.yml.

### JSON shape

Object with exactly three top-level keys:

```json
{
  "required": true,
  "path": "Packs/MyPack/ReleaseNotes/1_2_3.md",
  "verified": true
}
```

| Key | Type | Description |
|---|---|---|
| `required` | `bool` | Whether the migration introduced changes that mandate a release-notes entry. Computed from `git diff HEAD --name-only -- <integration>.py <integration>.yml`. |
| `path` | `str` \| `null` | Repo-relative path to the verified release-notes file. `null` when `required=false` or when no RN file was found. |
| `verified` | `bool` | Whether the file at `path` contains the required substring (case-sensitive exact match): `Enabled support for UCP`. Always `false` when `required=false`. |

### Cross-field rules

- `required: true` requires `path` to be a non-empty string.
- `required: false` requires `path: null` AND `verified: false` (nothing to verify).
- Extra top-level keys are rejected.

### Setter

[`workflow_state.py set-release-notes "<Integration ID>"`](workflow_state/cli.py:1)
([`cmd_set_release_notes`](workflow_state/cli.py:1)). The setter takes
no JSON payload — the cell shape is auto-computed from the working
tree:

1. `git diff HEAD --name-only -- <py> <yml>` decides `required`.
2. When `required=true`, look for the newest `Packs/<Pack>/ReleaseNotes/<Version>.md` file (highest version number across the directory).
3. Substring-match `"Enabled support for UCP"` (exact, case-sensitive) anywhere in that file.

If `required=true` and `verified=false`, the setter rejects with a
diagnostic that includes the recommended invocation:

```bash
demisto-sdk update-release-notes -i Packs/<PackName>
# Then edit the generated RN file to include the substring
# "Enabled support for UCP", and re-run set-release-notes.
```

### Reset semantics

`Release Notes` is **wiped** by every reset path (`reset`, `set-auth`,
`fail`, `reset-to`). It does NOT carry `preserve_on_reset: true`. Re-run
the setter after any reset.

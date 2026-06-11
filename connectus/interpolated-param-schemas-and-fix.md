# Interpolated Param Feature — Profile Schemas & Fix Plan

> Schema reference **and** fix plan for the UCP param-interpolation feature
> (implemented in `CommonServer.js` and `CommonServerPython.py`). Companion to
> [`interpolation-javascript-parity.md`](interpolation-javascript-parity.md).
>
> The feature reshapes a UCP credentials **envelope** (returned at runtime by
> `getUCPCredentials`) into the nested legacy `params` shape integrations expect,
> driven by a per-profile `interpolation_mapping` string defined in the manifest.

---

## 1. The three moving parts

```
  MANIFEST (connection.yaml)              RUNTIME (getUCPCredentials envelope)
  ────────────────────────────           ─────────────────────────────────────
  profiles[].metadata.xsoar              {"type": "<t>", "<t>": { ...fields... }}
    .interpolation_mapping
        "FIELD_ID:dest.path,..."
              │  ▲                                     │
              │  │ FIELD_ID must equal ───────────────┘ runtime envelope key
              │  └──────────────────────────────────────┐
              ▼                                          │
  fields[].metadata.auth.parameter ──────────────────────┘  (this is the
                                                              envelope key)
```

There are **three distinct schemas**, one per profile `type`, and they differ in:

1. **Nesting depth** of the field values inside the envelope.
2. **Which manifest fields appear in the envelope at all** (only auth-tagged
   fields; `none_*`/pubsub config fields do **not**).
3. **What key the field is stored under** in the envelope (= `auth.parameter`,
   *not* the manifest field `id`).

The interpolation code (`buildUcpParams` / `build_ucp_params`) does:

```
mapping = profile.metadata.xsoar.interpolation_mapping        # "FIELD_ID:dest,..."
pairs   = parse(mapping)                                       # [(FIELD_ID, dest)]
env     = getUCPCredentials(profile.method_unique_id)         # {"type","<t>":{...}}
flat    = flatten(env)                                         # see §3
for FIELD_ID, dest in pairs:
    value = flat.get(FIELD_ID)        # <-- KEY LOOKUP — must match exactly
    if value is not None:
        placeByPath(result, dest, value)
merge result into params
```

If `FIELD_ID` does not exactly match a key in `flat`, the value is **silently
dropped** (logged at debug only). That silent drop is the failure mode behind
every bug below.

---

## 2. Runtime envelope schemas (observed)

Captured via the `[UCP-SCHEMA-DUMP]` debug logs (`getUCPCredentials` envelope):

### 2.1 `plain`

```json
{
  "type": "plain",
  "plain": { "username": "user", "password": "pass" }
}
```

- Fields live **directly** under `creds["plain"]`.
- Envelope keys: `username`, `password`.
- Source code that produces/consumes these keys:
  `_apply_ucp_plain` reads `credentials["plain"].get("username"/"password")`
  (`CommonServerPython.py:9975-9981`).

### 2.2 `api_key`

```json
{
  "type": "api_key",
  "api_key": { "key": "sdaadasdasd", "header_name": "X-API-Key" }
}
```

- Fields live **directly** under `creds["api_key"]`.
- Envelope keys: **`key`**, `header_name`.
- Source: `_apply_ucp_api_key` reads `credentials["api_key"].get("key")`
  (`CommonServerPython.py:9956-9957`). **The key is `key`, not `api_key`.**

### 2.3 `passthrough`

```json
{
  "type": "passthrough",
  "passthrough": {
    "parameters": {
      "client_id": "...",
      "client_secret": "...",
      "server_url": "...",
      "token_url": "...",
      "ca_bundle": "...",
      "tls_min_version": "tls13",
      "insecure": false,
      "useproxy": false,
      "pubsub_grant_type": "refresh_token",
      "pubsub_oauth_scopes": "read:dns",
      "integrationLogLevel": "Verbose"
    }
  }
}
```

- Fields live **one level deeper**, under `creds["passthrough"]["parameters"]`.
- Envelope keys = each field's `metadata.auth.parameter` (free-form; passthrough
  is the escape hatch with no enum) — e.g. `client_id`, `server_url`,
  `tls_min_version`, `useproxy`, `ca_bundle`, `insecure`.
- `pubsub_*` keys are present too (delivered via the lifecycle event), and an
  extra `integrationLogLevel` the platform injects.

### Schema comparison table

| Aspect | `plain` | `api_key` | `passthrough` |
|---|---|---|---|
| Value location | `creds.plain.<field>` | `creds.api_key.<field>` | `creds.passthrough.parameters.<field>` |
| Extra nesting | none | none | **`parameters`** sub-dict |
| Envelope key = | `auth.parameter` | `auth.parameter` | `auth.parameter` (free-form) |
| Standard keys | `username`, `password` | `key`, `header_name` | arbitrary |
| Fields NOT in envelope | `none_*`, `pubsub_*` (no auth tag) | `none_*`, `pubsub_*` | `none_*` only (pubsub IS present) |

---

## 3. How `flatten` normalizes the three schemas

`_flattenUcpCredentialsGeneric` (JS, `CommonServer.js:2614-2630`) and the inline
flatten in `build_ucp_params` (Python, `CommonServerPython.py:9916-9931`) do:

```
flat = creds[creds.type]      # descend into the type key  ({"plain":{...}} -> {...})
if flat has "parameters":     # passthrough only
    flat = flat["parameters"] # descend one more level
# fallback: if creds[creds.type] is not a dict, use creds as-is
```

So after flatten, all three collapse to a **flat dict of `auth.parameter -> value`**:

| type | flat result keys |
|---|---|
| `plain` | `username`, `password` |
| `api_key` | `key`, `header_name` |
| `passthrough` | `client_id`, `server_url`, `token_url`, `tls_min_version`, ... |

**Therefore the contract is unambiguous:** the `FIELD_ID` (left of the colon in
`interpolation_mapping`) MUST equal the field's `metadata.auth.parameter`, which
is the envelope/flat key. The generator docstring agrees
(`manifest_generator.py:5416-5418`), but the generator does not honor it (§5).

---

## 4. How to interact with the fields

### 4.1 From the manifest (`connection.yaml`)

- **Declare a field** under `profiles[].configurations[].fields[]`.
- **To make a field appear in the credentials envelope**, give it
  `metadata.auth.parameter: <key>`. The platform keys the envelope by that
  parameter. Fields without `auth.parameter` (the `none_*` config fields) are
  **never** in the envelope and cannot be interpolated from it.
- **To interpolate that field into `params`**, add an entry to
  `profiles[].metadata.xsoar.interpolation_mapping`:

  ```
  <auth.parameter>:<dotted.params.path>
  ```

  Multiple entries are comma-separated. Two entries sharing a parent path fold
  into one dict (the classic type-9 credentials shape):

  ```
  username:creds.identifier,password:creds.password
  #  -> params["creds"] = {"identifier": ..., "password": ...}
  ```

### 4.2 From the runtime body (envelope)

- Always branch on `creds["type"]`, then read `creds[type]`.
- For `passthrough`, descend into `creds[type]["parameters"]`.
- Look fields up by their **`auth.parameter` name**, never the manifest `id`.
- A missing key returns `None`/`undefined` and is skipped — never assume a
  mapped field is present (e.g. optional `ca_bundle`).

---

## 5. Root-cause analysis of the current bug

Comparing the live envelopes (§2) against `connectors/mxtoolbox/connection.yaml`:

| Profile | mapping `FIELD_ID`s | flat envelope keys | Outcome |
|---|---|---|---|
| `plain` (L155) | `username`, `password`, **`server_url`** | `username`, `password` | `username`/`password` ✅; **`server_url` dropped** — it is the `none_server_url` config field with **no `auth.parameter`**, so never in the envelope |
| `api_key` (L16) | **`api_key`** | `key`, `header_name` | **Total miss** — `FIELD_ID=api_key` ≠ envelope key `key` → nothing interpolated |
| `passthrough` (L276) | `client_id`, `client_secret`, `token_url`, `server_url` | matching keys present | ✅ works |

Two independent defects, both in the **generator**:

**Defect A — `api_key` FIELD_ID is remapped the wrong way.**
`manifest_generator.py:5320-5322`:

```python
ROLE_TO_AUTH_PARAMETER = { ("api_key", "key"): "api_key" }
```

The classifier role for an API key secret is `key`, which is *also* the runtime
envelope key (`_apply_ucp_api_key` reads `.get("key")`). This map rewrites the
correct `key` into `api_key`, so the emitted mapping (`api_key:api_key.password`)
looks up a key that does not exist. The remap is inverted relative to its own
docstring ("LEFT side ... matches ... the runtime credentials-envelope key").

**Defect B — non-auth fields are mapped despite never being in the envelope.**
The `plain` mapping includes `server_url:none_server_url`, but `none_server_url`
has no `metadata.auth.parameter`, so it is a config field the platform does not
return in the credentials envelope. Mapping it can never succeed via
interpolation; it must come from the normal `params` path instead.

---

## 6. Fix plan

### 6.1 Where to fix — options & recommendation

| Option | What | Pros | Cons |
|---|---|---|---|
| **A. Generator-side (recommended)** | Correct `interpolation_mapping` emission so `FIELD_ID == auth.parameter` and non-auth fields are excluded | Fixes the data at the source; runtime stays a faithful, dumb interpolator; all newly generated manifests correct; matches the documented contract | Existing already-emitted manifests must be regenerated |
| B. Runtime fallback | Make `buildUcpParams`/`build_ucp_params` tolerant (alias `api_key`→`key`, try field `id` if `auth.parameter` misses) | Fixes already-shipped manifests without regen | Hides the real defect; per-type special-casing creeps into the runtime; JS/Python must stay in lockstep; ambiguous when alias collides |
| C. Both | A for correctness + a thin, well-logged runtime guard as defense-in-depth | Robust during the regen transition | Most work; risk of masking future generator regressions |

**Recommendation: Option A**, with an optional, clearly-logged transitional
alias from Option C if there are already-shipped manifests in the field that
cannot be regenerated immediately. Rationale: the runtime already implements the
contract correctly and identically in both languages; the bug is purely
generated data, and the generator's own docstring already specifies the correct
behavior.

### 6.2 Generator changes (`connectus_migration/manifest_generator.py`)

1. **Fix Defect A — remove/correct the inverted remap.**
   - Delete the `("api_key", "key"): "api_key"` entry from
     `ROLE_TO_AUTH_PARAMETER` (line 5321) so the role `key` passes through
     unchanged. **Verify** `_auth_parameter_for_role` then yields `key`, AND that
     the field's emitted `metadata.auth.parameter` is also `key` (the two MUST
     agree — they are the same envelope key). If the field is intentionally
     tagged `api_key`, then instead change the runtime expectation — but per
     `_apply_ucp_api_key` the platform uses `key`, so `key` is correct.
   - Add a unit assertion: for an APIKey auth type, the emitted
     `interpolation_mapping` left-hand side equals the emitted field's
     `auth.parameter`.

2. **Fix Defect B — never map fields with no `auth.parameter`.**
   - In `build_interpolation_mapping` (line 5410), skip any `xsoar_param_map`
     entry whose field will be emitted without a `metadata.auth.parameter`
     (i.e. `none_*` config fields). These belong to the regular `params` path,
     not interpolation.
   - Confirm `none_server_url` (and similar) are dropped from the `plain`
     mapping after this change.

3. **Add an invariant check in the generator** (cheap, high-value): after
   building each profile, assert every `interpolation_mapping` `FIELD_ID` has a
   corresponding field with that exact `auth.parameter`. Fail generation loudly
   rather than emitting a silently-broken mapping.

### 6.3 Runtime changes (only if Option C transitional guard is adopted)

Keep JS and Python **1:1**. If a transitional alias is required:

- In the flatten/lookup step, when `flat.get(FIELD_ID)` misses, attempt a single
  documented alias (`api_key`→`key`) and emit a `demisto.error`/`logError`
  marker like `[UCP][interp] alias-fallback used for FIELD_ID=...` so broken
  manifests are visible and can be regenerated. Remove once regen is complete.
- Do **not** add `id`-based fallback; it reintroduces the field-id-vs-parameter
  ambiguity the design eliminated.

### 6.4 Regenerate & validate manifests

- Regenerate `connectors/mxtoolbox/connection.yaml` with the fixed generator.
  Expected results:
  - `api_key` profile: `interpolation_mapping: key:api_key.password`
    (or whatever the correct destination is — see open question OQ-2).
  - `plain` profile: `username:api_username.identifier,password:api_username.password`
    (the `server_url` entry removed).
  - `passthrough` profile: unchanged.
- Run the connection schema + OPA validators in `unified-connectors-content`.

### 6.5 Tests

- **Generator** (`manifest_connection_builders_test.py`): assert FIELD_ID ==
  auth.parameter for api_key; assert non-auth fields excluded from mapping.
- **Runtime** (`CommonServerPython_test.py` + JS suite): add fixtures for all
  three envelope shapes (esp. `api_key` with key `key`, and `passthrough` with
  the `parameters` nesting) and assert correct `placeByPath` results. Keep the
  Python and JS scenarios identical (parity).

### 6.6 Plan B — Generator-enforced interpolation schema (hard gate)

> Plan B is **complementary to Option A**, not an alternative to it. Option A
> fixes *what* the generator emits; Plan B makes the generator **refuse to emit
> a broken `interpolation_mapping` at all** — it turns the contract in §1–§3
> from a convention into a build-time invariant. Where §6.2 item 3 suggests an
> "invariant check", Plan B specifies the full, fail-loud gate.

**Why a hard gate.** The failure mode behind every bug in §5 is a *silent* drop
at runtime (§1: a mismatched `FIELD_ID` is logged at debug and discarded). A
silently-broken mapping ships, and the breakage only surfaces as a missing
credential in production. Moving the check into the generator converts that
silent runtime drop into a loud generation-time error with full context
(connector id + profile + offending entry), so a bad manifest can never be
written.

#### 6.6.1 Reconciliation with the current runtime (flatten-v3)

The runtime has moved on since §5 was written. `CommonServerPython.py:13711`
and `CommonServer.js:2147` now define a **canonical-key alias map**:

```python
_UCP_CANONICAL_FIELD_KEYS = {
    'api_key': {'api_key': 'key'},                      # auth.parameter 'api_key' -> envelope key 'key'
    'plain':   {'username': 'username', 'password': 'password'},
}
```

and `build_ucp_params` resolves `lookup_key = canonical_keys.get(field_id, field_id)`
before reading the envelope (`CommonServerPython.py:13959-13962`,
`CommonServer.js:2738-2744`; both tagged `[UCP-CODE-VERSION] flatten-v3`).

**This changes the §5 Defect-A conclusion.** Defect A said the `api_key` remap
to `api_key` was inverted because the envelope key is `key`. With flatten-v3 the
runtime now **owns** that alias: the correct, parity-safe `FIELD_ID` (and the
field's `metadata.auth.parameter`) is **`api_key`**, and the runtime aliases it
to envelope key `key` itself. Therefore the generator must emit `api_key` on the
LEFT — *not* `key`, and *not* the pre-flatten-v3 "delete the remap" fix. Plan B
enforces alignment with flatten-v3, superseding the "delete the remap" step in
§6.2 item 1. (OQ-2/OQ-3 in §7 are likewise updated: the `key` destination and
`header_name` questions are now answered by the canonical-key map, not by a
generator remap.)

#### 6.6.2 The enforced invariants

Enforced inside the connection-profile builder (`build_interpolation_mapping` /
`build_connection_profile`, `connectus_migration/manifest_generator.py`):

| ID | Invariant | Rationale / source |
|---|---|---|
| **INV-1** | Every `interpolation_mapping` LEFT (`FIELD_ID`) equals an emitted field's `metadata.auth.parameter` **in the same profile** | The §1–§3 contract: LEFT must match the flattened-envelope key. |
| **INV-2** | No field lacking `metadata.auth.parameter` (i.e. `none_*` config fields) appears in the mapping | Defect B, §5: such fields are never in the credentials envelope and can only come from the normal `params` path. |
| **INV-3** | For `api_key`, LEFT is `api_key` (the `auth.parameter`), consistent with `_UCP_CANONICAL_FIELD_KEYS['api_key'] = {'api_key':'key'}` | §6.6.1: runtime aliases `api_key`→`key`; generator must emit `api_key`, never raw `key`. |
| **INV-4** | No `,` or `:` in any role (LEFT) and no `,` in any destination path (RIGHT) | The grammar has **no escaping** (`_parse_param_map` hard-splits on `,` and first `:`). |
| **INV-5** | `metadata.xsoar.interpolated: true` is present on every emitted profile | ALWAYS-INTERPOLATE gate — every profile is interpolated regardless of `type`. |

#### 6.6.3 Where & how to enforce

- Add a single validation pass at the **end of `build_connection_profile`**,
  after the field loop and the `build_interpolation_mapping` call, before the
  `return`.
- The pass receives the built profile dict (fields + emitted mapping) and
  checks INV-1…INV-5 against the profile's own fields.
- On any violation, **raise** a descriptive error that names the connector id,
  the profile (`type` + `name`/`id`), and the exact offending entry — e.g.:
  `manifest_generator: interpolation_mapping entry 'server_url:none_server_url'`
  `in profile 'plain.mxtoolbox' references field with no metadata.auth.parameter`
  `(INV-2). Map only auth-tagged fields.`
- Generation **aborts**; a broken `connection.yaml` is never written. This is
  cheaper to debug than a silent runtime drop and impossible to ship past.

#### 6.6.4 Tests (generator-side)

Extend `connectus/connectus_migration/manifest_connection_builders_test.py`:

- One **positive** test per invariant (a well-formed profile passes the gate).
- One **must-raise** negative per invariant:
  - INV-1: mapping LEFT with no matching `auth.parameter` ⇒ raises.
  - INV-2: a `none_*` field in the mapping ⇒ raises.
  - INV-3: `api_key` profile emitting `key:...` instead of `api_key:...` ⇒ raises.
  - INV-4: a role/path containing `,` or a role containing `:` ⇒ raises.
  - INV-5: a profile missing `interpolated: true` ⇒ raises.
- **Round-trip parse guard:** feed each gate-approved `interpolation_mapping`
  through `_parse_param_map` semantics and assert it yields exactly the
  `(auth.parameter, xsoar_path)` pairs for the profile — proving every emitted
  string is parseable and round-trips. Keep this identical to the runtime
  parser so the generator and runtime can never disagree.

---

## 7. Open questions

- **OQ-1 (regen scope):** Are there already-shipped manifests beyond mxtoolbox
  that were generated with the inverted `api_key` remap? If yes → adopt the
  transitional runtime alias (Option C) until all are regenerated.
  > **Update (flatten-v3, §6.6.1):** the runtime now aliases `api_key`→`key`
  > itself via `_UCP_CANONICAL_FIELD_KEYS`, so an already-shipped manifest that
  > emits `api_key:...` is now correct. The regen concern is reduced to
  > manifests that emitted the raw `key:...` LEFT (which INV-3 now forbids).
- **OQ-2 (api_key destination):** For mxtoolbox, the api_key mapping targets
  `api_key.password` (a type-9-style nesting). Confirm the integration actually
  reads the key from `params["api_key"]["password"]`, or whether it should be a
  flat destination. The destination (right side) is a separate concern from the
  FIELD_ID fix.
  > **Update (flatten-v3):** the LEFT/FIELD_ID side is now settled — it is the
  > `auth.parameter` `api_key`, aliased to envelope key `key` by the runtime.
  > Only the RIGHT-side destination remains an integration-specific question.
- **OQ-3 (header_name):** The `api_key` envelope also carries `header_name`
  (`X-API-Key`). Is that meant to drive a custom header placement (via
  `_apply_ucp_api_key` override) or be interpolated into params? Currently
  unmapped. `header_name` is **not** in `_UCP_CANONICAL_FIELD_KEYS`, so it is
  only reachable if a profile maps it explicitly; the canonical path remains the
  `_apply_ucp_api_key` override.
- **OQ-4 (extra envelope keys):** `passthrough` returns platform-injected keys
  (`integrationLogLevel`) and `pubsub_*` values. Confirm none need interpolation
  and that ignoring unmapped keys is the intended behavior.

---

## 8. Key file references

| Concern | File | Lines |
|---|---|---|
| JS flatten | `Packs/Base/Scripts/CommonServer/CommonServer.js` | 2614–2630 |
| JS build/interp | `…/CommonServer.js` | 2657–2728 |
| Python flatten (inline) | `Packs/Base/Scripts/CommonServerPython/CommonServerPython.py` | 9916–9931 |
| Python build_ucp_params | `…/CommonServerPython.py` | 13812–13946 |
| Python apply api_key (`.get("key")`) | `…/CommonServerPython.py` | 9937–9961 |
| Generator mapping builder | `connectus/connectus_migration/manifest_generator.py` | 5410–5428 |
| **Inverted remap (Defect A)** | `…/manifest_generator.py` | 5320–5322 |
| **Canonical-key alias map (flatten-v3, §6.6.1)** | `…/CommonServerPython.py` | 13711–13714 |
| Canonical-key alias map (JS) | `…/CommonServer.js` | 2147–2150 |
| Canonical-key lookup in build (Py / JS) | `…/CommonServerPython.py` / `…/CommonServer.js` | 13959–13962 / 2738–2744 |
| Profile schema (type enum) | `unified-connectors-content/schema/connection.schema.json` | 128, 133 |
| mxtoolbox manifest | `unified-connectors-content/connectors/mxtoolbox/connection.yaml` | 16, 155, 276 |

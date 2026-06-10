# Interpolation Map — Research-Backed Implementation Plan

**Status:** Planning/research only. No `.py` edited. This document is the spec
handed to the implementation subtask.

**Goal:** Make the ConnectUs manifest generator translate each XSOAR
`auth_types[].xsoar_param_map` (the `Auth Details` cell) into UCP-manifest
**interpolation expressions**, matching BOTH (1) the UCP connector-manifest
placeholder grammar AND (2) the `CommonServerPython` runtime contract that
substitutes them.

---

## 1. Findings (ground truth, with file:line citations)

### 1.1 UCP interpolation syntax (real connector manifests)

The interpolation expression lives on a **connection profile** under
`metadata.xsoar.interpolation_mapping`, and it is a **single
comma-separated string** of `role:dotted.xsoar.path` entries — NOT `${...}`,
NOT `{{...}}`, NOT `<<...>>`.

Evidence — [`../unified-connectors-content/connectors/microsoft365-services/connection.yaml`](../../../unified-connectors-content/connectors/microsoft365-services/connection.yaml):

- Authorization-Code passthrough profile, lines 188–190:
  ```yaml
  metadata:
    xsoar:
      interpolation_mapping: "client_id:credentials_auth_id.password,authorization_code:auth_code_creds.password,redirect_uri:redirect_uri"
  ```
- Certificate passthrough profile, lines 263–265:
  ```yaml
  metadata:
    xsoar:
      interpolation_mapping: "client_id:credentials_auth_id.password,certificate_thumbprint:credentials_certificate_thumbprint.password,private_key:private_key"
  ```
- Client-Credentials passthrough profile, lines 338–340:
  ```yaml
  metadata:
    xsoar:
      interpolation_mapping: "client_id:credentials_auth_id.password,client_secret:credentials_enc_key.password"
  ```
- Managed-Identity passthrough profile, lines 397–399:
  ```yaml
  metadata:
    xsoar:
      interpolation_mapping: "managed_identity_client_id:managed_identities_client_id.password"
  ```

**Grammar of each entry:** `LEFT:RIGHT` where
- **LEFT** = the field's **`metadata.auth.parameter`** value (the canonical
  auth *role*). E.g. the auth-code profile's first field has
  `metadata.auth.parameter: client_id`
  ([line 198](../../../unified-connectors-content/connectors/microsoft365-services/connection.yaml)),
  matching the `client_id:` prefix in the mapping at line 190.
- **RIGHT** = the **dotted XSOAR param leaf path** the integration's
  `demisto.params()` expects at runtime (e.g. `credentials_auth_id.password`,
  or a flat `redirect_uri` / `private_key`).

**Separate, unrelated template syntax — `{{...}}`.** The file also uses
`{{tenant_id}}` inside `discovery_url`
([line 136](../../../unified-connectors-content/connectors/microsoft365-services/connection.yaml)).
This is a **field-reference template for URL composition** (a *different*
feature) and is NOT the param-interpolation mechanism. The migration's
`xsoar_param_map` translation uses `interpolation_mapping`, not `{{...}}`.

**Where the keys appear in the manifest:**
- `metadata.xsoar.interpolation_mapping` — on each `profiles[]` entry (the
  interpolation expression string).
- `metadata.auth.parameter` — on each `profiles[].configurations[].fields[]`
  entry (the role; the LEFT side of each interpolation pair).
- `metadata.xsoar.interpolated` — on each `profiles[]` entry, the boolean flag
  the parity runtime reads (see §1.3).

> NOTE: In the MS365 example, the field `id` (e.g. `auth_code_client_id`,
> line 193) is DIFFERENT from the role on the LEFT of the mapping (`client_id`).
> The interpolation LEFT side is the **role / `metadata.auth.parameter`**, NOT
> the field `id`. This is corroborated by the CommonServerPython contract (§1.2).

### 1.2 CommonServerPython interpolation contract (the runtime)

The runtime substitutes interpolation placeholders in
[`Packs/Base/Scripts/CommonServerPython/CommonServerPython.py`](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py).

Key functions:

- **`build_ucp_params(connector_metadata, capability=None)`**
  ([CommonServerPython.py:13812](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)) —
  the core. For each in-scope profile it reads
  `profile['metadata']['xsoar']['interpolation_mapping']`
  ([line 13898](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)),
  parses it with `_parse_param_map`, fetches the credentials envelope via
  `get_ucp_credentials(method_unique_id)`
  ([line 13909](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)),
  flattens it, then for each `(field_id, destination)` pair looks up
  `cred_values.get(field_id)` and writes it with `_place_by_path`
  ([lines 13935–13943](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).

- **`_parse_param_map(param_map)`**
  ([CommonServerPython.py:13738](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)) —
  the grammar parser. Canonical form is **a single comma-separated string of
  `field_id:dotted.destination`**
  ([docstring lines 13742–13745](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).
  Parsing rules (exact):
  - Split on `,` ([line 13760](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).
  - Each entry is `.strip()`-ed; **empty entries skipped** ([lines 13761–13763](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).
  - Entry must contain `:`; entries with no `:` are logged + skipped ([lines 13764–13768](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).
  - Split on the **first** `:` only — `entry.split(':', 1)`
    ([line 13769](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).
    ⇒ the RIGHT side (destination path) MAY contain `:`? No — it is split once,
    so any further `:` stays in the destination. In practice destinations are
    dotted paths with no `:`.
  - Both sides `.strip()`-ed; pair dropped if either side is empty
    ([lines 13771–13779](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)).
  - A `dict` form `{field_id: destination}` is ALSO accepted for
    backward-compat ([docstring lines 13747–13748](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)),
    but the comma-string is canonical and what real manifests emit.

- **`_place_by_path(target, path, value)`**
  ([CommonServerPython.py:13699](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py)) —
  splits the destination on `.` (empty segments dropped, line 13725),
  creates/reuses intermediate dicts, sets the leaf. So
  `credentials.password` → `{"credentials": {"password": <value>}}`; two paths
  sharing a parent merge (lines 13705–13709). A single-segment path
  (`url`, `redirect_uri`) places a flat scalar.

**The decisive direction-of-mapping fact** — confirmed by the runtime test
`TestUcpInterpolationPassthroughDeep`
([CommonServerPython_test.py:13687–13764](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py)):
the LEFT side (`field_id` in `_parse_param_map` terms) is matched against the
**flattened credentials-envelope keys**, and those keys are the
**`metadata.auth.parameter` role values** (e.g. `username`, `app_password`,
`client_key`, `client_secret`), NOT the connector field `id`s. The envelope
`parameters` dict in the test is keyed exactly by those roles
([lines 13719–13734](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py)),
and the RIGHT side is the dotted XSOAR destination
(`credentials.identifier`, `credentials.password`, `credentials.metadata.email`, …).
Assertion at [lines 13745–13764](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py)
confirms the nested XSOAR shape produced.

**Envelope-flatten rule** (so the implementer knows what the LEFT side keys
must equal):
[CommonServerPython.py:13916–13931](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py) —
`{"type": <t>, <t>: {...}}` is descended into `credentials[type]`; for
`passthrough` it descends one more level into `parameters`. The keys at that
final level are the auth-parameter roles. Per-type layouts documented in
`TestUcpInterpolationByProfileType`
([CommonServerPython_test.py:13830–13841](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py)):
- `plain`: `{"type":"plain","plain":{<role>:<v>}}` (flat)
- `api_key`: `{"type":"api_key","api_key":{<role>:<v>}}` (flat)
- `passthrough`: `{"type":"passthrough","passthrough":{"parameters":{<role>:<v>}}}` (wrapped)

**Escaping rules:** none. `_parse_param_map` has no escape mechanism — `,` and
`:` are hard delimiters (`:` only on first occurrence). Therefore roles and
XSOAR field paths MUST NOT contain `,` (and roles MUST NOT contain `:`).
In practice neither does — roles are identifiers and XSOAR leaf paths are
dot-segmented identifiers.

**Net contract:** each interpolation entry the generator emits must be
`"{role}:{xsoar_field_path}"`, where `{role}` equals the field's
`metadata.auth.parameter` (so the runtime finds it in the credentials
envelope) and `{xsoar_field_path}` is the dotted destination
`demisto.params()` should receive.

### 1.3 The `interpolated` boolean flag (parity-gate contract)

The parity runtime reads interpolation enablement from the **profile**, not
the Auth Details cell:
[`connectus/runtime_demisto.params_parity/resolver.py`](runtime_demisto.params_parity/resolver.py)
`_is_interpolated()` ([resolver.py:310–327](runtime_demisto.params_parity/resolver.py))
reads ONLY `profile['metadata']['xsoar']['interpolated']` and treats either a
JSON bool `true` OR the string `"true"` (case-insensitive) as enabled
([lines 322–326](runtime_demisto.params_parity/resolver.py)). The
`Auth Details` object's own `interpolated` key is explicitly NOT consulted
([docstring lines 313–314](runtime_demisto.params_parity/resolver.py)).

### 1.4 How the generator handles auth today (the gap)

The connection profile builder is
[`build_connection_profile()`](connectus_migration/manifest_generator.py:4803)
in [`connectus/connectus_migration/manifest_generator.py`](connectus_migration/manifest_generator.py).
Assembled by
[`build_connection_yaml()`](connectus_migration/manifest_generator.py:5432)
which is called from `create_manifest_from_scratch`
([line 5898](connectus_migration/manifest_generator.py)) and
`add_handler_to_existing_connector`
([line 6262](connectus_migration/manifest_generator.py)).

Current per-entry rendering ([lines 4828–4866](connectus_migration/manifest_generator.py)):

- Reads `xsoar_param_map` ([line 4828](connectus_migration/manifest_generator.py)).
- For each sorted map key ([line 4832](connectus_migration/manifest_generator.py)):
  - `role = xsoar_param_map[map_key]` (line 4833).
  - `field_id = _connection_field_id_from_map_key(map_key, map_keys)`
    ([line 4834](connectus_migration/manifest_generator.py); helper at
    [4744–4761](connectus_migration/manifest_generator.py)):
    `<p>.identifier` → `<p>_username`; `<p>.password` → `<p>_password` (if
    `.identifier` sibling present) else bare `<p>`; flat key → verbatim.
  - `auth_parameter = _auth_parameter_for_role(profile_type, role)`
    ([line 4835](connectus_migration/manifest_generator.py); helper 4764–4771):
    APIKey `key` → `api_key` (via `ROLE_TO_AUTH_PARAMETER`,
    [4684–4686](connectus_migration/manifest_generator.py)); plain &
    passthrough roles pass through verbatim.
  - Emits a field `{id, title, field_type:"input", metadata:{auth:{parameter}}, options:{...}}`
    ([lines 4837–4849](connectus_migration/manifest_generator.py)).
- Returns the profile dict `{id, type, view_group, title, description, configurations}`
  ([lines 4851–4866](connectus_migration/manifest_generator.py)).

**What is MISSING today:**
1. **No `metadata.xsoar.interpolation_mapping`** is ever emitted on the
   profile. Grep confirms zero occurrences of `interpolation_mapping` in
   [`manifest_generator.py`](connectus_migration/manifest_generator.py) (only
   `xsoar.config_type` / `xsoar.dynamic_values` appear, on NON-auth fields:
   lines 3238, 3430, 3471, 4934, 5062, 5085). ⇒ The runtime's
   `build_ucp_params` finds no mapping → `_parse_param_map` returns `[]` →
   nothing is interpolated.
2. **No `metadata.xsoar.interpolated` boolean** is emitted on the profile,
   even though the `Auth Details` cell ALWAYS carries `interpolated: true`
   per the ALWAYS-INTERPOLATE GATE
   ([column-schemas.md:110–123](column-schemas.md)). ⇒ The parity gate's
   `_is_interpolated()` always reads `false` for generated manifests.

The classifier-side `interpolated` flag IS present in the `Auth Details`
JSON (it's forced `true` by `set-auth`), and the generator receives it inside
each `auth_type_entry`, but `build_connection_profile` never reads
`auth_type_entry.get("interpolated")` (grep: the only `interpolated` references
in the generator dir are in
[`run_pre_manifest_steps.py`](connectus_migration/run_pre_manifest_steps.py)
where the classifier *writes* it, never where the manifest builder *reads* it).

### 1.5 Auth Details JSON shape + role enums (confirmed)

From [`connectus/column-schemas.md`](column-schemas.md:16) and the loaded
skill:

- `xsoar_param_map` is `{ "<xsoar_field_path>": "<role>" }`
  ([column-schemas.md:26–29, 74–94](column-schemas.md)).
- Keys are dotted YML leaf paths: flat param id (types 0/4/14/17) → bare id;
  credentials param (type 9) → `<paramid>.identifier` + `<paramid>.password`
  ([column-schemas.md:79–91](column-schemas.md)).
- Role enum per type
  ([column-schemas.md:96–103](column-schemas.md)):

  | `type` | allowed role values |
  |---|---|
  | `APIKey` | `key` |
  | `Plain` | `username`, `password` |
  | `Passthrough` | any non-empty string (`client_id`, `client_secret`, `access_token`, …) |
  | `NoneRequired` | n/a — no `auth_types[]` entry |

- `interpolated` is forced `true` on every entry by `set-auth`
  ([column-schemas.md:110–123](column-schemas.md)).

---

## 2. Mapping table — `xsoar_param_map` entry → emitted interpolation

For a given auth entry `{type, xsoar_param_map}`, each map entry
`{<xsoar_field_path>: <role>}` produces:

1. A connection **field** (already emitted today) whose
   `metadata.auth.parameter` = **auth_parameter** (the role after the
   `ROLE_TO_AUTH_PARAMETER` remap).
2. **NEW:** one **interpolation-mapping entry**
   `"{auth_parameter}:{xsoar_field_path}"`, joined with `,` across all map
   keys, written to the profile's `metadata.xsoar.interpolation_mapping`.

> Key direction reminder: `xsoar_param_map` is `{xsoar_path: role}`. The
> interpolation entry is `role:xsoar_path` (i.e. the map is *inverted* into
> the string, with the role first), where `role` is the **post-remap**
> `auth_parameter` (so it equals the field's `metadata.auth.parameter`, which
> is the key in the runtime credentials envelope).

| auth `type` | `xsoar_param_map` entry (`xsoar_path` → `role`) | field `metadata.auth.parameter` (auth_parameter) | interpolation entry emitted | manifest key |
|---|---|---|---|---|
| `APIKey` | `{"api_key": "key"}` | `api_key` (remapped) | `api_key:api_key` | `profiles[].metadata.xsoar.interpolation_mapping` |
| `APIKey` (hiddenusername) | `{"credentials.password": "key"}` | `api_key` | `api_key:credentials.password` | same |
| `Plain` | `{"credentials.identifier":"username","credentials.password":"password"}` | `username`, `password` | `username:credentials.identifier,password:credentials.password` | same |
| `Plain` (two flat params) | `{"server_user":"username","server_password":"password"}` | `username`, `password` | `username:server_user,password:server_password` | same |
| `Passthrough` (client-creds) | `{"credentials_auth_id.password":"client_id","credentials_enc_key.password":"client_secret"}` | `client_id`, `client_secret` | `client_id:credentials_auth_id.password,client_secret:credentials_enc_key.password` | same |
| `Passthrough` (multi-secret bag) | `{"credentials.password":"primary_api_key","hunting_credentials.password":"hunting_api_key"}` | `primary_api_key`, `hunting_api_key` | `primary_api_key:credentials.password,hunting_api_key:hunting_credentials.password` | same |

Plus, for EVERY profile (all types, since ALWAYS-INTERPOLATE):
`profiles[].metadata.xsoar.interpolated: true`.

**Ordering:** emit the interpolation entries in the **same sorted order** the
field loop already uses (`sorted(xsoar_param_map.keys())`,
[line 4832](connectus_migration/manifest_generator.py)) so the string is
deterministic and 1:1 with the emitted fields.

**Validity note (APIKey remap edge case):** for `APIKey`, role `key`
remaps to auth_parameter `api_key`. The runtime envelope for an `api_key`
profile is keyed by `api_key` (per
[CommonServerPython_test.py:13837](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py)),
so the LEFT side must be the remapped `api_key`, NOT the raw classifier role
`key`. ⇒ The implementation MUST use the post-remap `auth_parameter`
(`_auth_parameter_for_role`) on the LEFT, not the raw `xsoar_param_map` value.

---

## 3. Code-level change plan (functions/lines in `manifest_generator.py`)

All changes are localized to the connection-profile builder. No other file
needs to change.

### 3.1 Add a pure helper: `build_interpolation_mapping(...)`

New function (place it next to `_auth_parameter_for_role`,
~[line 4772](connectus_migration/manifest_generator.py)). Signature:

```python
def build_interpolation_mapping(profile_type: str, xsoar_param_map: dict[str, str]) -> str:
    """Return the UCP 'role:xsoar_path,...' interpolation_mapping string.

    LEFT side is the post-remap auth_parameter (matches metadata.auth.parameter
    and the runtime credentials-envelope key); RIGHT side is the dotted XSOAR
    field path. Entries are sorted by xsoar_path to match the field-emit order.
    """
```

Behavior:
- Iterate `for map_key in sorted(xsoar_param_map.keys())`.
- `role = xsoar_param_map[map_key]`;
  `auth_parameter = _auth_parameter_for_role(profile_type, role)`.
- Append `f"{auth_parameter}:{map_key}"`.
- `return ",".join(entries)`.
- Empty map → `""` (caller decides whether to attach; map is required-non-empty
  per schema, so this is defensive only).

Rationale for a separate pure function: directly unit-testable per the TDD
list, and reused identically by both from-scratch and append paths (both go
through `build_connection_profile`).

### 3.2 Wire it into `build_connection_profile`

In [`build_connection_profile()`](connectus_migration/manifest_generator.py:4803),
after the field loop and before the `return` ([lines 4851–4866](connectus_migration/manifest_generator.py)):

1. Compute `interpolation_mapping = build_interpolation_mapping(profile_type, xsoar_param_map)`.
2. Read the interpolate flag from the entry:
   `interpolated = bool(auth_type_entry.get("interpolated", False))`.
   (Per ALWAYS-INTERPOLATE this is effectively always `True`, but read it from
   the entry so the generator is faithful to the cell rather than hard-coding.)
3. Add to the returned profile dict a `metadata` block:
   ```python
   "metadata": {
       "xsoar": {
           "interpolated": interpolated,            # bool true
           "interpolation_mapping": interpolation_mapping,  # only when non-empty
       }
   },
   ```
   - Place `metadata` BEFORE `configurations` to match the real manifest key
     order (MS365 profiles put `metadata` above `configurations`,
     [connection.yaml:188–191](../../../unified-connectors-content/connectors/microsoft365-services/connection.yaml)).
   - Omit the `interpolation_mapping` key entirely when the string is empty
     (defensive; never expected given non-empty-map schema rule), but ALWAYS
     emit `interpolated`.

> Decision to surface to reviewer: whether `interpolated` should be hard-forced
> `True` for every generated profile (matching the documented gate) or read
> from the entry. Recommended: read from the entry with default `False`; since
> `set-auth` forces it `true` upstream, the persisted cell already guarantees
> `True`, and reading-not-forcing keeps the generator honest and testable with
> both inputs.

### 3.3 No changes needed elsewhere

- `build_connection_yaml` ([5432](connectus_migration/manifest_generator.py))
  already routes every entry through `build_connection_profile` — it picks up
  the new metadata automatically.
- The append path (`merge_connection_data`,
  [5501](connectus_migration/manifest_generator.py)) copies whole profile
  dicts, so the new metadata rides along with zero changes.
- `_dump_yaml` ([1172](connectus_migration/manifest_generator.py)) already
  serializes with `sort_keys=False`, so the chosen key order is preserved.

---

## 4. TDD test list (write these FIRST, before the impl)

Target test files:
[`connectus/connectus_migration/manifest_connection_builders_test.py`](connectus_migration/manifest_connection_builders_test.py)
(unit, imports `manifest_generator as cb`) and
[`connectus/connectus_migration/manifest_generator_test.py`](connectus_migration/manifest_generator_test.py)
(end-to-end). All assertions below cite the exact expected emitted string.

### 4.1 Unit — `build_interpolation_mapping` (the pure helper)

1. **APIKey flat — role remap on LEFT.**
   - Input: `profile_type="api_key"`, `xsoar_param_map={"api_key": "key"}`.
   - Expect: `"api_key:api_key"` (LEFT is remapped `api_key`, not raw `key`).
2. **APIKey hiddenusername (dotted leaf).**
   - Input: `("api_key", {"credentials.password": "key"})`.
   - Expect: `"api_key:credentials.password"`.
3. **Plain — both leaves, sorted, verbatim roles.**
   - Input: `("plain", {"credentials.identifier":"username","credentials.password":"password"})`.
   - Expect: `"username:credentials.identifier,password:credentials.password"`
     (sorted by xsoar_path: `credentials.identifier` < `credentials.password`).
4. **Plain — two separate flat params.**
   - Input: `("plain", {"server_user":"username","server_password":"password"})`.
   - Expect sorted by key: `"password:server_password,username:server_user"`
     (`server_password` < `server_user`).
5. **Passthrough multi-secret — free-form roles, verbatim.**
   - Input: `("passthrough", {"credentials_auth_id.password":"client_id","credentials_enc_key.password":"client_secret"})`.
   - Expect: `"client_id:credentials_auth_id.password,client_secret:credentials_enc_key.password"`.
6. **Passthrough secrets-bag (2 keys, distinct roles).**
   - Input: `("passthrough", {"credentials.password":"primary_api_key","hunting_credentials.password":"hunting_api_key"})`.
   - Expect: `"primary_api_key:credentials.password,hunting_api_key:hunting_credentials.password"`.
7. **Round-trip parse guard (cross-check against the runtime parser).**
   - Feed each expected string above into the same grammar
     `CommonServerPython._parse_param_map` semantics (re-implement the split
     inline in the test, OR import if available in the test env) and assert it
     yields `[(role, xsoar_path), ...]` matching the input map — proving the
     emitted string is parseable and round-trips to `role → xsoar_path`.

### 4.2 Unit — `build_connection_profile` emits the metadata

8. **APIKey profile carries `metadata.xsoar.interpolation_mapping` + `interpolated`.**
   - Input entry: `{"type":"APIKey","name":"api_key","interpolated":True,"xsoar_param_map":{"api_key":"key"}}`.
   - Assert `prof["metadata"]["xsoar"]["interpolation_mapping"] == "api_key:api_key"`.
   - Assert `prof["metadata"]["xsoar"]["interpolated"] is True`.
   - Assert the existing field shape is unchanged (regression: `id == "api_key"`,
     `metadata.auth.parameter == "api_key"`).
9. **Plain profile mapping matches field roles 1:1.**
   - Entry with both leaves (as test #3); assert the LEFT-side roles in the
     mapping string exactly equal the set of `metadata.auth.parameter` across
     the profile's fields.
10. **Passthrough profile, `interpolated: true`.**
    - Entry as test #5 with `"interpolated": True`; assert mapping string and
      `interpolated is True`.
11. **`interpolated` defaults / faithful read.**
    - Entry WITHOUT an `interpolated` key → assert
      `prof["metadata"]["xsoar"]["interpolated"] is False` (faithful default).
    - Entry with `"interpolated": True` → assert `True`. (Documents the
      "read-from-entry, not hard-forced" decision in §3.2.)
12. **Key order: `metadata` precedes `configurations`** in the returned dict
    (assert `list(prof.keys()).index("metadata") < list(prof.keys()).index("configurations")`).

### 4.3 End-to-end — `build_connection_yaml` / `create_manifest_from_scratch`

13. **Single-profile connector emits interpolation on the written
    `connection.yaml`.**
    - Reuse the MS-Graph-shaped fixture
      ([manifest_generator_test.py:6407](connectus_migration/manifest_generator_test.py)).
    - After `create_manifest_from_scratch`, read `connection.yaml` and assert
      `profiles[0]["metadata"]["xsoar"]["interpolation_mapping"]` equals the
      expected `role:path,...` string for that fixture's `xsoar_param_map`,
      and `interpolated is True`.
14. **Append path preserves + adds interpolation.**
    - Extend
      [test_append_handler_adds_profile_view_group_and_general_config](connectus_migration/manifest_generator_test.py:6521):
      assert BOTH appended profiles (`passthrough.inta`, `api_key.intb`) carry
      their own `metadata.xsoar.interpolation_mapping`
      (`password:creds.password` and `api_key:apikey` respectively) and
      `interpolated`.
15. **Runtime-parity smoke (optional, high-value):** construct a fake
    `connectionProfiles` metadata using a generated profile's
    `metadata.xsoar.interpolation_mapping` + a credentials envelope keyed by
    the profile's `metadata.auth.parameter` roles, call
    `CommonServerPython.build_ucp_params`, and assert the resulting
    `demisto.params()` shape matches the dotted XSOAR paths (e.g.
    `{"credentials":{"password": ...}}`). This proves the generator's output is
    consumable by the real runtime end-to-end.

---

## 5. Open questions / risks for the implementer

1. **`interpolated` force-vs-read** (see §3.2 decision) — recommend read from
   entry, default `False`; reviewer to confirm.
2. **Field `id` vs role on the interpolation LEFT side.** The MS365 example
   uses the *role* (`client_id`), not the field `id` (`auth_code_client_id`),
   on the LEFT — and the runtime envelope is keyed by role. The plan uses the
   post-remap `auth_parameter` (= `metadata.auth.parameter`) on the LEFT, which
   is correct. Do NOT use `_connection_field_id_from_map_key` output there.
3. **No escaping** in the grammar (§1.2). If any future role/path could contain
   `,` or `:` the string would corrupt — none do today; add a defensive
   assertion in `build_interpolation_mapping` if desired (reject `,`/`:` in
   role and `,` in path).

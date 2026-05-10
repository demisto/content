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
      "name": "<connection_type_name>",
      "xsoar_params": ["<xsoar_field_path>", "<xsoar_field_path>", ...],
      "interpolated": <bool>
    }
  ],
  "config": "REQUIRED(<connection_type_name>, ...) [+ OPTIONAL(<connection_type_name2>, ...)] | CHOICE(<connection_type_name>, <connection_type_name>) | NoneRequired"
}
```

- `auth_types` — **Each entry is one complete UCP connection type** — for
  example, one `APIKey` auth, one `Plain` auth (which bundles a username
  **and** a password as a single connection), one `OAuth2ClientCreds`
  auth, etc. The entry is *not* one XSOAR param; it groups together every
  field needed to stand up that one auth flow. A single XSOAR field that
  legitimately feeds more than one connection type (e.g. the same
  `credentials.password` backing both a Plain profile and an OAuth
  profile) appears in **multiple entries**, listed inside each entry's
  `xsoar_params` array. Entries are sorted by `(type, name)`.
- `auth_types[].type` — Auth-type enum value identifying the kind of
  connection this entry describes (see the enum table in
  [`Readme.md`](Readme.md:19)). Pick exactly one.
- `auth_types[].name` — Free-form logical id chosen for this connection
  type. Must be unique across entries within this row. This is the
  identifier referenced by `config` (not the XSOAR param id, not the
  enum value).
- `auth_types[].xsoar_params` — Array of XSOAR **field paths** (strings)
  whose values supply the secrets for this one connection type.
  Conventions:
  - For a flat XSOAR param (YML types `0` text, `4` encrypted, `14` cert
    key, etc.), use the bare param id, e.g. `"api_key"`,
    `"server_token"`.
  - For a credentials-typed XSOAR param (YML type `9`), treat its two
    sub-fields as separate leaf fields and list them with dotted
    notation: `"<paramid>.identifier"` (the username slot) and
    `"<paramid>.password"`. A Plain auth backed by a single credentials
    param therefore lists both, e.g.
    `["credentials.identifier", "credentials.password"]`.
  - A Plain auth built from two separate flat params lists both ids
    directly, e.g. `["server_user", "server_password"]`.
  - The same field path may appear in the `xsoar_params` of multiple
    entries when one XSOAR field feeds several connection types.
- `auth_types[].interpolated` — Optional boolean (defaults to `false`).
  When `true`, the manifest generator sets the `interpolated` flag in
  this entry's metadata in the generated manifest (signaling that the
  value is interpolated from another source/template at runtime rather
  than supplied verbatim by the user).
- `config` — Auth Config Expression. Same operators as the README grammar
  in [`Auth Config Expression Format`](Readme.md:8) — `REQUIRED(...)`,
  `OPTIONAL(...)`, `CHOICE(...)`, joined with `+`, plus the literal
  `NoneRequired`. **The operands inside the parens are connection-type
  names that must each appear as some `auth_types[].name`** — not
  auth-type enum values and not XSOAR param ids. Examples:
  - `REQUIRED(api_key)` — single required connection type named `api_key`
  - `REQUIRED(privateApiKey, publicApiKey)` — two required connection types
  - `CHOICE(credentials, hunting_credentials)` — pick one of two optional connection types
  - `REQUIRED(credentials) + OPTIONAL(credentials_consumer)` — Plain connection required, OAuth connection optional
  - `NoneRequired` — no auth required

Schema validation is enforced by
[`workflow_state.py validate_auth_detail()`](workflow_state.py:432) and runs
automatically on every `set-auth` invocation.

Setter:
[`workflow_state.py set-auth "<Integration ID>" '<json>'`](workflow_state.py:833).
Setting this value resets the workflow back to the first checkpoint
(`generated manifest`).

---

## `Params to Commands`

Mapping of integration commands to the parameter IDs each command needs (by
name). Connection-level params (e.g. URL, credentials) are intentionally NOT
listed per-command — those are configured once at the integration level.

```json
{
  "integration": "<Integration ID>",
  "commands": {
    "<command-name>": ["<param_id>", "<param_id>", ...]
  }
}
```

Example:

```json
{
  "integration": "QRadar v3",
  "commands": {
    "test-module": ["url", "credentials", "longRunning", "max_fetch"],
    "fetch-incidents": ["url", "credentials", "max_fetch", "longRunning"],
    "qradar-offenses-list": ["max_fetch", "longRunning"]
  }
}
```

Notes:

- `commands` is a flat object: command name → array of parameter IDs.
- Parameter IDs match those in the integration's YML `configuration` section.
- Free-form: no enforced ordering or required keys beyond `integration` and
  `commands`.

Setter:
[`workflow_state.py set-params-to-commands "<Integration ID>" '<json>'`](workflow_state.py:682).
Must be valid JSON. Required before `generated manifest` can be marked passed.

---

## `Params for test with default in code`

The list of parameter IDs whose default value is hardcoded in the integration's
Python/JS/PWSH source (not provided through the XSOAR UI). These need to be
substituted during test runs.

Recommended shape — a JSON array of strings:

```json
["param_id_1", "param_id_2", "param_id_3"]
```

Alternative shape — a JSON object whose values are the in-code defaults:

```json
{
  "param_id_1": "<default value as encoded in code>",
  "param_id_2": "<default value as encoded in code>"
}
```

Notes:

- Either shape is accepted; pick one and stay consistent within a row.
- Must be valid JSON.

Setter:
[`workflow_state.py set-params-for-test "<Integration ID>" '<json>'`](workflow_state.py:687).
Required before `generated manifest` can be marked passed.

---

## `Params same in other handlers` (optional)
```json
{
    "paramname" :  {"otherintegrationID1" : "paramname", "otherintegrationID2" : "paramnamedifferent" },
    "param2name" :  {"integrationID1" : ""},

}
Must be valid JSON when set. Not a prerequisite for any checkpoint.
```
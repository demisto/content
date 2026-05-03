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
    {"type": "<AuthEnum>", "name": "<param_name>", "interpolated": <bool>}
  ],
  "config": "REQUIRED(<param_name>, ...) [+ OPTIONAL(<param_name>, ...)] | CHOICE(<param_name>, <param_name>) | NoneRequired",
  "params": {
    "<param_name>": {
      "type": "<AuthEnum>",
      "xsoar_type": <int>,
      "required": <bool>
    }
  },
  "notes": "<string or null>"
}
```

- `auth_types` — Array of `{type, name, interpolated}` entries, sorted by
  `(type, name)`.
- `auth_types[].interpolated` — Optional boolean (defaults to `false`).
  When `true`, the manifest generator sets the `interpolated` flag in this
  param's metadata in the generated manifest (signaling that the value is
  interpolated from another source/template at runtime rather than supplied
  verbatim by the user).
- `config` — Auth Config Expression. Same operators as the README grammar
  in [`Auth Config Expression Format`](Readme.md:8) — `REQUIRED(...)`,
  `OPTIONAL(...)`, `CHOICE(...)`, joined with `+`, plus the literal
  `NoneRequired` — but **the operands inside the parens are param names
  from `params`**, not auth-type enum values. Examples:
  - `REQUIRED(api_key)` — single required API key (param `api_key`)
  - `REQUIRED(privateApiKey, publicApiKey)` — two required API key params
  - `CHOICE(credentials, hunting_credentials)` — pick one of two optional params
  - `REQUIRED(credentials) + OPTIONAL(credentials_consumer)` — Plain credentials required, OAuth optional
  - `NoneRequired` — no auth params
- `params.<name>.type` — Which auth type this param belongs to. May be a
  string or a list of strings (when one param can play multiple roles).
- `params.<name>.xsoar_type` — XSOAR widget type:
  `0` = text, `4` = encrypted, `8` = bool, `9` = credentials,
  `14` = cert key, `15` = select.
- `params.<name>.required` — Whether the param is required in the XSOAR
  configuration.
- `notes` — Explanation for complex auth setups (managed identity,
  device code, ROPC, etc.). MUST be non-null when any `Other` auth type
  is used. `null` otherwise.

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
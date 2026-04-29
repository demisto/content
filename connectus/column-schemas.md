# Column Schemas

This file documents the expected JSON shapes for the JSON-valued columns in
[`connectus/integrations_report.csv`](integrations_report.csv). The CSV column
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
  "auth_types": [{"type": "<AuthEnum>", "name": "<param_name>"}],
  "config": "<requirement_expression>",
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

- `auth_types` — Array of `{type, name}` entries, sorted by `(type, name)`.
- `config` — Auth Config Expression (e.g. `REQUIRED(APIKey)`,
  `CHOICE(APIKey, Plain)`). See the
  [`Auth Config Expression Format`](Readme.md:8) section in the README.
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

Validation rules:

1. Must be valid JSON with keys: `auth_types`, `config`, `params`, `notes`.
2. `auth_types` entries sorted by `(type, name)`.
3. Every param in `params` must appear in `auth_types` (by name).
4. Every type in `config` must appear in at least one param's `type` field,
   OR be explained in `notes`.
5. If `config` is `NoneRequired`, then `auth_types` must be `[]` and
   `params` must be `{}`.
6. If `Other` is used, `notes` MUST be non-null.
7. `xsoar_type` values must match the YML param widget types listed above.
8. `required` values must match the YML param `required` field.

Setter:
[`workflow_state.py set-auth "<Integration ID>" '<json>'`](workflow_state.py:1).
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
[`workflow_state.py set-inputs "<Integration ID>" '<json>'`](workflow_state.py:1).
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
[`workflow_state.py set-params-for-test "<Integration ID>" '<json>'`](workflow_state.py:1).
Required before `generated manifest` can be marked passed.

---

## `Params same in other handlers` (optional)

For multi-handler integrations, the list of parameter IDs that are shared
verbatim with sibling handlers (i.e. the same param appears in another
integration's handler with identical semantics). Used to spot duplication
opportunities and avoid redundant manifest entries.

Recommended shape — a JSON array of strings:

```json
["param_id_1", "param_id_2"]
```

Alternative shape — keyed by sibling integration ID:

```json
{
  "<other Integration ID>": ["param_id_1", "param_id_2"],
  "<other Integration ID>": ["param_id_3"]
}
```

Notes:

- This column is **optional**. Leave empty if not applicable (single-handler
  integration, or no shared params identified).
- Must be valid JSON when set.
- Not a prerequisite for any checkpoint.

Setter:
[`workflow_state.py set-shared-params "<Integration ID>" '<json>'`](workflow_state.py:1).

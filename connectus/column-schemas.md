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
      "xsoar_param_map": {
        "<xsoar_field_path>": "<role>",
        "<xsoar_field_path>": "<role>"
      },
      "interpolated": <bool>
    }
  ],
  "config": "REQUIRED(<connection_type_name>, ...) [+ OPTIONAL(<connection_type_name2>, ...)] | CHOICE(<connection_type_name>, <connection_type_name>) | NoneRequired",
  "other_connection": ["<yml_param_id>", "<yml_param_id>", ...]
}
```

All three top-level keys (`auth_types`, `config`, `other_connection`) are
**required** on every `set-auth` write. Legacy CSV rows written before
`other_connection` existed lack the key; the read/display path tolerates
that and surfaces a `(not set — re-run set-auth)` hint, but new writes
must include it.

- `auth_types` — **Each entry is one complete UCP connection type** — for
  example, one `APIKey` auth, one `Plain` auth (which bundles a username
  **and** a password as a single connection), one `OAuth2ClientCreds`
  auth, etc. The entry is *not* one XSOAR param; it groups together every
  field needed to stand up that one auth flow. A single XSOAR field that
  legitimately feeds more than one connection type (e.g. the same
  `credentials.password` backing both a Plain profile and an OAuth
  profile) appears in **multiple entries**, listed inside each entry's
  `xsoar_param_map`. Entries are sorted by `(type, name)`.
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
  | `OAuth2ClientCreds`, `OAuth2AuthCode`, `OAuth2JWT`, `Other` | any non-empty string (enum **deliberately undefined for now** — will be narrowed in a future PR) |
  | `NoneRequired` | n/a (no entries in `auth_types[]` at all) |

  See [`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1)
  for the full classification procedure that picks the right role for
  each XSOAR field.
- `auth_types[].interpolated` — Optional boolean (defaults to `false`).
  When `true`, the manifest generator sets the `interpolated` flag in
  this entry's metadata in the generated manifest (signaling that the
  value is interpolated from another source/template at runtime rather
  than supplied verbatim by the user). The `xsoar_param_map` is still
  required and non-empty on interpolated entries — the map describes
  the role each XSOAR field plays regardless of whether the value is
  user-supplied or templated at runtime.
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
- `other_connection` — Flat sorted list of YML param ids that are
  **connection-adjacent but not auth secrets**: everything you reasonably
  need to define the integration's connection besides the secrets
  themselves. Typical members: `url`, `proxy`, `insecure`, `port`,
  `verify_certificate`, `server`, `host`, `region`. The list captures
  the ids exactly as they appear in the integration YML's
  `configuration[].name`. Constraints:
  - Must be a JSON array of non-empty strings.
  - Strings must be unique within the list.
  - Must be sorted ascending (alphabetical). The validator rejects
    unsorted input with a clear suggestion of the sorted form.
  - Empty list `[]` is valid (= the integration has no connection-adjacent
    params besides its auth secrets).
  - There is **no overlap requirement** with `auth_types[].xsoar_param_map`
    — keeping the two lists disjoint is the classifier's responsibility,
    not the validator's. (Auth secrets are keyed in
    `auth_types[].xsoar_param_map`; per-command behavioral params go
    in `Params to Commands`; framework params like
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
- `interpolated` is **optional** and defaults to `false`. When
  present it must be a JSON boolean.
- `NoneRequired` integrations have **no** `auth_types[]` entries
  (the array is `[]`), so the map requirement is moot for them — see
  Example 5.

### Migration from `xsoar_params`

The pre-2026-05 shape — `auth_types[].xsoar_params: list[str]` — is
**gone**. `set-auth` rejects any payload that still contains
`xsoar_params` (the validator returns a migration-help error pointing
at this section). To re-classify a legacy row:

1. Look up the YML param ids that were in the old `xsoar_params`
   array.
2. Pick a `type` from the table above and assign each XSOAR field
   path a role from that type's allowed set.
3. Write the new payload using one of the 5 canonical examples below
   as a template.
4. Re-run `set-auth`. The cascade reset wipes downstream artifacts
   exactly as it did before — the schema change does not alter reset
   semantics.

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
  "config": "REQUIRED(credentials)",
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
  "config": "REQUIRED(credentials)",
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
  "config": "REQUIRED(auth)",
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example 4 — OAuth2ClientCreds with credentials widget (enum-undefined regime, any non-empty string accepted):**

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      }
    }
  ],
  "config": "REQUIRED(credentials)",
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example 5 — NoneRequired:**

```json
{
  "auth_types": [],
  "config": "NoneRequired",
  "other_connection": []
}
```

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

## `verify button placement` (flag)

> **Status:** placeholder added in the 2026-05 schema simplification.
> Details (UI semantics, manifest implications) **to be filled in later**.

Enum values: `connection`, `configuration`, `none`. The cell stores the
raw enum string verbatim (no JSON wrapping).

| Value | Intended meaning (TBD) |
|---|---|
| `connection` | The verify/test button lives at the per-connection level (default on read when the cell is empty). |
| `configuration` | The verify/test button lives at the per-integration / per-configuration level. |
| `none` | The integration exposes no verify/test button. |

Setter:
[`workflow_state.py set-verify-placement "<Integration ID>" <value>`](workflow_state/cli.py:1)
([`cmd_set_verify_placement`](workflow_state/cli.py:1)). Case-insensitive
input is canonicalised to the YAML spelling on write. Empty cells read
as `connection` and do NOT block the workflow's "current step" from
advancing past step #4.

> **Reset semantics.** `verify button placement` is **wiped** by all
> reset paths (`reset`, `set-auth`, `fail`, `reset-to`). It does not
> carry `preserve_on_reset: true`. Today only `Params to Commands`
> retains that flag (the historical `Params for test with default in
> code` and `Params same in other handlers` columns were removed in the
> 2026-05 schema simplification).
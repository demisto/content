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
  - There is **no overlap requirement** with `auth_types[].xsoar_params`
    — keeping the two lists disjoint is the classifier's responsibility,
    not the validator's. (Auth secrets go in `auth_types[].xsoar_params`;
    per-command behavioral params go in `Params to Commands`; framework
    params like `longRunning`/`feedReputation` are ignored entirely.)

Worked example with `other_connection`:

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_params": ["api_key"]
    }
  ],
  "config": "REQUIRED(api_key)",
  "other_connection": ["insecure", "proxy", "url"]
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
  either as a projected `auth_types[].xsoar_params` entry (dotted forms
  collapse to the segment before the first `.`) or as an
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
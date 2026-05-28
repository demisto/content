Note, this folder should not be merged to master.

> **Architecture note.** [`connectus/workflow_state.py`](workflow_state.py:1) is now a thin backward-compatible shim that re-exports the real package at [`connectus/workflow_state/`](workflow_state/__init__.py:1). The CLI entrypoint, validators, state machine, CSV I/O, display helpers, and config loader live there. Behavior is identical; the file split is purely for maintainability. The canonical Python import is `from workflow_state import …`.

## Authentication Type Catalog

Each integration's authentication is classified into an **Auth Class** string
value, with per-parameter details captured in a structured **Auth Detail** JSON
object.

### Profile Model (post-2026-05)

Each entry in `auth_types[]` is one **profile** — one self-contained,
mutually-exclusive way the user can configure the integration. The
relationship between profiles is **implicit and always exclusive-OR**:

- `auth_types: []` → no authentication required (the historical
  `NoneRequired`).
- `auth_types: [X]` → profile X is always used.
- `auth_types: [X, Y, …]` → the user picks exactly ONE profile at
  configuration time.

The pre-2026-05 `config` expression key
(`REQUIRED(...)` / `OPTIONAL(...)` / `CHOICE(...)` / `+`-joining /
`NoneRequired`) was removed: it carried no information beyond what
`auth_types[]` already encodes (length + names). `set-auth` hard-rejects
any payload still containing a `config` key. See
[`column-schemas.md`](column-schemas.md:1) §"Migration from `config`"
for re-classification rules.

#### Auth Type Values

Each value maps onto one of the canonical UCP authentication profile types (see [`column-schemas.md`](column-schemas.md:1) "Authentication Profile Types — Fields Reference" for the per-profile field shapes). `Passthrough` is the explicit "doesn't fit a canonical profile" catch-all.

| Value | UCP Profile Type | Description | Examples |
|---|---|---|---|
| `OAuth2ClientCreds` | `oauth2_client_credentials` | OAuth 2.0 Client Credentials flow (`client_id` + `client_secret`) | CrowdStrike Falcon, Wiz |
| `OAuth2JWT` | `oauth2_jwt_bearer` | OAuth 2.0 JWT Bearer flow (service-account / signed assertion) | Google integrations |
| `APIKey` | `api_key` | **Single** static secret (header / query param / single-secret HMAC). Two-or-more keys → `Passthrough`. | Abnormal Security, VirusTotal |
| `Plain` | `plain` | Single username + password pair (basic auth, login form, bearer-token-as-password, single-cert pair) | ActiveMQ, AWS S3, CyberArk |
| `Passthrough` | n/a (no canonical profile) | Catch-all: OAuth2 **Authorization Code** (browser flow), Device Code, ROPC, Managed Identity, mTLS, dual-key API (Datadog `api_key`+`application_key`, AWS access_key+secret_key, Akamai EdgeGrid's 3 tokens, GitHub App), custom HMAC schemes. **When in doubt, prefer `Passthrough`.** | Lansweeper (Authorization Code), Azure WAF (Managed Identity), Datadog (dual-key) |
| `NoneRequired` | n/a | No authentication needed | AlienVault Reputation Feed |

> **Enum history (2026-05).** The previous `OAuth2AuthCode` value was removed (Authorization Code flows are now classified as `Passthrough`), and the previous `Other` value was renamed to `Passthrough`. There is no backward-compatibility alias — payloads using either old name are rejected by `set-auth`.

#### Worked Examples (post-2026-05 profile model)

| Integration | `auth_types[]` shape | Why |
|---|---|---|
| Abnormal Security | `[APIKey(api_key)]` | Single required API key — one profile, exclusive-OR is vacuous |
| AlienVault Reputation Feed | `[]` | No auth params; integration requires no authentication |
| CrowdStrike Falcon | `[OAuth2ClientCreds(credentials)]` | OAuth client credentials — one profile fits `oauth2_client_credentials` |
| Darktrace Admin | `[Passthrough(darktrace)]` | Two co-equal API keys (`privateApiKey` + `publicApiKey`); doesn't fit single-`api_key` profile → one `Passthrough` profile with both leaves in `xsoar_param_map` |
| Datadog | `[Passthrough(datadog)]` | `api_key` + `application_key` — two co-equal keys → `Passthrough`, same reason as Darktrace |
| AbuseIPDB | `[APIKey(credentials), APIKey(hunting_credentials)]` | Two **separate** API-key auth flows; user picks one (implicit exclusive-OR via 2-entry list) |
| Salesforce IAM | `[Plain(credentials), Passthrough(credentials_consumer)]` | Two alternative auth paths; user picks Plain or OAuth1 (consumer key/secret); implicit exclusive-OR |
| Wiz | `[OAuth2ClientCreds(credentials)]` | OAuth client credentials — single profile |
| Lansweeper / Gmail OAuth | `[Passthrough(oauth_code)]` | Browser-flow Authorization Code — no canonical `metadata.auth.parameter` shape → single `Passthrough` profile |
| Azure WAF | `[OAuth2ClientCreds(client_creds), Passthrough(managed_identity)]` | Two alternative auth paths; user picks Client-Credentials or Managed-Identity (implicit exclusive-OR) |
| Microsoft 4-flow | `[OAuth2ClientCreds(client_creds), Passthrough(auth_code), Passthrough(device_code), Passthrough(managed_identity)]` | Four alternative auth paths; user picks one (implicit exclusive-OR via 4-entry list) |

> **Reading the table.** Each `auth_types[]` shape is the value of the `Auth Details` JSON's `auth_types` field. `T(name)` reads as "type=T, name=name". The implicit exclusive-OR fires automatically when there are 2+ entries; no `config` expression key is needed (and is hard-rejected if present).

### How to Read the CSV Columns

#### Data Columns (not managed by workflow_state.py)

| # | Column | Description |
|---|---|---|
| 1 | `Integration ID` | ID of the integration |
| 2 | `Integration File Path` | Path to the integration's source files |
| 3 | `Connector ID` | The ID of the Connector |

#### JSON Column Schemas

The JSON shapes for `Auth Details`, `Params to Commands`,
`Params for test with default in code`, and `Params to Capabilities`
live in [`connectus/column-schemas.md`](column-schemas.md).

### Per-command parameter analysis

The `Params to Commands` column (step #3) is populated by the analyzer at
[`connectus/check_command_params.py`](check_command_params.py:1). It runs the
integration end-to-end via [`connectus/capture_proxy.py`](capture_proxy.py:1)
and combines static AST analysis with dynamic HTTP-proxy capture to determine
which YML configuration params each command actually consumes.

Standard invocation:

```bash
python3 connectus/check_command_params.py <integration_dir> \
    --ignore-params-file connectus/default_ignore_params.txt \
    --integration-id "<Integration ID>"
```

`--integration-id` is **optional but strongly recommended inside the
migration workflow**. When set, the analyzer additionally pulls the
auth-derived ignore set from
[`workflow_state.py auth-params <id>`](workflow_state/cli.py:1) and unions it
into its own ignore set, guaranteeing that any param already declared in
`Auth Details` (auth secrets + `other_connection`) cannot leak into the
per-command output. Standalone runs outside the migration workflow can
omit it.

Requirements:

- **Docker on the host** (default mode). The analyzer runs the integration's
  child process inside `demisto/py3-native:8.9.0.114862`. The integration's
  YML `script.dockerimage` is intentionally ignored — one pinned image keeps
  the analyzer reproducible. Pass `--docker never` to fall back to host
  Python (works only for integrations with no third-party deps); pass
  `--static-only` to skip the dynamic phase entirely.
- The default ignore list at
  [`connectus/default_ignore_params.txt`](default_ignore_params.txt:1) strips
  ~154 auth/connection/framework params (`url`, `credentials`, `proxy`,
  `insecure`, `longRunning`, the feed framework, …) so only **behavioral**,
  per-command-meaningful params remain.

The analyzer's stdout JSON has two top-level keys: `commands` (the polished
result that is persisted into the `Params to Commands` column, sorted lists
of param names per command) and `diagnostics` (internal AI metadata for the
migration skill — per-command status enum, failure excerpts, Scope-1
narrowing trace, etc.). **`diagnostics` is NOT to be persisted into pipeline
data** — it is consumed by the calling AI and discarded; the
`set-params-to-commands` payload contains only the `integration` and
`commands` keys.

See [`connectus/check_command_params_design.md`](check_command_params_design.md:1)
for the full design + current implementation status (the 7 layered fixes,
output schema, status enum, and known JS/PowerShell asymmetry), and
[`connectus/connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1)
§"Analyzing per-command parameters" for how the migration AI invokes the
analyzer and processes its output.

---

## Workflow State Machine (`workflow_state.py`)

The [`workflow_state.py`](workflow_state.py) script manages the **13 workflow columns** (columns 4–16) of [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv). It models the workflow as a **single linear 13-step sequence**, strictly gated. The current step is always the first step that is not yet done.

State is **purely derived from row contents** — there is no separate "current step" pointer. Re-issuing any `set-*`, `markpass`, or `skip` for a step at-or-behind the current step writes the new value AND clears every step that follows it ("cascade reset"). Two carve-outs apply:

- **`set-assignee`** never cascades (governed by the YAML flag `cascade_on_set: false`).
- **`reset-to` and `fail`** preserve any step tagged `preserve_on_reset: true` in [`workflow_state_config.yml`](workflow_state_config.yml). Today only step #3 `Params to Commands` carries that flag (the historical `Params for test with default in code` and `Params same in other handlers` columns were removed in 2026-05) — see Rule 8 below.

### The 13-Step Sequence

| # | Step (== CSV column) | Kind | Set via |
|---|---|---|---|
| 1 | `assignee` | data | `set-assignee` |
| 2 | `Auth Details` | data (JSON; `auth_types[]` + optional `other_connection` — see [`column-schemas.md`](column-schemas.md)) | `set-auth` — **rejects the cell unless the auth-parity test passes or structurally short-circuits** (see [`check_auth_parity.py`](check_auth_parity.py); no separate `auth parity test passes` checkpoint anymore) |
| 3 | `Params to Commands` | data (JSON) | `set-params-to-commands` |
| 4 | `Params for test with default in code` | data (JSON) | `set-param-defaults` |
| 5 | `Shadowed Integration Commands` | data (JSON) | `set-shadowed-commands` |
| 6 | `Params to Capabilities` | data (JSON) | `set-params-to-capabilities` |
| 7 | `generated manifest` | checkpoint | `markpass` |
| 8 | `run manifest make validate` | checkpoint | `markpass` |
| 9 | `write tests` | checkpoint | `markpass` |
| 10 | `precommit/validate/unit tests passed` | checkpoint | `markpass` |
| 11 | `param parity test passes` | checkpoint | `markpass` |
| 12 | `code reviewed` | checkpoint | `markpass` |
| 13 | `code merged` | checkpoint | `markpass` |

> **Schema_version=2 (2026-05) breaking change.** The standalone `wrote/checked code` and `auth parity test passes` checkpoints were removed:
>
> - `wrote/checked code` — code authorship/review was always redundant with the downstream `precommit/validate/unit tests passed` gate; no separate ledger checkpoint added value.
> - `auth parity test passes` — parity is now enforced *inside* `set-auth`. The parity test is invoked against the candidate `Auth Details` payload before it is committed; the cell is rejected unless parity passes or short-circuits structurally (`NO_BASECLIENT`, `NON_PYTHON`, `ALL_INTERPOLATED`, `CONNECTION_INTERPOLATED`, `INTEGRATION_REJECTS_HTTP`). A successful `set-auth` therefore *means* "parity has been verified", and there is no second cell to mark.

### Rules

1. **Single linear sequence.** The current step is the first step not yet done.
2. **Strict ordering.** Any `set-*`/`markpass`/`skip` targeting a step **ahead** of the current step is rejected with a message naming the missing prerequisite.
3. **Cascade reset.** Re-issuing any `set-*`/`markpass`/`skip` at-or-behind current writes the new value AND clears every step after it.
4. **`set-assignee` carve-out.** `set-assignee` (step #1) updates in place without cascading. Re-assigning an integration mid-flight does NOT wipe progress. Configured via `cascade_on_set: false` in [`workflow_state_config.yml`](workflow_state_config.yml).
5. **Normalization on read AND write.** Any value past the first incomplete step is auto-cleared (with a one-line stderr warning per affected row). Contradictions are not allowed to persist.
6. **`fail` and `reset-to` honour `preserve_on_reset`.** Both verbs clear the named step AND every step after it (the named step becomes the new current step). They have identical behaviour. **EXCEPTION:** any step tagged `preserve_on_reset: true` in [`workflow_state_config.yml`](workflow_state_config.yml) keeps its value across these operations — its name is reported in the CLI output (`Preserved (preserve_on_reset=true): [...]`) and in the api response (`result["preserved"]`). Today only step #3 `Params to Commands` is preserved so a failed checkpoint does not wipe per-command param research.
   - **Explicit-target carve-out:** if the user names a preserved step **directly** as the `reset-to`/`fail` target, that one step IS cleared (the user's intent wins), but later preserved steps in the same operation are still preserved.
   - **`set-auth` is NOT covered by `preserve_on_reset`.** Auth changes invalidate every downstream artifact — `set-auth` continues to wipe steps #3-#13 (`Params to Commands` included) by design. See `apply_step_action` in [`connectus/workflow_state/state_machine.py`](workflow_state/state_machine.py).
7. **`reset` (no step).** Clears all 13 workflow columns for the integration. Identity columns (`Integration ID`, `Integration File Path`, `Connector ID`) are preserved. **`preserve_on_reset` is intentionally ignored** — `reset` is the "wipe the row" verb with no carve-outs.
8. **Column-number addressability.** Every CLI verb that takes a column name (`show-step`, `markpass`, `skip`, `fail`, `reset-to`) also accepts a **1-based CSV column number** (1..16). Identity columns (#1-#3) are addressable only for read-only `show-step`; write verbs reject them with a verb-aware error. Example: `python3 connectus/workflow_state.py show-step CrowdstrikeFalcon 5` resolves to `Auth Details`. The CSV total of 16 reflects the schema_version=2 (2026-05) layout (3 identity + 13 workflow columns), after the standalone `wrote/checked code` and `auth parity test passes` checkpoints were dropped.
9. **`set-auth` runs the auth-parity test before committing.** The candidate `Auth Details` JSON is fed directly to [`check_auth_parity.check_auth_parity`](check_auth_parity.py); the CSV is only written when the result is `pass` for every connection or the analyzer returns a structural-skip code (`ERROR_NO_BASECLIENT`, `ERROR_NON_PYTHON`, `ERROR_ALL_INTERPOLATED`, `ERROR_CONNECTION_INTERPOLATED`, `ERROR_INTEGRATION_REJECTS_HTTP`). On a failed gate, the verb prints the failure summary and the full parity result is included in the api response under `result["parity"]`. Set `CONNECTUS_SKIP_AUTH_PARITY=1` to bypass (intended for tests; do not use as part of the normal migration workflow).

### CLI Commands

All commands take an Integration ID (case-insensitive) as the first argument
where applicable. **Every `set-*`/`markpass`/`skip` for a step at-or-behind
the current step cascade-resets every step after it.** The lone exception is
`set-assignee`, which never resets later steps.

```bash
# Show status (with [N/13] linear indicator)
python3 connectus/workflow_state.py status "Cisco Spark"

# Show all integrations with any progress
python3 connectus/workflow_state.py status-all

# Compact dashboard (13-cell progress bars)
python3 connectus/workflow_state.py dashboard

# Print the literal next action for an integration
python3 connectus/workflow_state.py next "Cisco Spark"

# Print next action for every in-progress integration assigned to current git user
python3 connectus/workflow_state.py next

# Print next action for every in-progress integration (all assignees)
python3 connectus/workflow_state.py next --all

# Show the value of a single column (pretty-prints JSON)
python3 connectus/workflow_state.py show-step "Cisco Spark" "Auth Details"

# Set the assignee (admin-only; never cascades)
python3 connectus/workflow_state.py set-assignee "Cisco Spark" "John Doe"

# Set Auth Details (validates JSON schema; runs the auth-parity test
# in-process against the candidate payload; rejects the cell unless
# parity passes or structurally short-circuits; on success, cascade-resets
# steps #3-#13).
# Each auth_types[] entry is one full UCP connection type. xsoar_param_map is
# a dict whose keys are XSOAR field paths supplying the secrets and whose
# values are the role each field plays in the connection (credentials params
# expand to `<paramid>.identifier` + `<paramid>.password` leaves). The
# `other_connection` field is a flat sorted list of YML param ids that are
# connection-adjacent but not auth secrets (url, proxy, insecure, port, host,
# region, ...). It lives INSIDE the Auth Details JSON, not as a separate CSV
# column. See column-schemas.md (incl. the per-type role-enum table).
python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"credentials.password":"key"}}],"other_connection":["insecure","proxy","url"]}'

# Set Params to Commands (validates JSON; cascade-resets steps #4-#13).
# REJECTED if any param in the payload also appears in Auth Details
# (auth secrets or other_connection). Run `auth-params <id>` first to
# see what to exclude, or pass `--integration-id <id>` to the analyzer
# so it pulls the exclusion set automatically.
python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{"integration":"Cisco Spark","commands":{"test-module":["fetch_query"]}}'

# Mark a checkpoint as passed (must be at-or-behind current; behind→cascade-resets).
# Every column-name argument below also accepts a 1-based CSV column number, e.g.
#   python3 connectus/workflow_state.py markpass "Cisco Spark" 10
# would target column #10 (`generated manifest`).
python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

# Fail a step (clears it + every step after)
python3 connectus/workflow_state.py fail "Cisco Spark" "write tests"

# Reset to a specific step (alias for fail; clears it + every step after)
python3 connectus/workflow_state.py reset-to "Cisco Spark" "write tests"

# Reset all 13 workflow columns
python3 connectus/workflow_state.py reset "Cisco Spark"

# List integrations currently at a specific step (any step kind)
python3 connectus/workflow_state.py at-step "write tests"

# List all integration IDs
python3 connectus/workflow_state.py list

# List integrations assigned to a specific person
python3 connectus/workflow_state.py list-by-assignee "John Doe"

# Print every YML param id declared in the integration's Auth Details
# (auth_types[].xsoar_param_map keys projected to bare YML ids + other_connection).
# This is the exclusion set that 'set-params-to-commands' enforces — any
# param appearing here MUST NOT appear in the per-command lists.
# Default output is one id per line; --format=json emits a JSON object.
python3 connectus/workflow_state.py auth-params "Cisco Spark"
python3 connectus/workflow_state.py auth-params "Cisco Spark" --format=json
```

#### CLI subcommand reference

| Subcommand | Purpose |
|---|---|
| `status <id>` | Show full per-step status of one integration |
| `status-all` | Show full status for every integration with progress |
| `dashboard` | Compact 13-cell progress bar for every in-progress integration |
| `next` / `next <id>` / `next --all` / `next --connector <c>` / `next --mine` | Print the literal next action |
| `show-step <id> <col\|#>` | Pretty-print one column's value (JSON-aware); `<col>` may be a name OR a 1-based CSV column number |
| `set-assignee <id> <name>` | Set the owner (admin; never cascades) |
| `set-auth <id> '<json>'` | Set Auth Details (validates schema; **runs the auth-parity test on the candidate payload and rejects the write unless parity passes or short-circuits structurally**; cascade-resets #3-#13) |
| `set-params-to-commands <id> '<json>'` | Set per-command param map. **Rejected** if any param overlaps with `Auth Details` (auth-secret or `other_connection`); use `auth-params` to inspect the exclusion set. |
| `markpass <id> <step\|#>` | Mark a checkpoint as passed; `<step>` may be a name OR a 1-based CSV column number (identity columns rejected) |
| `fail <id> <step\|#>` / `reset-to <id> <step\|#>` | Clear a step + every step after; column-number argument accepted |
| `reset <id>` | Clear all 13 workflow columns |
| `at-step <step>` | List integrations currently at a specific step |
| `list` | List every Integration ID |
| `list-by-assignee <name>` | List integrations for one assignee |
| `list-connectors` | List every distinct Connector ID |
| `list-by-connector <id>` | List integrations in one connector |
| `set-assignee-by-connector <id> <name>` | Assign every integration in a connector |
| `files <id> [--format=text\|paths\|json]` | Print all known source-file paths for an integration |
| `auth-params <id> [--format=text\|json]` | Print the auth-derived YML param ignore set (auth_types[].xsoar_param_map keys projected to bare YML ids + other_connection). Used by `set-params-to-commands` to enforce disjointness; the analyzer can pull this list automatically via `--integration-id`. |
| `help` | Print module docstring |

### Programmatic API (for AI agents / other scripts)

The script exposes functions that can be imported and called directly:

```python
from workflow_state import (
    get_integration_status,
    next_step_for,
    markpass_integration_step,
    skip_integration_step,
    fail_integration_step,
    reset_integration_to_step,
    set_integration_auth,
)

# Get status as a dict (includes current_step_index now)
status = get_integration_status("Cisco Spark")
# Returns: {name, current_step, current_step_index, workflow, completed_steps,
#           total_steps, progress_pct, all_complete}

# Get the next action for an integration
nxt = next_step_for("Cisco Spark")
# Returns: {complete: bool, step_index, step_name, setter, description, message}

# Mark a checkpoint as passed (cascade-resets later steps if at-or-behind current)
result = markpass_integration_step("Cisco Spark", "generated manifest")

# Fail / reset-to: clear the named step + every step after
result = fail_integration_step("Cisco Spark", "write tests")
result = reset_integration_to_step("Cisco Spark", "write tests")

# Set Auth Details — validates schema, then runs check_auth_parity against
# the candidate payload. Only writes the cell on a passing/short-circuited
# parity result. The returned dict has result["parity"] with the full
# analyzer envelope (or {"skipped": "..."} if bypassed via
# CONNECTUS_SKIP_AUTH_PARITY=1).
result = set_integration_auth("Cisco Spark", '{"auth_types":...}')
# Bypass the parity gate (tests only):
result = set_integration_auth("Cisco Spark", '...', skip_parity=True)
```

### Unit Tests

Run the test suite from the `connectus/` directory:

```bash
cd connectus && python3 -m pytest workflow_state_test.py -v
```

The current test suite lives under [`connectus/workflow_state/tests/`](workflow_state/tests/) and covers:
the YAML loader and its validation rules (`test_config_loader.py`); the
cascade-reset engine (`test_state_machine.py`); the 1-based
column-number addressability shared by `show-step`/`markpass`/`skip`/
`fail`/`reset-to` (`test_column_addressability.py`); and the destructive
schema-alignment `wipe-workflow-data` verb (`test_wipe_workflow_data.py`).
The legacy top-level [`workflow_state_test.py`](workflow_state_test.py)
is intentionally empty — see its module docstring for the migration map.

Run from the repo root:

```bash
python3 -m pytest connectus/workflow_state/tests/ -v
```

### Example Walkthrough

Below is a walkthrough showing what each command outputs under the unified
13-step sequence.

#### 1. Check initial status

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:        (unassigned)
  File Path:       (not set)
  Connector ID:    (not set)

  Workflow ([0/13]):
  ----------------------------------------
  ▶ 1. assignee                               : (not set)
    2. Auth Details                           : (not set)
    3. Params to Commands                     : (not set)
    4. Params for test with default in code   : (not set)
    5. Shadowed Integration Commands          : (not set)
    6. Params to Capabilities                 : (not set)
    7. generated manifest                     : ⬜
    8. run manifest make validate             : ⬜
    9. write tests                            : ⬜
   10. precommit/validate/unit tests passed   : ⬜
   11. param parity test passes               : ⬜
   12. code reviewed                          : ⬜
   13. code merged                            : ⬜

  ➡️  Current step: #1 assignee (run: set-assignee)
```

#### 2. Ask `next` what to do

```
$ python3 connectus/workflow_state.py next "Cisco Spark"

Cisco Spark — step 1 of 13: assignee
  Run:    python3 connectus/workflow_state.py set-assignee "Cisco Spark" "<your name>"
  About:  Assign an owner to drive this integration's migration.
```

#### 3. Try to markpass ahead of current step (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

ERROR: Cannot markpass 'generated manifest' (step 7/13) yet — current step is #1 'assignee'.
  Complete it first via 'set-assignee'.
```

#### 4. Try to set-params-to-commands with invalid JSON (rejected)

```
$ python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" "not json"

ERROR: 'Params to Commands' must be valid JSON.
  Got: not json
  Parse error: Expecting value: line 1 column 1 (char 0)
  Example: workflow_state.py set-params-to-commands "Cisco Spark" '{}'
```

#### 5. Walk through the linear sequence

```
$ python3 connectus/workflow_state.py set-assignee "Cisco Spark" "John Doe"
Set assignee for 'Cisco Spark' to: John Doe
  Current step: #2 Auth Details

$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"Plain","name":"credentials","xsoar_param_map":{"credentials.identifier":"username","credentials.password":"password"}}],"other_connection":["insecure","proxy","url"]}'
Set 'Auth Details' (step 2/13) for 'Cisco Spark'.
  Parity: all 1 connection(s) ok: ['pass']
  Current step: #3 Params to Commands

$ python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{}'
Set 'Params to Commands' (step 3/13) for 'Cisco Spark'.
  Current step: #4 Params for test with default in code

$ python3 connectus/workflow_state.py set-param-defaults "Cisco Spark" '{}'
Set 'Params for test with default in code' (step 4/13) for 'Cisco Spark'.
  Current step: #5 Shadowed Integration Commands

$ python3 connectus/workflow_state.py set-shadowed-commands "Cisco Spark" '{}'
Set 'Shadowed Integration Commands' (step 5/13) for 'Cisco Spark'.
  Current step: #6 Params to Capabilities

$ python3 connectus/workflow_state.py set-params-to-capabilities "Cisco Spark" '{}'
Set 'Params to Capabilities' (step 6/13) for 'Cisco Spark'.
  Current step: #7 generated manifest

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"
✅ 'generated manifest' (step 7/13) marked as passed for 'Cisco Spark'.
  Next step: #8 run manifest make validate
```

#### 6. Cascade reset: re-issuing `set-auth` mid-flight

```
$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[],"other_connection":[]}'
Set 'Auth Details' (step 2/13) for 'Cisco Spark'.
  Parity: no connections evaluated  (auth_types=[] → NoneRequired)
  Cleared 5 subsequent step(s): ['Params to Commands', 'Params for test with default in code', 'Shadowed Integration Commands', 'Params to Capabilities', 'generated manifest']
  Current step: #3 Params to Commands
```

Re-issuing any setter at-or-behind the current step writes the new value AND clears every step after it.

#### 6a. `set-auth` rejection when the parity test fails

```
$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"credentials.password":"key"}}],"other_connection":[]}'
ERROR: Auth Details rejected — parity gate failed for 'Cisco Spark':
  1 connection(s) did not pass: credentials='fail'

  Re-run `python3 connectus/check_auth_parity.py <integration_path> --integration-id 'Cisco Spark' --auth-details '<json>'`
  directly to inspect the full diff, then re-derive the Auth Details JSON before calling set-auth again.
  To bypass the gate (e.g. in a test), set CONNECTUS_SKIP_AUTH_PARITY=1.
```

The Auth Details cell is NOT written — the workflow row is left untouched. Fix the underlying issue (UCP header override, interpolated flag, code-side correction) and re-run `set-auth`.

#### 7. `set-assignee` is the carve-out — it never cascades

```
$ python3 connectus/workflow_state.py set-assignee "Cisco Spark" "Jane Smith"
Set assignee for 'Cisco Spark' to: Jane Smith
  Current step: #7 run manifest make validate
```

Re-assigning preserves all migration progress — only the `assignee` cell changes.

#### 8. Column-number addressability

```
# Numbers are 1-based into the full 16-column CSV (3 identity + 13 steps).
$ python3 connectus/workflow_state.py show-step "Cisco Spark" 5
# → resolves to column #5 → 'Auth Details'

$ python3 connectus/workflow_state.py markpass "Cisco Spark" 10
# → resolves to column #10 → 'generated manifest' (first checkpoint)

$ python3 connectus/workflow_state.py markpass "Cisco Spark" 1
ERROR: column #1 ('Integration ID') is an identity column; cannot apply markpass
```

#### 9. Dashboard view (13-cell bar)

```
$ python3 connectus/workflow_state.py dashboard

================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration ID                                Progress             → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [██████████░░░] 10/13  → param parity test passes

  Summary: 0 complete, 1 in progress, 981 not started
```

#### 10. `next` for everyone (or just yourself)

```
$ python3 connectus/workflow_state.py next --all
Cisco Spark — step 11 of 13: param parity test passes
  Run:    python3 connectus/workflow_state.py markpass "Cisco Spark" "param parity test passes"
  About:  Run the parameter-parity test.
```

`next` (no args) does the same but only for integrations whose `assignee` matches the current `git config user.name`.

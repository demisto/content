Note, this folder should not be merged to master.

> **Architecture note.** [`connectus/workflow_state.py`](workflow_state.py:1) is now a thin backward-compatible shim that re-exports the real package at [`connectus/workflow_state/`](workflow_state/__init__.py:1). The CLI entrypoint, validators, state machine, CSV I/O, display helpers, and config loader live there. Behavior is identical; the file split is purely for maintainability. The canonical Python import is `from workflow_state import …`.

## Authentication Type Catalog

Each integration's authentication is classified into an **Auth Class** string
value, with per-parameter details captured in a structured **Auth Detail** JSON
object.

### Auth Config Expression Format

This is the format used inside the `config` field of the **Auth Detail** JSON
(it is not a separate CSV column). It is a human-readable string with two parts
separated by ` — `:

**Part 1**: Auth types grouped by type with names (pipe-separated between types)
**Part 2**: Requirement expression using `REQUIRED()`, `OPTIONAL()`, `CHOICE()`, combined with `+`

Special case: `NoneRequired` (no auth params)

#### Auth Type Values

| Value | Description | Examples |
|---|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow | Lansweeper, Gmail |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow | CrowdStrike Falcon, Wiz |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow | Google integrations |
| `APIKey` | API Key, HMAC, and similar static secret mechanisms | Abnormal Security, VirusTotal |
| `Plain` | Plain text fields: username/password, basic auth, bearer tokens, AWS credentials, certificates | ActiveMQ, AWS S3, CyberArk |
| `Other` | Catch-all for auth mechanisms that don't fit the other categories (e.g., OAuth 2.0 Device Code flow, Managed Identity, ROPC). | Azure WAF, Azure Kubernetes Services |
| `NoneRequired` | No authentication needed | AlienVault Reputation Feed |

#### Requirement Expression

| Expression | Meaning |
|---|---|
| `REQUIRED(Type)` | One required param of that type |
| `REQUIRED(Type, Type)` | Two required params of the same type |
| `OPTIONAL(Type)` | Optional param(s) of that type |
| `CHOICE(Type1, Type2)` | Multiple types, all optional — pick one |
| `REQUIRED(X) + OPTIONAL(Y)` | X is required, Y is optional |

#### Auth Config Expression Examples

| Integration | Auth Config Expression | Why |
|---|---|---|
| Abnormal Security | `APIKey(api_key) — REQUIRED(APIKey)` | Single required API key |
| AlienVault Reputation Feed | `NoneRequired` | No auth params |
| CrowdStrike Falcon | `OAuth2ClientCreds(credentials) — REQUIRED(OAuth2ClientCreds)` | OAuth client credentials (effectively required) |
| Darktrace Admin | `APIKey(privateApiKey, publicApiKey) — REQUIRED(APIKey, APIKey)` | Two required API keys |
| AbuseIPDB | `APIKey(credentials, hunting_credentials) — OPTIONAL(APIKey)` | Two optional API key params |
| Salesforce IAM | `OAuth2ClientCreds(credentials_consumer) \| Plain(credentials) — REQUIRED(Plain) + OPTIONAL(OAuth2ClientCreds)` | Plain required, OAuth optional |
| Wiz | `OAuth2ClientCreds(credentials) — REQUIRED(OAuth2ClientCreds)` | OAuth client credentials |

### How to Read the CSV Columns

#### Data Columns (not managed by workflow_state.py)

| # | Column | Description |
|---|---|---|
| 1 | `Integration ID` | ID of the integration |
| 2 | `Integration File Path` | Path to the integration's source files |
| 3 | `Connector ID` | The ID of the Connector |

#### JSON Column Schemas

The JSON shapes for `Auth Details` and `Params to Commands` live in
[`connectus/column-schemas.md`](column-schemas.md). The same file also
covers the `verify button placement` flag (enum
`connection|configuration|none`, default `connection`).

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

The [`workflow_state.py`](workflow_state.py) script manages the **14 workflow columns** (columns 4–17) of [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv). It models the workflow as a **single linear 14-step sequence**, strictly gated. The current step is always the first step that is not yet done.

State is **purely derived from row contents** — there is no separate "current step" pointer. Re-issuing any `set-*`, `markpass`, or `skip` for a step at-or-behind the current step writes the new value AND clears every step that follows it ("cascade reset"). Two carve-outs apply:

- **`set-assignee`** never cascades (governed by the YAML flag `cascade_on_set: false`).
- **`reset-to` and `fail`** preserve any step tagged `preserve_on_reset: true` in [`workflow_state_config.yml`](workflow_state_config.yml). Today only step #3 `Params to Commands` carries that flag (the historical `Params for test with default in code` and `Params same in other handlers` columns were removed in 2026-05) — see Rule 8 below.

### The 14-Step Sequence

| # | Step (== CSV column) | Kind | Set via |
|---|---|---|---|
| 1 | `assignee` | data | `set-assignee` |
| 2 | `Auth Details` | data (JSON; includes `auth_types`, `config`, **and `other_connection`** — see [`column-schemas.md`](column-schemas.md)) | `set-auth` |
| 3 | `Params to Commands` | data (JSON) | `set-params-to-commands` |
| 4 | `verify button placement` | flag (`connection`/`configuration`/`none`; default `connection` on read) | `set-verify-placement` |
| 5 | `generated manifest` | checkpoint | `markpass` |
| 6 | `run manifest make validate` | checkpoint | `markpass` |
| 7 | `wrote/checked code` | checkpoint | `markpass` |
| 8 | `shadowed command test passes` | checkpoint | `markpass` |
| 9 | `write tests` | checkpoint | `markpass` |
| 10 | `precommit/validate/unit tests passed` | checkpoint | `markpass` |
| 11 | `auth parity test passes` | checkpoint | `markpass` (unconditional; the historical `requires auth parity test` gate flag was removed in 2026-05) |
| 12 | `param parity test passes` | checkpoint | `markpass` |
| 13 | `code reviewed` | checkpoint | `markpass` |
| 14 | `code merged` | checkpoint | `markpass` |

### Rules

1. **Single linear sequence.** The current step is the first step not yet done.
2. **Strict ordering.** Any `set-*`/`markpass`/`skip` targeting a step **ahead** of the current step is rejected with a message naming the missing prerequisite.
3. **Cascade reset.** Re-issuing any `set-*`/`markpass`/`skip` at-or-behind current writes the new value AND clears every step after it.
4. **`set-assignee` carve-out.** `set-assignee` (step #1) updates in place without cascading. Re-assigning an integration mid-flight does NOT wipe progress. Configured via `cascade_on_set: false` in [`workflow_state_config.yml`](workflow_state_config.yml).
5. **Default-on-read for `verify button placement`.** An empty cell at step #4 reads as `connection` (the YAML default). The cell still counts as "done" for current-step purposes, so an unset flag does NOT block step #5.
6. **Normalization on read AND write.** Any value past the first incomplete step is auto-cleared (with a one-line stderr warning per affected row). Contradictions are not allowed to persist.
7. **`fail` and `reset-to` honour `preserve_on_reset`.** Both verbs clear the named step AND every step after it (the named step becomes the new current step). They have identical behaviour. **EXCEPTION:** any step tagged `preserve_on_reset: true` in [`workflow_state_config.yml`](workflow_state_config.yml) keeps its value across these operations — its name is reported in the CLI output (`Preserved (preserve_on_reset=true): [...]`) and in the api response (`result["preserved"]`). Today only step #3 `Params to Commands` is preserved so a failed checkpoint does not wipe per-command param research.
   - **Explicit-target carve-out:** if the user names a preserved step **directly** as the `reset-to`/`fail` target, that one step IS cleared (the user's intent wins), but later preserved steps in the same operation are still preserved.
   - **`set-auth` is NOT covered by `preserve_on_reset`.** Auth changes invalidate every downstream artifact — `set-auth` continues to wipe steps #3-#14 (`Params to Commands` included) by design. See `apply_step_action` in [`connectus/workflow_state/state_machine.py`](workflow_state/state_machine.py).
8. **`reset` (no step).** Clears all 14 workflow columns for the integration. Identity columns (`Integration ID`, `Integration File Path`, `Connector ID`) are preserved. **`preserve_on_reset` is intentionally ignored** — `reset` is the "wipe the row" verb with no carve-outs.
9. **Column-number addressability.** Every CLI verb that takes a column name (`show-step`, `markpass`, `skip`, `fail`, `reset-to`) also accepts a **1-based CSV column number** (1..17). Identity columns (#1-#3) are addressable only for read-only `show-step`; write verbs reject them with a verb-aware error. Example: `python3 connectus/workflow_state.py show-step CrowdstrikeFalcon 5` resolves to `Auth Details`.

### CLI Commands

All commands take an Integration ID (case-insensitive) as the first argument
where applicable. **Every `set-*`/`markpass`/`skip` for a step at-or-behind
the current step cascade-resets every step after it.** The lone exception is
`set-assignee`, which never resets later steps.

```bash
# Show status (with [N/14] linear indicator)
python3 connectus/workflow_state.py status "Cisco Spark"

# Show all integrations with any progress
python3 connectus/workflow_state.py status-all

# Compact dashboard (14-cell progress bars)
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

# Set Auth Details (validates JSON schema; cascade-resets steps #3-#16)
# Each auth_types[] entry is one full UCP connection type. xsoar_param_map is
# a dict whose keys are XSOAR field paths supplying the secrets and whose
# values are the role each field plays in the connection (credentials params
# expand to `<paramid>.identifier` + `<paramid>.password` leaves). The
# `other_connection` field is a flat sorted list of YML param ids that are
# connection-adjacent but not auth secrets (url, proxy, insecure, port, host,
# region, ...). It lives INSIDE the Auth Details JSON, not as a separate CSV
# column. See column-schemas.md (incl. the per-type role-enum table).
python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"credentials.password":"key"}}],"config":"REQUIRED(credentials)","other_connection":["insecure","proxy","url"]}'

# Set Params to Commands (validates JSON; cascade-resets steps #4-#14).
# REJECTED if any param in the payload also appears in Auth Details
# (auth secrets or other_connection). Run `auth-params <id>` first to
# see what to exclude, or pass `--integration-id <id>` to the analyzer
# so it pulls the exclusion set automatically.
python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{"integration":"Cisco Spark","commands":{"test-module":["fetch_query"]}}'

# Set the verify-button placement flag (connection|configuration|none;
# default 'connection' on read when the cell is empty).
python3 connectus/workflow_state.py set-verify-placement "Cisco Spark" connection

# Mark a checkpoint as passed (must be at-or-behind current; behind→cascade-resets).
# Every column-name argument below also accepts a 1-based CSV column number, e.g.
#   python3 connectus/workflow_state.py markpass "Cisco Spark" 8
# would target column #8 (`generated manifest`).
python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

# Fail a step (clears it + every step after)
python3 connectus/workflow_state.py fail "Cisco Spark" "wrote/checked code"

# Reset to a specific step (alias for fail; clears it + every step after)
python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote/checked code"

# Reset all 14 workflow columns
python3 connectus/workflow_state.py reset "Cisco Spark"

# List integrations currently at a specific step (any step kind)
python3 connectus/workflow_state.py at-step "wrote/checked code"

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
| `dashboard` | Compact 14-cell progress bar for every in-progress integration |
| `next` / `next <id>` / `next --all` / `next --connector <c>` / `next --mine` | Print the literal next action |
| `show-step <id> <col\|#>` | Pretty-print one column's value (JSON-aware); `<col>` may be a name OR a 1-based CSV column number |
| `set-assignee <id> <name>` | Set the owner (admin; never cascades) |
| `set-auth <id> '<json>'` | Set Auth Details (validates schema; cascade-resets #3-#14) |
| `set-params-to-commands <id> '<json>'` | Set per-command param map. **Rejected** if any param overlaps with `Auth Details` (auth-secret or `other_connection`); use `auth-params` to inspect the exclusion set. |
| `set-verify-placement <id> connection\|configuration\|none` | Set the verify-button placement flag (#4); empty cell reads as `connection`. |
| `markpass <id> <step\|#>` | Mark a checkpoint as passed; `<step>` may be a name OR a 1-based CSV column number (identity columns rejected) |
| `fail <id> <step\|#>` / `reset-to <id> <step\|#>` | Clear a step + every step after; column-number argument accepted |
| `reset <id>` | Clear all 14 workflow columns |
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
result = fail_integration_step("Cisco Spark", "wrote/checked code")
result = reset_integration_to_step("Cisco Spark", "wrote/checked code")

# Set Auth Details (validates schema; cascade-resets steps #3-#14)
result = set_integration_auth("Cisco Spark", '{"auth_types":...}')
```

### Unit Tests

Run the test suite from the `connectus/` directory:

```bash
cd connectus && python3 -m pytest workflow_state_test.py -v
```

The current test suite lives under [`connectus/workflow_state/tests/`](workflow_state/tests/) and covers:
the YAML loader and its validation rules (`test_config_loader.py`); the
cascade-reset engine (`test_state_machine.py`); the `verify button
placement` flag column (`test_verify_button_placement.py`); the 1-based
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
14-step sequence.

#### 1. Check initial status

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:        (unassigned)
  File Path:       (not set)
  Connector ID:    (not set)

  Workflow ([0/14]):
  ----------------------------------------
  ▶ 1. assignee                               : (not set)
    2. Auth Details                           : (not set)
    3. Params to Commands                     : (not set)
    4. verify button placement                : connection (default; cell empty)
    5. generated manifest                     : ⬜
    6. run manifest make validate             : ⬜
    7. wrote/checked code                     : ⬜
    8. shadowed command test passes           : ⬜
    9. write tests                            : ⬜
   10. precommit/validate/unit tests passed   : ⬜
   11. auth parity test passes                : ⬜
   12. param parity test passes               : ⬜
   13. code reviewed                          : ⬜
   14. code merged                            : ⬜

  ➡️  Current step: #1 assignee (run: set-assignee)
```

#### 2. Ask `next` what to do

```
$ python3 connectus/workflow_state.py next "Cisco Spark"

Cisco Spark — step 1 of 14: assignee
  Run:    python3 connectus/workflow_state.py set-assignee "Cisco Spark" "<your name>"
  About:  Assign an owner to drive this integration's migration.
```

#### 3. Try to markpass ahead of current step (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

ERROR: Cannot markpass 'generated manifest' (step 5/14) yet — current step is #1 'assignee'.
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

$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"Plain","name":"credentials","xsoar_param_map":{"credentials.identifier":"username","credentials.password":"password"}}],"config":"REQUIRED(credentials)","other_connection":["insecure","proxy","url"]}'
Set 'Auth Details' (step 2/14) for 'Cisco Spark'.
  Current step: #3 Params to Commands

$ python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{}'
Set 'Params to Commands' (step 3/14) for 'Cisco Spark'.
  Current step: #4 verify button placement

# Step #4 (`verify button placement`) is a flag; empty cell reads as
# 'connection' (the YAML default) so the workflow does NOT block on it.
# Explicitly set it when you want a non-default value.
$ python3 connectus/workflow_state.py set-verify-placement "Cisco Spark" configuration
Set 'verify button placement' = configuration for 'Cisco Spark'.
  Current step: #5 generated manifest

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"
✅ 'generated manifest' (step 5/14) marked as passed for 'Cisco Spark'.
  Next step: #6 run manifest make validate
```

#### 6. Cascade reset: re-issuing `set-auth` mid-flight

```
$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[],"config":"NoneRequired","other_connection":[]}'
Set 'Auth Details' (step 2/14) for 'Cisco Spark'.
  Cleared 3 subsequent step(s): ['Params to Commands', 'verify button placement', 'generated manifest']
  Current step: #3 Params to Commands
```

Re-issuing any setter at-or-behind the current step writes the new value AND clears every step after it.

#### 7. `set-assignee` is the carve-out — it never cascades

```
$ python3 connectus/workflow_state.py set-assignee "Cisco Spark" "Jane Smith"
Set assignee for 'Cisco Spark' to: Jane Smith
  Current step: #6 run manifest make validate
```

Re-assigning preserves all migration progress — only the `assignee` cell changes.

#### 8. Column-number addressability

```
# Numbers are 1-based into the full 17-column CSV (3 identity + 14 steps).
$ python3 connectus/workflow_state.py show-step "Cisco Spark" 5
# → resolves to column #5 → 'Auth Details'

$ python3 connectus/workflow_state.py markpass "Cisco Spark" 8
# → resolves to column #8 → 'generated manifest' (first checkpoint)

$ python3 connectus/workflow_state.py markpass "Cisco Spark" 1
ERROR: column #1 ('Integration ID') is an identity column; cannot apply markpass
```

#### 9. Dashboard view (14-cell bar)

```
$ python3 connectus/workflow_state.py dashboard

================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration ID                                Progress             → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [███████████░░░] 11/14  → param parity test passes

  Summary: 0 complete, 1 in progress, 981 not started
```

#### 10. `next` for everyone (or just yourself)

```
$ python3 connectus/workflow_state.py next --all
Cisco Spark — step 14 of 16: param parity test passes
  Run:    python3 connectus/workflow_state.py markpass "Cisco Spark" "param parity test passes"
  About:  Run the parameter-parity test.
```

`next` (no args) does the same but only for integrations whose `assignee` matches the current `git config user.name`.

Note, this folder should not be merged to master.
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

The JSON shapes for `Auth Details`, `Params to Commands`,
`Params for test with default in code`, and `Params same in other handlers`
live in [`connectus/column-schemas.md`](column-schemas.md).

---

## Workflow State Machine (`workflow_state.py`)

The [`workflow_state.py`](workflow_state.py) script manages the **16 workflow columns** (columns 5–20) of [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv). It models the workflow as a **single linear 16-step sequence**, strictly gated. The current step is always the first step that is not yet done.

State is **purely derived from row contents** — there is no separate "current step" pointer. Re-issuing any `set-*`, `markpass`, or `skip` for a step at-or-behind the current step writes the new value AND clears every step that follows it ("cascade reset"). The ONLY exception is `set-assignee`, which is administrative and never resets later steps.

### The 16-Step Sequence

| # | Step (== CSV column) | Kind | Set via |
|---|---|---|---|
| 1 | `assignee` | data | `set-assignee` |
| 2 | `Auth Details` | data (JSON) | `set-auth` |
| 3 | `Params to Commands` | data (JSON) | `set-params-to-commands` |
| 4 | `Params for test with default in code` | data (JSON) | `set-params-for-test` |
| 5 | `Params same in other handlers` | data (JSON) | `set-shared-params` (or `skip`) |
| 6 | `generated manifest` | checkpoint | `markpass` |
| 7 | `run manifest make validate` | checkpoint | `markpass` |
| 8 | `wrote/checked code` | checkpoint | `markpass` |
| 9 | `shadowed command test passes` | checkpoint | `markpass` |
| 10 | `write tests` | checkpoint | `markpass` |
| 11 | `precommit/validate/unit tests passed` | checkpoint | `markpass` |
| 12 | `requires auth parity test` | flag (`YES`/`NO`/`N/A`) | `set-auth-flag` |
| 13 | `auth parity test passes` | checkpoint | `markpass` (auto-`N/A` when #12 is `NO`/`N/A`) |
| 14 | `param parity test passes` | checkpoint | `markpass` |
| 15 | `code reviewed` | checkpoint | `markpass` |
| 16 | `code merged` | checkpoint | `markpass` |

### Rules

1. **Single linear sequence.** The current step is the first step not yet done.
2. **Strict ordering.** Any `set-*`/`markpass`/`skip` targeting a step **ahead** of the current step is rejected with a message naming the missing prerequisite.
3. **Cascade reset.** Re-issuing any `set-*`/`markpass`/`skip` at-or-behind current writes the new value AND clears every step after it.
4. **`set-assignee` carve-out.** `set-assignee` is the ONLY exception — it updates step #1 in place without cascading. Re-assigning an integration mid-flight does NOT wipe progress.
5. **Optional step #5.** `Params same in other handlers` may be `skip`-ped; that writes the sentinel `"N/A"` and unblocks step #6. Setting it to a real JSON value later cascade-resets steps #6+.
6. **Flag step #12 → step #13 auto-N/A.** Setting `requires auth parity test` to `NO` or `N/A` automatically writes `"N/A"` into `auth parity test passes`. Setting it to `YES` leaves #13 empty so the user must `markpass` it.
7. **Normalization on read AND write.** Any value past the first incomplete step is auto-cleared (with a one-line stderr warning per affected row). Contradictions are not allowed to persist.
8. **`fail` and `reset-to`.** Both verbs clear the named step AND every step after it (the named step becomes the new current step). They have identical behavior; `reset-to` is the explicit name, `fail` reads as "this step failed, redo it".
9. **`reset` (no step).** Clears all 16 workflow columns for the integration. Identity columns (`Integration ID`, `Integration File Path`, `Connector ID`) are preserved.

### CLI Commands

All commands take an Integration ID (case-insensitive) as the first argument
where applicable. **Every `set-*`/`markpass`/`skip` for a step at-or-behind
the current step cascade-resets every step after it.** The lone exception is
`set-assignee`, which never resets later steps.

```bash
# Show status (with [N/16] linear indicator)
python3 connectus/workflow_state.py status "Cisco Spark"

# Show all integrations with any progress
python3 connectus/workflow_state.py status-all

# Compact dashboard (16-cell progress bars)
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
# Each auth_types[] entry is one full UCP connection type. xsoar_params lists
# the XSOAR field paths that supply its secrets (credentials params expand to
# `<paramid>.identifier` + `<paramid>.password`). See column-schemas.md.
python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"APIKey","name":"api_key","xsoar_params":["api_key"]}],"config":"REQUIRED(api_key)"}'

# Set Params to Commands (validates JSON; cascade-resets steps #4-#16)
python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{"integration":"Cisco Spark","commands":{"test-module":["credentials"]}}'

# Set Params for test with default in code (validates JSON; cascade-resets #5-#16)
python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '["bot_token"]'

# Set Params same in other handlers (validates JSON; cascade-resets #6-#16)
python3 connectus/workflow_state.py set-shared-params "Cisco Spark" '[]'

# Mark the (optional) step #5 as skipped
python3 connectus/workflow_state.py skip "Cisco Spark" "Params same in other handlers"

# Set the auth parity flag (YES/NO/N/A); NO/N/A auto-N/A's step #13
python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" YES

# Mark a checkpoint as passed (must be at-or-behind current; behind→cascade-resets)
python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

# Fail a step (clears it + every step after)
python3 connectus/workflow_state.py fail "Cisco Spark" "wrote/checked code"

# Reset to a specific step (alias for fail; clears it + every step after)
python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote/checked code"

# Reset all 16 workflow columns
python3 connectus/workflow_state.py reset "Cisco Spark"

# List integrations currently at a specific step (any step kind)
python3 connectus/workflow_state.py at-step "wrote/checked code"

# List all integration IDs
python3 connectus/workflow_state.py list

# List integrations assigned to a specific person
python3 connectus/workflow_state.py list-by-assignee "John Doe"
```

### Programmatic API (for AI agents / other scripts)

The script exposes functions that can be imported and called directly:

```python
from connectus.workflow_state import (
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

# Skip an optional step (only #5 is optional)
result = skip_integration_step("Cisco Spark", "Params same in other handlers")

# Fail / reset-to: clear the named step + every step after
result = fail_integration_step("Cisco Spark", "wrote/checked code")
result = reset_integration_to_step("Cisco Spark", "wrote/checked code")

# Set Auth Details (validates schema; cascade-resets steps #3-#16)
result = set_integration_auth("Cisco Spark", '{"auth_types":...}')
```

### Unit Tests

Run the test suite from the `connectus/` directory:

```bash
cd connectus && python3 -m pytest workflow_state_test.py -v
```

The suite covers: schema constants, `is_checked`, `get_current_step`,
`get_step_index`, `reset_from_step`, `markpass_step` (non-checkpoint
rejection, prerequisite enforcement, sequential enforcement, auth parity
cases, full workflow), `find_row`, `format_status`,
`format_dashboard_row`, `format_step_value`, `cmd_show_step`,
`set-shared-params` registration, round-trip scenarios, edge cases,
assignee handling, and the `Params*` workflow data columns including
the optional `Params same in other handlers`.

### Example Walkthrough

Below is a walkthrough showing what each command outputs under the unified
16-step sequence.

#### 1. Check initial status

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:        (unassigned)
  File Path:       (not set)
  Connector ID:    (not set)

  Workflow ([0/16]):
  ----------------------------------------
  ▶ 1. assignee                               : (not set)
    2. Auth Details                           : (not set)
    3. Params to Commands                     : (not set)
    4. Params for test with default in code   : (not set)
    5. Params same in other handlers          : (not set)
    6. generated manifest                     : ⬜
    7. run manifest make validate             : ⬜
    8. wrote/checked code                     : ⬜
    9. shadowed command test passes           : ⬜
   10. write tests                            : ⬜
   11. precommit/validate/unit tests passed   : ⬜
   12. requires auth parity test              : (not set)
   13. auth parity test passes                : ⬜
   14. param parity test passes               : ⬜
   15. code reviewed                          : ⬜
   16. code merged                            : ⬜

  ➡️  Current step: #1 assignee (run: set-assignee)
```

#### 2. Ask `next` what to do

```
$ python3 connectus/workflow_state.py next "Cisco Spark"

Cisco Spark — step 1 of 16: assignee
  Run:    python3 connectus/workflow_state.py set-assignee "Cisco Spark" "<your name>"
  About:  Assign an owner to drive this integration's migration.
```

#### 3. Try to markpass ahead of current step (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

ERROR: Cannot markpass 'generated manifest' (step 6/16) yet — current step is #1 'assignee'.
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

$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"Plain","name":"credentials","xsoar_params":["credentials.identifier","credentials.password"]}],"config":"REQUIRED(credentials)"}'
Set 'Auth Details' (step 2/16) for 'Cisco Spark'.
  Current step: #3 Params to Commands

$ python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{}'
Set 'Params to Commands' (step 3/16) for 'Cisco Spark'.
  Current step: #4 Params for test with default in code

$ python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '[]'
Set 'Params for test with default in code' (step 4/16) for 'Cisco Spark'.
  Current step: #5 Params same in other handlers

# Step #5 is optional — `skip` writes "N/A" and unblocks step #6
$ python3 connectus/workflow_state.py skip "Cisco Spark" "Params same in other handlers"
✓ Skipped step 5 ('Params same in other handlers') for 'Cisco Spark'.
  Next step: #6 generated manifest

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"
✅ 'generated manifest' (step 6/16) marked as passed for 'Cisco Spark'.
  Next step: #7 run manifest make validate
```

#### 6. Cascade reset: re-issuing `set-auth` mid-flight

```
$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[],"config":"NoneRequired"}'
Set 'Auth Details' (step 2/16) for 'Cisco Spark'.
  Cleared 4 subsequent step(s): ['Params to Commands', 'Params for test with default in code', 'Params same in other handlers', 'generated manifest']
  Current step: #3 Params to Commands
```

Re-issuing any setter at-or-behind the current step writes the new value AND clears every step after it.

#### 7. `set-assignee` is the carve-out — it never cascades

```
$ python3 connectus/workflow_state.py set-assignee "Cisco Spark" "Jane Smith"
Set assignee for 'Cisco Spark' to: Jane Smith
  Current step: #7 run manifest make validate
```

Re-assigning preserves all migration progress — only the `assignee` cell changes.

#### 8. Auth parity flag → step #13 auto-N/A

```
$ python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" NO
Set 'requires auth parity test' = NO for 'Cisco Spark'.
  Auto-set 'auth parity test passes' = N/A.
  Current step: #14 param parity test passes
```

#### 9. Dashboard view (16-cell bar)

```
$ python3 connectus/workflow_state.py dashboard

================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration ID                                Progress             → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [████████████░░░░] 12/16  → param parity test passes

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

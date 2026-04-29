Note, this folder should not be merged to master.
## Authentication Type Catalog

Each integration's authentication is classified into an **Auth Class** string
value, with per-parameter details captured in a structured **Auth Detail** JSON
object.

### Auth Config Expression Format

This is the format used inside the `config` field of the **Auth Detail** JSON
(it is not a separate CSV column). It is a human-readable string with two parts
separated by ` — `:

**Part 1**: Auth types grouped by type with param names (pipe-separated between types)
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
| `Other` | Catch-all for auth mechanisms that don't fit the other categories (e.g., OAuth 2.0 Device Code flow). The `notes` field MUST explain the specific auth mechanism. | Azure WAF, Azure Kubernetes Services |
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
| 4 | `special cases` | Frontend/Backend special hardcoded cases |

#### JSON Column Schemas

The JSON shapes for `Auth Details`, `Params to Commands`,
`Params for test with default in code`, and `Params same in other handlers`
live in [`connectus/column-schemas.md`](column-schemas.md).

---

## Workflow State Machine (`workflow_state.py`)

The [`workflow_state.py`](workflow_state.py) script manages the **16 workflow columns** (columns 5–20) of [`connectus/integrations_report.csv`](integrations_report.csv). It acts as a **state machine** where each integration progresses through ordered steps, and is designed to be used by both humans and AI agents.

The script distinguishes between two kinds of workflow columns:

- **Workflow data columns** (free-text / JSON, columns 5–9): `assignee`,
  `Auth Details`, `Params to Commands`,
  `Params for test with default in code`, `Params same in other handlers`.
  These are set with dedicated CLI commands (`set-assignee`, `set-auth`,
  `set-params-to-commands`, `set-params-for-test`, `set-shared-params`).
- **Workflow checkpoint columns** (sequential ✅, columns 10–15 and 17–20):
  `generated manifest`, `run manifest make validate`, `wrote/checked code`,
  `shadowed command test passes`, `write tests`,
  `precommit/validate/unit tests passed`, `auth parity test passes`,
  `param parity test passes`, `code reviewed`, `code merged`. These are
  marked passed with `markpass` and follow strict sequential ordering.

There is also one **workflow flag column** (column 16):
`requires auth parity test` (`YES` / `NO` / `N/A`), set with `set-auth-flag`.
It is NOT a checkpoint.

### Workflow Columns

| Responsible | Column | Type | Description |
|---|---|---|---|
|  | `assignee` | Free text | Who is working on this integration |
| Judah | `Auth Details` | Free text (JSON) | Details of the auth of the integration (see [`column-schemas.md`](column-schemas.md#auth-details)) |
| Judah | `Params to Commands` | Free text (JSON) | Mapping of integration commands to the parameter IDs each command needs (see [`column-schemas.md`](column-schemas.md#params-to-commands)) |
| Judah | `Params for test with default in code` | Free text (JSON) | Param IDs whose defaults are hardcoded in source (see [`column-schemas.md`](column-schemas.md#params-for-test-with-default-in-code)) |
| Judah | `Params same in other handlers` | Free text (JSON, optional) | Param IDs shared verbatim with sibling handlers (see [`column-schemas.md`](column-schemas.md#params-same-in-other-handlers-optional)) |
| Yuval | `generated manifest` | Checkpoint ✅ | Manifest YAML has been generated |
| Joey | `run manifest make validate` | Checkpoint ✅ | Make validate |
| Joey | `wrote/checked code` | Checkpoint ✅ | Python/JavaScript/PWSH code has been changed |
| Joey | `shadowed command test passes` | Checkpoint ✅ | Verify no conflicting commands in the same connector or make the changes if required |
| Joey | `write tests` | Checkpoint ✅ | Unit tests written |
| Yuval | `precommit/validate/unit tests passed` | Checkpoint ✅ | Pre-commit and validate (Yuval will decide what to skip) |
| Judah | `requires auth parity test` | Flag | `YES`, `NO`, or `N/A` |
| Judah | `auth parity test passes` | Checkpoint ✅ | Auth parity test passes (auto `N/A` if flag is `NO`) |
| Joey | `param parity test passes` | Checkpoint ✅ | Parameter parity test passes |
|  | `code reviewed` | Checkpoint ✅ | Code review completed |
|  | `code merged` | Checkpoint ✅ | Code merged to branch |

### Rules

1. **Explicit step naming** — You must explicitly name the step you are marking as passed via `markpass`. There is no general "advance" command.
2. **Sequential order** — Checkpoint columns must be completed in order. You cannot mark `wrote/checked code` before `run manifest make validate` is done. The script will reject the attempt and tell you what the current step is.
3. **Workflow data columns are not checkpoints** — `assignee`, `Auth Details`, `Params to Commands`, `Params for test with default in code`, and `Params same in other handlers` are free-text / JSON columns. Set them with their dedicated commands (`set-assignee`, `set-auth`, `set-params-to-commands`, `set-params-for-test`, `set-shared-params`); do not try to `markpass` them.
4. **Prerequisites for `generated manifest`** — `Params to Commands` and `Params for test with default in code` must both be set (valid JSON) before you can mark `generated manifest` as passed. Use `set-params-to-commands` and `set-params-for-test` respectively. `Params same in other handlers` is optional and is **not** a prerequisite.
5. **Setting `Auth Details` resets the workflow** — `set-auth` validates against the [Auth Details schema](column-schemas.md#auth-details), then clears all checkpoints and the auth-parity flag. The integration is reset to the first checkpoint (`generated manifest`).
6. **Non-checkpoint correction** — If you try to `markpass` a workflow data column or the auth-parity flag, the script tells you the correct setter command to use instead.
7. **Fail & reset** — When a step fails, use `fail` to reset that step **and all subsequent steps**.
8. **Reset to stage** — Use `reset-to` to go back to a specific checkpoint, clearing it and everything after it.
9. **Auth parity flag** — `requires auth parity test` is a flag, not a checkpoint. When set to `NO` or `N/A`, `auth parity test passes` is automatically set to `N/A` and skipped.

### CLI Commands

All commands take an Integration ID (case-insensitive) as the first argument
where applicable.

```bash
# Show status of an integration
python3 connectus/workflow_state.py status "Cisco Spark"

# Show all integrations with any progress
python3 connectus/workflow_state.py status-all

# Compact dashboard with progress bars
python3 connectus/workflow_state.py dashboard

# Show the value of a single column for an integration (pretty-prints JSON)
python3 connectus/workflow_state.py show-step "Cisco Spark" "Auth Details"

# Set the assignee (workflow data column, free text)
python3 connectus/workflow_state.py set-assignee "Cisco Spark" "John Doe"

# Set Auth Details (validates JSON schema, then resets workflow to 'generated manifest')
python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'

# Set Params to Commands (must be valid JSON)
python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{"integration":"Cisco Spark","commands":{"test-module":["credentials"]}}'

# Set Params for test with default in code (must be valid JSON)
python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '["bot_token"]'

# Set Params same in other handlers (optional; must be valid JSON)
python3 connectus/workflow_state.py set-shared-params "Cisco Spark" '[]'

# Mark a checkpoint as passed (must be the current step)
python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

# Fail a checkpoint (resets it + all subsequent checkpoints)
python3 connectus/workflow_state.py fail "Cisco Spark" "wrote/checked code"

# Set the auth parity flag (YES / NO / N/A)
python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" YES

# Reset to a specific checkpoint (clears that step and everything after it)
python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote/checked code"

# Reset all workflow columns
python3 connectus/workflow_state.py reset "Cisco Spark"

# List integrations currently at a specific checkpoint
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
    markpass_integration_step,
    fail_integration_step,
    reset_integration_to_step,
    set_integration_auth,
)

# Get status as a dict
status = get_integration_status("Cisco Spark")
# Returns: {name, current_step, workflow, completed_steps, total_steps, progress_pct, all_complete}

# Mark a specific checkpoint as passed (fails if not up to that step)
result = markpass_integration_step("Cisco Spark", "generated manifest")
# Returns: {message, completed_step, current_step} or {error: "..."}

# Fail a checkpoint and reset subsequent ones
result = fail_integration_step("Cisco Spark", "wrote/checked code")
# Returns: {message, current_step}

# Reset to a specific checkpoint
result = reset_integration_to_step("Cisco Spark", "wrote/checked code")
# Returns: {message, current_step}

# Set Auth Details (validates schema, resets workflow to 'generated manifest')
result = set_integration_auth("Cisco Spark", '{"auth_types":...}')
# Returns: {message, current_step} or {error: "..."}
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

Below is a full walkthrough showing what each command outputs. This walks through a typical integration lifecycle under the new schema.

#### 1. Check initial status

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:        (unassigned)
  File Path:       (not set)
  Connector ID:    (not set)

  Workflow Data:
  ----------------------------------------
    Auth Details                           : (not set)
    Params to Commands                     : (not set)
    Params for test with default in code   : (not set)
    Params same in other handlers          : (not set)

  Workflow Checkpoints:
  ----------------------------------------
    generated manifest                     : ⬜
    run manifest make validate             : ⬜
    wrote/checked code                     : ⬜
    shadowed command test passes           : ⬜
    write tests                            : ⬜
    precommit/validate/unit tests passed   : ⬜
    requires auth parity test              : (not set)
    auth parity test passes                : ⬜
    param parity test passes               : ⬜
    code reviewed                          : ⬜
    code merged                            : ⬜

  ➡️  Current step: generated manifest
```

#### 2. Try to markpass without setting Params to Commands first (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

ERROR: Cannot mark 'generated manifest' as passed — 'Params to Commands' must be set first.
  Use 'set-params-to-commands' to provide the params (JSON).
  Example: workflow_state.py set-params-to-commands "Cisco Spark" '{}'
```

#### 3. Try to set-params-to-commands with invalid JSON (rejected)

```
$ python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" "not json"

ERROR: 'Params to Commands' must be valid JSON.
  Got: not json
  Parse error: Expecting value: line 1 column 1 (char 0)
  Example: workflow_state.py set-params-to-commands "Cisco Spark" '{}'
```

#### 4. Set Auth Details, Params to Commands, and Params for test

```
$ python3 connectus/workflow_state.py set-auth "Cisco Spark" '{"auth_types":[{"type":"Plain","name":"credentials"}],"config":"REQUIRED(Plain)","params":{"credentials":{"type":"Plain","xsoar_type":9,"required":true}},"notes":null}'

Set 'Auth Details' for 'Cisco Spark'.
  Reset workflow to 'generated manifest' (cleared 10 checkpoint(s) and the auth parity flag).
  Current step: generated manifest

$ python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '{"integration":"Cisco Spark","commands":{"test-module":["credentials"]}}'

Set 'Params to Commands' for 'Cisco Spark' to: {"integration":"Cisco Spark","commands":{"test-module":["credentials"]}}

$ python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '["bot_token"]'

Set 'Params for test with default in code' for 'Cisco Spark' to: ["bot_token"]
```

#### 5. (Optional) Set Params same in other handlers

```
$ python3 connectus/workflow_state.py set-shared-params "Cisco Spark" '[]'

Set 'Params same in other handlers' for 'Cisco Spark' to: []
```

This column is optional and never blocks a checkpoint.

#### 6. Mark the first checkpoint as passed

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

✅ 'generated manifest' marked as passed for 'Cisco Spark'.
  Next step: run manifest make validate
```

#### 7. Try to skip ahead (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "write tests"

ERROR: Cannot mark 'write tests' as passed — you are not up to that step yet.
  Current step: 'run manifest make validate'
  Prior step 'run manifest make validate' is not yet complete.
```

#### 8. Try to markpass a non-checkpoint column (corrected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "Params to Commands"

ERROR: 'Params to Commands' is not a pass/fail checkpoint.
  Use 'set-params-to-commands' instead.
  Example: workflow_state.py set-params-to-commands "Cisco Spark" <value>
```

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "requires auth parity test"

ERROR: 'requires auth parity test' is not a pass/fail checkpoint.
  Use 'set-auth-flag' instead.
  Example: workflow_state.py set-auth-flag "Cisco Spark" <value>
```

#### 9. Continue marking checkpoints

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "run manifest make validate"
✅ 'run manifest make validate' marked as passed for 'Cisco Spark'.
  Next step: wrote/checked code

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "wrote/checked code"
✅ 'wrote/checked code' marked as passed for 'Cisco Spark'.
  Next step: shadowed command test passes

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "shadowed command test passes"
✅ 'shadowed command test passes' marked as passed for 'Cisco Spark'.
  Next step: write tests
```

#### 10. Fail a step (resets it and everything after)

```
$ python3 connectus/workflow_state.py fail "Cisco Spark" "wrote/checked code"

Reset 'wrote/checked code' and 7 subsequent step(s) for 'Cisco Spark'.
  Current step is now: wrote/checked code
```

#### 11. Reset to a specific checkpoint

```
$ python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote/checked code"

Reset to 'wrote/checked code' for 'Cisco Spark'.
  Cleared 'wrote/checked code' and 7 subsequent step(s).
  Current step is now: wrote/checked code
```

#### 12. Check status after partial progress

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:        (unassigned)
  File Path:       (not set)
  Connector ID:    (not set)

  Workflow Data:
  ----------------------------------------
    Auth Details                           : {"auth_types":[{"type":"Plain","name":"credentials"}],"config":"REQUIRED(Plain)","params":{"credentials":{"type":"Plain","xsoar_type":9,"required":true}},"notes":null}
    Params to Commands                     : {"integration":"Cisco Spark","commands":{"test-module":["credentials"]}}
    Params for test with default in code   : ["bot_token"]
    Params same in other handlers          : []

  Workflow Checkpoints:
  ----------------------------------------
    generated manifest                     : ✅
    run manifest make validate             : ✅
    wrote/checked code                     : ⬜
    shadowed command test passes           : ⬜
    write tests                            : ⬜
    precommit/validate/unit tests passed   : ⬜
    requires auth parity test              : (not set)
    auth parity test passes                : ⬜
    param parity test passes               : ⬜
    code reviewed                          : ⬜
    code merged                            : ⬜

  ➡️  Current step: wrote/checked code
```

#### 13. Dashboard view (multiple integrations)

```
$ python3 connectus/workflow_state.py dashboard

================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration ID                                Progress   Step   → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [██░░░░░░░░] 2/10  → wrote/checked code
  GLPI                                          [████████░░] 8/10  → code reviewed
  Wiz                                           [██████████] 10/10 → ✅ DONE

  Summary: 1 complete, 2 in progress, 980 not started
```

#### 14. Set auth flag and auto-skip

```
$ python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" NO

Set 'requires auth parity test' = NO and 'auth parity test passes' = N/A for 'Cisco Spark'.
```

When you later reach the `precommit/validate/unit tests passed` step and mark it as passed, `auth parity test passes` is automatically skipped (the next step becomes `param parity test passes`):

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "precommit/validate/unit tests passed"

✅ 'precommit/validate/unit tests passed' marked as passed for 'Cisco Spark'.
  Auto-skipped 'auth parity test passes' (flag=NO).
  Next step: param parity test passes
```

#### 15. List integrations at a specific checkpoint

```
$ python3 connectus/workflow_state.py at-step "wrote/checked code"

Integrations currently at step 'wrote/checked code' (3):
  - Cisco Spark
  - Abnormal Security
  - CrowdStrike Falcon
```

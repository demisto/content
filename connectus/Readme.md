Note, this folder should not be merged to master.
## Authentication Type Catalog

Each integration's authentication is classified into an **Auth Class** string
value, with per-parameter details captured in a structured **Auth Detail** JSON
object.

### Auth Class Format

The `Auth Class` column is a human-readable string with two parts separated by ` — `:

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
| `NoneRequired` | No authentication needed | AlienVault Reputation Feed |

#### Requirement Expression

| Expression | Meaning |
|---|---|
| `REQUIRED(Type)` | One required param of that type |
| `REQUIRED(Type, Type)` | Two required params of the same type |
| `OPTIONAL(Type)` | Optional param(s) of that type |
| `CHOICE(Type1, Type2)` | Multiple types, all optional — pick one |
| `REQUIRED(X) + OPTIONAL(Y)` | X is required, Y is optional |

#### Auth Class Examples

| Integration | Auth Class | Why |
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
| 1 | `assignee` | Who is working on this integration |
| 2 | `Integration Name` | Display name of the integration |
| 3 | `Support Level` | `xsoar` or `partner` |
| 4 | `Provider` | Vendor name |
| 5 | `Auth Class` | Human-readable auth classification (e.g., `OAuth2ClientCreds(credentials) — REQUIRED(OAuth2ClientCreds)`) |
| 6 | `Auth Detail` | JSON object with per-param auth mapping and notes |

#### Auth Detail JSON Schema

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

- `auth_types` — Array of `{type, name}` entries, sorted by (type, name)
- `config` — Requirement expression (e.g., `REQUIRED(APIKey)`, `CHOICE(APIKey, Plain)`)
- `params.<name>.type` — Which auth type this param belongs to (string or array)
- `params.<name>.xsoar_type` — XSOAR widget type (0=text, 4=encrypted, 8=bool, 9=credentials, 14=cert key, 15=select)
- `params.<name>.required` — Whether this param is required in the XSOAR config
- `notes` — Explanation for complex auth setups (managed identity, device code, etc.); null otherwise

---

## Workflow State Machine (`workflow_state.py`)

The `workflow_state.py` script manages the workflow tracking columns (columns 7–18) in `integrations_report.csv`. It acts as a **state machine** where each integration progresses through ordered steps, and is designed to be used by both humans and AI agents.

### Workflow Columns

| # | Column | Type | Description |
|---|--------|------|-------------|
| 0 | `assignee` | Free text | Who is working on this integration |
| 7 | `auth params set` | Checkpoint ✅ | Manual verification that Auth Class and Auth Detail are correct |
| 8 | `script inputs` | Free text (JSON) | The inputs/arguments for the script |
| 8b | `params required for test` | Free text (JSON) | Parameters needed for testing |
| 9 | `generated manifest` | Checkpoint ✅ | Manifest YAML has been generated |
| 10 | `wrote code` | Checkpoint ✅ | Python code has been written |
| 11 | `validations passed` | Checkpoint ✅ | `demisto-sdk validate` passes |
| 12 | `unit tests passed` | Checkpoint ✅ | Unit tests pass |
| 13 | `param parity test passes` | Checkpoint ✅ | Parameter parity test passes |
| 14 | `requires auth parity test` | Flag | `YES`, `NO`, or `N/A` |
| 15 | `auth parity test passes` | Checkpoint ✅ | Auth parity test passes (auto `N/A` if flag is `NO`) |
| 16 | `code reviewed` | Checkpoint ✅ | Code review completed |
| 17 | `code merged` | Checkpoint ✅ | Code merged to branch |

### Rules

1. **Explicit step naming** — You must explicitly name the step you are marking as passed via `markpass`. There is no general "advance" command.
2. **Sequential order** — Checkpoint columns 7–17 must be completed in order. You cannot mark "unit tests passed" before "wrote code" is done. The script will reject the attempt and tell you what the current step is.
3. **Auth params set** — Column 7 is the first checkpoint. It has no prerequisites and can be marked as passed at any time. It means someone has manually verified the Auth Class and Auth Detail columns are correct by reading the integration's YML and Python code. The Auth Class column uses the format described above (e.g., `APIKey(api_key) — REQUIRED(APIKey)`), and the Auth Detail column contains a JSON object with per-param auth mapping (see the Auth Detail JSON Schema section).
4. **Prerequisites for generated manifest** — `auth params set` must be passed (sequential enforcement), and both `script inputs` and `params required for test` must be set (valid JSON) before you can mark `generated manifest` as passed. Use `set-inputs` and `set-params-for-test` respectively.
5. **Non-checkpoint correction** — If you try to `markpass` a non-checkpoint step (like `script inputs`, `params required for test`, or `requires auth parity test`), the script tells you the correct command to use instead.
6. **Fail & reset** — When a step fails, use `fail` to reset that step **and all subsequent steps**.
7. **Reset to stage** — Use `reset-to` to go back to a specific stage, clearing it and everything after it.
8. **Auth parity flag** — Column 14 is a flag, not a checkpoint. When set to `NO` or `N/A`, column 15 is automatically set to `N/A` and skipped.

### CLI Commands

```bash
# Show status of an integration
python3 connectus/workflow_state.py status "Cisco Spark"

# Show all integrations with any progress
python3 connectus/workflow_state.py status-all

# Compact dashboard with progress bars
python3 connectus/workflow_state.py dashboard

# Set the assignee
python3 connectus/workflow_state.py set-assignee "Cisco Spark" "John Doe"

# Set script inputs (must be valid JSON)
python3 connectus/workflow_state.py set-inputs "Cisco Spark" '{"api_key": "str", "base_url": "str"}'

# Set params required for test (must be valid JSON)
python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '{"api_key": "test123"}'

# Mark a specific step as passed (must be the current step)
python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

# Fail a step (resets it + all subsequent steps)
python3 connectus/workflow_state.py fail "Cisco Spark" "unit tests passed"

# Set the auth parity flag
python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" YES

# Reset to a specific stage (clears that step and everything after it)
python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote code"

# Reset all workflow columns
python3 connectus/workflow_state.py reset "Cisco Spark"

# List integrations at a specific step
python3 connectus/workflow_state.py at-step "wrote code"

# List all integration names
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
)

# Get status as a dict
status = get_integration_status("Cisco Spark")
# Returns: {name, current_step, workflow, completed_steps, total_steps, progress_pct, all_complete}

# Mark a specific step as passed (fails if not up to that step)
result = markpass_integration_step("Cisco Spark", "generated manifest")
# Returns: {message, completed_step, current_step} or {error: "..."}

# Fail a step and reset subsequent ones
result = fail_integration_step("Cisco Spark", "unit tests passed")
# Returns: {message, current_step}

# Reset to a specific stage
result = reset_integration_to_step("Cisco Spark", "wrote code")
# Returns: {message, current_step}
```

### Unit Tests

Run the test suite from the `connectus/` directory:

```bash
cd connectus && python -m pytest workflow_state_test.py -v
```

85 tests covering: `is_checked`, `get_current_step`, `get_step_index`, `reset_from_step`, `markpass_step` (including non-checkpoint rejection, prerequisite enforcement, sequential enforcement, auth parity cases, full workflow), `find_row`, `format_status`, `format_dashboard_row`, round-trip scenarios, edge cases, assignee handling, and params-required-for-test handling.

### Example Walkthrough

Below is a full walkthrough showing what each command outputs. This walks through a typical integration lifecycle.

#### 1. Check initial status

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:      (unassigned)
  Support Level: xsoar
  Provider:      Cisco
  Auth Class:    Plain(credentials) — REQUIRED(Plain)

  Workflow Progress:
  ----------------------------------------
    auth params set                : ⬜
    script inputs                  : (not set)
    params required for test       : (not set)
    generated manifest             : ⬜
    wrote code                     : ⬜
    validations passed             : ⬜
    unit tests passed              : ⬜
    param parity test passes       : ⬜
    requires auth parity test      : (not set)
    auth parity test passes        : ⬜
    code reviewed                  : ⬜
    code merged                    : ⬜

  ➡️  Current step: auth params set
```

#### 2. Try to markpass without setting script inputs first (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

ERROR: Cannot mark 'generated manifest' as passed — 'script inputs' must be set first.
  Use 'set-inputs' to provide the script inputs (JSON).
  Example: workflow_state.py set-inputs "Cisco Spark" '{}'
```

#### 3. Try to set-inputs with invalid JSON (rejected)

```
$ python3 connectus/workflow_state.py set-inputs "Cisco Spark" "not json"

ERROR: script inputs must be valid JSON.
  Got: not json
  Parse error: Expecting value: line 1 column 1 (char 0)
  Example: workflow_state.py set-inputs "Cisco Spark" '{}'
```

#### 4. Set script inputs with valid JSON

```
$ python3 connectus/workflow_state.py set-inputs "Cisco Spark" '{"bot_token": "str"}'

Set 'script inputs' for 'Cisco Spark' to: {"bot_token": "str"}
```

#### 5. Set params required for test

```
$ python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '{"api_key": "test123"}'

Set 'params required for test' for 'Cisco Spark' to: {"api_key": "test123"}
```

#### 6. Mark steps as passed (sequential)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

✅ 'generated manifest' marked as passed for 'Cisco Spark'.
  Next step: wrote code
```

#### 7. Try to skip ahead (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "unit tests passed"

ERROR: Cannot mark 'unit tests passed' as passed — you are not up to that step yet.
  Current step: 'wrote code'
  Prior step 'wrote code' is not yet complete.
```

#### 8. Try to markpass a non-checkpoint step (corrected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "script inputs"

ERROR: 'script inputs' is not a pass/fail checkpoint.
  Use 'set-inputs' instead.
  Example: workflow_state.py set-inputs "Cisco Spark" <value>
```

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "requires auth parity test"

ERROR: 'requires auth parity test' is not a pass/fail checkpoint.
  Use 'set-auth-flag' instead.
  Example: workflow_state.py set-auth-flag "Cisco Spark" <value>
```

#### 9. Continue marking steps

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "wrote code"
✅ 'wrote code' marked as passed for 'Cisco Spark'.
  Next step: validations passed

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "validations passed"
✅ 'validations passed' marked as passed for 'Cisco Spark'.
  Next step: unit tests passed

$ python3 connectus/workflow_state.py markpass "Cisco Spark" "unit tests passed"
✅ 'unit tests passed' marked as passed for 'Cisco Spark'.
  Next step: param parity test passes
```

#### 10. Fail a step (resets it and everything after)

```
$ python3 connectus/workflow_state.py fail "Cisco Spark" "validations passed"

Reset 'validations passed' and 5 subsequent step(s) for 'Cisco Spark'.
  Current step is now: validations passed
```

#### 11. Reset to a specific stage

```
$ python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote code"

Reset to 'wrote code' for 'Cisco Spark'.
  Cleared 'wrote code' and 7 subsequent step(s).
  Current step is now: wrote code
```

#### 12. Check status after partial progress

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:      (unassigned)
  Support Level: xsoar
  Provider:      Cisco
  Auth Class:    Plain(credentials) — REQUIRED(Plain)

  Workflow Progress:
  ----------------------------------------
    auth params set                : ✅
    script inputs                  : {"bot_token": "str"}
    params required for test       : {"api_key": "test123"}
    generated manifest             : ✅
    wrote code                     : ⬜
    validations passed             : ⬜
    unit tests passed              : ⬜
    param parity test passes       : ⬜
    requires auth parity test      : (not set)
    auth parity test passes        : ⬜
    code reviewed                  : ⬜
    code merged                    : ⬜

  ➡️  Current step: wrote code
```

#### 13. Dashboard view (multiple integrations)

```
$ python3 connectus/workflow_state.py dashboard

================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration                                   Progress   Step   → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [██░░░░░░░] 2/9  → wrote code
  GLPI                                          [███████░░] 7/9  → code reviewed
  Wiz                                           [█████████] 9/9  → ✅ DONE

  Summary: 1 complete, 2 in progress, 980 not started
```

#### 14. Set auth flag and auto-skip

```
$ python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" NO

Set 'requires auth parity test' = NO and 'auth parity test passes' = N/A for 'Cisco Spark'.
```

When you later reach the `param parity test passes` step and mark it as passed, `auth parity test passes` is automatically skipped:

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "param parity test passes"

✅ 'param parity test passes' marked as passed for 'Cisco Spark'.
  Auto-skipped 'auth parity test passes' (flag=NO).
  Next step: code reviewed
```

#### 15. List integrations at a specific step

```
$ python3 connectus/workflow_state.py at-step "wrote code"

Integrations currently at step 'wrote code' (3):
  - Cisco Spark
  - Abnormal Security
  - CrowdStrike Falcon
```

Note, this folder should not be merged to master.
## Authentication Type Catalog

Each integration's authentication parameters are classified by the **actual
HTTP authentication mechanism** used, not by the XSOAR widget type.  Each auth
type is also tagged as **STATIC** or **DYNAMIC** based on its credential
lifecycle.

### Static vs Dynamic Credentials

| Lifecycle | Meaning |
|---|---|
| **STATIC** | The credentials themselves are sent directly with each request (API key in header, basic auth, bearer token). They don't change or expire (or expire very slowly). |
| **DYNAMIC** | The credentials are used to *obtain* a temporary access token from an auth endpoint. The actual API calls use the temporary token. Examples: OAuth flows, managed identity, any integration that calls a `/token` or `/auth` endpoint first. |

### Auth Type Enum Reference

| Auth Type Enum | Lifecycle | Description |
|---|---|---|
| `BASIC_AUTH` | STATIC | Basic Authentication — username:password sent as Base64 in Authorization header (or used directly in request body). STATIC. |
| `BEARER_TOKEN` | STATIC | Bearer Token — a token/key sent in Authorization: Bearer header or as a query/header param. STATIC. |
| `API_KEY` | STATIC | API Key — a key sent as a header (e.g., x-api-key), query parameter, or in request body. STATIC. |
| `OAUTH_CLIENT_CREDENTIALS` | DYNAMIC | OAuth 2.0 Client Credentials — client_id + client_secret exchanged for an access token via token endpoint. DYNAMIC. |
| `OAUTH_AUTH_CODE` | DYNAMIC | OAuth 2.0 Authorization Code — involves redirect_uri, auth_code, client_id, client_secret. DYNAMIC. |
| `OAUTH_DEVICE_CODE` | DYNAMIC | OAuth 2.0 Device Code flow. DYNAMIC. |
| `CERTIFICATE` | STATIC | Certificate/mTLS — client certificate + private key for mutual TLS. STATIC. |
| `AWS_SIGNATURE` | STATIC | AWS Signature V4 — access_key + secret_key used to sign requests. STATIC. |
| `MANAGED_IDENTITY` | DYNAMIC | Azure/GCP Managed Identity — no user credentials, identity from cloud platform. DYNAMIC. |
| `HMAC` | STATIC | HMAC-based signing — a secret key used to compute HMAC signatures on requests. STATIC. |
| `NONE` | STATIC | No authentication required. |

### How to Read the CSV Columns

| Column | Description |
|---|---|
| **assignee** | Who is working on this integration (first column) |
| **Integration Name** | Display name of the integration |
| **Support Level** | `xsoar`, `partner`, or `community` |
| **Provider** | The vendor / author of the pack |
| **Auth Types** | Pipe-separated list of auth type enums, e.g. `BASIC_AUTH \| OAUTH_CLIENT_CREDENTIALS` |
| **Auth Credential Lifecycle** | `STATIC`, `DYNAMIC`, or `STATIC + DYNAMIC` (if multiple auth types with different lifecycles) |
| **Auth Requirement** | Shows which auth types are required vs. optional. Examples: `REQUIRED(BASIC_AUTH)`, `CHOICE(API_KEY, OAUTH_CLIENT_CREDENTIALS)`, `REQUIRED(BASIC_AUTH) + OPTIONAL(CERTIFICATE)` |
| **Auth Params** | Semicolon-separated list of individual parameters, each tagged: `param_name[AUTH_TYPE](typeN,required/optional)` |

#### Requirement Semantics

- **REQUIRED(X)** — Auth type X must be configured.
- **OPTIONAL(X)** — Auth type X can optionally be configured.
- **CHOICE(X, Y)** — The integration has an auth-type selector; the user picks one of X or Y.
- **REQUIRED(X) + OPTIONAL(Y)** — X is mandatory, Y is an additional optional method.

---

## Workflow State Machine (`workflow_state.py`)

The `workflow_state.py` script manages the workflow tracking columns (columns 7–16) in `integrations_report.csv`. It acts as a **state machine** where each integration progresses through ordered steps, and is designed to be used by both humans and AI agents.

### Workflow Columns

| # | Column | Type | Description |
|---|--------|------|-------------|
| 0 | `assignee` | Free text | Who is working on this integration |
| 7 | `script inputs` | Free text (JSON) | The inputs/arguments for the script |
| 8 | `generated manifest` | Checkpoint ✅ | Manifest YAML has been generated |
| 9 | `wrote code` | Checkpoint ✅ | Python code has been written |
| 10 | `validations passed` | Checkpoint ✅ | `demisto-sdk validate` passes |
| 11 | `unit tests passed` | Checkpoint ✅ | Unit tests pass |
| 12 | `param parity test passes` | Checkpoint ✅ | Parameter parity test passes |
| 13 | `requires auth parity test` | Flag | `YES`, `NO`, or `N/A` |
| 14 | `auth parity test passes` | Checkpoint ✅ | Auth parity test passes (auto `N/A` if flag is `NO`) |
| 15 | `code reviewed` | Checkpoint ✅ | Code review completed |
| 16 | `code merged` | Checkpoint ✅ | Code merged to branch |

### Rules

1. **Explicit step naming** — You must explicitly name the step you are marking as passed via `markpass`. There is no general "advance" command.
2. **Sequential order** — Checkpoint columns 8–16 must be completed in order. You cannot mark "unit tests passed" before "wrote code" is done. The script will reject the attempt and tell you what the current step is.
3. **Script inputs prerequisite** — Column 7 (`script inputs`) must be set (valid JSON) before you can mark `generated manifest` as passed. Use `set-inputs` to provide it.
4. **Non-checkpoint correction** — If you try to `markpass` a non-checkpoint step (like `script inputs` or `requires auth parity test`), the script tells you the correct command to use instead.
5. **Fail & reset** — When a step fails, use `fail` to reset that step **and all subsequent steps**.
6. **Reset to stage** — Use `reset-to` to go back to a specific stage, clearing it and everything after it.
7. **Auth parity flag** — Column 13 is a flag, not a checkpoint. When set to `NO` or `N/A`, column 14 is automatically set to `N/A` and skipped.

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

68 tests covering: `is_checked`, `get_current_step`, `get_step_index`, `reset_from_step`, `markpass_step` (including non-checkpoint rejection, prerequisite enforcement, sequential enforcement, auth parity cases, full workflow), `find_row`, `format_status`, `format_dashboard_row`, round-trip scenarios, edge cases, and assignee handling.

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
  Auth Types:    BEARER_TOKEN

  Workflow Progress:
  ----------------------------------------
    script inputs                  : (not set)
    generated manifest             : ⬜
    wrote code                     : ⬜
    validations passed             : ⬜
    unit tests passed              : ⬜
    param parity test passes       : ⬜
    requires auth parity test      : (not set)
    auth parity test passes        : ⬜
    code reviewed                  : ⬜
    code merged                    : ⬜

  ➡️  Current step: generated manifest
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

#### 5. Mark steps as passed (sequential)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "generated manifest"

✅ 'generated manifest' marked as passed for 'Cisco Spark'.
  Next step: wrote code
```

#### 6. Try to skip ahead (rejected)

```
$ python3 connectus/workflow_state.py markpass "Cisco Spark" "unit tests passed"

ERROR: Cannot mark 'unit tests passed' as passed — you are not up to that step yet.
  Current step: 'wrote code'
  Prior step 'wrote code' is not yet complete.
```

#### 7. Try to markpass a non-checkpoint step (corrected)

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

#### 8. Continue marking steps

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

#### 9. Fail a step (resets it and everything after)

```
$ python3 connectus/workflow_state.py fail "Cisco Spark" "validations passed"

Reset 'validations passed' and 5 subsequent step(s) for 'Cisco Spark'.
  Current step is now: validations passed
```

#### 10. Reset to a specific stage

```
$ python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote code"

Reset to 'wrote code' for 'Cisco Spark'.
  Cleared 'wrote code' and 7 subsequent step(s).
  Current step is now: wrote code
```

#### 11. Check status after partial progress

```
$ python3 connectus/workflow_state.py status "Cisco Spark"

============================================================
  Cisco Spark
============================================================
  Assignee:      (unassigned)
  Support Level: xsoar
  Provider:      Cisco
  Auth Types:    BEARER_TOKEN

  Workflow Progress:
  ----------------------------------------
    script inputs                  : {"bot_token": "str"}
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

#### 12. Dashboard view (multiple integrations)

```
$ python3 connectus/workflow_state.py dashboard

================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration                                   Progress   Step   → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [█░░░░░░░] 1/8  → wrote code
  GLPI                                          [██████░░] 6/8  → code reviewed
  Wiz                                           [████████] 8/8  → ✅ DONE

  Summary: 1 complete, 2 in progress, 980 not started
```

#### 13. Set auth flag and auto-skip

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

#### 14. List integrations at a specific step

```
$ python3 connectus/workflow_state.py at-step "wrote code"

Integrations currently at step 'wrote code' (3):
  - Cisco Spark
  - Abnormal Security
  - CrowdStrike Falcon
```

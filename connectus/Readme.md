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
| 7 | `script inputs` | Free text | The inputs/arguments for the script |
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

1. **Sequential order** — Checkpoint columns 8–16 must be completed in order. You cannot mark "unit tests passed" before "wrote code" is done.
2. **Fail & reset** — When a step fails (e.g., unit tests break after a code change), use `fail` to reset that step **and all subsequent steps**. This forces the workflow back to the failed step.
3. **Auth parity flag** — Column 13 is a flag, not a checkpoint. When set to `NO` or `N/A`, column 14 is automatically set to `N/A` and skipped during advancement.
4. **Script inputs** — Column 7 is free text and is not part of the sequential checkpoint chain.

### CLI Commands

```bash
# Show status of an integration
python3 connectus/workflow_state.py status "Cisco Spark"

# Show all integrations with any progress
python3 connectus/workflow_state.py status-all

# Compact dashboard with progress bars
python3 connectus/workflow_state.py dashboard

# Set free-text script inputs
python3 connectus/workflow_state.py set-inputs "Cisco Spark" "api_key, base_url"

# Advance to next step (mark current step as done)
python3 connectus/workflow_state.py advance "Cisco Spark"

# Mark a specific step as done
python3 connectus/workflow_state.py complete "Cisco Spark" "wrote code"

# Fail a step (resets it + all subsequent steps)
python3 connectus/workflow_state.py fail "Cisco Spark" "unit tests passed"

# Set the auth parity flag
python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" YES

# Reset all workflow columns
python3 connectus/workflow_state.py reset "Cisco Spark"

# List integrations at a specific step
python3 connectus/workflow_state.py at-step "wrote code"

# List all integration names
python3 connectus/workflow_state.py list
```

### Programmatic API (for AI agents / other scripts)

The script exposes three functions that can be imported and called directly:

```python
from connectus.workflow_state import (
    get_integration_status,
    advance_integration,
    fail_integration_step,
)

# Get status as a dict
status = get_integration_status("Cisco Spark")
# Returns: {name, current_step, workflow, completed_steps, total_steps, progress_pct, all_complete}

# Advance to next step
result = advance_integration("Cisco Spark")
# Returns: {message, completed_step, current_step}

# Fail a step and reset subsequent ones
result = fail_integration_step("Cisco Spark", "unit tests passed")
# Returns: {message, current_step}
```

### Example: Dashboard Output

```
================================================================================
  WORKFLOW DASHBOARD
================================================================================
  Integration                                   Progress   Step   → Current Step
  ---------------------------------------------------------------------------
  Cisco Spark                                   [████░░░░] 4/8  → unit tests passed
  GLPI                                          [██████░░] 6/8  → code reviewed
  Wiz                                           [████████] 8/8  → ✅ DONE

  Summary: 1 complete, 2 in progress, 980 not started
```

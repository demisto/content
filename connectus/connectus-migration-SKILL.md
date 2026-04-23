---
name: connectus-migration
description: This skill should be used when migrating integrations to connectus
---

# ConnectUs Migration Skill

## Overview

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows a **10-step workflow state machine** tracked in `connectus/integrations_report.csv` via the `connectus/workflow_state.py` CLI tool.

## Critical Rules

1. **NEVER edit `connectus/integrations_report.csv` directly.** All CSV modifications MUST go through `connectus/workflow_state.py` CLI commands.
2. **Follow the workflow steps sequentially.** You cannot skip ahead — the state machine enforces ordering.
3. **Always check status first** before doing any work on an integration.
4. **Use `execute_command` to run all workflow_state.py commands** from the workspace root.
5. If a step does not pass, such as unit tests passing other any other step, it might be because a previous step was not done well and you should go back to it.

## Linked Files

- `connectus/Readme.md` — Full reference for auth types, CSV columns, and workflow walkthrough
- `connectus/workflow_state.py` — The state machine CLI (source of truth for workflow)
- `connectus/integrations_report.csv` — The tracking spreadsheet (DO NOT EDIT DIRECTLY)

## Step 0: Identify the Integration

When the user asks to migrate an integration, first identify it:

```bash
# List all available integrations
python3 connectus/workflow_state.py list

# Check current status
python3 connectus/workflow_state.py status "<Integration Name>"
```

The status output shows:
- **Assignee** — who is working on it
- **Support Level** — `xsoar`, `partner`, or `community`
- **Provider** — the vendor
- **Auth Types** — authentication mechanisms used
- **Workflow Progress** — which steps are done, which remain
- **Current step** — what to work on next

If the integration has no assignee, set one:

```bash
python3 connectus/workflow_state.py set-assignee "<Integration Name>" "<Name>"
```

## Workflow Steps

### Step 1: Set Script Inputs (column 7)

Before any code generation, you must define the script inputs as valid JSON. This is a prerequisite for all subsequent steps.

```bash
python3 connectus/workflow_state.py set-inputs "<Integration Name>" '<JSON>'
```

The JSON should describe the parameters the integration needs. Derive these from the **Auth Params** column in the status output and from examining the integration's existing YAML configuration.

**Auth Params format:** `param_name[AUTH_TYPE](typeN,required/optional)` separated by semicolons.

Example: For an integration with `credentials[BASIC_AUTH](type9,required)`:
```bash
python3 connectus/workflow_state.py set-inputs "MyIntegration" '{"credentials": {"type": "type9", "required": true, "auth_type": "BASIC_AUTH"}}'
```

**Validation:** The command rejects invalid JSON and tells you the parse error.

### Step 2: Generate Manifest (column 8)

Generate the ConnectUs manifest YAML for the integration. Once generated and verified:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "generated manifest"
```

### Step 3: Write Code (column 9)

Write the Python integration code. Follow the patterns in `Templates/Integrations/` and the project's `AGENTS.md` rules:

- Import `demistomock as demisto` at the top
- Import `from CommonServerPython import *`
- Use `demisto.params()` for configuration, `demisto.args()` for command arguments
- Use `CommandResults` with `return_results()`
- Use `return_error()` for user-facing errors
- Use `demisto.debug()` / `demisto.info()` for logging, never `print()`

When code is written:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "wrote code"
```

### Step 4: Validations Passed (column 10)

Run `demisto-sdk validate` on the integration:

```bash
demisto-sdk validate -i Packs/<PackName>/Integrations/<IntegrationName>/
```

If validation passes:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "validations passed"
```

If validation fails, fix the issues and retry. If you need to reset:

```bash
python3 connectus/workflow_state.py fail "<Integration Name>" "validations passed"
```

### Step 5: Unit Tests Passed (column 11)

Run unit tests via demisto-sdk pre-commit (which runs in Docker):

```bash
demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When tests pass:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "unit tests passed"
```

### Step 6: Param Parity Test Passes (column 12)

Run the parameter parity test to verify the ConnectUs integration's parameters match the original:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "param parity test passes"
```

### Step 7: Auth Parity Flag (column 13)

This is a **flag**, not a checkpoint. Set it based on whether the integration requires auth parity testing:

```bash
# If auth parity testing is needed
python3 connectus/workflow_state.py set-auth-flag "<Integration Name>" YES

# If NOT needed (e.g., NONE auth type)
python3 connectus/workflow_state.py set-auth-flag "<Integration Name>" NO

# If not applicable
python3 connectus/workflow_state.py set-auth-flag "<Integration Name>" N/A
```

**Important:** When set to `NO` or `N/A`, the next step (auth parity test passes) is automatically set to `N/A` and skipped.

### Step 8: Auth Parity Test Passes (column 14)

Only relevant if the auth flag is `YES`. Run the auth parity test to verify authentication works identically:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "auth parity test passes"
```

If the flag was `NO` or `N/A`, this step is auto-skipped.

### Step 9: Code Reviewed (column 15)

After code review is complete:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "code reviewed"
```

### Step 10: Code Merged (column 16)

After the code is merged to the branch:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "code merged"
```

## Error Recovery Commands

### Fail a step (resets it and all subsequent steps)

```bash
python3 connectus/workflow_state.py fail "<Integration Name>" "<step name>"
```

### Reset to a specific stage

```bash
python3 connectus/workflow_state.py reset-to "<Integration Name>" "<step name>"
```

### Reset all workflow columns

```bash
python3 connectus/workflow_state.py reset "<Integration Name>"
```

## Dashboard and Batch Commands

```bash
# See all integrations with progress
python3 connectus/workflow_state.py dashboard

# See all integrations at a specific step
python3 connectus/workflow_state.py at-step "<step name>"

# See all integrations with any progress
python3 connectus/workflow_state.py status-all

# See all integrations assigned to a specific person
python3 connectus/workflow_state.py list-by-assignee "<assignee name>"
```

## Auth Type Reference

When analyzing an integration's authentication, use these enum values:

| Auth Type Enum | Lifecycle | Description |
|---|---|---|
| `BASIC_AUTH` | STATIC | Username:password as Base64 in Authorization header |
| `BEARER_TOKEN` | STATIC | Token in Authorization: Bearer header |
| `API_KEY` | STATIC | Key as header, query param, or request body |
| `OAUTH_CLIENT_CREDENTIALS` | DYNAMIC | client_id + client_secret exchanged for access token |
| `OAUTH_AUTH_CODE` | DYNAMIC | Redirect URI + auth code + client_id + client_secret |
| `OAUTH_DEVICE_CODE` | DYNAMIC | Device code flow |
| `CERTIFICATE` | STATIC | Client certificate + private key for mTLS |
| `AWS_SIGNATURE` | STATIC | AWS Signature V4 signing |
| `MANAGED_IDENTITY` | DYNAMIC | Azure/GCP managed identity |
| `HMAC` | STATIC | HMAC-based request signing |
| `NONE` | STATIC | No authentication |

**STATIC** = credentials sent directly with each request, don't change.
**DYNAMIC** = credentials used to obtain a temporary token first.

## Auth Requirement Semantics

- **REQUIRED(X)** — Auth type X must be configured
- **OPTIONAL(X)** — Auth type X can optionally be configured
- **CHOICE(X, Y)** — User picks one of X or Y
- **REQUIRED(X) + OPTIONAL(Y)** — X is mandatory, Y is additional/optional

## Mode Switching Guidance

Different workflow steps are best handled in different modes:

| Step | Recommended Mode |
|------|-----------------|
| Analyzing auth types, understanding integration | Ask |
| Planning script inputs, designing manifest | Architect |
| Writing integration code, unit tests | Code |
| Fixing validation/test failures | Debug |
| Full migration lifecycle coordination | Orchestrator |

When switching modes, the skill will be re-loaded automatically if the user's request matches the skill trigger.

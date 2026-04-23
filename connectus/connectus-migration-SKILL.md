---
name: connectus-migration
description: This skill should be used when migrating integrations to connectus
---

# ConnectUs Migration Skill

## Overview

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows an **11-step workflow** tracked in `connectus/integrations_report.csv` via the `connectus/workflow_state.py` CLI tool. Step 1 (Verify Auth Classification) is a manual pre-check; steps 2–11 are tracked by the state machine.

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
- **Auth Class** — authentication class and detail
- **Workflow Progress** — which steps are done, which remain
- **Current step** — what to work on next

If the integration has no assignee, set one:

```bash
python3 connectus/workflow_state.py set-assignee "<Integration Name>" "<Name>"
```

## Workflow Steps

### Step 1: Verify Auth Classification

**Before starting any migration work**, manually verify that the Auth Class and Auth Detail for this integration are correct. The automated classification was done by analyzing YML param metadata (widget types), which produces systematic errors that must be caught before proceeding.

#### Why This Step Exists

The automated classifier has known blind spots:

| Scenario | Classifier Output | Likely Correct Value |
|---|---|---|
| `type=9` (credentials widget) used for OAuth2 client_credentials flow | `Plain` | `OAuth2ClientCreds` |
| `type=9` (credentials widget) used as static API key | `Plain` | `APIKey` |
| `type=4` (encrypted) param that is an OAuth client secret | `APIKey` | `OAuth2ClientCreds` |
| JWT signing with private keys | `Plain` or `APIKey` | `OAuth2JWT` |
| Old `type=4` + new `type=9` params for the same credential (one hidden/deprecated) | `CHOICE(APIKey, Plain)` | Single mechanism (e.g., `APIKey` or `Plain`) |
| OAuth/JWT flows detected in code but not mapped to params | Missing from Auth Class | Should be included |

#### Procedure

1. **Check the current Auth Class** from the status output:

   ```bash
   python3 connectus/workflow_state.py status "<Integration Name>"
   ```

2. **Read the integration's YML** — open the `configuration` section and identify all auth-related params:

   - `type: 9` — credentials widget (username + password pair)
   - `type: 4` — encrypted text field
   - `type: 14` — certificate/key text
   - `hiddenusername: true` — hides the username field (often means API key, not user/pass)
   - `display` / `displaypassword` — labels that reveal the actual credential type

   **Pay special attention to hidden and deprecated params:**
   - Params with `hidden: true` are excluded from the classification but may still be used in code. Check whether they represent an old input path for the same credential (e.g., an old `type=4` param replaced by a new `type=9` param).
   - Params with `deprecated: true` or names containing `_deprecated` should be ignored entirely — they are no longer functional.
   - If a hidden param and a visible param carry the same credential (old/new migration), the classification should reflect only the visible param's mechanism, **not** `CHOICE` between two types.

3. **Read the integration's Python code** to understand the actual auth flow. Search for these patterns:

   - **OAuth2 Client Credentials**: `grant_type.*client_credentials`, `client_credentials`, `/oauth2/token`, `MicrosoftClient(`
   - **OAuth2 Authorization Code**: `authorization_code`, `redirect_uri`, `oauth-start`, `oauth-complete`
   - **OAuth2 JWT Bearer**: `jwt.encode`, `urn:ietf:params:oauth:grant-type:jwt-bearer`, `ServiceAccountCredentials`, `google.auth`
   - **API Key**: `X-API-Key`, `apikey` header, `api_key` query param
   - **Basic Auth**: `requests.auth.HTTPBasicAuth`, `auth=(username, password)`
   - **Bearer Token**: `Authorization: Bearer`, `Bearer {token}`

4. **Compare the code's actual auth mechanism against the CSV classification.** Common corrections:

   - If a `type=9` `credentials` param is used to carry OAuth2 client ID + secret → change from `Plain(credentials)` to `OAuth2ClientCreds(credentials)`
   - If a `type=9` param with `hiddenusername: true` carries a static API key → change from `Plain(credentials)` to `APIKey(credentials)`
   - If `type=4` params named `client_secret` or `enc_key` are OAuth secrets → change from `APIKey(client_secret)` to `OAuth2ClientCreds(client_secret)`
   - If the code does JWT signing → ensure `OAuth2JWT` is in the Auth Class
   - If old `type=4` (hidden) and new `type=9` (visible) params exist for the same credential → it's not `CHOICE`, it's a single mechanism; classify based on the visible param only

5. **If corrections are needed**, edit the Auth Class and Auth Detail columns directly in `connectus/integrations_report.csv`. These are data columns (not managed by `workflow_state.py`).

#### Auth Type Reference

See `connectus/Readme.md` for the full Auth Type definitions:

| Value | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API Key, HMAC, and similar static secret mechanisms |
| `Plain` | Plain text fields: username/password, basic auth, bearer tokens, AWS credentials, certificates |
| `NoneRequired` | No authentication needed |

### Step 2: Set Script Inputs (column 7)

Before any code generation, you must define the script inputs as valid JSON. This is a prerequisite for all subsequent steps.

```bash
python3 connectus/workflow_state.py set-inputs "<Integration Name>" '<JSON>'
```

The JSON should describe the parameters the integration needs. Derive these from the **Auth Class** and **Auth Detail** columns in the status output and from examining the integration's existing YAML configuration.

- **Auth Class** column — contains a two-part format: `Type(params) | Type2(params) — EXPR`
- **Auth Detail** column — contains JSON with keys: `auth_types`, `config`, `params`, `notes`

Example: For an integration with Auth Class `Plain(credentials) — REQUIRED`:
```bash
python3 connectus/workflow_state.py set-inputs "MyIntegration" '{"credentials": {"type": "type9", "required": true, "auth_class": "Plain"}}'
```

**Validation:** The command rejects invalid JSON and tells you the parse error.

### Step 3: Generate Manifest (column 8)

Generate the ConnectUs manifest YAML for the integration. Once generated and verified:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "generated manifest"
```

### Step 4: Write Code (column 9)

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

### Step 5: Validations Passed (column 10)

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

### Step 6: Unit Tests Passed (column 11)

Run unit tests via demisto-sdk pre-commit (which runs in Docker):

```bash
demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When tests pass:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "unit tests passed"
```

### Step 7: Param Parity Test Passes (column 12)

Run the parameter parity test to verify the ConnectUs integration's parameters match the original:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "param parity test passes"
```

### Step 8: Auth Parity Flag (column 13)

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

### Step 9: Auth Parity Test Passes (column 14)

Only relevant if the auth flag is `YES`. Run the auth parity test to verify authentication works identically:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "auth parity test passes"
```

If the flag was `NO` or `N/A`, this step is auto-skipped.

### Step 10: Code Reviewed (column 15)

After code review is complete:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "code reviewed"
```

### Step 11: Code Merged (column 16)

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

## Auth Class Reference

When analyzing an integration's authentication, use these enum values:

| Auth Class Enum | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API key authentication (header or query parameter) |
| `Plain` | Simple credentials (username/password, token, etc.) |
| `NoneRequired` | No authentication required |

## Auth Requirement Semantics

- **REQUIRED(X)** — Auth type X must be configured
- **OPTIONAL(X)** — Auth type X can optionally be configured
- **CHOICE(X, Y)** — User picks one of X or Y
- **REQUIRED(X) + OPTIONAL(Y)** — X is mandatory, Y is additional/optional

## Mode Switching Guidance

Different workflow steps are best handled in different modes:

| Step | Recommended Mode |
|------|-----------------|
| Analyzing auth class, understanding integration | Ask |
| Planning script inputs, designing manifest | Architect |
| Writing integration code, unit tests | Code |
| Fixing validation/test failures | Debug |
| Full migration lifecycle coordination | Orchestrator |

When switching modes, the skill will be re-loaded automatically if the user's request matches the skill trigger.

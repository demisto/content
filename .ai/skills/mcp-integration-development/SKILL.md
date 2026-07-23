# MCP Integration Developer

| Section    | Purpose |
|------------|---------|
| SETUP      | Verify workspace is the `content` repository via `content-descriptor.json` and `poetry run` prefix |
| PURPOSE    | Generate complete, production-ready MCP integration packs from user-provided specifications and input |
| WORKFLOW   | Gather requirements & research → plan → Python implementation → Python review → YAML configuration → YAML review → unit tests → documentation & release notes → final refinement |
| BEHAVIOR   | Auth type handling, naming conventions, MCPApiModule usage, code organization, error handling, YAML constraints, vendor-specific parameter design |
| FORMAT     | Pack structure, Python patterns, YAML schema, unit test structure, documentation templates |
| VALIDATION | Per-phase checklists: structure, Python review, YAML review, test quality, metadata, final review |
| EXAMPLES   | Reference implementations from existing MCP packs |

---

## SETUP

**CRITICAL: WORKSPACE VERIFICATION**

- Verify `content-descriptor.json` exists at workspace root (unique to `content` repository)
- If not found, stop and inform user to open the `content` repository
- MUST use `poetry run` prefix for all `demisto-sdk` commands
- All file paths are relative to workspace root (e.g., `Packs/GitHubMCP/...`)

---

## PURPOSE

- Generate complete, production-ready MCP (Model Context Protocol) integration packs, or enhance existing ones
- Each pack connects to an external MCP server and exposes its tools as agentic system actions
- All packs MUST follow patterns established by existing MCP packs in the repository
- Do not invent new yml/json fields or sections that are not present in any of the reference packs
- The shared `MCPApiModule` handles all MCP protocol operations — integrations MUST NOT reimplement MCP logic
- **Source of Truth**: User-provided specifications or direct input
- **Mandatory Review**: Python and YAML reviews are NOT optional — MUST complete before proceeding

---

## WORKFLOW

### 1. Information Gathering & Research

**Gather requirements for the integration:**

- Identify or ask the user for: the vendor name, MCP server URL, authentication method, and any vendor-specific configuration parameters or toolsets.

**Vendor Documentation:**

- Do NOT fetch vendor documentation independently. All vendor-specific values MUST come from user-provided specifications, user input, or user-provided documentation

**Reference Packs:**

- `Packs/GenericMCP/` — Full-featured generic integration (all auth types, validation)
- `Packs/AtlassianCloudMCP/` — Dynamic Client Registration, hardcoded URL
- `Packs/CloudFlareMCP/` — Server selection dropdown, conditional auth, URL templates
- `Packs/GitHubMCP/` — Bearer token, custom headers, toolset/readonly toggles
- `Packs/ApiModules/Scripts/MCPApiModule/MCPApiModule.py` — Shared module API

**Existence Check**: Check if a pack with this vendor name already exists under `Packs/`. If found, ask: (a) Update existing, (b) Create new.

- **If "Update existing"**: Read the existing pack's `.py`, `.yml`, `_test.py`, `_description.md`, `README.md`, and `pack_metadata.json` files. Identify what needs changing. Same phased workflow applies (Python → Python Review → YAML → YAML Review → Tests → Docs), modifying existing files. Release notes MUST be generated via `poetry run demisto-sdk update-release-notes -i Packs/<PackName>` and wrapped in `<~PLATFORM>`.
- **If "Create new"**: Proceed with full pack generation.

### 2. Planning & Approval

1. Present a plan including:
   - Pack name and integration name
   - Auth type and configuration parameters
   - File list to be generated
   - Vendor-specific customizations
   - Reference packs for each aspect
2. Get explicit user approval before generating files.

### 3. Phase 1: Python Implementation

1. **Enhancement**: Read the existing pack's `.py` file. Identify what needs changing. / **New**: Read reference packs' `.py` files.
2. Analyze how the `Client` class from MCPApiModule is used.
3. Generate (new) or modify (enhancement) the Python implementation:
   - Define constants: `BASE_URL`, `AUTH_TYPE`, `COMMAND_PREFIX`, `SERVER_NAME`
   - Extract parameters from `demisto.params()` based on auth type
   - Implement `validate_required_params()` if the integration has configurable auth
   - Create `Client` instance with appropriate parameters
   - Implement command routing in `async def main()` — MUST implement exactly the commands defined in "Mandatory Commands Specification" (see BEHAVIOR section). MUST NOT add any commands beyond those specified.
4. Present Python implementation

### 4. Phase 1.5: Python Review

This review should be performed in a clean context to ensure an unbiased review:

- If possible, delegate this review to a fresh agent or task. Ensure these instructions (including the review checklist below) are referenced in the new context.
- Otherwise, perform the review directly in the current session. Focus heavily on objectivity and strictly apply the checklist below without bias.

**Minimal, non-leading instruction to start the review context (if delegating):**
Include ONLY:

  1. Reference to these instructions.
  2. "Perform a Phase 1.5 Python Review."
  3. The file path: `Packs/<Vendor>MCP/Integrations/<Vendor>MCP/<Vendor>MCP.py`
  4. "Read the file, apply the Phase 1.5 Python Review checklist from your instructions, and report all findings."

**Do NOT include** auth type, server URL, command list, expected parameters, or implementation details that would bias the reviewer.

**The reviewing agent MUST check:**

1. Mandatory commands match specification; `else: raise NotImplementedError(...)` present
2. Code review: Async pattern, Client usage, error handling (BaseException, extract_root_error_message), client closed in finally, no reimplemented MCP logic
3. Parameters: Correct extraction patterns, match auth type, no unused/missing params, sensible defaults, boolean params use argToBoolean()
4. Integration constants: BASE_URL valid and correctly formatted, AUTH_TYPE uses correct AuthMethods enum, COMMAND_PREFIX follows kebab-case, SERVER_NAME is human-readable, no placeholder values, no trailing slashes unless required
5. Implementation consistency: Server URL constant properly defined and used, auth type consistent throughout, custom headers properly parsed and passed to Client, all vendor-specific parameters are used
6. Auth type verification: Compare parameter extraction against auth type requirements
7. Present review results

**After the review subtask completes:** Read the review findings. IF issues found: Fix immediately, then re-delegate review. MUST NOT proceed to Phase 2 until all issues are resolved.

### 5. Phase 2: YAML Configuration

1. **Enhancement**: Read the existing pack's `.yml` file. Identify what needs changing. / **New**: Read reference packs' `.yml` files.
2. Generate (new) or modify (enhancement) the YAML configuration:
   - Set `category`, `provider`, `sectionorder`
   - Define `commonfields` with correct `id`
   - Define `configuration` parameters — MUST match exactly what the Python file reads from `demisto.params()`:
     - Every `params.get("X")` call in Python MUST have a corresponding `configuration` entry with `name: X` in YAML
     - Every `configuration` entry in YAML MUST be read by the Python file — no orphan parameters
   - Define commands using **exactly** the definitions from "Mandatory Commands Specification" (see BEHAVIOR section). MUST NOT add any commands beyond those specified.
   - Set `script.mcp: true`, correct docker image, correct `fromversion`
3. Present YAML configuration

### 6. Phase 2.5: YAML Review (MANDATORY — Clean Context Review)

This review should be performed in a clean context to ensure an unbiased review:

- If possible, delegate this review to a fresh agent or task. Ensure these instructions (including the review checklist below) are referenced in the new context.
- Otherwise, perform the review directly in the current session. Focus heavily on objectivity and strictly apply the checklist below without bias.

**Minimal, non-leading instruction to start the review context (if delegating):**
Include ONLY:

  1. Reference to these instructions.
  2. "Perform a Phase 2.5 YAML Review."
  3. The file paths: Python: `Packs/<Vendor>MCP/Integrations/<Vendor>MCP/<Vendor>MCP.py` and YAML: `Packs/<Vendor>MCP/Integrations/<Vendor>MCP/<Vendor>MCP.yml`
  4. "Read both files, apply the Phase 2.5 YAML Review checklist from your instructions, and report all findings."

**Do NOT include** auth type, server URL, command list, expected parameters, or implementation details that would bias the reviewer.

**The reviewing agent MUST check:**

1. Mandatory commands match specification; `test-module` does NOT appear in YAML commands (it is a built-in)
2. YAML review: Configuration parameters match auth type requirements, `script.mcp: true` is set, docker image and fromversion are correct, descriptions are clear and don't include "Options:" when using `auto: PREDEFINED`
3. Python↔YAML parameter parity (CRITICAL): List every `params.get("X")` call in Python — each MUST have a matching `configuration` entry with `name: X` in YAML. List every `configuration` entry in YAML — each MUST be read by Python via `params.get()`. No orphan parameters. Parameter types in YAML MUST match how Python uses them.
4. Python↔YAML command argument parity (CRITICAL): For each command, list every `args["X"]` or `args.get("X")` call in Python — each MUST have a matching `arguments` entry with `name: X` in YAML. For each command, list every `arguments` entry in YAML — each MUST be accessed by Python. `required: true` in YAML MUST match `args["X"]` in Python; optional args MUST use `args.get("X", default)`. No orphan arguments.
5. Cross-file consistency: COMMAND_PREFIX in Python matches command names in YAML, integration name matches between `commonfields.id`, `display`, and `name`, all commands in YAML have handlers in Python, all handlers in Python have command definitions in YAML (except `test-module` which is built-in)
6. Implementation consistency: Configuration parameters are complete and consistent with Python implementation, descriptions are clear and accurately reflect the integration's purpose
7. Present review results

**After the review subtask completes:** Read the review findings. IF issues found: Fix immediately, then re-delegate review. MUST NOT proceed to Phase 3 until all issues are resolved.

### 7. Phase 3: Unit Tests

**NOTE: MUST confirm with user that Python and YAML are approved before proceeding.**

1. **Enhancement**: Read the existing pack's `_test.py` file. Update tests to cover changes. / **New**: Read reference packs' `_test.py` files.
2. Generate comprehensive tests covering:
   - `test-module` command (success for token auth, DemistoException for OAuth)
   - `list-tools` command (mock session, verify results)
   - `call-tool` command with arguments (mock session, verify tool call)
   - `call-tool` command without arguments (verify empty args handling)
   - Auth-test command (if applicable)
   - Generate-login-url command (if applicable)
   - Unknown command handling (NotImplementedError)
   - Exception handling (verify return_error called)
   - Validation tests (if `validate_required_params` exists)
3. Use `@pytest.mark.asyncio` for all async tests
4. Use `AsyncMock` for mocking async client methods
5. Follow Given/When/Then docstring pattern
6. Present tests

### 8. Phase 4: Documentation & Metadata

**NOTE: MUST confirm with user that unit tests are approved before proceeding.**

1. Generate pack-level files:
   - `pack_metadata.json` with all required fields
   - `README.md` with pack description and tools list
   - `.pack-ignore` (empty)
   - `.secrets-ignore` (vendor URLs)
2. Generate integration-level files:
   - `_description.md` with setup instructions
   - Integration `README.md`: Generate using `poetry run demisto-sdk generate-docs -i Packs/<PackName>/Integrations/<Vendor>MCP/<Vendor>MCP.yml -o Packs/<PackName>/Integrations/<Vendor>MCP`
3. **Release notes**:
   - **New packs**: MUST NOT create `ReleaseNotes/1_0_0.md` — initial version `1.0.0` does not have release notes.
   - **Enhancements**: Run `poetry run demisto-sdk update-release-notes -i Packs/<PackName>` to generate release notes, then wrap in `<~PLATFORM>`.
4. Inform user about `_image.png` requirement (72x72 PNG vendor logo)

### 9. Phase 5: Final Refinement

**CRITICAL: Git staging required for pre-commit hooks.** Pre-commit hooks skip untracked files. New files MUST be staged before running hooks.

1. **Stage new files**: `git add Packs/<PackName>/`
2. **Run pre-commit**: `poetry run demisto-sdk pre-commit -i Packs/<PackName>`
3. IF pre-commit failures: Fix issues, re-run until clean
4. **Run validate**: `poetry run demisto-sdk validate -i Packs/<PackName>`
5. IF validate failures: Fix issues, re-run until clean
6. **Unstage files**: `git restore --staged Packs/<PackName>/`
7. Final comprehensive review across all files
8. Present final summary of all generated files

---

## BEHAVIOR

### Reference Pack Patterns

| Auth Type | Relevant Packs | Key Patterns to Study |
|-----------|---------------|----------------------|
| Bearer / Token / Api-Key | GitHubMCP | Hardcoded URL, token param, custom headers |
| Dynamic Client Registration | AtlassianCloudMCP, CloudflareMCP | Auth code param, generate-login-url command |
| OAuth 2.0 Authorization Code | GenericMCP | Client ID/Secret, auth code, generate-login-url |
| OAuth 2.0 Client Credentials | GenericMCP | Client ID/Secret, scope |
| No Authorization | GenericMCP, CloudflareMCP (docs server) | No auth params needed |
| Server selection dropdown | CloudflareMCP | URL templates, conditional auth |
| Custom headers / toolsets | GitHubMCP | Vendor-specific HTTP headers, config toggles |
| Configurable (multiple auth types) | GenericMCP | Full auth type dropdown, validation |

### Auth Type Command Mapping

| Auth Type | test-module | auth-test | generate-login-url |
|-----------|------------|-----------|-------------------|
| Bearer / Token / Api-Key / Basic | Direct `test_connection()` | Not needed | Not needed |
| OAuth (any type) | Raise DemistoException → use auth-test | Required | Required |
| No Authorization | Direct `test_connection()` | Not needed | Not needed |

### Mandatory Commands Specification (CRITICAL)

Every MCP integration MUST expose exactly these commands. The command names, arguments, and behavior are **fixed and non-negotiable**.

#### 1. `test-module` (built-in, no YAML definition needed)

- **Triggered by**: Pressing the "Test" button in the integration configuration UI
- **Arguments**: None
- **Token/Bearer/Basic/Api-Key auth**: Call `await client.test_connection()` and `return_results(result)`
- **OAuth auth**: Raise `DemistoException` directing user to use `!<prefix>-auth-test` instead
- **Returns**: `"ok"` string on success (handled by `Client.test_connection()`)

#### 2. `list-tools` (hidden command)

See implementation in `Packs/GenericMCP/Integrations/GenericMCP/GenericMCP.yml` and `GenericMCP.py`. Key requirements:

- Arguments: None
- Hidden: true
- Outputs: None
- Python handler calls `await client.list_tools(SERVER_NAME)`

#### 3. `call-tool` (hidden command)

See implementation in `Packs/GenericMCP/Integrations/GenericMCP/GenericMCP.yml` and `GenericMCP.py`. Key requirements:

- Arguments: `name` (required) — The name of the tool to call; `arguments` (optional) — Parameters for the tool execution (JSON string)
- Hidden: true
- Outputs: None
- Python handler calls `await client.call_tool(args["name"], args.get("arguments", ""))`

#### 4. `<prefix>-auth-test` (OAuth only)

See implementation in `Packs/AtlassianCloudMCP/Integrations/AtlassianCloudMCP/AtlassianCloudMCP.yml` and `AtlassianCloudMCP.py`. Key requirements:

- Arguments: None
- Only include when: Auth type is OAuth (Authorization Code, Client Credentials, or Dynamic Client Registration)
- Python handler calls `await client.test_connection(auth_test=True)`

#### 5. `<prefix>-generate-login-url` (OAuth only)

See implementation in `Packs/AtlassianCloudMCP/Integrations/AtlassianCloudMCP/AtlassianCloudMCP.yml` and `AtlassianCloudMCP.py`. Key requirements:

- Arguments: None
- Only include when: Auth type is OAuth (Authorization Code, Client Credentials, or Dynamic Client Registration)
- Python handler calls `generate_login_url()` with appropriate parameters

**MUST NOT:**

- Add any other commands beyond these 3 (or 5 for OAuth)
- Change the argument names (`name`, `arguments`) or their required/optional status
- Remove `hidden: true` from `list-tools` or `call-tool`
- Add `outputs` to `list-tools` or `call-tool`
- Omit `auth-test` or `generate-login-url` when auth type is OAuth

### Naming Conventions

- **Pack/Integration name**: `<Vendor>MCP` (PascalCase)
- **COMMAND_PREFIX**: kebab-case (e.g., `github-mcp`)
- **SERVER_NAME**: Human-readable (e.g., `"GitHub MCP"`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `VENDOR_BASE_URL`)

### MCPApiModule Usage

All MCP integrations MUST use the shared `MCPApiModule`:

- **IMPORTANT** API module import must be a star import: `from MCPApiModule import *`
- Use `Client` class for all MCP operations (`test_connection`, `list_tools`, `call_tool`)
- Use `OAuthHandler` and `generate_login_url` for OAuth flows
- Use `AuthMethods` enum for auth type constants
- Use `extract_root_error_message()` for error handling
- Use `parse_custom_headers()` for custom header parsing
- Use `REDIRECT_URI` constant as default redirect URI

**MUST NOT:**

- Reimplement any MCP protocol logic
- Create custom HTTP clients for MCP communication
- Override `Client` class methods
- Duplicate functionality already in MCPApiModule

### Code Organization

**Python file structure**: Imports → Constants → Validation (if needed) → async main() → Entry point

**Code quality**: Clean main function, single responsibility, descriptive names, type hints, `# pragma: no cover` on main()

### Error Handling

Error handling MUST follow the pattern in `Packs/GenericMCP/Integrations/GenericMCP/GenericMCP.py`:

- Use `BaseException` to catch async exception groups
- Use `extract_root_error_message()` to unwrap nested exceptions
- Close client in `finally` block
- MUST NOT wrap in `try/except` just to re-raise

### Parameter Extraction Patterns

Refer to `Packs/ApiModules/Scripts/MCPApiModule/MCPApiModule.py` for supported auth types. Common patterns:

- **Token**: `params.get("token", {}).get("password")`
- **OAuth**: `params.get("oauth_credentials", {}).get("identifier")` and `params.get("oauth_credentials", {}).get("password")`
- **Basic**: `params.get("credentials", {}).get("identifier")` and `params.get("credentials", {}).get("password")`
- **Boolean**: `argToBoolean(params.get("insecure", False))`
- **Custom headers**: `parse_custom_headers(params.get("custom_headers") or "")`
- **Scope**: `params.get("scope", "")`
- **Redirect URI**: `params.get("redirect_uri", "") or REDIRECT_URI`

### YAML Configuration Rules

**Parameter types:**

| Type | Value | Usage |
|------|-------|-------|
| 0 | Short text | URLs, names, endpoints |
| 8 | Boolean | Checkboxes (insecure, readonly) |
| 9 | Credentials | Tokens, passwords, auth codes |
| 12 | Long text | Custom headers, multiline input |
| 15 | Single select | Auth type dropdown, server selection |
| 16 | Multi select | Toolset selection |

**Schema constraints:**

- `required: true` — only when parameter is always required
- MUST NOT include `required: false` (it's the default)
- `hiddenusername: true` — for credential fields that only need the password
- `advanced: true` — for optional/advanced parameters
- `section: Connect` — all MCP params go in the Connect section
- `auto: PREDEFINED` for dropdown choices — MUST NOT include "Options:" in description

### Vendor-Specific Parameter Design

When the vendor's MCP server has special configuration:

1. **Server selection** (like Cloudflare): Use `type: 15` (single select) with `options` list
2. **Toolset selection** (like GitHub): Use `type: 16` (multi select) with `options` list
3. **Read-only mode** (like GitHub): Use `type: 8` (boolean checkbox)
4. **Custom redirect URI**: Use `type: 0` with `advanced: true` and `defaultvalue`

Examine how existing packs handle these patterns and adapt to the vendor's needs.

---

## FORMAT

### Pack Directory Structure

See `Packs/GenericMCP/` for complete example structure.

### pack_metadata.json

Template: `Packs/GenericMCP/pack_metadata.json`

Key fields to customize:

- `name`: "<Vendor Display Name> MCP"
- `description`: Describe vendor integration
- `categories`: Appropriate category
- `currentVersion`: "1.0.0" for new packs

### Unit Test Pattern

Study complete implementations:

- **Token Auth**: `Packs/GitHubMCP/Integrations/GitHubMCP/GitHubMCP_test.py`
- **OAuth**: `Packs/AtlassianCloudMCP/Integrations/AtlassianCloudMCP/AtlassianCloudMCP_test.py`

**Key patterns:**

- Use `@pytest.mark.asyncio` for async tests
- Use `AsyncMock` for client methods
- Follow Given/When/Then docstring pattern
- Test: success, error, edge cases, unknown commands

### Description File Pattern

**For OAuth-based integrations**, see `Packs/AtlassianCloudMCP/Integrations/AtlassianCloudMCP/AtlassianCloudMCP_description.md` for the standard pattern.

**For token-based integrations**, see `Packs/GitHubMCP/Integrations/GitHubMCP/GitHubMCP_description.md` for vendor-specific instructions.

### Integration README

1. **Generate** using `demisto-sdk generate-docs` AFTER the YAML file is finalized and reviewed:

```
poetry run demisto-sdk generate-docs -i Packs/<PackName>/Integrations/<Vendor>MCP/<Vendor>MCP.yml -o Packs/<PackName>/Integrations/<Vendor>MCP
```

This auto-generates the `README.md` from the YAML configuration, including the configuration table, command documentation, and argument/output tables.

2. **Review and update** the generated README if additional information is needed (e.g., authentication type details, vendor-specific setup notes). MUST NOT create the README manually from scratch.

### Pack README Pattern

See `Packs/GenericMCP/README.md` for the standard template structure.

### Release Notes Pattern

**New packs (version 1.0.0):** MUST NOT create release notes. The initial version does not have a `ReleaseNotes/` directory or `1_0_0.md` file.

**Subsequent updates (1.0.1+):** Use `poetry run demisto-sdk update-release-notes -i Packs/<PackName>` to generate, then wrap with `<~PLATFORM>`:

```markdown
<~PLATFORM>

#### Integrations

##### <Vendor Display Name> MCP

- <Description of the change>.

</~PLATFORM>
```

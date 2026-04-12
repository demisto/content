# Collector Developer Mode — Rules & Specification

## Purpose

This mode generates production-ready **XSIAM Collector integrations** from scratch (0 → 1).
Every generated integration MUST follow the **HelloWorldV2** reference architecture, the
**XSIAM Collector Development Process** guidelines from Confluence, and the project-wide
coding standards defined in **AGENTS.md**.

---

## 1. Workflow

When the user asks to generate a collector, follow these steps **in order**:

### 1.1 Gather Requirements (interactive)

Ask the user for the following (do NOT guess):

| # | Question | Required | Why |
|---|----------|----------|-----|
| 1 | **Product / vendor name** (e.g. "Acme Security") | Yes | Pack name, file names, context prefix |
| 2 | **API base URL** | Yes | Client class, YML default |
| 3 | **Authentication method** (API key, Bearer token, Basic auth, OAuth2, other) | Yes | Auth handler selection |
| 4 | **Event types to collect** (e.g. "alerts", "audit_logs") | No | Only needed if the API exposes multiple event types that the user can select. Skip if the API returns a single stream or event types are fixed. |
| 5 | **API pagination style** (offset, cursor, link-header, timestamp, none) | Yes | Pagination implementation |
| 6 | **Max fetch & page size** — max events per entire run and per single API request | No | Defaults to sensible values if not specified. Ask when the API has known limits. |
| 7 | **Rate limits** (per-type or global, requests/sec or /min) | No | Retry / backoff config. Ask only if known. |
| 8 | **Does the API support filtering by time range?** (start_time / end_time params) | Yes | Fetch window logic |
| 9 | **XSIAM-only or unified (XSOAR + XSIAM)?** | Yes | Marketplace visibility, fetch-incidents vs fetch-events |
| 10 | **Pack name** (if different from product name) | No | Directory structure. Defaults to product name. |
| 11 | **Docker image** (or "default") | No | YML dockerimage field. Defaults to standard image. |
| 12 | **Design document or parameter list** — the configuration params, their sections (Connect/Collect), order, and types | Yes | YML configuration section. Do NOT guess params — they come from the design. |
| 13 | **Integration icon** (`<Name>_image.png`) | Yes | The user must provide this file. Do NOT generate or guess the image. |

Once you have answers, confirm the plan before generating any files.

### 1.2 Generate Files

Generate files in a single pack directory: `Packs/<PackName>/Integrations/<IntegrationName>/`

| File | Required | Description |
|------|----------|-------------|
| `<Name>.py` | Yes | Main integration Python code |
| `<Name>.yml` | Yes | YAML configuration (params, commands, outputs) |
| `<Name>_description.md` | Yes | Help section shown in the UI |
| `<Name>_test.py` | Yes | Unit tests with pytest |
| `<Name>_image.png` | Yes | Integration icon |
| `README.md` | Yes | Documentation with troubleshooting section |
| `test_data/*.json` | If needed | Mock JSON response files for unit tests |

### 1.3 Validate

After generation, use `demisto-sdk` (per AGENTS.md) to format and validate:
- `demisto-sdk format -i <path>` — fixes style/lint issues
- `demisto-sdk validate -i <path>` — validates against content standards

---

## 2. Python File Architecture (`<Name>.py`)

The Python file MUST follow this exact section structure (matching HelloWorldV2):

```
# Imports
# Constants
# Parameters (Pydantic model inheriting BaseParams)
# Auth & Client (Client class inheriting ContentClient)
# test-module
# fetch-events logic
# get-events command (mandatory debug command)
# Additional commands (if any)
# ExecutionConfig (inheriting BaseExecutionConfig)
# Main function & entrypoint
```

### 2.1 Imports (mandatory)

```python
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from ContentClientApiModule import *
from BaseContentApiModule import *
```

Additional standard library imports as needed (e.g., `json`, `asyncio`, `time`, `traceback`).
Use `from typing import Any` and `from pydantic import ...` as needed.

### 2.2 Constants

- Define `BASE_CONTEXT_OUTPUT_PREFIX` (e.g., `"AcmeSecurity"`).
- Define dataset config enums per event type:

```python
class EventsDatasetConfigs(str, Enum):
    VENDOR = "<vendor_name>"
    PRODUCT = "<product_name>"
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    TIME_KEY = "_time"
    SOURCE_LOG_TYPE_KEY = "source_log_type"
```

- Use `CAN_SEND_EVENTS = is_xsiam() or is_platform()` for runtime detection.
- Define test-module defaults:

```python
class TestModuleDefaults(int, Enum):
    LOOKBACK_MINUTES = 5
    MAX_EVENTS = 1
```

### 2.3 Parameters Model

- Inherit from `BaseParams`.
- Include connection params (`url`, `credentials`).
- Include fetch params (`is_fetch_events`, `first_fetch`, `max_events_fetch`).
- Include pagination params:
  - `max_fetch` — maximum total events per entire fetch run.
  - `page_size` — maximum events per single API request (page). May differ from `max_fetch`.
  - Both should have sensible defaults but be configurable by the user when needed.
- Use `Field(alias=...)` to match YML parameter names.
- Add `@property` methods for `api_key`, `first_fetch_time`, `is_fetch`, `max_fetch`.
- `first_fetch_time` should default to current time (last 1 minute) on XSIAM.
- Add `@validator` for URL cleanup (strip trailing slash).

### 2.4 Auth & Client

- Use one of the built-in `AuthHandler` subclasses when possible:
  - `APIKeyAuthHandler` — for API key in header
  - `BearerTokenAuthHandler` — for Bearer token
  - `BasicAuthHandler` — for username/password
  - You may also define a custom `AuthHandler` if the API requires a non-standard authentication flow.
- Client class should inherit from `ContentClient` when possible. If not feasible, use `BaseClient` from `CommonServerPython`.
- Client class should NOT use `demisto.*` functions — keep it pure API logic.
- One method per API endpoint.
- Use `self.get()`, `self.post()` etc. for HTTP calls.
- Include a `log_optional_diagnostic_report()` method for troubleshooting.

### 2.5 test-module

```python
def test_module(client, params) -> str:
```

- Test API connectivity (e.g., a lightweight API call).
- Do a small test fetch with `should_push=False`, using `TestModuleDefaults.LOOKBACK_MINUTES` and `TestModuleDefaults.MAX_EVENTS`.
- Catch `ContentClientAuthenticationError` and return a readable message.
- Return `"ok"` on success.

### 2.6 fetch-events

- Define a `LastRun` model (inheriting `ContentBaseModel`) with:
  - `start_time: str | None` — ISO 8601 timestamp of the last fetched event.
  - Any dedup fields needed (e.g., `last_event_ids: list[str]`).
  - A `set()` method that calls `demisto.setLastRun(...)`.

- Implement `format_as_events()` to add `_time` and `source_log_type` fields to each event.

- Implement `create_events()` using `send_events_to_xsiam()`:
  ```python
  send_events_to_xsiam(
      events=events,
      vendor=EventsDatasetConfigs.VENDOR.value,
      product=EventsDatasetConfigs.PRODUCT.value,
      client_class=ContentClient,
  )
  ```

- Implement the main fetch function with:
  - Batch fetching loop with deduplication.
  - Async push to XSIAM using `asyncio.to_thread()` for concurrent fetch + push.
  - Proper `last_run` state management — do NOT update `set_last_run` on failure (state protection per Confluence).
  - Pagination must be stateful — handle mid-way stops gracefully.

### 2.7 get-events Debug Command

Every collector MUST include a `<prefix>-get-events` command (per Confluence guidelines).
This is a manual debug command for troubleshooting connectivity and recovering missed events after outages.

**Behavior (from HelloWorldV2 pattern):**
- Does NOT call `set_last_run` — completely independent from the fetch cycle.
- Define a Pydantic args model (e.g., `GetEventsArgs`) with fields like `start_time`, `limit`, `should_push_events`, and any API-specific filters (e.g., `severity`, `event_type`).
- Validate `start_time` with `arg_to_datetime` so users can provide flexible formats (relative like "3 hours ago" or ISO 8601).
- Validate `should_push_events` against `CAN_SEND_EVENTS` — raise `ValueError` if pushing is requested on an unsupported tenant.
- Reuse the same fetch logic as `fetch-events` but with `should_push` controlled by the argument.
- Return `CommandResults` with `tableToMarkdown` for human-readable output.

**YML definition (from HelloWorldV2 pattern):**
- `should_push_events` argument with `auto: PREDEFINED`, predefined `["true", "false"]`, default `"false"`.
- `limit` argument with a sensible `defaultValue` (e.g., `"10"`).
- Description: *"Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism."*

**XSOAR visibility:** If the collector is part of an XSOAR-supported integration, mark the command as `hidden` in the YML and note in the description that it is not supported on XSOAR.

### 2.8 ExecutionConfig

- Inherit from `BaseExecutionConfig`.
- Add a `@property` for `params` returning the validated params model.
- Add a `@property` for each command's args model (e.g., `get_events_args`).
- Add a `@property` for `last_run` returning the validated last run model.

### 2.9 Main Function

```python
def main() -> None:
    execution = <Name>ExecutionConfig()
    command = execution.command
    client = None
    try:
        params = execution.params
        client = <Name>Client(params)
        match execution.command:
            case "test-module":
                return_results(test_module(client, params))
            case "fetch-events":
                last_run = execution.last_run
                next_run = fetch_events(client, last_run, ...)
                next_run.set()
            case "<prefix>-get-events":
                args = execution.get_events_args
                return_results(get_events_command(client, args))
            case _:
                raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        demisto.error(f"[Main] Failed to execute {command=}: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")
    finally:
        if client:
            client.log_optional_diagnostic_report()

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
```

---

## 3. YML File Structure (`<Name>.yml`)

### 3.1 Top-level keys

```yaml
category: Analytics & SIEM
sectionorder:
- Connect
- Collect
commonfields:
  id: <IntegrationName>
  version: -1
```

### 3.2 Configuration Parameters

- The configuration parameters, their sections (Connect/Collect), order, and types MUST come from the **design document** provided by the user. Do NOT guess or hardcode params.
- Per Confluence: **No required params in the Collect section** — use code or trigger fields instead.
- Per Confluence: `first_fetch` should be **hidden** on `marketplacev2` and `platform` (set internally to current time).
- Per Confluence: **The first key in the yml should always be the name/Display name** for quick search when collapsed.
- Per Confluence: use **trigger fields** for fields that can be hidden when not needed, to simplify customer experience.

### 3.3 Script section

The `get-events` command definition follows the pattern from Section 2.7. The script section must include:

```yaml
script:
  commands:
  - name: <prefix>-get-events
    description: "Use this command for development and debugging only..."
    arguments: [...]  # as defined in Section 2.7
  dockerimage: <docker_image>
  isfetchevents: true
  isfetchevents:xsoar: false
  runonce: false
  script: '-'
  subtype: python3
  type: python
```

### 3.4 Marketplace & Description

- `description:` should contain 1-2 lines about what the product is (per Confluence).
- Collectors should be available in `MarketplaceV2` (XSIAM) and `platform`.
- Per Confluence: for partner packs, add `supportlevelheader: xsoar` at yml root.

### 3.5 Metadata

```yaml
fromversion: 6.8.0
tests:
- No tests (auto formatted)
```

---

## 4. Description File (`<Name>_description.md`)

- The description file content should be provided by the user or taken from the design document. Ask the user to specify the exact text.
- Per Confluence: the description **only shows relevant text for the relevant marketplace**.
- Per Confluence: **troubleshooting should only be found in README**, NOT in the description file.

---

## 5. Integration Icon (`<Name>_image.png`)

The user must provide the integration icon file. Do NOT generate or guess the image. Ask the user to supply the PNG file and place it in the integration directory.

---

## 6. README File (`README.md`)

The README is auto-generated using `demisto-sdk generate-docs`. Run this after the YML and Python files are created:

```bash
demisto-sdk generate-docs -i Packs/<PackName>/Integrations/<IntegrationName>/
```

After generation, manually add a **Troubleshooting** section at the end of the README. Per Confluence, troubleshooting content belongs in the README.

---

## 7. Unit Tests (`<Name>_test.py`)

**Test coverage must be sufficient (>90%).**

### 7.1 Structure (from HelloWorldV2 pattern)

```python
import json
import pytest
from pytest_mock import MockerFixture
from CommonServerPython import ...
from <Name> import (
    <Name>Client,
    <Name>Params,
    <Name>LastRun,
    ...
)

@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture):
    mocker.patch("ContentClientApiModule.support_multithreading")

def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())
```

### 7.2 Required Tests

At minimum, include tests for:
- Credentials / params validation
- `test-module` (success and auth failure)
- `fetch-events` (first fetch, subsequent fetch, deduplication, empty response)
- `get-events` command
- Each additional command

### 7.3 Test Data

- Create `test_data/` directory with mock JSON files when needed for unit tests.
- Use `util_load_json("test_data/<file>.json")` to load test data.

---

## 8. Confluence Collector Guidelines Checklist

Before presenting the final code, verify ALL of these:

- [ ] Collector name does NOT contain "Event Collector" (unless specified in design)
- [ ] Auth errors (401/403) are logged and stop execution
- [ ] Pagination is stateful — handles mid-way stops
- [ ] `set_last_run` is NOT updated on failure (state protection)
- [ ] `get-events` debug command is implemented
- [ ] `first_fetch` defaults to current time on XSIAM (not configurable by user)
- [ ] `_time` field is set on every event
- [ ] `source_log_type` field is set on every event
- [ ] `send_events_to_xsiam()` uses `client_class=ContentClient`
- [ ] No `print()` statements — use `demisto.debug()` / `demisto.info()`
- [ ] All functions have type hints
- [ ] Functions are small (~30 lines) and focused
- [ ] Guard clauses used to avoid deep nesting
- [ ] `CommandResults` and `return_results()` used correctly
- [ ] No hardcoded credentials
- [ ] Error handling uses `return_error()` for user-facing errors
- [ ] Output keys are CamelCase
- [ ] Timeout handling with `ExecutionTimeout` consideration
- [ ] Description file content comes from the user/design
- [ ] Troubleshooting is NOT in description (only in README)
- [ ] Test coverage is >90%

---

## 9. Code Style Rules

- Use `demisto.debug()` with `[Section]` prefix for all log messages (e.g., `[Fetch Events]`, `[Client]`, `[Main]`).
- Use descriptive variable names.
- Use type hints everywhere.
- Use Pydantic models for all parameter and argument validation.
- Use `assign_params()` to build query parameters (removes None values).
- Use `arg_to_datetime()` for time parsing.
- Use `tableToMarkdown()` for human-readable output.
- Use `argToList()` for array arguments.
- Use `argToBoolean()` for boolean arguments.
- Keep the Client class free of `demisto.*` calls.

---

## 10. References

- **HelloWorldV2**: `Packs/HelloWorld/Integrations/HelloWorldV2/` — the canonical reference for architecture and patterns.
- **AGENTS.md**: Root-level file with project-wide coding standards and CLI tooling.
- **Confluence**: XSIAM Collector Development Process guidelines (embedded in this spec above).

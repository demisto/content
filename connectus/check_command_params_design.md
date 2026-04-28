> **⚠️ STATUS: Design Proposal — Not Yet Implemented**
>
> This document describes a planned tool. The referenced files
> (`connectus/check_command_params.py` and `connectus/capture_proxy.py`)
> do not exist yet. This is a design proposal only.

# Design: Integration Command Parameter Usage Analyzer

## Purpose

Determine which YML configuration parameters are used by each command in an XSOAR integration.

## Usage

```bash
python3 connectus/check_command_params.py <integration_path> [--commands cmd1 cmd2 ...] [--static-only]
```

The `integration_path` is relative to the content repo root and points to the integration directory (e.g., `Packs/QRadar/Integrations/QRadar_v3`).

```bash
# Analyze ALL commands in the integration (default)
python3 connectus/check_command_params.py Packs/QRadar/Integrations/QRadar_v3

# Analyze specific commands only
python3 connectus/check_command_params.py Packs/QRadar/Integrations/QRadar_v3 --commands test-module fetch-incidents

# Static analysis only (skip dynamic proxy check)
python3 connectus/check_command_params.py Packs/QRadar/Integrations/QRadar_v3 --static-only

# Combine both
python3 connectus/check_command_params.py Packs/HelloWorld/Integrations/HelloWorldV2 --commands test-module --static-only
```

### Command Discovery

By default, the tool analyzes **every command** the integration supports. Commands are discovered from the YML file:

| Source | Commands added |
|--------|---------------|
| `script.commands[].name` | All custom commands (e.g., `qradar-offenses-list`) |
| Always present | `test-module` |
| `script.isfetch: true` | `fetch-incidents` |
| `script.isfetchevents: true` | `fetch-events` |
| `script.isRemoteSyncIn: true` | `get-remote-data`, `get-modified-remote-data` |
| `script.isRemoteSyncOut: true` | `update-remote-system` |
| `script.longRunning: true` | `long-running-execution` |

Use `--commands` to filter to a subset of these.

### Language Support

| Language | Static Analysis | Dynamic Analysis |
|----------|----------------|-----------------|
| **Python** | Full support via AST | Full support via proxy |
| **JavaScript** | Not supported | Full support via proxy |
| **PowerShell** | Not supported | Full support via proxy |

Static analysis is Python-only. Dynamic analysis works for any language because it intercepts HTTP traffic at the network level via a proxy.

## Output

JSON to stdout. Output is keyed by command:

```json
{
  "integration": "QRadar v3",
  "commands": {
    "test-module": {
      "url": true,
      "credentials": true,
      "longRunning": true,
      "max_fetch": false
    },
    "fetch-incidents": {
      "url": true,
      "credentials": true,
      "max_fetch": true,
      "longRunning": false
    },
    "qradar-offenses-list": {
      "url": true,
      "credentials": true,
      "max_fetch": false,
      "longRunning": false
    }
  }
}
```

Each param is `true` (relevant to the command) or `false` (not relevant). The tool merges results from both static and dynamic analysis internally — if either method detects usage, the param is `true`.

---

## Analysis Approach

The tool uses two complementary analysis methods. Both run by default. Use `--static-only` to skip dynamic analysis (e.g., for quick checks or when the integration can't be executed).

### Static Analysis via Python AST

Parse the integration's Python source code **without executing it**. Trace parameter flow from `demisto.params()` through `main()` into the target command handler.

#### Two scopes of analysis

The analysis collects params from two distinct scopes and unions them:

**Scope 1: Pre-dispatch params in `main()`**

Everything in `main()` that happens *before* the command dispatch block (`if command == ...` / `match command:` / `commands = {...}`). These are params used for Client construction and apply to ALL commands.

```python
def main():
    params = demisto.params()                    # ← identify params variable
    base_url = params.get("url")                 # ← Scope 1: pre-dispatch
    verify = not params.get("insecure", False)   # ← Scope 1: pre-dispatch
    proxy = params.get("proxy")                  # ← Scope 1: pre-dispatch
    client = Client(base_url, verify, proxy)     # ← Client construction
    command = demisto.command()

    # ---- dispatch line ---- (everything above is Scope 1)

    if command == "test-module":                  # ← dispatch begins here
        return_results(test_module(client, params))
    elif command == "fetch-incidents":
        ...
```

The script identifies the dispatch line by finding the first `if ... command ...`, `match command:`, or `commands = {` pattern. Only `params.get("X")` calls *above* that line are collected in Scope 1.

**Scope 2: Handler function + 3 nesting levels**

Starting from the handler function for the target command, trace `params.get("X")` calls recursively through up to 3 levels of function calls:

```
Level 1: test_module_command(client, params)
  │       └─ params.get("longRunning")           ← found
  │
  ├─ Level 2: validate_long_running_params(params)
  │            └─ params.get("mirror_options")    ← found
  │            └─ check_mirror_config(params)
  │                 │
  │                 └─ Level 3: (functions called by check_mirror_config)
  │                              └─ params.get("close_incident")  ← found
  │
  └─ Level 2: client.offenses_list(...)           ← not a params access, skip
```

At each level, the tracer looks for:
- `params.get("key")` — dict-style access
- `params["key"]` — subscript access
- `params.key` — attribute access (Pydantic model pattern)

The tracer also checks if the function's signature uses common alternative names for the params argument (`params`, `integration_params`, `config`, `PARAMS`) and traces those too.

**Final result** = Scope 1 ∪ Scope 2

#### Pydantic alias resolution

Modern integrations (e.g., HelloWorldV2) use Pydantic models with `Field(alias="...")`:

```python
class HelloWorldParams(BaseParams):
    is_fetch_events: bool = Field(default=False, alias="isFetchEvents")
```

When the handler accesses `params.is_fetch_events`, the tracer resolves the alias and maps it back to the YML param name `isFetchEvents`.

#### Command handler resolution

The script supports three patterns for finding which function handles a command:

1. **if/elif chain**: `if command == "test-module": test_module(client, params)`
2. **Dict dispatch**: `commands = {"test-module": test_module_command, ...}`
3. **match/case** (Python 3.10+): `case "test-module": return_results(test_module(client, params))`

#### What it detects

| Pattern | Detected? | How |
|---------|-----------|-----|
| `params.get("url")` in main() before dispatch | Yes | Scope 1: pre-dispatch scan |
| `params.get("longRunning")` in handler | Yes | Scope 2: Level 1 |
| `validate_params(params)` → `params.get("X")` | Yes | Scope 2: Level 2 |
| Helper called by validator → `params.get("Y")` | Yes | Scope 2: Level 3 |
| `params.severity` (Pydantic attribute) | Yes | Attribute access detection |
| `Field(alias="isFetch")` mapping | Yes | Pydantic alias resolution |
| `getattr(params, key)` (dynamic) | No | Dynamic dispatch not traceable |
| Params consumed inside `CommonServerPython` | No | External module not parsed |

#### Accuracy

~90% for standard integration patterns. May miss params consumed through dynamic dispatch or deeply inherited methods. Errs on the side of false negatives (reports NOT used when it actually is).

#### Architecture

```
connectus/check_command_params.py
├── find_integration_files(path) → yml_path, py_path
├── parse_yml_params(yml_path) → list of param names
├── discover_commands(yml_data) → list of command names
├── analyze_command_static(py_source, command) → set of used param names
│   ├── ast.parse(source) → AST tree
│   ├── build_function_map(tree) → {name: FunctionDef}
│   ├── find_main(tree) → main FunctionDef
│   ├── find_params_var(main) → variable name (e.g., "params")
│   ├── find_command_dispatch_line(main) → line number
│   ├── collect_pre_dispatch_params(main, params_var) → set[str]     ← Scope 1
│   ├── find_command_handler(main, command) → handler function name
│   ├── handler_receives_params(main, handler, params_var) → bool
│   ├── trace_params_in_function(handler, depth=3) → set[str]        ← Scope 2
│   └── find_pydantic_aliases(tree) → {attr: alias}
├── analyze_command_dynamic(integration_path, commands, yml_params) → {command: {param: bool}}
│   ├── prepare_content(integration_path) → unified .py path
│   ├── proxy.new_session() → session_id
│   ├── run_with_params(unified_path, command, params) → exception or None
│   ├── proxy.get_requests(session_id) → list of captured requests
│   └── diff_requests(baseline, modified) → bool
├── check_command_params(path, commands) → JSON result
└── main() → CLI: parse args, discover or filter commands, loop, merge results, print JSON

connectus/capture_proxy.py  (reusable standalone module)
├── CaptureProxy(port) — main class
│   ├── start() → starts server in background thread
│   ├── stop() → shuts down server
│   ├── new_session() → session_id
│   ├── get_requests(session_id) → list of recorded requests
│   ├── delete_session(session_id) → clears session data
│   └── list_sessions() → list of active session IDs
├── CaptureHandler(BaseHTTPRequestHandler) — handles all HTTP methods
│   ├── Catch-all: records request, returns 200 {}
│   └── Control plane: /_session/* endpoints
└── main() → CLI: standalone server mode with --port flag
```

---

### Dynamic Analysis via HTTP Proxy

Actually **execute** the integration's command and observe which parameters affect the outgoing HTTP requests. Uses a local HTTP proxy to intercept traffic — making this approach **language-agnostic** (works for Python, JavaScript, and PowerShell integrations).

#### How it works

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Harness                              │
│                                                             │
│  1. Start local HTTP proxy on localhost                      │
│  2. Configure integration to route traffic through proxy    │
│  3. Set all params to known sentinel values                 │
│  4. For each command:                                       │
│     a. Execute the command with all params → baseline       │
│     b. Capture all outgoing HTTP requests at the proxy      │
│     c. For each param:                                      │
│        - Remove that one param                              │
│        - Re-execute the command                             │
│        - If exception thrown → param IS RELEVANT            │
│        - If request differs from baseline → param RELEVANT  │
│        - If no change → param NOT relevant                  │
│  5. Detect param dependencies via pairwise removal          │
│  6. Output results per command                              │
└─────────────────────────────────────────────────────────────┘
```

#### Content preparation pipeline

To execute an integration standalone, we need a fully self-contained Python file. The runtime normally injects these at startup, so we must assemble them ourselves:

1. **Prepend `demistomock.py`** — from `Packs/Base/Scripts/CommonServerPython/demistomock.py`
   - Provides the `demisto` object with `.params()`, `.command()`, `.args()`, etc.
   - We patch this to return our controlled param values

2. **Prepend `CommonServerPython.py`** — from `Packs/Base/Scripts/CommonServerPython/CommonServerPython.py`
   - `prepare-content` / `unify` does NOT prepend this — the runtime injects it
   - We must do it ourselves

3. **Run `demisto-sdk prepare-content -i <path>`** — attaches API modules
   - Inlines modules like `ContentClientApiModule`, `MicrosoftApiModule`, etc.
   - These are referenced in the YML and normally loaded by the runtime

4. **Result**: a single `.py` file that can be imported and executed standalone

#### Execution flow

```bash
# What happens internally for each command:
# 1. Proxy already running on localhost:18080
# 2. Create session: POST /_session/new → session_id="baseline_test-module"
# 3. Set params: url=http://localhost:18080, api_key=SENTINEL_KEY, ...
# 4. Patch demisto.params() to return these values
# 5. Import and run the integration's command handler
# 6. Retrieve captured requests: GET /_session/baseline_test-module/requests
#    → [{method: GET, path: /api/v1/health, headers: {Authorization: Bearer SENTINEL_KEY}}]
# 7. For param "api_key":
#    a. Create new session: POST /_session/new → session_id="without_api_key"
#    b. Remove api_key from params, re-run command
#    c. Retrieve: GET /_session/without_api_key/requests
#    d. Diff against baseline → Authorization header missing → api_key IS USED
#    e. Cleanup: DELETE /_session/without_api_key
# 8. Repeat step 7 for each param
# 9. Cleanup: DELETE /_session/baseline_test-module
```

#### Why a proxy instead of requests_mock

| Aspect | requests_mock | HTTP Proxy |
|--------|--------------|------------|
| **Language support** | Python only | Python, JavaScript, PowerShell, any language |
| **Setup** | Patch Python `requests` library | Set `HTTP_PROXY`/`HTTPS_PROXY` env vars |
| **Captures** | Only `requests` library calls | All HTTP traffic from the process |
| **TLS inspection** | N/A (mocks before TLS) | Needs proxy CA cert (mitmproxy handles this) |
| **Integration changes needed** | None (monkey-patches) | None (env var based) |
| **Works with Docker** | Needs to be inside container | Proxy runs on host, container routes to it |

#### Proxy implementation

A **custom lightweight HTTP capture server** implemented as a reusable standalone module at `connectus/capture_proxy.py`. Designed to be used by `check_command_params.py` and any future tools that need to observe HTTP traffic from integrations.

**Session-based architecture:**

The proxy uses **session IDs** to isolate captured requests between test runs. Each test run creates a new session, and all requests during that session are stored under that session ID. This prevents stale data from previous runs from contaminating results.

```
┌──────────────────────────────────────────────────────────────┐
│  capture_proxy.py - Reusable HTTP Capture Server             │
│                                                              │
│  Endpoints:                                                  │
│                                                              │
│  Control plane (used by test harness):                       │
│    POST /_session/new          → {session_id: "abc123"}      │
│    GET  /_session/<id>/requests → [{method, url, headers...}]│
│    DELETE /_session/<id>       → clears session data          │
│    GET  /_sessions             → list all active sessions     │
│                                                              │
│  Catch-all (used by integration under test):                 │
│    ANY  /<anything>            → 200 OK, body: {}            │
│    Records: method, path, headers, body, timestamp           │
│    Assigns request to the currently active session           │
│                                                              │
│  Session lifecycle:                                          │
│    1. Harness calls POST /_session/new → gets session_id     │
│    2. Harness sets active session via header or param         │
│    3. Integration makes HTTP calls → proxy records them      │
│    4. Harness calls GET /_session/<id>/requests → gets data  │
│    5. Harness calls DELETE /_session/<id> → cleanup           │
└──────────────────────────────────────────────────────────────┘
```

**How sessions work:**

The test harness sets the active session by including an `X-Capture-Session` header in the integration's params (e.g., as a custom header), or more simply: the harness calls `POST /_session/new` right before each test run, and the proxy assigns all subsequent requests to the most recently created session until a new one is created.

**Key properties:**
- Pure Python stdlib (`http.server` or `socketserver`) — no external dependencies
- No TLS complexity needed (integration connects to `http://localhost:PORT`)
- Accepts all requests on catch-all routes, returns `200 OK` with empty JSON `{}`
- Records: method, full URL path, query params, headers, body, timestamp per request
- Thread-safe session storage (multiple concurrent test runs supported)
- Can run as a standalone server or be started/stopped programmatically

**Standalone usage:**

```bash
# Start the capture proxy server
python3 connectus/capture_proxy.py --port 18080

# From another terminal or script:
# Create a session
curl -X POST http://localhost:18080/_session/new
# → {"session_id": "s_1714234567_001"}

# ... integration makes requests to http://localhost:18080/api/v1/health ...

# Retrieve captured requests for this session
curl http://localhost:18080/_session/s_1714234567_001/requests
# → [{"method": "GET", "path": "/api/v1/health", "headers": {...}, "body": "", "timestamp": "..."}]

# Clean up
curl -X DELETE http://localhost:18080/_session/s_1714234567_001
```

**Programmatic usage (from check_command_params.py):**

```python
from capture_proxy import CaptureProxy

proxy = CaptureProxy(port=18080)
proxy.start()  # starts in background thread

session_id = proxy.new_session()
# ... run integration command ...
requests = proxy.get_requests(session_id)
proxy.delete_session(session_id)

proxy.stop()
```

#### What it detects that static analysis cannot

- Params that end up in HTTP headers (e.g., `Authorization: Bearer {api_key}`)
- Params that affect the request URL (e.g., `base_url` / `server`)
- Params that affect the request body (e.g., `tenant_id` in OAuth token requests)
- Params consumed by `CommonServerPython.BaseClient` internally (e.g., `proxy`, `insecure`)
- Params used by imported API modules (e.g., `MicrosoftClient`, `Boto3`)

#### Accuracy

~99% — the only things it can't detect are params that affect behavior without changing HTTP requests (e.g., `isFetch` which controls whether fetch-incidents validation runs inside test-module, but doesn't change the HTTP call itself). Static analysis catches those.

#### Limitations

- Requires the integration to be importable (Python deps available, or Docker)
- Some integrations make multiple API calls in test-module — all are captured
- Integrations that validate responses may fail on the dummy `{}` response — need error handling
- JavaScript/PowerShell integrations need a different execution harness (not Python import)

---

## Handling Exceptions in Dynamic Analysis

When the proxy-based check removes a param and the command throws an exception **before** making any HTTP request, this is **not a failure** — it is the strongest possible signal that the param is relevant.

Exceptions that occur **after** the HTTP call reached the proxy are **ignored entirely**. The proxy already captured the request, so we have the data we need. These post-request exceptions typically happen because the proxy returns a dummy `{}` response that the integration can't parse — this is expected and irrelevant to param detection.

### Decision table for dynamic check

| Outcome when param removed | Param relevant? | Why |
|---|---|---|
| Exception thrown before HTTP call | Yes | Code requires this param to even run |
| HTTP request differs from baseline | Yes | Param value flows into the request |
| HTTP request identical to baseline | No | Param has no effect on this command |
| Exception thrown after HTTP call | Ignore | Proxy already captured the request; exception is from dummy response parsing |
| No exception and no HTTP request | No | Command ran fine without it |

### Detecting param dependencies

The same approach reveals which params depend on each other:

```
1. Run with ALL params → baseline
2. For each param P:
   - Remove P, run again
   - Record: exception, request diff, or no change
3. For each param P that caused an exception:
   - For each other param Q:
     - Remove both P and Q, run again
     - If no exception → P depends on Q
       e.g. first_fetch depends on isFetch
```

This produces a dependency graph: "first_fetch is only relevant when isFetch is True".

---

## Implementation Plan

### 1. Capture Proxy (`connectus/capture_proxy.py`)
- Reusable standalone HTTP capture server
- Python stdlib only: `http.server`, `json`, `threading`, `argparse`
- Session-based request storage with unique session IDs
- Control plane endpoints: `/_session/new`, `/_session/<id>/requests`, `/_session/<id>` (DELETE), `/_sessions`
- Catch-all handler: accepts any HTTP method/path, returns `200 {}`, records request
- Thread-safe: supports concurrent sessions
- Dual usage: programmatic (`CaptureProxy` class) and standalone (`python3 capture_proxy.py --port 18080`)
- No external dependencies

### 2. Static Analysis Module (`connectus/check_command_params.py`)
- Python stdlib only: `ast`, `yaml`, `json`, `argparse`, `pathlib`, `glob`
- No external dependencies
- Accepts integration path + optional command filter
- Discovers all commands from YML if no filter provided
- Loops over each command, runs AST analysis per command

### 3. Dynamic Analysis Module (in `connectus/check_command_params.py`)
- Uses `CaptureProxy` from `capture_proxy.py`
- Content preparation pipeline:
  1. Prepend `demistomock.py` from `Packs/Base/Scripts/CommonServerPython/`
  2. Prepend `CommonServerPython.py` from `Packs/Base/Scripts/CommonServerPython/`
  3. Run `demisto-sdk prepare-content -i <path>` to attach API modules
  4. Produce a single unified `.py` file
- For each command:
  - Create baseline session → run with all params → capture requests
  - For each param: create new session → remove param → run again
  - Exception before HTTP call → param is relevant
  - Exception after HTTP call → ignore (proxy already captured)
  - Request diff → param is relevant
  - No change → param is not relevant
  - Clean up sessions after each comparison
- Detect param dependencies via pairwise removal
- For JS/PowerShell: execute via subprocess with `HTTP_PROXY` env var

### 4. Merging Results
- Static result: `{param: bool}` per command
- Dynamic result: `{param: bool}` per command
- Final: `param = static_result OR dynamic_result` (union — if either says relevant, it's relevant)
- Output: `{commands: {command: {param: true/false}}}` JSON to stdout

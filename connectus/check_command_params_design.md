# Design: Integration Command Parameter Usage Analyzer

## Purpose

Determine which YML configuration parameters are used by specific commands (e.g., `test-module`, `fetch-incidents`) in an XSOAR integration.

## Usage

```bash
python3 connectus/check_command_params.py <integration_name> [command1 command2 ...]
```

```bash
# Single command
python3 connectus/check_command_params.py "Abnormal Security" test-module

# Multiple commands
python3 connectus/check_command_params.py "QRadar v3" test-module fetch-incidents

# Default: test-module if no command specified
python3 connectus/check_command_params.py "Abnormal Security"

# Static analysis only (skip dynamic proxy check)
python3 connectus/check_command_params.py "QRadar v3" test-module --static-only
```

### Language Support

| Language | Static Analysis | Dynamic Analysis |
|----------|----------------|-----------------|
| **Python** | Full support via AST | Full support via proxy |
| **JavaScript** | Not supported | Full support via proxy |
| **PowerShell** | Not supported | Full support via proxy |

Static analysis is Python-only. Dynamic analysis works for any language because it intercepts HTTP traffic at the network level via a proxy.

## Output

JSON to stdout. Output is always keyed by command:

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
├── find_integration_files(name) → yml_path, py_path
├── parse_yml_params(yml_path) → list of param names
├── analyze_command_static(py_source, command) → {handler_found, handler_name, used_params, error}
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
│   ├── start_proxy() → proxy instance
│   ├── run_with_params(unified_path, command, params) → {requests, exception}
│   └── diff_requests(baseline, modified) → bool
├── check_command_params(name, commands) → JSON result
└── main() → CLI: parse args, loop over commands, merge results, print JSON
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
│  4. For each command in the list:                           │
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
# 1. Starts proxy on localhost:18080
# 2. Sets params: url=http://localhost:18080, api_key=SENTINEL_KEY, ...
# 3. Patches demisto.params() to return these values
# 4. Imports and runs the integration's command handler
# 5. Proxy captures: GET http://localhost:18080/api/v1/health
#    Headers: {Authorization: Bearer SENTINEL_KEY, ...}
# 6. Removes api_key, re-runs → request has no Authorization header
#    → api_key IS USED in this command
# 7. Removes proxy param, re-runs → request still goes through
#    → proxy param affects routing but not the request itself
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

A **custom lightweight proxy** is simplest for this use case:
- Accepts all requests, returns `200 OK` with empty JSON `{}`
- Logs: method, URL, headers, body for each request
- No TLS complexity needed (integration connects to `http://localhost:PORT`)
- Pure Python stdlib (`http.server` or `socketserver`)

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

When the proxy-based check removes a param and the command throws an exception before making any HTTP request, this is **not a failure** — it is the strongest possible signal that the param is relevant.

### Decision table for dynamic check

| Outcome when param removed | Param relevant? | Why |
|---|---|---|
| Exception thrown before HTTP call | Yes | Code requires this param to even run |
| HTTP request differs from baseline | Yes | Param value flows into the request |
| HTTP request identical to baseline | No | Param has no effect on this command |
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

### Static Analysis Module
- Implement in `connectus/check_command_params.py`
- Python stdlib only: `ast`, `yaml`, `json`, `argparse`, `pathlib`, `glob`
- No external dependencies
- Accepts integration name + list of commands
- Loops over each command, runs AST analysis per command

### Dynamic Analysis Module
- Implement in same file or as `connectus/check_command_params_dynamic.py`
- Content preparation pipeline:
  1. Prepend `demistomock.py` from `Packs/Base/Scripts/CommonServerPython/`
  2. Prepend `CommonServerPython.py` from `Packs/Base/Scripts/CommonServerPython/`
  3. Run `demisto-sdk prepare-content -i <path>` to attach API modules
  4. Produce a single unified `.py` file
- Lightweight HTTP proxy using Python stdlib
- For each command in the list:
  - Run with all params → capture baseline requests
  - For each param: remove it, run again
  - Exception → param is relevant
  - Request diff → param is relevant
  - No change → param is not relevant
- Detect param dependencies via pairwise removal
- For JS/PowerShell: execute via subprocess with `HTTP_PROXY` env var

### Merging Results
- Static result: `{param: bool}` per command
- Dynamic result: `{param: bool}` per command
- Final: `param = static_result OR dynamic_result` (union — if either says relevant, it's relevant)
- Output: `{command: {param: true/false}}` JSON to stdout

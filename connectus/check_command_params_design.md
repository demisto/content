> **✅ STATUS: Implemented and Shipping**
>
> [`connectus/check_command_params.py`](check_command_params.py:1) and
> [`connectus/capture_proxy.py`](capture_proxy.py:1) are both in the repo
> and used in production by the migration pipeline. **The implemented
> behavior diverges in important ways from the original design captured
> in this document** — most notably, the dynamic phase is sentinel-driven
> single-run (Strategy 8), runs inside Docker by default, and reports
> per-command structured `diagnostics`. Read the
> ["Implementation Status & Divergences from Original Design"](#implementation-status--divergences-from-original-design)
> section at the bottom of this file FIRST for the authoritative current
> behavior; the rest of the document is preserved as the original design
> rationale.

# Design: Integration Command Parameter Usage Analyzer

## Purpose

Determine which YML configuration parameters are used by each command in an XSOAR integration.

## Usage

```bash
python3 connectus/check_command_params.py <integration_path> \
    [--commands cmd1 cmd2 ...] \
    [--static-only] \
    [--ignore-params PARAM [PARAM ...]] \
    [--ignore-params-file PATH]
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

# Exclude specific params from analysis (passed inline)
python3 connectus/check_command_params.py Packs/QRadar/Integrations/QRadar_v3 \
    --ignore-params proxy insecure longRunning

# Exclude params from a file (recommended for batch runs)
python3 connectus/check_command_params.py Packs/QRadar/Integrations/QRadar_v3 \
    --ignore-params-file path/to/ignore_list.txt
```

### `--ignore-params` and `--ignore-params-file`

Both flags **exclude params from analysis entirely**. Excluded params are not statically traced and are not included in the dynamic param-removal loop, which directly reduces the cost of dynamic analysis (see [Performance & Scaling](#performance--scaling)). They simply do not appear in the per-command output.

```text
--ignore-params PARAM [PARAM ...]    Skip analysis for these params (they will not appear in output)
--ignore-params-file PATH            Read ignore list from a file (one param per line, # comments allowed)
```

If both flags are supplied, the lists are unioned. Passing many params on every CLI call is unwieldy in batch operations, so `--ignore-params-file` is the preferred form when running across many integrations.

This tool intentionally does **not** ship with a built-in default ignore list. Curating which params are "framework / infrastructure" (e.g., `proxy`, `insecure`, `longRunning`, feed framework params) is the responsibility of an upstream pipeline stage or the caller — the tool only consumes the list it is given.

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
    "test-module": ["adv_params", "fetch_query"],
    "fetch-incidents": ["fetch_query", "first_fetch", "max_fetch"],
    "qradar-offenses-list": ["fetch_query", "filter"]
  },
  "diagnostics": {
    "test-module":          {"status": "param_caused_failure", "captured_requests": 0, "failing_params": ["adv_params"], "failure_excerpt": "..."},
    "fetch-incidents":      {"status": "ok", "captured_requests": 3, "scope_1_narrowed": true, "scope_1_dropped": ["adv_params"]},
    "qradar-offenses-list": {"status": "ok", "captured_requests": 1}
  }
}
```

Each command maps to a sorted list of param names that are relevant. Params not in the list (and params in `--ignore-params` / `--ignore-params-file`) are not relevant or were excluded. The tool merges results from both static and dynamic analysis internally — if either method detects usage, the param appears in the list. Lists are sorted alphabetically (case-sensitive) so output is deterministic; an empty list (`[]`) is the correct value for a command with no relevant params.

> **Note (post-implementation).** In the current shipping output the
> standard invocation passes
> [`connectus/default_ignore_params.txt`](default_ignore_params.txt:1)
> via `--ignore-params-file`, which strips ~154 framework /
> auth / connection params (`url`, `credentials`, `proxy`, `insecure`,
> `longRunning`, the feed framework, …) before the analyzer ever runs.
> The example above reflects that post-ignore-list reality — only
> behavioral, per-command-meaningful params remain. The `diagnostics`
> object is **internal AI metadata** and MUST be stripped before any
> persisted artifact (CSV, manifest, `set-params-to-commands` payload).
> See the [Implementation Status](#implementation-status--divergences-from-original-design)
> section for the full schema and the `diagnostics` status enum.

---

## Performance & Scaling

Dynamic analysis is by far the most expensive part of this tool. The naive design has a quadratic cost that does not scale to the full content backlog. This section documents the cost honestly and lays out the optimization strategies that bring it back into a practical budget.

### The cost problem

Let **N** = number of YML params on an integration and **C** = number of commands being analyzed. With each integration re-run taking roughly **5 seconds** (cold import, content prep, command dispatch, proxy round-trips), the dynamic phase costs:

| Strategy                                                      | Re-runs per command | Per command (5s/run) | Per integration (C=10) |
|---------------------------------------------------------------|---------------------|----------------------|------------------------|
| Single-pass per-param removal — O(N)                          | N                   | 5N seconds           | 50N seconds            |
| Pairwise dependency detection (current design, lines 437–447) | up to N²            | 5N² seconds          | 50N² seconds           |

For an integration with **N = 30**:

- Per-param removal alone: 30 × 5 = **150 seconds** per command.
- Full pairwise dependency detection: 900 × 5 = **75 minutes** per command.

For the full **982-integration backlog** at the pairwise rate, that is roughly **51 days** of wall time on a single machine. This is not acceptable as a default.

### Optimization strategies

The following strategies are presented independently. Most can be combined.

#### Strategy 1: `--ignore-params`

Reduce N by excluding well-known infrastructure params curated upstream. Costs scale with N², so any reduction compounds. Example: if 8 of 20 params on a typical integration are framework-owned, N drops from 20 → 12 and pairwise re-runs drop from 400 → 144 (**~64% reduction** in dynamic cost for that integration).

#### Strategy 2: Cap dependency-detection scope

Pairwise dependency detection is the dominant cost driver. Most real param dependencies in practice involve a small number of params (e.g., `first_fetch` depends on `isFetch`). Cap the number of params for which the pairwise pass runs — for example, only the first **K** params that triggered an exception in the single-pass phase, with K = 5 as a reasonable default. This caps the pairwise cost at **K × N** instead of **N × N**.

#### Strategy 3: Skip params that never appear in static analysis output

If static analysis reports that a param is not referenced by any command in the integration, it is almost certainly framework-owned (consumed by `BaseClient` / API modules) and dynamic analysis will not yield new information. Skip it.

This catches `proxy`, `insecure`, and similar params automatically — even when the caller did not list them in `--ignore-params`. Combine with `--ignore-params` for explicit, deterministic control.

#### Strategy 4: Batch dynamic runs per command, not per param

The current design re-runs the entire integration for each removed param. A faster pattern is to permute params **within a single integration startup** if the integration supports re-invocation without re-import.

**Caveat:** many integrations have module-level side effects (`Client(...)` constructed at import time, network calls during module init), so this only works for integrations using lazy initialization. Document as a future-only optimization, gated behind detection of import-time purity.

#### Strategy 5: Parallelism

The capture proxy is already session-based — multiple sessions can run concurrently without contaminating each other. Spawn **W** worker processes, each with its own session ID, running param-removal experiments in parallel.

- On a typical CI machine: 4–8× speedup with 8 workers.
- **Caveat:** each worker needs its own copy of the unified Python file imported in isolation. Use `multiprocessing` (separate interpreters), **not** `threading` (shared module state would cause cross-talk).

#### Strategy 6: Caching by integration version

Hash the integration's `.py` + `.yml` files (and the unified-content build inputs). Cache analysis results keyed by that hash. Re-running on unchanged integrations is free, which makes incremental backlog passes cheap and makes CI integration practical.

#### Strategy 7: Skip dynamic verification for params already proven by static analysis

If static analysis says "param X is used in command Y", dynamic analysis will only confirm it. Only run the dynamic check on:

1. Params where static says "not used" (to catch false negatives), and
2. Non-Python integrations (where static analysis does not run at all).

In practice this eliminates roughly 80% of dynamic re-runs, since most params in standard integrations are caught by the AST trace.

#### Strategy 8: Sentinel-driven differential (single-run analysis) — biggest win

Instead of re-running the integration once per param, do this:

1. Set every param to a **unique sentinel value**, e.g. `SENTINEL_PARAM_<name>`.
2. Run the command **once**.
3. Capture all outgoing HTTP requests via the proxy.
4. Grep request URLs / headers / bodies for each sentinel string. Each hit tells you exactly which params flowed into the request.

This collapses the dynamic phase from **O(N) re-runs** to **O(1) re-runs per command** — a massive win and the single biggest optimization available to this tool.

**Caveat:** sentinels only catch params that flow into HTTP traffic. They do not catch params that affect *behavior* without flowing into a request — for example, `isFetch` toggling a validation branch inside `test-module`. For those cases, fall back to per-param removal (which is now a small targeted set, not the whole list).

**Recommendation:** make sentinel-based differential the **default** dynamic mode.

### Recommended optimization stack

In priority order, the recommended layering is:

1. **Static-only by default** — fast, ~90% accurate, zero dynamic cost.
2. **Sentinel-based differential** when dynamic analysis is enabled — single-run per command.
3. **`--ignore-params`** to drop framework / infrastructure params before either phase.
4. **Result caching by integration hash** for repeated runs and CI.
5. **Process-level parallelism** for batch jobs over the backlog.
6. **Pairwise dependency detection** opt-in only via an explicit flag — never the default.

### Realistic time budget after optimization

| Mode                                                          | Per integration   | Full 982-integration backlog                |
|---------------------------------------------------------------|-------------------|---------------------------------------------|
| Static-only                                                   | 1–3 seconds       | ~15–50 minutes serial                       |
| Sentinel-based dynamic + ignore-list + caching                | 5–15 seconds      | ~30 minutes with parallelism (W=8)          |
| Single-pass per-param removal (no sentinels)                  | minutes           | hours to a day                              |
| Pairwise dependency detection (current naïve design)          | up to ~75 min     | ~51 days                                    |

The tool should default to the cheapest mode that still satisfies the caller's accuracy requirement and require explicit opt-in for anything more expensive.

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

~99%[^sentinel-accuracy] — the only things it can't detect are params that affect behavior without changing HTTP requests (e.g., `isFetch` which controls whether fetch-incidents validation runs inside test-module, but doesn't change the HTTP call itself). Static analysis catches those.

[^sentinel-accuracy]: This figure assumes either single-pass per-param removal **or** the sentinel-based differential mode described in [Performance & Scaling](#performance--scaling). Sentinel mode achieves comparable accuracy at a fraction of the cost for params that flow into HTTP traffic; behavior-only params still depend on the static or per-param-removal fallback.

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

### 1. Capture Proxy ([`connectus/capture_proxy.py`](connectus/capture_proxy.py))
- Reusable standalone HTTP capture server
- Python stdlib only: `http.server`, `json`, `threading`, `argparse`
- Session-based request storage with unique session IDs
- Control plane endpoints: `/_session/new`, `/_session/<id>/requests`, `/_session/<id>` (DELETE), `/_sessions`
- Catch-all handler: accepts any HTTP method/path, returns `200 {}`, records request
- Thread-safe: supports concurrent sessions
- Dual usage: programmatic (`CaptureProxy` class) and standalone (`python3 capture_proxy.py --port 18080`)
- No external dependencies

### 2. Static Analysis Module ([`connectus/check_command_params.py`](connectus/check_command_params.py))
- Python stdlib only: `ast`, `yaml`, `json`, `argparse`, `pathlib`, `glob`
- No external dependencies
- Accepts integration path + optional command filter
- Discovers all commands from YML if no filter provided
- Honors `--ignore-params` / `--ignore-params-file`: excluded params are dropped from the static trace before per-command output is emitted
- Loops over each command, runs AST analysis per command

### 3. Dynamic Analysis Module (in [`connectus/check_command_params.py`](connectus/check_command_params.py))
- Uses `CaptureProxy` from [`connectus/capture_proxy.py`](connectus/capture_proxy.py)
- Content preparation pipeline:
  1. Prepend `demistomock.py` from `Packs/Base/Scripts/CommonServerPython/`
  2. Prepend `CommonServerPython.py` from `Packs/Base/Scripts/CommonServerPython/`
  3. Run `demisto-sdk prepare-content -i <path>` to attach API modules
  4. Produce a single unified `.py` file
- Honors `--ignore-params` / `--ignore-params-file`: excluded params are skipped in the param-removal loop entirely (this is the primary lever for keeping dynamic cost bounded — see [Performance & Scaling](#performance--scaling))
- For each command:
  - Create baseline session → run with all params → capture requests
  - For each param **not in the ignore list**: create new session → remove param → run again
  - Exception before HTTP call → param is relevant
  - Exception after HTTP call → ignore (proxy already captured)
  - Request diff → param is relevant
  - No change → param is not relevant
  - Clean up sessions after each comparison
- Pairwise dependency detection is **opt-in** (off by default); see Strategy 2 / Strategy 6 in [Performance & Scaling](#performance--scaling) for why
- For JS/PowerShell: execute via subprocess with `HTTP_PROXY` env var

### 4. Recommended optimization stack (implementation order)
The performance section above lays out the full menu. Initial implementation should target, in order:

1. Static-only as the default mode.
2. `--ignore-params` / `--ignore-params-file` plumbing through both static and dynamic phases.
3. Sentinel-based differential as the default dynamic strategy (single-run per command).
4. Result caching keyed by a hash of the integration's `.py` + `.yml`.
5. Process-level parallelism (`multiprocessing`) for batch runs.
6. Pairwise dependency detection only behind an explicit opt-in flag.

### 5. Merging Results
- Static result: `{param: bool}` per command
- Dynamic result: `{param: bool}` per command
- Final: `param = static_result OR dynamic_result` (union — if either says relevant, it's relevant)
- Params in the ignore list are excluded from both phases and omitted from the output
- Output: `{commands: {command: [param, ...]}}` JSON to stdout (sorted list of relevant param names per command)

---

## Implementation Status & Divergences from Original Design

This section is the **authoritative description of the shipped behavior**.
The sections above describe the original design; where they conflict
with the bullets below, the bullets below win.

### What's actually implemented

The shipping analyzer ([`connectus/check_command_params.py`](check_command_params.py:1))
implements the original design's **sentinel-driven differential
strategy** (Strategy 8) plus seven additional fixes layered on top:

1. **Per-command exception isolation.** A failure in one command's
   dynamic phase no longer aborts the rest of the integration. Each
   command produces its own row in `diagnostics` and contributes
   independently to `commands`.
2. **`return_error` patch.** The injected `demistomock` overrides
   `return_error` so the child exits with a distinct non-zero code
   (`RC_RETURN_ERROR_PATCHED = 7`) instead of silently swallowing the
   error. The analyzer treats `rc=7 + captures>0` as a partial success.
3. **Pre-import param seeding.** `demistomock.demisto.params/command/args`
   are patched on disk via a tmp mock dir + `sys.path` injection
   **before** the unified module is imported. This is critical for
   integrations whose `Client(...)` is constructed at import time and
   reads params during construction.
4. **YML-type-aware coercion.** Sentinels are coerced to the type
   declared in the YML so they survive runtime validation:
   booleans → `True`, ints → `1`, credentials (`type: 9`) →
   `{"identifier": "SENTINEL_PARAM_<name>_id", "password": "SENTINEL_PARAM_<name>"}`,
   multi-select → CSV string, single-select → first option, etc.
   Strings get the `SENTINEL_PARAM_<name>` value used for grep matching.
5. **Docker child execution.** The per-command child runs inside
   `demisto/py3-native:8.9.0.114862` (pinned via `DEFAULT_DOCKER_IMAGE`).
   The integration's YML `script.dockerimage` is **deliberately
   ignored** — one image for all integrations keeps the analyzer
   reproducible. `--docker auto` (default) uses Docker when the daemon
   is reachable and falls back to host Python otherwise; `--docker
   always` requires Docker; `--docker never` runs in host Python only
   (will fail on integrations needing third-party deps). The
   `--docker-image <ref>` flag overrides the pinned image for testing.
6. **Structured `diagnostics` field.** A second top-level JSON key
   alongside `commands`, with one entry per command. The status enum
   is one of:
   - `ok` — completed, ≥1 HTTP request captured.
   - `ok_no_capture` — completed cleanly (rc=0) but proxy saw zero
     requests. Param list comes from static analysis only.
   - `param_caused_failure` — failed, and one or more
     `SENTINEL_PARAM_<name>` substrings appeared in the failure
     message. Matching params are listed in `failing_params` and
     pre-elevated into `commands[cmd]`.
   - `no_data` — failed without specific param attribution.
     `failure_excerpt` is still informative.
   - `timeout` — child hit the per-command wall-clock timeout.
   - `docker_error` — Docker invocation itself failed (rc=125/126/127).
   - `module_not_found` — child crashed with `ModuleNotFoundError`.
     Integration needs a third-party package not in the pinned image.
     The missing package name is in `missing_module`. The calling AI
     must read the source manually (analogous to JS / PowerShell).

   Optional fields per command: `failure_excerpt` (truncated to 500
   chars), `failing_params`, `missing_module`, `captured_requests`,
   `scope_1_narrowed`, `scope_1_dropped`. Under `--static-only` the
   `diagnostics` key is **omitted entirely**.

   ⚠️ **`diagnostics` is internal AI signal. It MUST NEVER be
   persisted into pipeline data (CSV, manifest, etc.).**

7. **Hybrid Scope-1 narrowing.** When a command's dynamic phase
   captured `≥1` HTTP request **and** ≥1 sentinel hit was detected on
   the wire, the analyzer treats the captured-set as an authoritative
   bound on which params reached the wire for that command. It then
   narrows the static Scope-1 set (pre-dispatch params shared across
   all commands — the `Client(api_key=…, max_fetch=…, …)` fan-out
   pattern in `main()`) to the intersection with the captured params.
   Scope-2 (per-command handler-traced params) is preserved unchanged.
   This kills the dominant false-positive class where every command
   appears to use every Client-init param. Narrowed commands carry
   `diagnostics[cmd].scope_1_narrowed: true` and a `scope_1_dropped`
   list of the params that were removed. When dynamic did not capture
   (`ok_no_capture`, `module_not_found`, etc.) or hit zero sentinels,
   the analyzer falls back to the full `scope_1 | scope_2` static
   union and adds no extra diagnostic field. Narrowing is silent in
   `commands` and visible in `diagnostics` only.

### Output schema (current, authoritative)

```text
{
  "integration": "<display name>",
  "commands": {
    "<cmd>": ["<param>", ...]            # sorted, case-sensitive
  },
  "diagnostics": {                        # omitted under --static-only
    "<cmd>": {
      "status": "ok" | "ok_no_capture" | "param_caused_failure"
              | "no_data" | "timeout" | "docker_error" | "module_not_found",
      "captured_requests": <int>,
      "failure_excerpt": "<str, max 500 chars, optional>",
      "failing_params": ["<param>", ...],   # only if param_caused_failure
      "missing_module": "<str>",            # only if module_not_found
      "scope_1_narrowed": true,             # only if Fix-7 narrowing fired
      "scope_1_dropped": ["<param>", ...]   # only if Fix-7 narrowing fired
    }
  }
}
```

The per-command value is a **sorted list of param names** — NOT the
original `{param: bool}` map described in the
["Merging Results"](#5-merging-results) section above. The list shape
is the only shape the migration pipeline accepts.

### Default ignore list

There is now a curated default ignore list at
[`connectus/default_ignore_params.txt`](default_ignore_params.txt:1)
(154 entries: 23 framework + 108 auth/connection + 21 from validation
pass + assorted). The standard invocation always passes it via
`--ignore-params-file`:

```bash
python3 connectus/check_command_params.py <integration_dir> \
    --ignore-params-file connectus/default_ignore_params.txt
```

This means production output will never contain `url`,
`credentials`, `proxy`, `insecure`, `longRunning`, the feed-framework
params, etc. The analyzer itself still ships **without** a built-in
default — the file is the convention, not a hard-coded list.

### CLI surface (current)

The shipped CLI adds two flags beyond the original design:

```text
--timeout SECONDS                Per-command wall-clock timeout (default 30)
--docker {auto,always,never}     Run child in Docker (default: auto)
--docker-image <ref>             Override the pinned demisto/py3-native image
                                 (testing/debug only — production runs with
                                 the pinned image)
```

Exit codes:

- `0` — success.
- `2` — bad CLI args / path.
- `3` — unhandled analyzer error (also emitted with empty stdout for
  non-Python integrations in dynamic mode — see Asymmetry below).

### Sentinel implementation (single-pass)

Per the original Strategy 8 recommendation, the dynamic phase runs
each command **exactly once** with all params seeded to unique
sentinels. There is no per-param removal loop, no pairwise dependency
detection, no `--all-pairs` flag. The analyzer greps each captured
HTTP request (URL + headers + body) against the sentinel table in a
single pass. This is the only dynamic mode that ships.

### Static analysis: what's in vs out

In: scope-1 + scope-2 trace, Pydantic alias resolution, three
handler-resolution patterns (if/elif, dict dispatch, match/case),
3-level call depth.

Out: nothing was cut from the original static design — all of it is
implemented.

### Language asymmetry (known limitation)

| Language     | Static analysis | Dynamic analysis (current) |
|--------------|-----------------|----------------------------|
| Python       | Full            | Full                       |
| JavaScript   | Graceful skip — empty static set, clear stderr log, rc=0 | **rc=3 with empty stdout** |
| PowerShell   | Graceful skip — empty static set, clear stderr log, rc=0 | **rc=3 with empty stdout** |

Static analysis on JS/PowerShell is a clean no-op (returns an empty
set). Dynamic analysis on JS/PowerShell currently exits non-zero with
empty stdout — which is louder than the static path but inconsistent
with it. This asymmetry is **known and tracked as a future
improvement**; for now the calling AI treats `module_not_found` and
non-Python rc=3 outcomes the same way (read the source manually).

### Performance — actual vs. predicted

| Mode                                         | Per integration  |
|----------------------------------------------|------------------|
| `--static-only`                              | 1–3 seconds      |
| Default (Docker + sentinel single-run)       | 5–60 seconds     |
| First-time Docker image pull                 | +20–60 seconds (one-time) |

The original `Performance & Scaling` section above was costed against
single-pass / pairwise re-run strategies that **do not ship**.
Strategy 8 (sentinel single-run) collapsed the dynamic phase to
`O(C)` not `O(N·C)`, and Docker startup is now the dominant cost
driver per command, not param re-runs.

### What was deferred / never built

From the original optimization stack:

- **Result caching by integration hash** (Strategy 6) — not
  implemented. Re-runs are still full re-runs.
- **Process-level parallelism** (Strategy 5) — not implemented in
  the analyzer itself. The batch runner
  ([`connectus/run_check_command_params_batch.py`](run_check_command_params_batch.py:1))
  handles parallelism above the per-integration level.
- **Pairwise dependency detection** (Strategy 2) — not implemented
  and intentionally skipped per the original "opt-in only" guidance.
- **Behavior-only param fallback** (the per-param removal Strategy 8
  caveat) — not implemented. Behavior-only params are caught only if
  static analysis sees them.

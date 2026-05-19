# Design: Auth Parity Test

> **⚠️ Status banner (2026-05, revised):** the workflow schema was
> simplified, then one column was reinstated:
>
> - `Params for test with default in code` — **PRESENT** (step #5 in the
>   16-step workflow — see
>   [`connectus/workflow_state_config.yml`](workflow_state_config.yml)).
>   Briefly displayed as `Param Defaults`; the original name is now
>   restored. Its value is a JSON object mapping YML param name → default
>   value (any JSON type; `{}` is valid). The auth-parity analyzer
>   (`check_auth_parity.py`) reads this cell as the **first-precedence**
>   source for non-auth required-param values when building the test
>   payload; type-aware placeholders from `check_command_params.build_param_values`
>   remain the fallback for any param not covered by the cell. See §2.4.
> - `requires auth parity test` (the gate **flag**) — **REMOVED.**
>   `auth parity test passes` (step #13 in the current 16-step workflow
>   — see [`connectus/workflow_state_config.yml`](workflow_state_config.yml))
>   is now **unconditional**; the test is expected to be runnable on
>   every integration. There is no longer a `set-auth-flag` verb that
>   would auto-`N/A` the checkpoint. To opt out, an operator must mark
>   the checkpoint `N/A` explicitly.
>
> The body of this document below is the **original design proposal**
> and has not been rewritten line-by-line. Treat it as historical
> context; the current sources of truth are:
>
> - [`connectus/workflow_state_config.yml`](workflow_state_config.yml) — current YAML schema (14 steps).
> - [`connectus/column-schemas.md`](column-schemas.md) — current JSON-valued column shapes.
> - [`connectus/Readme.md`](Readme.md) — current CLI and step table.
> - [`connectus/workflow_state_DESIGN.md`](workflow_state_DESIGN.md) §12 — schema-change decision log.

## Purpose

Verify that for each **non-interpolated** connection declared in an
integration's `Auth Details`, the secret values end up in the **same
place** on every outgoing HTTP request regardless of whether they were
supplied the "old way" (via [`demisto.params()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9736) →
integration code → [`BaseClient`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9703)) or the
"new way" (params **omitted** from `demisto.params()`, secrets
**injected by BaseClient** via the UCP credential-injection
infrastructure — [`_inject_ucp_credentials()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9919),
[`_apply_ucp_credentials()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9799),
[`get_ucp_credentials()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13849)).

"Same place" means: the same header name, query-param name, body
field, basic-auth slot, bearer-token slot, cookie, or URL-userinfo
position — byte-for-byte on the sentinel value, modulo the
canonicalization rules in [§4](#4-the-parity-comparison).

### Scope: interpolated connections are NOT in this flow

> **Hard rule:** interpolated connections (`"interpolated": true` on
> an `auth_types[]` entry) are **explicitly out of scope** for this
> test and MUST NOT be exercised.

Interpolated connections have their values templated at runtime by
the manifest generator — there is no user-supplied secret flowing
through `demisto.params()` and there is no UCP injection path to
compare against. There is nothing to grep for and nothing to diff.
The "old path" and "new path" do not meaningfully exist for these
entries.

This has two consequences the harness MUST enforce:

1. **Per-connection skip.** Any individual `auth_types[]` entry with
   `interpolated: true` is reported as
   `"status": "skipped_interpolated"` and **no run is attempted** for
   it. No sentinels are generated, no proxy session is opened, no
   integration code is loaded on its behalf.
2. **All-interpolated short-circuit ⇒ step is migrated.** If
   **every** `auth_types[]` entry is interpolated, the parity
   question is vacuous: there is no legacy-vs-UCP code path to
   compare because there is no integration-resident auth code in the
   picture at all. We can safely treat step #11 (`auth parity test
   passes`) as **migrated**. The tool emits `ERROR_ALL_INTERPOLATED`
   (exit 12) with a message the migration skill recognizes as "this
   step is effectively migrated — just `markpass` step #11". See
   [§5.5](#55-error-codes--hard-errors) and
   [§5.6](#56-skill-error-handling).

### What a parity FAILURE means (and the "interpolated as last resort" escape hatch)

A reported `fail` from this test is a **strong signal** that the
integration's auth code is genuinely diverging between the legacy
path and the UCP injection path. The expected response, in order of
preference:

1. **Fix the integration code.** Adjust the integration so that the
   UCP injection path lands the secret in the same wire location as
   the legacy path. This is the correct outcome the overwhelming
   majority of the time.
2. **Fix the UCP shape / `_apply_ucp_*` override.** If the mismatch
   is in CommonServerPython's injection mapping for this auth type,
   fix it there.
3. **Last resort — and only with explicit reviewer sign-off:** mark
   the offending `auth_types[]` entry as `"interpolated": true`. This
   is an escape hatch, not a routine fix; it means "we are giving up
   on automated parity verification for this connection and handing
   it to the manifest-generated runtime template instead."

When the skill takes path (3), it MUST reset workflow state back to
the `Auth Details` step (#5) so the downstream steps that depend on
auth details — manifest generation in particular — are re-run from
the corrected auth shape. The exact reset procedure is documented in
[§5.6](#56-skill-error-handling).

### Non-goals

| # | Non-goal | Why |
|---|----------|-----|
| 1 | Checking parameter correctness / coverage | That is [`check_command_params.py`](connectus/check_command_params.py:1)'s job. |
| 2 | Checking that the API actually accepts the request | The test only inspects the **request** side; responses are canned. |
| 3 | Validating `interpolated: true` connections | **Explicitly out of scope — see the "Scope" section above.** Interpolated connections have their values templated at runtime by the manifest generator; there is no user-supplied secret flowing through `demisto.params()` and no UCP injection path to compare. The harness MUST NOT generate sentinels, open a proxy session, or load integration code for an interpolated entry. The tool emits `ERROR_ALL_INTERPOLATED` (treated by the skill as "step migrated, `markpass`") when every connection is interpolated, or `"skipped_interpolated"` per-connection when only some are (see [§5.5](#55-error-codes--hard-errors)). |
| 4 | Validating `other_connection` values (URL, proxy, insecure, …) | Only auth secrets (XSOAR paths keyed in `auth_types[].xsoar_param_map`) are in scope. Connection metadata is orthogonal. |
| 5 | Non-Python integrations or integrations without `BaseClient` | **Hard error, not a skip.** The tool emits `ERROR_NON_PYTHON` or `ERROR_NO_BASECLIENT` and exits immediately. The migration skill must mark the affected connections as `"interpolated": true` and re-run `set-auth`. See [§5.5](#55-error-codes--hard-errors). |

---

## 1. Inputs

> **Architecture rule (2026-05).** The analyzer is **stateless** with
> respect to the workflow CSV. It does NOT shell out to
> `workflow_state.py show-step`, does NOT import the `workflow_state`
> package, and does NOT read `connectus-migration-pipeline.csv`. All
> pipeline-cell inputs are passed in by the orchestrator (the
> connectus-migration skill) via dedicated CLI flags. The skill is the
> single layer that knows the integration id → cell mapping; the
> analyzer is a pure transformation of YML + source + injected cells.
> See §5.1 for the flag surface.

| Input | Source | Purpose |
|-------|--------|---------|
| Integration directory | CLI positional arg (same as [`check_command_params.py`](connectus/check_command_params.py:1)) | Locate YML + Python source. |
| `Auth Details` cell | **Passed in** via `--auth-details <json>` / `--auth-details-file <path>` (mutually exclusive; one is required). The orchestrator reads it once with `workflow_state.py show-step --raw "<id>" "Auth Details"`. | Provides `auth_types[]` with `xsoar_param_map`, `interpolated`, `name`, `type`, and the `config` expression — parsed into typed [`AuthDetails`](connectus/auth_config_parser/types.py:102) / [`AuthEntry`](connectus/auth_config_parser/types.py:52) dataclasses inside the analyzer. |
| `Params for test with default in code` cell | **Passed in** via `--param-defaults <json>` / `--param-defaults-file <path>` (mutually exclusive; both optional, default `{}`). The orchestrator reads it once with `workflow_state.py show-step --raw "<id>" "Params for test with default in code"`. | Supplies throwaway defaults for non-auth required params so the integration can start. |
| `Params to Commands` cell | Not consumed by this analyzer (the test picks commands directly per [Command selection strategy](#command-selection-strategy) below). | — |
| Integration ID | CLI arg `--integration-id` | Identifier for log/diagnostic messages and a fallback for the top-level `integration` field in the output JSON. **Not** used to look up workflow state. |
| Display name (optional) | CLI arg `--display-name <str>` | Human-readable name for the output `integration` field. Falls back to YML `display`, then to `--integration-id`. |

### Command selection strategy

The test must exercise at least:

1. **`test-module`** — always present, always exercises the primary
   auth path.
2. **One representative command per distinct auth-bearing code path.**
   In practice, most integrations use a single `Client` constructed
   once in `main()`, so `test-module` alone covers the auth surface.
   However, integrations with multiple `Client` instances or
   per-command auth overrides (e.g. a `fetch-events` command that uses
   a different token than `test-module`) need additional commands.

**Heuristic:** start with `test-module`. If the `Params to Commands`
cell shows commands whose param lists include auth-adjacent params not
present in `test-module`'s list, add those commands. If no such
commands exist, `test-module` alone is sufficient. The analyzer can
also accept `--commands cmd1 cmd2 ...` for manual override.

---

## 2. The two runs — old vs new

For each non-interpolated `auth_types[]` entry (call it **connection
C**):

### 2.1 Old run (legacy path)

Build a `demisto.params()` dict that includes C's `xsoar_param_map`
keys populated with **distinguishable sentinel values**. Non-auth
required params are filled from `Params for test with default in
code` plus a generic placeholder pass. Run the selected command(s)
under [`capture_proxy.py`](connectus/capture_proxy.py:1). Record
every captured outgoing request.

### 2.2 New run (UCP injection path)

Build a `demisto.params()` dict that **omits** every key in C's
`xsoar_param_map` entirely (iterate `entry.xsoar_param_map.keys()`
and drop each one from the seeded params). Instead, patch the UCP
injection seam so that
[`get_ucp_credentials()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13849)
returns a credential dict containing the **same sentinel values**,
routed through the appropriate type envelope. Run the same command(s)
under [`capture_proxy.py`](connectus/capture_proxy.py:1). Record
every captured outgoing request.

### 2.3 Sentinel value generation

One sentinel is generated per `(xsoar_path, role)` pair from the
connection's `xsoar_param_map` — i.e. per `(key, value)` item of
the map. Encoding both the XSOAR path AND the role into the
sentinel value makes the captured request trivially attributable
when grepping: the diff comparator can recover both "which XSOAR
field?" (path) and "which UCP role?" (e.g. `key`, `username`,
`password`, `client_secret`) from the matched sentinel alone.

```
__AUTHPARITY__<connection_name>__<xsoar_param_path>__<role>__<uuid8>
```

Example for a `Plain` connection named `credentials` (map:
`{"credentials.identifier": "username", "credentials.password": "password"}`):

```
__AUTHPARITY__credentials__credentials.identifier__username__a1b2c3d4
__AUTHPARITY__credentials__credentials.password__password__e5f6g7h8
```

Example for an `APIKey` connection named `credentials` with
`hiddenusername: true` (map: `{"credentials.password": "key"}`) —
note only one sentinel is generated because the suppressed
`.identifier` leaf is not a map key:

```
__AUTHPARITY__credentials__credentials.password__key__c3d4e5f6
```

Properties:
- **Unique per `(xsoar_path, role)` pair** — so we can disambiguate
  which secret landed where even when multiple secrets share a
  header, AND we know at grep-time which UCP role each sentinel
  was meant to fill.
- **Long enough** (≥40 chars) to be unambiguous in grep.
- **ASCII-safe** — no characters that would be mangled by URL-encoding
  or base64 in ways that hide the sentinel.
- The `uuid8` suffix is 8 hex chars from `uuid.uuid4().hex[:8]`,
  regenerated per test run.

> **Why this changed (2026-05).** Previously the tool used a
> **leaf-name heuristic** to pick where each sentinel belonged in
> the UCP envelope — it looked at the suffix of the XSOAR path
> (`.identifier` → username slot, `.password` → password slot) and
> guessed. That heuristic broke in two ways:
>
> 1. For non-credentials-widget cases (e.g. a `Plain` auth backed
>    by two flat params `server_user` + `server_password`), there
>    are no `.identifier` / `.password` suffixes and the heuristic
>    had no signal to work with.
> 2. For `APIKey` integrations where the YML credentials widget
>    has `hiddenusername: true`, the secret sits at
>    `<id>.password` but its UCP role is `"key"`, not `"password"`.
>    A leaf-name heuristic would mis-route it.
>
> The explicit `xsoar_param_map` removes the guess: the classifier
> writes down the role directly, and the parity test reads it.

### 2.4 Non-auth param filling

1. Read `Params for test with default in code` — use those values
   verbatim.
2. For any remaining required YML param not in the ignore set and not
   an auth param: seed with a type-aware placeholder (reuse the
   coercion logic from
   [`check_command_params.py`](connectus/check_command_params.py:1) —
   booleans → `True`, ints → `1`, strings → `"PLACEHOLDER_<name>"`,
   credentials → `{"identifier": "placeholder", "password":
   "placeholder"}`, etc.).
3. Param correctness is out of scope — if the integration crashes
   because a placeholder is wrong, the run is `inconclusive`, not a
   parity failure.

### 2.5 UCP injection wiring

The test harness must intercept the UCP credential-resolution chain.
The seam is [`get_ucp_credentials(method_unique_id)`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13849),
which normally delegates to `demisto.getUCPCredentials(...)`. **The
implementation patches `demisto.getUCPCredentials` directly** (the
camel-case method on the `demisto` object exposed by `demistomock`),
rather than the CSP wrapper. Patching the lower-level seam catches
both call patterns in one shot: code that goes through
[`CommonServerPython.get_ucp_credentials()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13849)
hits the mock (because the wrapper delegates to
`demisto.getUCPCredentials`), and integrations that call
`demisto.getUCPCredentials(...)` directly — bypassing the CSP wrapper —
also hit the mock.

**Contract the parity test requires from the injection hook:**

```python
def mock_get_ucp_credentials(method_unique_id: str) -> dict:
    """Return a credential dict whose secret fields contain the
    same sentinel values that the old run seeded into demisto.params().

    The dict shape depends on the auth type:

    APIKey:
        {"type": "api_key", "api_key": {"key": "<sentinel>"}}

    Plain:
        {"type": "plain", "plain": {"username": "<sentinel_id>", "password": "<sentinel_pw>"}}

    OAuth2 (any sub-type):
        {"type": "oauth2", "oauth2": {"access_token": "<sentinel>", "token_type": "Bearer"}}
    """
```

The mapping from `auth_types[].type` to credential-dict shape is:

| `auth_types[].type` | UCP `type` field | Sentinel placement |
|---------------------|------------------|--------------------|
| `APIKey` | `"api_key"` | `api_key.key` ← sentinel for the map entry whose role is `"key"` |
| `Plain` | `"plain"` | `plain.username` ← sentinel for the map entry whose role is `"username"`; `plain.password` ← sentinel for the map entry whose role is `"password"` |
| `OAuth2ClientCreds` | `"oauth2"` | `oauth2.access_token` ← sentinel for the map entry whose role names the OAuth secret (`"client_secret"`, etc. — the role enum for OAuth types is deliberately undefined for now; see [`column-schemas.md`](connectus/column-schemas.md:1) "Auth Details" § "type → allowed role values") |
| `OAuth2AuthCode` | `"oauth2"` | same as above |
| `OAuth2JWT` | `"oauth2"` | same as above |
| `Other` | varies | **skip** — see [§6 edge cases](#6-edge-cases--open-questions) |
| `NoneRequired` | n/a | no run needed |

Implementation note: `_ucp_shape_api_key()` and `_ucp_shape_plain()`
(and their OAuth counterparts) MUST select the sentinel for each UCP
slot **by role** — i.e. by looking up the map entry whose value
matches the slot — NOT by leaf-name heuristic on the XSOAR path.
This is the core behavioural change the `xsoar_param_map` migration
delivers; see the "Why this changed" note in [§2.3](#23-sentinel-value-generation).

If the exact injection API changes before this test ships, the
**contract** above is what the test needs: a function that accepts a
connection-name → sentinel-values map and returns the correctly-shaped
credential dict. The test does not depend on the internal UCP cache,
TTL, or capability-resolution logic — it short-circuits all of that.

Additionally, the harness must ensure [`is_ucp_enabled()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13671)
returns `False` for the old run and `True` for the new run, and that
[`should_use_ucp_auth()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13671)
follows suit. These two flags remain patched on `CommonServerPython`
as **branch selectors** — they decide whether the integration takes
the UCP code path at all. They are distinct from the credential
fetcher (`demisto.getUCPCredentials`, patched above): the flags
control which branch runs, while the demisto-object mock supplies
the actual credentials when the UCP branch is taken.

This controls whether integrations like
[`Salesforce_IAM`](Packs/Salesforce/Integrations/Salesforce_IAM/Salesforce_IAM.py:42)
take the legacy `get_access_token_()` path or the UCP path.

### 2.6 Network mocking

Requests must be allowed to leave the integration code but MUST be
intercepted before hitting the real API.
[`capture_proxy.py`](connectus/capture_proxy.py:1) already does this:
it accepts any HTTP method on any path, returns `200 {}`, and records
the full request (method, path, query, headers, body, timestamp).

The integration's `url` / `base_url` param is pointed at
`http://localhost:<proxy_port>` so all traffic routes through the
proxy. Responses are canned/empty; the test only inspects the
**request** side.

### 2.7 Execution model

This section describes how the harness loads integration code, wires
the proxy, injects sentinels, and handles crashes. The pattern mirrors
[`check_command_params.py`](connectus/check_command_params.py:1)'s
dynamic phase.

#### 2.7.1 How the integration code is loaded

The harness uses the same content-preparation pipeline as
[`check_command_params.py`](connectus/check_command_params.py:1):

1. **Prepend [`demistomock.py`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:1)**
   — provides the `demisto` object with `.params()`, `.command()`,
   `.args()`, etc. The harness patches these to return controlled
   values (see [§2.7.2](#272-how-the-proxy-is-wired-in)).
2. **Prepend [`CommonServerPython.py`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:1)**
   — provides [`BaseClient`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9703),
   UCP injection functions, and the rest of the runtime.
3. **Run `demisto-sdk prepare-content -i <path>`** — inlines API
   modules (e.g. `MicrosoftApiModule`, `AWSApiModule`).
4. **Result:** a single unified `.py` file that can be imported and
   executed standalone.

The unified file is loaded via
[`importlib.util.spec_from_file_location()`](connectus/check_command_params.py:2650)
as module `"integration_under_test"`, then executed with
[`spec.loader.exec_module(module)`](connectus/check_command_params.py:2656).
After import, `return_error` is patched to exit with a distinct code
(`RC_RETURN_ERROR_PATCHED = 7`) so errors are observable. Finally,
[`module.main()`](connectus/check_command_params.py:2677) is called.

Params are seeded **before import** via env vars
(`CHECK_PARAMS_JSON`, `CHECK_COMMAND`) read by the on-disk
`demistomock.py` mock — this is critical for integrations whose
`Client(...)` is constructed at import time and reads params during
construction (the pre-import param seeding pattern from
[`check_command_params.py`](connectus/check_command_params.py:2640)).

#### 2.7.2 How the proxy is wired in

Since the auth parity test **requires** [`BaseClient`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9703)
usage, proxy wiring is simpler than in
[`check_command_params.py`](connectus/check_command_params.py:2889):

1. **URL rewriting:** The `url` param in `demisto.params()` is set to
   `http://127.0.0.1:<proxy.port>`. Since we require `BaseClient`,
   this covers all HTTP traffic — `BaseClient.__init__` stores
   [`self._base_url = base_url`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9746)
   from the `url` param, and all subsequent
   [`_http_request()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:10186)
   calls use `urljoin(self._base_url, url_suffix)`.

2. **Insecure flag:** Set `demisto.params()["insecure"] = True` so
   `BaseClient.__init__` calls
   [`skip_cert_verification()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9764)
   and does not reject the plain HTTP connection.

3. **No `HTTP_PROXY` env var needed.** Unlike
   [`check_command_params.py`](connectus/check_command_params.py:2889)
   which sets `HTTP_PROXY` / `HTTPS_PROXY` env vars to catch traffic
   from non-BaseClient code paths, the auth parity test does NOT need
   this — we require `BaseClient`, so URL rewriting is sufficient.
   This avoids the `boto3` proxy-bypass problem entirely.

#### 2.7.3 Sentinel injection — old vs new run

For each `(connection, command)` pair, the harness executes two runs:

- **Old run:** Sentinels are placed directly into `demisto.params()`
  at the XSOAR field paths that are keys of `xsoar_param_map` (see
  [§2.1](#21-old-run-legacy-path)). UCP is disabled:
  `is_ucp_enabled() → False`.
- **New run:** Every key in `xsoar_param_map` is **omitted** from
  `demisto.params()` (the implementation iterates
  `entry.xsoar_param_map.keys()` and drops each path). Sentinels are
  injected via the UCP mock (see [§2.5](#25-ucp-injection-wiring))
  with each sentinel routed to the UCP slot named by its role. UCP
  is enabled: `is_ucp_enabled() → True`,
  `should_use_ucp_auth() → True`.

Both runs use the same sentinel values so the location comparison
is meaningful.

#### 2.7.4 Sequence diagram — one connection, one command

```
Harness                    Proxy                Integration
  |                          |                       |
  |-- start proxy ---------->|                       |
  |<-- port=P ---------------|                       |
  |                          |                       |
  |== OLD RUN =======================================|
  |                          |                       |
  |-- new_session() -------->|                       |
  |<-- sid_old --------------|                       |
  |                          |                       |
  |-- seed params:                                   |
  |   url=http://127.0.0.1:P                         |
  |   insecure=True                                  |
  |   xsoar_param_map keys=sentinels                 |
  |   is_ucp_enabled=False                           |
  |                          |                       |
  |-- load unified .py ----->|                       |
  |-- call main() --------->                    ---->|
  |                          |<-- HTTP req 1 --------|
  |                          |--- 200 {} ----------->|
  |                          |<-- HTTP req 2 --------|
  |                          |--- 200 {} ----------->|
  |<-- main() returns / crashes                      |
  |                          |                       |
  |-- get_requests(sid_old)->|                       |
  |<-- old_requests ---------|                       |
  |                          |                       |
  |== NEW RUN =======================================|
  |                          |                       |
  |-- new_session() -------->|                       |
  |<-- sid_new --------------|                       |
  |                          |                       |
  |-- seed params:                                   |
  |   url=http://127.0.0.1:P                         |
  |   insecure=True                                  |
  |   xsoar_param_map keys=OMITTED                   |
  |   is_ucp_enabled=True                            |
  |   demisto.getUCPCredentials=mock with sentinels  |
  |     (routed by role)                             |
  |                          |                       |
  |-- load unified .py ----->|                       |
  |-- call main() --------->                    ---->|
  |                          |<-- HTTP req 1 --------|
  |                          |--- 200 {} ----------->|
  |                          |<-- HTTP req 2 --------|
  |                          |--- 200 {} ----------->|
  |<-- main() returns / crashes                      |
  |                          |                       |
  |-- get_requests(sid_new)->|                       |
  |<-- new_requests ---------|                       |
  |                          |                       |
  |== COMPARE =======================================|
  |                          |                       |
  |-- extract_locations(old_requests, sentinels)      |
  |-- extract_locations(new_requests, sentinels)      |
  |-- locations_old == locations_new?                 |
  |   YES -> PASS                                    |
  |   NO  -> FAIL + classify diffs                   |
```

#### 2.7.5 Crash handling

When the integration crashes during a run (old or new):

1. **Capture the exception** — record the traceback in
   `diagnostics.<connection>.<command>.<run>.stderr_excerpt`.
2. **Emit `"inconclusive"`** for that command — do NOT treat it as a
   parity failure.
3. **Do NOT abort the entire run.** Other commands for the same
   connection, and other connections, continue independently. This
   mirrors [`check_command_params.py`](connectus/check_command_params.py:1)'s
   per-command exception isolation (Fix #1 in the implementation
   status).

---

## 3. Invariants

For each non-interpolated connection C and each exercised command:

> **Parity invariant:** For every sentinel value S generated for C's
> `xsoar_param_map` entries, the set of locations where S appears in
> the old run's captured requests MUST equal the set of locations where S
> appears in the new run's captured requests.

A "location" is a structured path — see [§4](#4-the-parity-comparison).

---

## 4. The parity comparison

### 4.1 Location taxonomy

For each captured request, extract the **locations** where each
sentinel value appears. A location is one of:

| Location type | Format | Example |
|---------------|--------|---------|
| HTTP header (raw) | `header:<name>` | `header:X-Api-Key` |
| HTTP header (Bearer) | `header:Authorization:Bearer` | Bearer token body |
| HTTP header (Basic — user slot) | `header:Authorization:Basic:user` | Decoded user from `Basic <b64>` |
| HTTP header (Basic — pass slot) | `header:Authorization:Basic:pass` | Decoded pass from `Basic <b64>` |
| HTTP header (Token/custom prefix) | `header:Authorization:<prefix>` | e.g. `Token`, `SSWS` |
| Query parameter | `query:<name>` | `query:api_key` |
| JSON body field | `body.json:<dotted.path>` | `body.json:auth.client_secret` |
| Form body field | `body.form:<name>` | `body.form:client_id` |
| URL userinfo | `url.userinfo:user` or `url.userinfo:pass` | `https://user:pass@host/` |
| Cookie | `cookie:<name>` | `cookie:session_token` |

### 4.2 Canonicalization rules

To avoid false failures from cosmetic differences:

1. **Header name case:** case-insensitive comparison (normalize to
   lowercase).
2. **Basic auth:** decode the `Basic` header's base64 payload and
   compare the user and password slots independently — never compare
   the raw base64 blob.
3. **Bearer / Token / custom prefixes:** strip the scheme prefix
   (e.g. `Bearer `, `Token `, `SSWS `), compare the token body only.
   The prefix itself is recorded in the location type for diagnostic
   purposes but is not part of the parity check on the sentinel value.
4. **Multiple requests in a run:** compare as **multisets** keyed by
   `(method, url_path_template, location)`. The same auth header
   appearing on every request in both runs is fine; appearing in old
   but not new (or vice versa) is a fail.
5. **Order of headers / query params:** irrelevant. Location sets are
   unordered.
6. **URL-encoding:** sentinels are ASCII-safe by design, but if a
   sentinel appears URL-encoded in a query string, decode before
   comparison.

### 4.3 Building location sets

For each run (old, new) and each sentinel S:

```
locations(S) = {
    (method, url_path, location_type)
    for request in captured_requests
    for location_type in extract_locations(request, S)
}
```

Where `url_path` is the request path with the proxy host stripped
(e.g. `/api/v1/health`). Query-string parameters are NOT part of
`url_path` — they are captured as `query:<name>` locations.

### 4.4 Parity verdict

The integration **passes parity** for connection C iff for every
sentinel S generated for C:

```
locations_old(S) == locations_new(S)
```

### 4.5 Failure taxonomy

| Code | Meaning | Severity |
|------|---------|----------|
| `MISSING_IN_NEW` | Sentinel appeared in old request at location L, not in new at L. | **Fail** — the new path lost a secret placement. |
| `EXTRA_IN_NEW` | Sentinel appeared in new at location L, not in old. | **Fail** — the new path added an unexpected secret placement. |
| `WRONG_LOCATION` | Sentinel present in both runs but at different locations. Special case combining the above two; surfaced explicitly because it is the most diagnostic. | **Fail** |
| `MISSING_IN_BOTH` | Sentinel never appeared in any captured request for this command. | **Diagnostic only** — the command may not exercise that connection (fine), or the integration may be dead (note it). Not a parity failure. |
| `RUN_FAILED_OLD` | The integration crashed before issuing any request in the old run. | **Inconclusive** |
| `RUN_FAILED_NEW` | The integration crashed before issuing any request in the new run. | **Inconclusive** |
| `NO_REQUESTS_CAPTURED` | Ran cleanly but issued zero HTTP calls. | **Inconclusive** |

### 4.6 Diff comparator — user-visible identifier

Sentinels now encode both the **XSOAR path** and the **role** (see
[§2.3](#23-sentinel-value-generation)), but the user-visible identifier
in diff reports — the `"sentinel"` field of each entry in
`diagnostics.<connection>.<command>.diffs[]` and any human-readable
rendering of a failure — is still the **XSOAR path** (e.g.
`"credentials.password"`, not `"credentials.password__password"`). This
keeps reports byte-compatible with the pre-2026-05 output so operators
reading a failure can locate the offending YML field the same way they
always have. The role is available in `diagnostics` for tooling that
wants it, but it is not the primary label.

---

## 5. CLI / output shape

### 5.1 Invocation

```bash
python3 connectus/check_auth_parity.py <integration_dir> \
    --integration-id "<Integration ID>" \
    (--auth-details '<json>' | --auth-details-file <path>) \
    [--param-defaults '<json>' | --param-defaults-file <path>] \
    [--display-name "<Human Name>"] \
    [--commands cmd1 cmd2 ...] \
    [--connection <connection_name>] \
    [--timeout SECONDS] \
    [--docker {auto,always,never}] \
    [--docker-image <ref>] \
    [--use-integration-docker]
```

Mostly mirrors [`check_command_params.py`](connectus/check_command_params.py:4206)'s
CLI surface, with one architectural difference: this analyzer takes
its pipeline-cell inputs as CLI args rather than looking them up. The
orchestrator (the connectus-migration skill) is the layer that knows
the `Integration ID -> cell` mapping; the analyzer is a pure
transformation. See §1 for rationale.

Flag semantics (the cell-input flags are the new surface; the rest is
unchanged):

- **`--integration-id`** (required) — identifier for log messages and
  fallback `integration` field. NOT used for any CSV lookup.
- **`--auth-details` / `--auth-details-file`** (mutually exclusive,
  **one is required**) — raw JSON of the `Auth Details` cell. Inline
  takes a single quoted string; the file flag takes a path. Inline
  accepts `-` to read from stdin. Empty input is a hard error
  (argparse-level, exit 2) — there is no silent default.
- **`--param-defaults` / `--param-defaults-file`** (mutually exclusive,
  both optional) — raw JSON of the `Params for test with default in
  code` cell. Same shape as the auth flags. Empty input or omission
  both default to `{}`.
- **`--display-name`** (optional) — overrides the `integration` field
  in the output JSON. Falls back to YML `display`, then
  `--integration-id`.
- **`--connection`** (optional) — restricts the test to a single
  `auth_types[].name` (useful when re-running after removing an
  interpolated connection from the test).

The orchestrator invocation pattern is:

```bash
AUTH=$(python3 connectus/workflow_state.py show-step --raw "<id>" "Auth Details")
DEFAULTS=$(python3 connectus/workflow_state.py show-step --raw "<id>" "Params for test with default in code")
python3 connectus/check_auth_parity.py Packs/.../Integrations/<Name> \
    --integration-id "<id>" \
    --auth-details "$AUTH" \
    --param-defaults "${DEFAULTS:-{}}"
```

The `--raw` flag on `show-step` is the machine-consumer contract — see
[`workflow_state.cli.cmd_show_step`](workflow_state/cli.py:1). It
prints the cell value verbatim with no decorative header or
flag-default substitution.

### 5.2 Stdout JSON shape

```json
{
  "integration": "<display name>",
  "auth_parity": {
    "<connection_name>": {
      "status": "pass | fail | skipped_interpolated | skipped_other_type | skipped_signed | skipped_mtls | inconclusive",
      "commands": {
        "<command>": "pass | fail | inconclusive"
      }
    }
  },
  "diagnostics": {
    "<connection_name>": {
      "sentinels": {
        "<xsoar_param_path>": "<sentinel_value>"
      },
      "commands": {
        "<command>": {
          "old_run": {
            "status": "ok | crashed | no_requests",
            "captured_request_count": 3,
            "locations": {
              "<sentinel>": ["header:authorization:bearer", "..."]
            },
            "stderr_excerpt": "..."
          },
          "new_run": {
            "status": "ok | crashed | no_requests",
            "captured_request_count": 3,
            "locations": {
              "<sentinel>": ["header:authorization:bearer", "..."]
            },
            "stderr_excerpt": "..."
          },
          "diffs": [
            {
              "sentinel": "<xsoar_param_path>",
              "failure_code": "MISSING_IN_NEW | EXTRA_IN_NEW | WRONG_LOCATION | MISSING_IN_BOTH",
              "old_locations": ["header:authorization:bearer"],
              "new_locations": []
            }
          ],
          "request_set_diff": {
            "only_in_old": [{"method": "POST", "path": "/oauth/token"}],
            "only_in_new": []
          }
        }
      }
    }
  }
}
```

### 5.3 Diagnostics stripping rule

Same convention as [`check_command_params.py`](connectus/check_command_params.py:1):

> ⚠️ **The `diagnostics` field MUST be stripped before persisting.**
> It is internal signal for the migration skill's decision-making.
> The persisted artifact contains only `integration` and
> `auth_parity`.

### 5.4 Persisted result — proposed column and setter

**Recommendation:** use the existing workflow step **#13 `auth parity
test passes`** (a checkpoint, not a data column). The parity test's
`auth_parity` JSON is consumed by the AI to decide whether to
`markpass` or `fail` step #13. There is no need for a new CSV column —
the JSON output is ephemeral (like `check_command_params.py`'s output
is ephemeral before being distilled into `Params to Commands`).

The workflow interaction is:

1. Run `check_auth_parity.py` → JSON to stdout.
2. AI reads `auth_parity` → all connections `pass` or
   `skipped_interpolated`?
   - **Yes** →
     `python3 connectus/workflow_state.py markpass "<id>" "auth parity test passes"`
   - **No** → investigate failures, fix code, re-run.

> **Schema note (2026-05):** the `requires auth parity test` gate
> column was removed; step #11 (`auth parity test passes`) is
> unconditional. The harness still short-circuits via
> `ERROR_ALL_INTERPOLATED` when every connection is interpolated —
> the skill treats that exit code as "step migrated, `markpass`",
> which is the modern equivalent of the old `requires auth parity
> test = NO` branch.

### 5.5 Error codes — hard errors

The tool's scope is **strictly** Python integrations that use
[`BaseClient`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9703).
Everything outside this scope produces a **hard error** (not a skip,
not inconclusive) with a specific error code. The error is reported
as a top-level `"error"` key in the JSON output (consistent with
[`check_command_params.py`](connectus/check_command_params.py:1)'s
pattern of emitting structured JSON on stdout even for failures) and
a non-zero process exit code.

| Error code | Exit code | Detection | Error message |
|------------|-----------|-----------|---------------|
| `ERROR_NON_PYTHON` | `10` | YML `script.type` is not `python` / `python3`, or the integration directory contains no `.py` file (only `.js` or `.ps1`). | `"Auth parity test only supports Python integrations. This integration is <language>. Mark its auth as interpolated if it cannot use BaseClient injection."` |
| `ERROR_NO_BASECLIENT` | `11` | The integration is Python but its `.py` file does not import or instantiate `BaseClient` (or a subclass). Detection: statically check whether the source contains `class <Name>(BaseClient)`, `BaseClient(`, or `from CommonServerPython import ... BaseClient`. | `"Auth parity test requires BaseClient usage. This integration does not use BaseClient. Mark its auth as interpolated if it cannot use BaseClient injection."` |
| `ERROR_ALL_INTERPOLATED` | `12` | Every `auth_types[]` entry in `Auth Details` has `"interpolated": true`. | `"All auth types are interpolated. Auth parity test is not applicable — interpolated connections are handled by infrastructure, not integration code. Step #11 (auth parity test passes) is effectively migrated — markpass."` |
| `ERROR_CONNECTION_INTERPOLATED` | `13` | A specific connection name was requested via `--connection <name>` but that connection has `"interpolated": true`. | `"Connection '<name>' is interpolated. Auth parity test only applies to non-interpolated connections. Remove the interpolated flag or skip this connection."` |
| `ERROR_INTEGRATION_REJECTS_HTTP` | `14` | The integration code checks that the URL starts with `https://` and rejects `http://`, causing the proxy-redirected URL to fail. Detected when the old run crashes with an error message containing `http://` or `https` and `scheme`/`protocol`. | `"Integration rejects HTTP URLs. Auth parity test requires BaseClient URL rewriting to http://. Mark its auth as interpolated if it cannot use BaseClient injection."` |

**JSON shape on hard error:**

```json
{
  "integration": "<display name>",
  "error": {
    "code": "ERROR_NON_PYTHON",
    "message": "Auth parity test only supports Python integrations. This integration is javascript. Mark its auth as interpolated if it cannot use BaseClient injection.",
    "exit_code": 10
  }
}
```

**Partial interpolation** (some `auth_types[]` entries are
interpolated, some are not) is **NOT** an error. The tool runs parity
checks only on the non-interpolated entries and reports
`"skipped_interpolated"` for the interpolated ones in the
`auth_parity` output. This is the one case where a skip status is
acceptable — because the tool IS running, just not for those specific
connections.

### 5.6 Skill error handling

When the migration skill (in
[`connectus/connectus-migration-SKILL.md`](connectus/connectus-migration-SKILL.md))
encounters these error codes, it must react as follows:

#### `ERROR_NON_PYTHON` or `ERROR_NO_BASECLIENT` or `ERROR_INTEGRATION_REJECTS_HTTP`

These three errors mean "this integration cannot be exercised by the
parity harness at all." The harness has no way to verify the legacy
vs UCP wire output, so the affected connections must be treated as
**non-testable** and re-classified as interpolated so the
manifest-generator path takes over.

This is the **"interpolated as last resort"** path described in the
Purpose section — it is not the routine response to a parity
mismatch. It only fires when the harness itself cannot run.

Skill procedure:

1. **Reset workflow state** back to the `Auth Details` step (#5)
   using
   `python3 connectus/workflow_state.py reset "<id>" "Auth Details"`
   (or the equivalent `goto`/rewind verb in the current CLI). The
   reset is **required** because changing auth details invalidates
   every downstream step that consumes them — manifest generation,
   the parity test itself, etc. The skill must not attempt to
   `markpass` step #11 on top of stale downstream state.
2. **Re-run `set-auth`** with all `auth_types[]` entries for the
   affected connections changed to `"interpolated": true`.
3. **Re-run manifest generation** (since auth details changed).
4. **Continue the workflow from step #5 forward.** When the parity
   step (#11) is reached again, it will short-circuit on
   `ERROR_ALL_INTERPOLATED` (assuming all entries are now
   interpolated) and `markpass` cleanly.

The error messages are designed to be parseable by the skill — they
contain the literal string `"Mark its auth as interpolated"` as a
signal. The skill should pattern-match on this substring to trigger
the interpolation-and-retry flow.

#### `ERROR_ALL_INTERPOLATED` — the "step is migrated" signal

This error code is the harness's way of telling the skill **"step
#11 is effectively migrated, just `markpass` it."** It is not a
failure. It means every `auth_types[]` entry is interpolated, so
there is no integration-resident auth code left to compare against
the UCP injection path — the parity question is vacuous and the
checkpoint is satisfied by definition.

Skill procedure:

```bash
python3 connectus/workflow_state.py markpass "<id>" "auth parity test passes"
```

No reset, no re-run, no investigation. Move on to the next step.

#### `ERROR_CONNECTION_INTERPOLATED`

The skill should remove that connection from the test invocation and
retry with only non-interpolated connections. If no non-interpolated
connections remain after removal, treat as `ERROR_ALL_INTERPOLATED`
(i.e. `markpass` step #11).

#### `fail` verdict on a non-interpolated connection (the normal failure)

A `fail` from a connection that actually ran is the test working as
intended. The skill must **not** immediately reach for the
`interpolated: true` escape hatch. The correct order is:

1. Read the `diagnostics.<connection>.<command>.diffs` and
   `request_set_diff` blocks to localize the mismatch.
2. Attempt a code fix in the integration (or the relevant
   `_apply_ucp_*` mapping in CommonServerPython).
3. Re-run the parity test.
4. **Only if a code fix is genuinely infeasible** — e.g. the auth
   shape cannot be expressed through the standard UCP injection
   path and the integration owner declines to refactor — fall back
   to marking the offending entry as `"interpolated": true`. This
   triggers the same reset-to-Auth-Details flow described above.
   This branch should be rare and should be called out explicitly in
   review.

### 5.7 Pre-emptive interpolation at the `Auth Details` step

The skill should not wait for the parity step (#11) to discover that
an integration is fundamentally untestable. At the **`Auth Details`
step (#5)** the skill already knows enough to short-circuit the
parity test entirely by classifying everything as interpolated up
front:

> **Rule for the `Auth Details` step:** if the integration is
> **non-Python** *or* does **not use `BaseClient`** (statically
> detectable from the YML `script.type` and a grep of the `.py`
> source for `BaseClient`), the skill should default **every**
> `auth_types[]` entry to `"interpolated": true`. Manifest
> generation then templates the values at runtime and step #11
> short-circuits to `markpass` via `ERROR_ALL_INTERPOLATED`.

Detection (mirrors the harness's own checks in [§5.5](#55-error-codes--hard-errors)):

| Trigger | How the skill detects it at step #5 |
|---------|--------------------------------------|
| Non-Python integration | YML `script.type` ∉ {`python`, `python3`} |
| Python without `BaseClient` | `.py` source contains no `class <Name>(BaseClient)`, no `BaseClient(`, and no `BaseClient` symbol imported from `CommonServerPython` |
| HTTPS-only enforcement (likely `ERROR_INTEGRATION_REJECTS_HTTP` candidate) | `.py` source rejects URLs not starting with `https://` |

Rationale: these are the exact conditions under which the parity
harness will later refuse to run. Discovering them at step #5
instead of step #11 avoids an unnecessary
reset-to-`Auth Details`-and-retry cycle. The harness still emits
`ERROR_NON_PYTHON` / `ERROR_NO_BASECLIENT` /
`ERROR_INTEGRATION_REJECTS_HTTP` as a backstop, but in the happy
path the skill prevents those errors from ever being reached.

This is a **default**, not a hard requirement — if a reviewer
explicitly wants to attempt non-interpolated auth on a non-Python or
non-BaseClient integration (e.g. because it is being migrated to
BaseClient as part of the same change), they can override the
default and let the parity step fail naturally.

---

## 6. Edge cases & open questions

### 6.1 `CHOICE(a, b)` configs

Run parity for **each branch independently**. A `CHOICE` means the
user picks one of several connection types at configuration time. The
parity test must verify that whichever branch the user picks, the
secrets land in the same place under old vs new. Each branch gets its
own `auth_parity["<connection_name>"]` entry.

### 6.2 `REQUIRED(a) + OPTIONAL(b)`

Test the optional connection **when it is non-interpolated**. Run it
as a separate parity check with its own sentinel set. The optional
auth is activated by seeding the keys of its `xsoar_param_map` (old
run) or injecting its UCP credentials (new run) — independently of
the required connection's run. This avoids conflating the two
connections' sentinel locations.

If the optional connection's `xsoar_param_map` keys overlap with the
required connection's (same XSOAR field backing both), the sentinels
will
differ between the two runs (each run generates fresh UUIDs), so
there is no cross-contamination.

### 6.3 Signed requests (HMAC, AWS SigV4)

The sentinel will **not** appear verbatim in the `Authorization`
header — it is consumed as an input to a signing function whose output
is a derived signature.

**Recommendation: skip with `status: "skipped_signed"`.**

Rationale: the parity test's core mechanism is sentinel-grep. For
signed auth, the sentinel is an input to a one-way function; the
output is not greppable. Comparing derived signatures would require
the test to replicate the signing algorithm, which defeats the purpose
of a black-box parity check. These integrations are better verified
by a targeted unit test that asserts the signing inputs are identical.

Detection: integrations classified as `APIKey` whose code imports
`hmac`, `hashlib.sha256` for signing, `botocore`, `AWSApiModule`, or
Akamai EdgeGrid patterns. The analyzer can flag these statically.

### 6.4 mTLS / cert-key auth (YML type 14)

The "secret" is a PEM certificate/key. It typically lands in the TLS
handshake, not in the HTTP request body or headers.
[`capture_proxy.py`](connectus/capture_proxy.py:1) operates at the
HTTP layer and does **not** surface TLS client-certificate
negotiation.

**Recommendation: skip with `status: "skipped_mtls"`.**

The limitation is structural — the capture proxy would need to be
replaced with a TLS-terminating MITM proxy to observe client certs,
which is a significant complexity increase for a rare auth type.
Document the skip and recommend a manual TLS-layer probe for these
integrations.

### 6.4.1 Multiple base URLs

Some integrations construct a second
[`BaseClient`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9703)
with a different URL (e.g. an auth endpoint vs an API endpoint, or a
graph endpoint vs a management endpoint). Since the harness sets the
`url` param to `http://127.0.0.1:<port>`, the proxy captures **all**
traffic to that address regardless of path.

The `Host` header in captured requests distinguishes the original
target — the integration typically sets `Host: api.example.com` via
[`BaseClient._headers`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9749)
or the request itself. The parity comparison uses `(method,
url_path)` tuples (see [§4.3](#43-building-location-sets)), so
requests to different paths are naturally separated even though they
all hit the same proxy port.

If the integration constructs a second `BaseClient` with a
**hardcoded** URL (not from `demisto.params()`), that traffic will
NOT reach the proxy. This is acceptable — the parity test only
covers auth paths that flow through `demisto.params()["url"]`.

### 6.4.2 HTTPS enforcement in code

If the integration code checks that the URL starts with `https://`
and rejects `http://`, the test will fail during the old run before
any HTTP request is made. This is caught as
`ERROR_INTEGRATION_REJECTS_HTTP` (see [§5.5](#55-error-codes--hard-errors))
with a specific diagnostic: `"integration_rejects_http"`.

The skill should treat this the same as `ERROR_NO_BASECLIENT` — mark
the affected connections as `"interpolated": true` and re-run
`set-auth`.

### 6.4.3 OAuth token exchange

[`BaseClient`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9703)'s
built-in OAuth methods may make a token request to an auth server
before the API call. Both old and new runs will make this request
through the proxy. The proxy returns `200 {}` which will likely cause
the OAuth flow to fail — the response lacks the expected
`access_token` field.

**Mitigation:** For OAuth2 auth types (`OAuth2ClientCreds`,
`OAuth2AuthCode`, `OAuth2JWT`), the harness should detect token-
exchange requests and return a canned OAuth response instead of the
default `200 {}`:

```json
{
  "access_token": "__AUTHPARITY__oauth_token__<connection_name>__<uuid8>",
  "token_type": "bearer",
  "expires_in": 3600
}
```

The canned `access_token` is itself a sentinel — it will appear in
subsequent API requests as a `Bearer` token, and the parity
comparison will verify it lands in the same `header:authorization:bearer`
location in both runs.

Detection: the proxy identifies a token-exchange request by matching
common OAuth token endpoint patterns (`POST` to a path containing
`/token`, `/oauth`, or `/oauth2`, with a `Content-Type:
application/x-www-form-urlencoded` body containing `grant_type`).
When matched, the proxy returns the canned response instead of
`200 {}`.

### 6.5 Cookie-based session auth (login round-trip)

The sentinel password is sent to a login endpoint, which returns a
session cookie. Subsequent requests carry the cookie, not the
password.

**Parity judgment:** compare the **login request** (where the sentinel
password appears), not the downstream requests. The downstream
requests carry a session cookie whose value is server-generated (in
our case, the proxy returns `200 {}` so there is no real cookie — but
the login request itself is where parity matters).

If the old run sends `POST /login` with `password=<sentinel>` in the
body, and the new run sends the same `POST /login` with the same
sentinel in the same body field, parity holds — even though
subsequent requests differ (no real session cookie from the proxy).

### 6.6 Integration mutates the secret before sending

Example: base64-encodes the API key, wraps it in a JWT, or hashes it
with a nonce.

**Parity here is byte-for-byte at the wire.** If the old run's
integration code does `base64(sentinel)` and the new run's
`_apply_ucp_api_key` does the same `base64(sentinel)`, the wire
values match and parity holds. If the mutation moves from integration
code to BaseClient injection, parity still holds as long as the wire
output is identical.

The sentinel will appear in the captured request in its **mutated**
form. The grep must therefore search for both the raw sentinel AND
common transformations (base64, URL-encoding). The location extractor
should:

1. Search for the raw sentinel.
2. Search for `base64(sentinel)` (both standard and URL-safe).
3. If neither is found, record `MISSING_IN_BOTH` — the mutation is
   opaque and the test cannot verify parity for this sentinel.

### 6.7 Different number of requests between old and new

Example: the new injection path skips a discovery call that the old
path made, or the new path adds a token-refresh call.

**Proposal:** align on the **union** of `(method, url_path)` tuples
from both runs. Parity-check the **intersection** only — requests
present in both runs. Report the symmetric difference as
`diagnostics.<connection>.<command>.request_set_diff`, not as a parity
failure.

Rationale: the parity test answers "do secrets land in the same
place?" — not "do both paths make the same number of calls?" A
discovery call that only the old path makes is not an auth-parity
issue; it is a behavioral difference that may be intentional.

### 6.8 `Other` auth type

Connections classified as `Other` (DeviceCode, ROPC,
ManagedIdentity, custom signing) have no standardized UCP credential
shape. The test cannot construct a meaningful
`mock_get_ucp_credentials` return value without per-integration
knowledge.

**Recommendation: skip with `status: "skipped_other_type"`.**

These connections require manual parity verification or a
per-integration test override.

### 6.9 Open questions for reviewer

1. **UCP injection seam stability.** The design assumes
   [`get_ucp_credentials()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:13849)
   is the correct seam to patch for the new run. If the injection
   architecture changes (e.g. credentials are injected at a lower
   level, or `_http_request` itself is modified to call a different
   function), the harness must be updated. **Is this seam considered
   stable for testing purposes?**

2. **OAuth2 token exchange.** In the old run, OAuth2 integrations
   typically exchange `client_id` + `client_secret` for an
   `access_token` via a token endpoint. The sentinel appears in the
   token-exchange request, not in subsequent API requests (which carry
   the exchanged token). In the new run, UCP provides the
   `access_token` directly — there is no token-exchange request.
   **Should parity be judged on the token-exchange request (old-only)
   or on the API requests (where the old run carries a real token and
   the new run carries the sentinel)?** The current design proposes
   comparing the intersection of requests (§6.7), which would skip
   the token-exchange request. Is this acceptable?

3. **Multi-connection integrations with shared `xsoar_param_map` keys.**
   When the same XSOAR field (e.g. `credentials.password`) appears as
   a key in multiple `auth_types[]` entries' `xsoar_param_map`s, the
   parity test generates
   different sentinels for each entry. But the old run can only seed
   one value into `demisto.params()["credentials"]["password"]`. **How
   should the test handle this?** Proposed: run each connection's
   parity check in isolation (separate old+new run pairs), each with
   its own sentinel. The old run seeds only the params for the
   connection under test.

4. **`_apply_ucp_*` overrides.** Integrations that override
   [`_apply_ucp_api_key()`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9855)
   or similar methods may place the credential in a non-default
   location (e.g. `X-API-Key` header instead of `Authorization:
   Bearer`). The parity test will catch this correctly (the new run
   will show the sentinel in the overridden location), but **should
   the test also verify that the override exists and is correct?** The
   current design says no — that is a code-review concern, not a
   parity concern.

5. **Batch execution.** Should the parity test support a batch mode
   (run across all integrations with `requires auth parity test =
   YES`)? If so, should it produce a summary report similar to
   [`bulk_static_results.json`](connectus/bulk_static_results.json:1)?
   The current design covers single-integration invocation only.

---

## 7. Suggested file layout

### New files

| File | Purpose |
|------|---------|
| `connectus/check_auth_parity.py` | Main analyzer script |
| `connectus/check_auth_parity_test.py` | Unit + integration tests |

### Reused files

| File | What is reused |
|------|----------------|
| [`connectus/capture_proxy.py`](connectus/capture_proxy.py:1) | HTTP capture server — session-based request recording, identical usage pattern. |
| [`connectus/check_command_params.py`](connectus/check_command_params.py:1) | Content preparation pipeline (unified `.py` assembly), Docker child execution, YML parsing, command discovery, sentinel coercion logic. |
| [`connectus/workflow_state.py`](connectus/workflow_state.py:1) | `show-step` to read `Params for test with default in code` and `Params to Commands`. |
| [`connectus/auth_config_parser/`](connectus/auth_config_parser/__init__.py:1) | [`parse_auth_details()`](connectus/auth_config_parser/parser.py:1) to parse `Auth Details` JSON into typed [`AuthDetails`](connectus/auth_config_parser/types.py:102) / [`AuthEntry`](connectus/auth_config_parser/types.py:52) dataclasses; [`auth_param_ids()`](connectus/auth_config_parser/utils.py:1) to extract XSOAR param IDs; [`validate_auth_details()`](connectus/auth_config_parser/validator.py:1) to validate the structure before use. |

### Dependencies

| Library | Purpose |
|---------|---------|
| [`auth_config_parser`](connectus/auth_config_parser/__init__.py:1) | **Canonical shared library** for parsing and validating Auth Details JSON and config expressions. Used by both [`workflow_state.py`](connectus/workflow_state.py:1) and the auth parity test tooling. Provides typed dataclasses ([`AuthDetails`](connectus/auth_config_parser/types.py:102), [`AuthEntry`](connectus/auth_config_parser/types.py:52), [`ConfigExpression`](connectus/auth_config_parser/types.py:100), [`AuthType`](connectus/auth_config_parser/types.py:11)) and pure functions ([`parse_auth_details()`](connectus/auth_config_parser/parser.py:1), [`validate_auth_details()`](connectus/auth_config_parser/validator.py:1), [`auth_param_ids()`](connectus/auth_config_parser/utils.py:1), [`auth_param_ids_with_sources()`](connectus/auth_config_parser/utils.py:1)). |

### Module structure sketch

```
connectus/check_auth_parity.py
├── SentinelMap                          # dataclass: connection_name → {xsoar_param_path → sentinel_value}
├── generate_sentinels(details: AuthDetails)  # Build SentinelMap from parsed AuthDetails
│   └── skip entries where entry.interpolated is True
├── build_old_params(sentinel_map, ...)  # Build demisto.params() dict for old run
├── build_ucp_mock(sentinel_map, ...)    # Build mock_get_ucp_credentials for new run
├── map_auth_type_to_ucp_shape(entry: AuthEntry)  # entry.type (AuthType enum) → UCP credential dict template
├── run_old(integration_path, command, params, proxy) → list[CapturedRequest]
├── run_new(integration_path, command, params, ucp_mock, proxy) → list[CapturedRequest]
│   ├── patch is_ucp_enabled → True
│   ├── patch should_use_ucp_auth → True
│   └── patch demisto.getUCPCredentials → ucp_mock
├── extract_sentinel_locations(requests, sentinel) → set[Location]
│   ├── scan headers (with Basic/Bearer decomposition)
│   ├── scan query params
│   ├── scan body (JSON + form)
│   ├── scan URL userinfo
│   ├── scan cookies
│   └── try base64 variants of sentinel
├── compare_locations(old_locs, new_locs) → list[Diff]
│   └── classify: MISSING_IN_NEW, EXTRA_IN_NEW, WRONG_LOCATION, MISSING_IN_BOTH
├── compare_request_sets(old_reqs, new_reqs) → RequestSetDiff
├── check_connection_parity(connection, commands, ...) → ConnectionResult
├── check_auth_parity(integration_path, integration_id, ...) → FullResult
│   ├── parse Auth Details via auth_config_parser.parse_auth_details()
│   ├── read Params for test, Params to Commands via workflow_state show-step
│   ├── for each non-interpolated connection: check_connection_parity
│   └── assemble auth_parity + diagnostics
├── _parse_args(argv) → argparse.Namespace
└── main(argv) → int
```

### Test structure sketch

```
connectus/check_auth_parity_test.py
├── Unit tests
│   ├── test_generate_sentinels — correct sentinel shape, interpolated skipped
│   ├── test_map_auth_type_to_ucp_shape — each auth type maps correctly
│   ├── test_extract_sentinel_locations_header_bearer
│   ├── test_extract_sentinel_locations_header_basic
│   ├── test_extract_sentinel_locations_query_param
│   ├── test_extract_sentinel_locations_json_body
│   ├── test_extract_sentinel_locations_form_body
│   ├── test_extract_sentinel_locations_base64_variant
│   ├── test_compare_locations_pass — identical sets
│   ├── test_compare_locations_missing_in_new
│   ├── test_compare_locations_extra_in_new
│   ├── test_compare_locations_wrong_location
│   ├── test_compare_locations_missing_in_both
│   ├── test_compare_request_sets — symmetric difference
│   └── test_canonicalization — header case, basic decode, bearer strip
├── Integration tests (curated pack examples)
│   ├── test_apikey_integration — e.g. AbnormalSecurity (header Bearer)
│   ├── test_plain_integration — e.g. Salesforce IAM (basic auth / ROPC)
│   └── test_oauth2_integration — e.g. CrowdStrike Falcon (client creds)
```

---

## 8. Auth Details parsing

The auth parity test uses the [`auth_config_parser`](connectus/auth_config_parser/__init__.py:1)
package as the single source of truth for parsing and validating Auth
Details JSON. This replaces the earlier pattern of calling internal
helpers from [`workflow_state.py`](connectus/workflow_state.py:1)
directly.

### 8.1 Parsing Auth Details

```python
from auth_config_parser import parse_auth_details, AuthDetails, AuthEntry, AuthType

# raw_json comes from workflow_state.py show-step "Auth Details"
details: AuthDetails = parse_auth_details(raw_json)

for entry in details.auth_types:          # entry: AuthEntry (frozen dataclass)
    if entry.interpolated:
        continue                          # skip interpolated connections
    print(entry.name, entry.type, entry.xsoar_param_map)
    # entry.type is an AuthType enum: AuthType.APIKey, AuthType.Plain, …
    # entry.xsoar_param_map is a dict[str, str]: {xsoar_path: role}
```

### 8.2 Validating before use

```python
from auth_config_parser import validate_auth_details

errors: list[str] = validate_auth_details(raw_json)
if errors:
    raise ValueError(f"Invalid Auth Details: {errors}")
```

### 8.3 Extracting param IDs

```python
from auth_config_parser import auth_param_ids, auth_param_ids_with_sources, AuthDetails

ids: set[str] = auth_param_ids(details)                    # {"api_key", "credentials"}
ids_sourced: dict[str, str] = auth_param_ids_with_sources(details)
# {"api_key": "api_key_conn", "credentials": "creds_conn"}
```

### 8.4 Parsing config expressions

```python
from auth_config_parser import parse_config, ConfigExpression, ConfigClause

expr: ConfigExpression = parse_config("REQUIRED(api_key) + OPTIONAL(oauth)")
for clause in expr.clauses:              # clause: ConfigClause
    print(clause.operator, clause.names) # ClauseOperator.REQUIRED, ["api_key"]
```

### 8.5 Mapping `AuthEntry.type` to UCP shape

The [`map_auth_type_to_ucp_shape()`](connectus/check_auth_parity.py:1)
function in the parity test uses [`AuthEntry.type`](connectus/auth_config_parser/types.py:75)
(an [`AuthType`](connectus/auth_config_parser/types.py:11) enum) to
select the correct UCP credential dict template. This replaces raw
string comparisons against `auth_types[].type` dict values:

```python
from auth_config_parser import AuthType

match entry.type:
    case AuthType.APIKey:
        return {"type": "api_key", "api_key": {"key": sentinel}}
    case AuthType.Plain:
        return {"type": "plain", "plain": {"username": sentinel_id, "password": sentinel_pw}}
    case AuthType.OAuth2ClientCreds | AuthType.OAuth2AuthCode | AuthType.OAuth2JWT:
        return {"type": "oauth2", "oauth2": {"access_token": sentinel, "token_type": "Bearer"}}
    case AuthType.Other:
        return None   # skip — see §6.8
    case AuthType.NoneRequired:
        return None   # no auth
```

---

## Appendix: Execution flow diagram

```mermaid
flowchart TD
    Z[Start] --> Z1{Is integration Python?}
    Z1 -->|No| Z2[ERROR_NON_PYTHON - exit 10]
    Z1 -->|Yes| Z3{Uses BaseClient?}
    Z3 -->|No| Z4[ERROR_NO_BASECLIENT - exit 11]
    Z3 -->|Yes| A[Parse Auth Details via auth_config_parser]
    A --> A1{All auth_types interpolated?}
    A1 -->|Yes| A2[ERROR_ALL_INTERPOLATED - exit 12]
    A1 -->|No| B{For each auth_types entry}
    B -->|interpolated: true| C[Skip - status: skipped_interpolated]
    B -->|type: Other| D[Skip - status: skipped_other_type]
    B -->|type: NoneRequired| E[Skip - no auth]
    B -->|non-interpolated, standard type| F[Generate sentinels per xsoar_param_map entry]
    F --> G[Build old-run params with sentinels in demisto.params]
    F --> H[Build new-run UCP mock with same sentinels]
    G --> I[Old run: execute command under capture_proxy]
    H --> J[New run: execute command under capture_proxy with UCP patched]
    I --> K[Extract sentinel locations from old captured requests]
    J --> L[Extract sentinel locations from new captured requests]
    K --> M{locations_old == locations_new?}
    L --> M
    M -->|Yes| N[Connection PASS]
    M -->|No| O[Connection FAIL - classify diffs]
    I -->|Crashed| P[Inconclusive - RUN_FAILED_OLD]
    J -->|Crashed| Q[Inconclusive - RUN_FAILED_NEW]
    I -->|Zero requests| R[Inconclusive - NO_REQUESTS_CAPTURED]
    J -->|Zero requests| R
    I -->|Rejects HTTP| S[ERROR_INTEGRATION_REJECTS_HTTP - exit 14]
```

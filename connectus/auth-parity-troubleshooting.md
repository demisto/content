# Auth-Parity Gate — Troubleshooting Playbook

> This file is linked from connectus-migration-SKILL.md §1.12; read it when the auth-parity gate inside set-auth BLOCKS and you need the per-failure-class fix (UCP header overrides, startup-validator gating, boto3/feed interpolated cases, UCP-strip crashes, --seed-param recovery, sentinel grammar). The SKILL.md §1.12 stub keeps the gate-decision table + the core "blocked → mark interpolated or make parity runnable" rule.

## Per-param value seeding via `--seed-param NAME=VALUE` (operator escape hatch)

Some YML params have **format validators** that fire at integration module-load time and reject the analyzer's auto-generated `SENTINEL_PARAM_<name>` placeholder before any HTTP call. The analyzer already auto-coerces a few well-known patterns — params whose NAME (case-insensitive substring match) contains `thumbprint`, `certificate`, or `private_key` get a syntactically-valid stub (40-char hex thumbprint, stub PEM cert, stub PEM private key) instead of the generic sentinel string. That covers the Microsoft cert-thumbprint slot but **does not** cover every format validator in the wild. For example:

- **JWT secrets with a regex format validator** — the integration's `BaseClient.__init__` calls `jwt.decode(secret, …)` at startup; the sentinel string fails the JOSE format check.
- **OIDC issuer URLs** — startup code does `urlparse(issuer).scheme == "https"` and refuses to construct the client when the sentinel doesn't parse as `https://…`.
- **Custom hex / regex-validated tokens** beyond the auto-coerced `thumbprint` substring (e.g. a 64-char hex API token whose YML name is `api_token`).
- **Cert thumbprint validators in `MicrosoftClient`** whose YML name doesn't match the substring (e.g. `cert_fingerprint` — `thumbprint` substring miss).

The escape hatch is the repeatable `--seed-param NAME=VALUE` flag on the `set-auth` verb (and on the standalone [`check_auth_parity.py`](check_auth_parity.py:1) CLI when iterating manually):

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param NAME=VALUE [--seed-param NAME=VALUE ...]
```

**Semantics:**

- Repeatable; each `--seed-param` appends to an in-memory dict that is forwarded **only** to the parity gate for this single `set-auth` invocation. The dict is **never** persisted to the CSV.
- Values ≥4 chars long act as ad-hoc traceable sentinels (they appear verbatim in captured HTTP, exactly like the auto-generated sentinels).
- The override takes effect inside the type-aware placeholder pass in [`check_command_params.build_param_values`](check_command_params.py:1) — wins over the YML `defaultvalue`, the auto-coercion (cert/thumbprint/private_key), and the generic `SENTINEL_PARAM_<name>` string.

**Dotted-leaf rule for YML `type:9` (credentials) widgets:**

- `--seed-param creds.identifier=<v>` sets the identifier leaf.
- `--seed-param creds.password=<v>` sets the password leaf.
- Either leaf may be omitted — the omitted leaf keeps its default sentinel.
- **Flat `--seed-param creds=<value>` on a `type:9` widget is rejected with exit code 2** and an actionable error pointing at the dotted-leaf form (the integration expects a dict-shaped value at runtime; a flat string would have the wrong shape).
- Stray dotted-leaf overrides (unknown parent param, parent param is the wrong type, leaf is neither `identifier` nor `password`) surface as `[seed] WARNING` lines on stderr and do **NOT** abort the run.

**Auth-overlap rejection (hard error before the parity gate runs):**

If a `--seed-param` key (or its dotted-leaf parent) references a param that is already declared in the candidate `Auth Details` — projected from `auth_types[].xsoar_param_map.keys()` (with dotted leaves collapsing to the segment before the first `.`) unioned with every `other_connection` entry — the `set-auth` call is hard-rejected **before** the parity gate runs with the error envelope:

```
{"error": {"code": "ERROR_SEED_AUTH_OVERLAP", "message": "...", "exit_code": 2}}
```

The reason: any param already declared in `Auth Details` is supplied via UCP credential injection (not via `demisto.params()`) in the new run anyway, so the seed value would be silently discarded by the UCP injection seam — masking real auth-routing bugs. The fix is to either drop the override (the analyzer already routes the secret via UCP; you don't need a sentinel value for it) or, if the param is genuinely NOT an auth param and was misclassified, revert to Step 1 with `set-auth` and remove it from `auth_types[].xsoar_param_map` / `other_connection` first.

**Worked example — Microsoft cert-thumbprint integration:**

```bash
# 40-char hex thumbprint — required by the MicrosoftClient startup validator
# even when the actual cert is supplied via UCP credential injection.
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param certificate_thumbprint=0123456789ABCDEF0123456789ABCDEF01234567
```

**Worked example — JWT secret with format validation:**

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param jwt_secret=real-jwt-format-secret-12345
```

**Worked example — OIDC issuer URL:**

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param oidc_issuer=https://login.microsoftonline.com/common/v2.0
```

**Worked example — `type:9` credentials with format-validated password:**

```bash
# Note the dotted-leaf form. Flat 'service_account=<v>' would be rejected
# with exit code 2.
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param service_account.identifier=test@example.com \
    --seed-param service_account.password=p@ssw0rd-with-special-chars-12
```

**Recovery loop:** when the parity gate fails with `RUN_FAILED_OLD` and the stderr_excerpt is a format-validator crash at module-load time:

1. Identify the offending param from the stderr excerpt (`ValueError: invalid thumbprint`, `jwt.exceptions.InvalidTokenError`, etc.).
2. Read the integration's `.py` to see what format the validator expects.
3. Re-run `set-auth` with `--seed-param <name>=<a-value-that-passes-the-validator>`.
4. If the auth-overlap rejection fires, the param is actually an auth param — re-classify `Auth Details` to remove the bad seed target (or drop the seed; UCP will route the real secret per-request).

## Troubleshooting playbook — when the parity gate blocks

The two failure modes you will encounter in practice are (a) the integration uses a non-standard auth header and the default UCP injection writes the secret into the wrong slot, and (b) the integration has a startup-time auth validator that raises before the `Client` is constructed and the parity tool never reaches the request-emission stage. Both have well-defined fixes.

### A. UCP support for integrations using non-standard auth headers

When UCP is enabled, [`BaseClient._http_request`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:10200) auto-injects credentials via [`_inject_ucp_credentials`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9919) → `_apply_ucp_credentials` → `_apply_ucp_<type>`. The defaults assume vendors use the standard `Authorization` header:

- [`_apply_ucp_api_key`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9855) → writes `Authorization: Bearer <key>`.
- [`_apply_ucp_plain`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9881) → sets `ctx.auth = (username, password)` (a tuple consumed by `requests` as HTTP Basic Auth, equivalent to `Authorization: Basic <base64(user:pass)>`).
- [`_apply_ucp_oauth2`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9836) → writes `Authorization: <token_type> <access_token>` (default token type `Bearer`).

**The problem.** Many vendors do NOT use `Authorization`. APIVoid uses `X-API-Key`; some vendors use `Apikey`; some carry the secret in a custom query parameter; signed-request schemes (HMAC, AWS SigV4) write into multiple headers at once. For any such integration, the default UCP injection writes the secret into the **wrong** header. The integration's own code reads from the ORIGINAL header — which is empty under UCP because the user-facing params were stripped from `demisto.params()`. Net result: **the outbound request goes out unauthenticated**, but no exception is raised at the injection layer.

**Detection.** This manifests as the auth parity result reporting `MISSING_IN_NEW` for the secret's role-tagged sentinel. The old run's `locations` show the secret at the integration's actual header (e.g. `header:x-api-key`); the new run's `locations` are empty.

**Fix.** Override the appropriate `_apply_ucp_<type>` method on the integration's `Client` class (the `BaseClient` subclass). The override receives the UCP credentials dict and a request-context object with mutable `.headers`, `.params`, `.auth`, `.data`, `.json_data` attributes, and is expected to write the secret into the slot the integration's own request code actually reads from.

**Worked example — APIVoid.** APIVoid's `Client.__init__` constructs `headers = {"X-API-Key": apikey, ...}`. To make UCP route the credential into the same slot, add `_apply_ucp_api_key`:

```python
class Client(BaseClient):
    def __init__(self, base_url, apikey, verify, proxy):
        headers = {"X-API-Key": apikey, "Content-Type": "application/json"}
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def _apply_ucp_api_key(self, credentials: dict, ctx: Any) -> None:
        """
        UCP override: write the API key into the non-standard ``X-API-Key`` header
        instead of the default ``Authorization: Bearer ...``.
        """
        api_key_data = credentials.get("api_key", credentials)
        ctx.headers["X-API-Key"] = api_key_data.get("key", "")
```

**Sibling overrides for other auth types.** The same pattern applies to the other two `_apply_ucp_*` methods. The `credentials` argument is the dict returned by the UCP shape (see [`auth_parity_test_design.md`](auth_parity_test_design.md:1) §2.5 for the per-type shapes); `ctx` has mutable `.headers`, `.params`, `.auth`, `.data`, `.json_data` attributes.

- **`Plain` with custom header(s)** — override [`_apply_ucp_plain`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9881):

  ```python
  def _apply_ucp_plain(self, credentials: dict, ctx: Any) -> None:
      plain_data = credentials.get("plain", credentials)
      # Example: vendor wants username + password in two separate custom headers
      ctx.headers["X-Vendor-User"] = plain_data.get("username", "")
      ctx.headers["X-Vendor-Pass"] = plain_data.get("password", "")
      # — OR — preserve Basic Auth but use HTTPBasicAuth for additional flexibility:
      # from requests.auth import HTTPBasicAuth
      # ctx.auth = HTTPBasicAuth(plain_data.get("username", ""), plain_data.get("password", ""))
  ```

- **`OAuth2*` with non-`Authorization: Bearer`** — override [`_apply_ucp_oauth2`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9836):

  ```python
  def _apply_ucp_oauth2(self, credentials: dict, ctx: Any) -> None:
      oauth2_data = credentials.get("oauth2", credentials)
      ctx.headers["X-Auth-Token"] = oauth2_data.get("access_token", "")
  ```

**Cross-reference to CSP source** for the default implementations and the entry point — read these when you need to confirm exactly what defaults you are replacing:

- [`_apply_ucp_api_key`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9855) (default writes `Authorization: Bearer <key>`; docstring shows the canonical override at lines 9865–9870).
- [`_apply_ucp_plain`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9881) (default sets `ctx.auth = (username, password)` for `requests` Basic Auth).
- [`_apply_ucp_oauth2`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9836) (default writes `Authorization: <token_type> <access_token>`).
- [`_inject_ucp_credentials`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9919) — the per-request entry point invoked from `BaseClient._http_request`.
- [`_http_request`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:10200) — the UCP block inside the HTTP request loop.

**Cheat sheet — when you need the override:**

- **YOU NEED IT** if the integration's existing code reads the secret from a non-`Authorization` header. Grep the integration's `Client.__init__` for the `headers={...}` dict it passes to `super().__init__` — anything other than `Authorization: Bearer <...>` (for APIKey / OAuth2) or `Authorization: Basic <...>` / `HTTPBasicAuth(...)` (for Plain) means UCP's default writes to the wrong slot.
- **YOU PROBABLY DON'T NEED IT** if the integration sends `Authorization: Bearer <token>` for APIKey / OAuth2, or uses `HTTPBasicAuth(user, pass)` (or the equivalent `auth=(user, pass)` tuple) for Plain — the defaults already cover these.
- **The parity gate inside `set-auth` will surface `MISSING_IN_NEW`** for the relevant role-tagged sentinel if you forgot the override. Use the rejected `set-auth` payload + `result["parity"]` as the regression catch — apply the override, then re-run `set-auth` with the same payload to confirm the diff goes green.

### B. Multi-auth integrations with startup-time auth-combo validation

Some integrations (Jira V3 is the canonical example) gate `main()` on a `validate_auth_params()` / `check_credentials()` / `assert_auth()` helper that runs **before** the `Client` is constructed. The helper inspects `demisto.params()` and raises `DemistoException` / `return_error` if some required combination of auth fields is empty. Under UCP this is a precondition that fires before any HTTP call.

**Detection — grep recipe.** Look for a validator function whose body raises before any client is built:

```bash
grep -nE "def (validate_auth|check_credentials|assert_auth)" Packs/<Pack>/Integrations/<Name>/<Name>.py
# then read its body — if it ends in `raise DemistoException(...)` / `return_error(...)`
# AND it is called from `main()` BEFORE the Client constructor, this section applies.
```

**Why it breaks under UCP.** `demisto.params()` is intentionally empty for auth fields under UCP — UCP supplies the secrets per-request via `getUCPCredentials`, not via `params`. The startup validator sees nothing in `params`, concludes no auth was configured, and raises before any HTTP call. The parity tool never reaches the request-emission stage.

**Detection from the parity-gate output.** Identical-shape `RUN_FAILED_OLD` + `RUN_FAILED_NEW` (or `MISSING_IN_BOTH`) errors across **every** auth profile in a multi-profile (exclusive-OR) configuration; the `stderr_excerpt` contains phrases like *"are mandatory"*, *"must be provided together"*, or *"the required parameters were not provided"*.

**TWO valid fixes.**

**Option A — Gate the validator under UCP** (preferred when the integration is going to be a first-class UCP citizen and you want continued parity coverage):

```python
# BEFORE
validate_auth_params(username, api_key, client_id, client_secret, pat)

# AFTER
if not is_ucp_enabled():
    validate_auth_params(username, api_key, client_id, client_secret, pat)
```

Import `is_ucp_enabled` from `CommonServerPython` — it is already exported via `from CommonServerPython import *`. Worked example: [`Packs/Jira/Integrations/JiraV3/JiraV3.py:4857`](Packs/Jira/Integrations/JiraV3/JiraV3.py:4857).

**Option B — Mark every `auth_types[]` entry as `interpolated: true`:**

No code change. Re-classify `Auth Details` so that every `auth_types[]` entry carries `"interpolated": true`. The parity gate's `ERROR_ALL_INTERPOLATED` structural-skip code fires, `set-auth` is allowed through, the workflow advances, and the integration's existing startup validator stays in place untouched. This is the **simpler, faster path** when the integration's UCP behavior is not the migration's first priority.

**When to pick A vs B.**

- Pick **A** if this integration is queued to be migrated to UCP soon AND you want parity coverage to catch the next round of UCP-related bugs (e.g., non-standard auth header overrides — see the previous sub-section).
- Pick **B** if the integration is queued for later, or if its UCP wiring is genuinely complex (multi-auth combined with per-`Client`-construction header building, conditional flags computed from `params` at init, etc.). Re-visit when the integration is actually prioritized.

**Completeness note if you pick A.** Gating the validator is necessary but **not sufficient** for a fully UCP-aware multi-auth integration. If the `Client.__init__` computes flags from params (e.g., Jira's `is_basic_auth = bool(username and api_key)`), those flags will be `False` under UCP and the `Client`'s branching will pick the wrong path at request time. The `Client` itself needs to consult `get_ucp_credentials()` per-request to pick the right header style — see sub-section A above for the per-request override pattern. **For multi-auth integrations, Option A may require BOTH the startup gate AND the `Client` UCP-awareness override.** This is the principal reason Option B (`interpolated: true`) is often the pragmatic choice.

### C. Structural-skip gate ordering and the boto3 / AWS family

The parity tool's structural-skip gates fire in a **fixed order** — the first one matched wins, and downstream gates are never evaluated. The order is:

1. `ERROR_NON_PYTHON` (exit 10)
2. `ERROR_NO_BASECLIENT` (exit 11) — refined into `APIMODULE_INTEGRATION_CANNOT_VERIFY` (exit 15) when the integration's `.py` contains `from <Foo>ApiModule import`. Same structural-skip semantics; clearer diagnostic.
3. `MULTI_SECRET_PASSTHROUGH` (exit 16) — a `Passthrough` profile carrying 2+ credential-named keys. Per cross-cutting decision #2, this is by design, not a failure. Fires before `ERROR_ALL_INTERPOLATED` so the more specific code wins.
4. `ERROR_ALL_INTERPOLATED` (exit 12)
5. `ERROR_CONNECTION_INTERPOLATED` (exit 13)
6. `ERROR_INTEGRATION_REJECTS_HTTP` (exit 14)
7. Per-connection skips inside the run: `skipped_signed`, `skipped_mtls`, `skipped_passthrough`.

Per-command crash post-classification (does not short-circuit the gate;
just refines the `RUN_FAILED_NEW` diagnostic):

- `UCP_STRIP_CRASHED_UNCONDITIONAL_READ` — replaces the
  generic `RUN_FAILED_NEW` when the new run crashed reading a key from
  the connection's `xsoar_param_map` (KeyError) or via a defensive
  `.get("credentials").get(...)` chain that hits the stripped parent
  (TypeError: NoneType not subscriptable). See sub-section D below.

**Boto3 / AWS integrations always trip `ERROR_NO_BASECLIENT` first**, NOT `skipped_signed`. They use `boto3.Session.client()` directly rather than subclassing `BaseClient`, so gate #2 catches them before gate #6 is even reached. The `skipped_signed` path conceptually exists for boto3 but is structurally unreachable for it — `skipped_signed` only fires for integrations that DO subclass `BaseClient` AND ALSO import `hmac` (or another signed-request module).

**Required action for boto3 / AWS integrations: classify with `interpolated: true` on every `auth_types[]` entry. There is no code-change alternative.** Same reasoning as the feed framework (§1.9.1): no `BaseClient` → no UCP injection → no parity testing possible without re-architecting the integration onto `BaseClient`, which is out of scope.

**Detection during classification:** grep the integration's `.py` for `import boto3|from boto3|import botocore|from botocore|AWSApiModule`. If any match, mark `interpolated: true` up front on every `auth_types[]` entry — `set-auth` will then short-circuit via `ERROR_ALL_INTERPOLATED` and proceed without ever attempting the parity run.

### D. UCP-strip crash on unconditional `params["credentials"]` reads

When the new
(UCP) run crashes with `KeyError: 'identifier'` (or a similar leaf
from the connection's `xsoar_param_map`), or with `TypeError:
'NoneType' object is not subscriptable` from a
`.get("credentials").get(...)` chain, the parity gate post-classifies
the diff as `UCP_STRIP_CRASHED_UNCONDITIONAL_READ`.

**Why this happens.** The new run, by design, strips every key listed
in the connection's `xsoar_param_map` from the `params` dict before
invoking the child — because UCP is supposed to inject the secret via
`demisto.getUCPCredentials()` instead. Integrations whose `main()`
reads those keys **unconditionally** (e.g. AMPv2's
`client_id = params["credentials"]["identifier"]`) crash.

**TWO valid fixes** (per Hints policy / cross-cutting #1: prescription
ambiguous, choose by context).

**Fix path 1 — keep the integration UCP-clean (add an override).**
Add `_apply_ucp_plain` (or the analogous APIKey/OAuth2 override) on
the `Client` class so it consumes UCP-shape credentials directly:

```python
class Client(BaseClient):
    def _apply_ucp_plain(self, credentials: dict, ctx: Any) -> None:
        plain_data = credentials.get("plain", credentials)
        ctx.auth = (
            plain_data.get("username", ""),
            plain_data.get("password", ""),
        )
```

This is the right path when the integration is going to be a
first-class UCP citizen and you want continued parity coverage.

**Fix path 2 — minimal diff (`is_ucp_enabled()` gating).** Gate the
unconditional `params[...]` read on `is_ucp_enabled()`:

```python
# BEFORE
client_id = params["credentials"]["identifier"]
api_key   = params["credentials"]["password"]

# AFTER
if is_ucp_enabled():
    creds = demisto.getUCPCredentials()
    client_id = creds["plain"]["username"]
    api_key   = creds["plain"]["password"]
else:
    client_id = params["credentials"]["identifier"]
    api_key   = params["credentials"]["password"]
```

This is the right path when the integration's `Client` doesn't
subclass `BaseClient` cleanly (e.g. constructs `requests` manually
with `auth=(client_id, api_key)`) so the override approach can't
fully fix the dotted-access pattern.

**Fix path 3 (escape valve) — mark `interpolated: true`.** When you
just need to advance the migration, classify the profile
`interpolated: true` per cross-cutting decision #3. Document the
reason in the commit notes. This is the documented fallback.

### E. Permanent `interpolated: true` candidates (no parity testing possible)

Three categories of integrations are permanent `interpolated: true` candidates — the parity tool cannot test them and emits a cannot-verify short-circuit, and that is the **expected** outcome (not a bug to chase):

1. **Legacy HTTP layer / no `BaseClient` subclass** — short-circuits with `ERROR_NO_BASECLIENT`. Example: CrowdStrike Falcon.
2. **Feed-framework integrations** (any `*FeedApiModule` import) — short-circuits with `ERROR_NO_BASECLIENT`. See §1.9.1.
3. **`boto3` / `botocore` / `AWSApiModule` integrations** — short-circuits with `ERROR_NO_BASECLIENT` (see sub-section C above).

For all three, the fix is to classify with `interpolated: true` on every `auth_types[]` entry. Do **not** attempt to refactor the integration onto `BaseClient` just to make the parity tool reachable — that is out of scope for the migration.

> **AUTH-PARITY GATE STRICTNESS FIX (2026-06-03):** these cannot-verify short-circuits (`ERROR_NO_BASECLIENT`, `APIMODULE_INTEGRATION_CANNOT_VERIFY`, `ERROR_NON_PYTHON`, `ERROR_INTEGRATION_REJECTS_HTTP`, `MULTI_SECRET_PASSTHROUGH`) **no longer auto-pass** the `set-auth` gate. Until you mark the auth(s) `interpolated: true`, `set-auth` **BLOCKS** (`would_commit: false`) so an untested, non-interpolated secret-placement can't be silently committed. Once marked `interpolated: true`, the payload flows through the `ERROR_ALL_INTERPOLATED` clean path and the gate allows it.

### F. Sentinel grammar (for grepping diagnostics)

Parity sentinels encode both the XSOAR path AND the **role** the secret plays, in the form `__AUTHPARITY__<connection>__<xsoar_path>__<role>__<uuid8>` — e.g. `__AUTHPARITY__credentials__credentials.password__key__86ad7936`. Diff messages can be grepped by role, which makes "missing-in-new on the `key` sentinel of `credentials`" trivially attributable to a missing `_apply_ucp_api_key` override (sub-section A above). See [`auth_parity_test_design.md`](auth_parity_test_design.md:1) §2.3 for the full sentinel grammar.

## Manual re-runs of `check_auth_parity.py` (for debugging only)

The parity gate inside `set-auth` is the canonical entry point. If you want to inspect the analyzer's output without committing the cell — for instance, while iterating on a UCP override or a `--seed-param` recovery — you can run it directly:

```bash
AUTH='{"auth_types":[...]}'  # the candidate payload
python3 connectus/check_auth_parity.py Packs/<PackName>/Integrations/<IntegrationName> \
    --integration-id "<id>" \
    --auth-details "$AUTH" \
    [--seed-param NAME=VALUE ...]   # mirror whatever set-auth would receive
```

The same JSON envelope is what `set-auth` evaluates internally. Once the manual run goes green, re-run `set-auth` with the same payload (and the same `--seed-param` flags, if any).

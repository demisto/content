# `check_auth_parity.py` — Design

Design doc for the Auth Parity Test analyzer at
[`connectus/check_auth_parity.py`](check_auth_parity.py). This file is
the authoritative spec for what the analyzer does; the implementation
should be read alongside it.

> **Status (2026-05 rewrite).** This document was rewritten to match the
> current implementation after the auth-schema simplification. The pre-
> 2026-05 design carried a `config` expression in `Auth Details`, the
> `OAuth2AuthCode` and `Other` enum members, a per-row `requires auth
> parity test` flag column, and a planned cell-lookup model where the
> analyzer read `Auth Details` directly from the workflow CSV. All of
> those were removed. See
> [Appendix A — Historical design notes](#appendix-a--historical-design-notes)
> for the short version of what changed. The canonical Auth Details
> schema lives at [`column-schemas.md`](column-schemas.md:1).

---

## 1. Purpose

Verify that for **each non-interpolated `auth_types[]` profile** in an
integration's `Auth Details`, the secret values reach the wire in the
**same location** whether they were supplied via:

- the **non-UCP path** — `demisto.params()` → integration code →
  `BaseClient.__init__` → `BaseClient._http_request`; or
- the **UCP path** — credential injection via
  `demisto.getUCPCredentials()` (and the
  `CommonServerPython.get_ucp_credentials()` wrapper that delegates to
  it) → `BaseClient._inject_ucp_credentials` →
  `_apply_ucp_credentials` → `_apply_ucp_<type>`.

If the wire locations differ, UCP migration would silently break the
integration. As of schema_version=2 (2026-05) the analyzer is the
parity gate invoked **inside** [`workflow_state.set_integration_auth`](workflow_state/api.py)
(the `set-auth` CLI verb); a passing or structurally-skipped result is
the precondition for the `Auth Details` cell to be persisted at all.
The standalone `auth parity test passes` checkpoint has been removed.

The analyzer is intentionally orchestration-light:

- Parsing of `Auth Details` delegates to the
  [`auth_config_parser`](auth_config_parser/) package.
- File discovery, YML interrogation, content-prep pipeline, and child-
  process docker runtime reuse the helpers in
  [`check_command_params.py`](check_command_params.py) (imported as
  `_ccp`).
- HTTP capture reuses
  [`capture_proxy.CaptureProxy`](capture_proxy.py:1).

---

## 2. Run model

For each non-interpolated, non-skipped profile in
`details.auth_types`, the analyzer performs a paired old/new run for
every selected command and compares the captured requests.

```
┌──────────────────────────────────────────────────────────────────┐
│ for entry in details.auth_types:                                  │
│   if connection_skip_status(entry, …) is not None: record + skip │
│   for cmd in commands:                                            │
│     ┌─────────────────────────┐        ┌─────────────────────────┐│
│     │  run_old(cmd)            │        │  run_new(cmd)            ││
│     │  - inject sentinels into │        │  - inject sentinels via  ││
│     │    demisto.params()      │        │    getUCPCredentials()   ││
│     │  - capture every request │        │  - capture every request ││
│     └─────────────┬───────────┘        └────────────┬────────────┘│
│                   │   captured requests             │             │
│                   └──────────────► diff ◄───────────┘             │
│                                                                   │
│ aggregate per-command diffs → per-connection status               │
│ aggregate per-connection statuses → top-level integration status  │
└──────────────────────────────────────────────────────────────────┘
```

Both runs use the **same sentinel values** for a given profile so any
location-only difference is unambiguous; only how those values get
into the integration changes between runs.

---

## 3. Sentinel generation (§2.3)

For each non-interpolated `auth_types[]` entry the analyzer builds one
[`SentinelLeaf`](check_auth_parity.py:130) per `(xsoar_path, role)`
pair from the entry's `xsoar_param_map`. Each leaf has:

- `path` — the XSOAR field path (key in `xsoar_param_map`).
- `role` — the UCP role (value in `xsoar_param_map`, e.g. `"key"`,
  `"username"`, `"password"`, `"client_secret"`).
- `value` — the sentinel string.

Sentinel format:

```
__AUTHPARITY__<connection_name>__<xsoar_param_path>__<role>__<uuid8>
```

The role is encoded into the value itself, so a downstream grep on a
captured request can recover both the XSOAR path AND the role from the
matched sentinel alone. The `uuid8` suffix is regenerated per call so
sentinels are unique across runs.

Interpolated entries (`entry.interpolated is True`) are skipped at
sentinel-generation time — there is no user-supplied secret to seed.

Implementation: [`_make_sentinel`](check_auth_parity.py:197) and
[`generate_sentinels`](check_auth_parity.py:216).

---

## 4. UCP shape mapping (§2.5)

The new-side mock for `demisto.getUCPCredentials()` (and the
`get_ucp_credentials()` wrapper) returns a credential envelope shaped
per the entry's `AuthType`. The shape selector is in
[`map_auth_type_to_ucp_shape`](check_auth_parity.py:247); per-type
helpers fill slots using **role-based lookup** so the routing is
unaffected by the XSOAR path's naming convention.

| `AuthType` | UCP envelope shape | Slot filling |
|---|---|---|
| `APIKey` | `{"type": "api_key", "api_key": {"key": <sentinel>}}` | leaf whose role is `"key"`; if multiple, the lex-min path wins |
| `Plain` | `{"type": "plain", "plain": {"username": <s>, "password": <s>}}` | role lookups for `"username"` and `"password"`; missing roles become `""` |
| `OAuth2ClientCreds` / `OAuth2JWT` | `{"type": "oauth2", "oauth2": {"access_token": <s>, "token_type": "Bearer"}}` | lex-min path's sentinel (OAuth2 roles are free-form for now) |
| `Passthrough` | None — no synthesizable shape | caller surfaces `skipped_passthrough` |
| `NoneRequired` | None — never appears in `auth_types[]` | caller surfaces `skipped_passthrough` |

The role-driven design replaces the pre-2026-05 leaf-name heuristic
(which inspected XSOAR-path suffixes like `.identifier` / `.password`).
The heuristic was wrong for flat-param `Plain` configs (no dotted
path) and for `APIKey` configs with `hiddenusername: true` (the secret
sits at `<id>.password` but its role is `"key"`).
[`_leaves_with_role`](check_auth_parity.py:281) is the deterministic
selector underlying every per-type helper.

The mock callable itself is built by
[`build_ucp_mock`](check_auth_parity.py:359). It ignores the
`method_unique_id` argument the real `getUCPCredentials` takes —
there is exactly one connection in scope per parity run.

For the non-UCP-side seeding, [`build_old_params`](check_auth_parity.py:389)
deep-copies the base param dict and writes each sentinel into the
exact XSOAR path the integration would normally read from. Dotted
paths (`credentials.password`) expand into nested dicts.

---

## 5. Capture + diff (§4)

Both runs share one `CaptureProxy` instance. Captured requests are
recorded as a list of dicts with `method`, `path`, `url`, `headers`,
`query`, `body` keys.

### 5.1 Sentinel location extraction

[`extract_sentinel_locations`](check_auth_parity.py:446) walks one
request and returns the set of [`Location`](check_auth_parity.py:106)s
where the sentinel appears. Each `Location` carries `(method, path,
locator)` where `locator` is one of:

| Locator family | Examples |
|---|---|
| `header:<lname>` | `header:x-api-key`, `header:apikey` |
| `header:authorization:<scheme>` | `header:authorization:bearer`, `header:authorization:token`, `header:authorization:ssws` |
| `header:authorization:basic:user` / `header:authorization:basic:pass` | After base64-decoding a `Basic` blob and splitting on `:` |
| `cookie:<name>` | RFC 6265 cookie value |
| `query:<name>` | URL-decoded query parameter |
| `body.json:<dotted-path>` | Any string leaf in a JSON body; arrays indexed `[N]` |
| `body.form:<name>` | `application/x-www-form-urlencoded` body fields |
| `body.raw` | Unknown content-type fallback |
| `url:userinfo:user` / `url:userinfo:pass` | `user:pass@host` slot in the request URL |

The sentinel is searched in **three variants** (raw, base64, urlsafe-
base64) so it is found even when middleware re-encodes the value (e.g.
HTTP Basic auth concatenates `user:pass` then base64-encodes the
result).

### 5.2 Diff classification

[`compare_locations`](check_auth_parity.py:625) takes one sentinel's
old-side location set and new-side location set and emits a single
`Diff` of one of these codes:

| Diff code | Meaning |
|---|---|
| `MISSING_IN_NEW` | Old-side has locations; new-side has none. UCP injection lost the secret entirely. |
| `EXTRA_IN_NEW` | New-side has locations; old-side has none. UCP added an unwanted placement. |
| `WRONG_LOCATION` | Both sides have locations but they don't match. UCP routes the same secret to a different wire slot. |
| `MISSING_IN_BOTH` | Neither side saw the sentinel. Likely an unexercised code path. |
| `RUN_FAILED_OLD` / `RUN_FAILED_NEW` | Child crashed before issuing any request. Emitted per-command, not per-sentinel. |
| `NO_REQUESTS_CAPTURED` | Child ran cleanly but the capture proxy never saw a request. |

### 5.3 Status aggregation

| Layer | Logic | Source |
|---|---|---|
| Per-command | `fail` if any `Diff` is in `_FAIL_CODES` (`MISSING_IN_NEW`, `EXTRA_IN_NEW`, `WRONG_LOCATION`); else `inconclusive` if any is in `_INCONCLUSIVE_CODES` (`MISSING_IN_BOTH`, `RUN_FAILED_OLD`, `RUN_FAILED_NEW`, `NO_REQUESTS_CAPTURED`); else `pass`. | [`check_auth_parity.py:1532`](check_auth_parity.py:1532) |
| Per-connection | `inconclusive` if every command was inconclusive; else `fail` if any failed; else `pass` if all passed; else `pass` when at least one passed (the rest were inconclusive); else `inconclusive`. | [`check_auth_parity.py:1577`](check_auth_parity.py:1577) |
| Top-level (per integration) | Per-connection results returned as `auth_parity[<conn>] = {status, commands}`; hard errors override (see [§7](#7-hard-errors-and-skip-codes)). | [`check_auth_parity.py:1827`](check_auth_parity.py:1827) |

The XSOAR path (not the sentinel value) is the user-visible
identifier in every diff entry's `sentinel` field — operator clarity
trumps internal precision.

---

## 6. Connection-level skip codes

[`_connection_skip_status`](check_auth_parity.py:1431) inspects each
entry before running it and may short-circuit with one of:

| Skip status | Trigger | Rationale |
|---|---|---|
| `skipped_interpolated` | `entry.interpolated is True` | No user-supplied secret to compare. |
| `skipped_passthrough` | `entry.type` is `Passthrough` or `NoneRequired` | The analyzer has no canonical UCP envelope shape for these — they are "doesn't fit a profile" buckets by definition. |
| `skipped_signed` | [`detect_signed_auth`](check_auth_parity.py:748) finds `hmac`, `botocore`, `AWSApiModule`, or `EdgeGridAuth` imports in the Python source | The secret is HMAC'd into a derived signature; sentinel-grep can never follow it. |
| `skipped_mtls` | [`detect_mtls`](check_auth_parity.py:756) finds a YML config param with `type: 14` (certificate) | mTLS handshake credentials don't appear in request bodies/headers. |

Skips are recorded in `auth_parity[<conn>].status`; they are not
failures and do not block migration. The migration skill (per
[`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1))
treats every skip code as an explicit acknowledgement that parity
cannot be machine-verified for this profile.

---

## 7. Hard errors and skip codes

Hard errors short-circuit the entire run (no per-connection diffs are
emitted). Each one carries a fixed `(ERROR_*, EXIT_*)` pair and a
message that contains a stable, grep-able literal for the migration
skill.

| Error code | Exit | Trigger | Skill grep literal |
|---|---|---|---|
| `ERROR_NON_PYTHON` | 10 | YML `type` is not `python` (JS / PS) | `_LITERAL_MARK_AUTH` |
| `ERROR_NO_BASECLIENT` | 11 | No `BaseClient` subclass found in the Python source | `_LITERAL_MARK_AUTH` |
| `ERROR_ALL_INTERPOLATED` | 12 | Every entry in `auth_types[]` is `interpolated: true` | `_LITERAL_MARKPASS_STEP_11` |
| `ERROR_CONNECTION_INTERPOLATED` | 13 | `--connection <name>` targets a single entry whose `interpolated` is `true` | n/a (caller already knows the entry id) |
| `ERROR_INTEGRATION_REJECTS_HTTP` | 14 | Per-command stderr from the OLD run matches the rejection signature (`detect_integration_rejects_http`) | n/a |

Process-level exit codes:

| Exit | Meaning |
|---|---|
| `0` | Ran to completion; parity verdict in stdout JSON. |
| `2` | Bad CLI input (missing `--auth-details`, file not found, invalid JSON). |
| `3` | Unhandled exception (`ERROR_UNHANDLED`) — top-level guard. |
| `10` – `14` | The hard-error codes above. |

Hard-error checks fire in this order inside
[`check_auth_parity`](check_auth_parity.py:1771):

1. `ERROR_NON_PYTHON` — YML-level check first (cheapest).
2. `ERROR_NO_BASECLIENT` — Python-source grep.
3. `validate_auth_details` — short-circuits with `ValueError` on any
   schema problem. The wrapping `try` in `main()` converts this to
   `ERROR_UNHANDLED` (exit 3).
4. `ERROR_ALL_INTERPOLATED` / `ERROR_CONNECTION_INTERPOLATED` — only
   after the schema is known valid.
5. Per-connection skip codes (`skipped_*`) — emitted per entry, never
   short-circuit the whole run.
6. `ERROR_INTEGRATION_REJECTS_HTTP` — checked only after at least one
   connection ran (its signature comes from the OLD-run stderr).

---

## 8. CLI surface

```
python3 connectus/check_auth_parity.py <integration_path> \
    --integration-id <id> \
    --auth-details '<json>' | --auth-details-file <path> \
    [--param-defaults '<json>' | --param-defaults-file <path>] \
    [--display-name <human name>] \
    [--commands <cmd> [<cmd> ...]] \
    [--connection <auth_types[].name>] \
    [--timeout <seconds>] \
    [--docker auto|always|never] \
    [--docker-image <image>] \
    [--use-integration-docker]
```

The orchestrator (workflow_state CLI or the migration skill) is the
**only** source of `--auth-details`. The analyzer does NOT look it up
in the CSV — passing the cell value at the CLI keeps the analyzer
stateless and re-runnable outside the pipeline. Empty input is an
exit-2 error; pass `-` to read from stdin.

`--param-defaults` is optional and defaults to `{}`. (The pre-2026-05
`Params for test with default in code` CSV column that used to feed
this flag was removed. Operators needing specific defaults pass an
inline JSON object.)

Output: a single JSON object on stdout with these top-level keys:

| Key | When | Shape |
|---|---|---|
| `integration` | always | The display name (from `--display-name`, then YML `display`, then `--integration-id`) |
| `auth_parity` | success | `{<conn_name>: {status, commands}}` |
| `diagnostics` | success | `{<conn_name>: {…internal metadata…}}` — for the migration skill |
| `error` | hard-error path | `{code, message, exit_code}` |

---

## 9. Operator workflow integration

The migration skill (per
[`connectus-migration-SKILL.md`](connectus-migration-SKILL.md:1))
invokes the analyzer **as part of `set-auth`** (schema_version=2). The
analyzer's result decides whether the candidate `Auth Details` cell is
persisted at all; the standalone `auth parity test passes` workflow
checkpoint that used to follow has been removed. The orchestration
recipe inside [`set_integration_auth`](workflow_state/api.py) is roughly:

1. The candidate JSON payload arrives directly via the API/CLI call.
2. Invoke `check_auth_parity.check_auth_parity` in-process with the
   payload (no subprocess fork; no CSV round-trip).
3. Evaluate the resulting JSON envelope:
   - **All per-connection statuses are `pass` (or a recognized skip)**
     → commit the `Auth Details` cell to the CSV (cascade-reset
     downstream Params\* columns per the normal `set-auth` semantics).
   - **Any `fail`** → reject the write; return the full parity envelope
     under `result["parity"]` so the operator/AI can fix the code
     (typically by overriding `BaseClient._apply_ucp_<type>` to set the
     integration's actual wire slot, or by marking the offending entry
     `interpolated: true` as a last resort), re-run `set-auth`, repeat.
   - **`inconclusive`** → treated as a *pass* by the gate (so set-auth
     proceeds). Inspect the parity envelope; most often a `RUN_FAILED_*`
     from a `test-module` that crashes before issuing HTTP (Aruba-style,
     or pre-flight URL rejection). If the failure indicates a real
     regression that the gate let through, manually re-run
     `check_auth_parity.py` with a different `--commands <other-cmd>`
     to confirm.
   - **A hard error / structural skip** → treated as a *pass* by the
     gate (so set-auth proceeds), since these codes (`ERROR_NO_BASECLIENT`,
     `ERROR_NON_PYTHON`, `ERROR_ALL_INTERPOLATED`,
     `ERROR_CONNECTION_INTERPOLATED`, `ERROR_INTEGRATION_REJECTS_HTTP`)
     are the well-defined "not parity-testable" cases. The grep literal
     in the message still helps operators: `_LITERAL_MARK_AUTH` flags
     the integration as a permanent `interpolated: true` candidate;
     `_LITERAL_PARITY_GATE_SKIPPED` still appears in the
     all-interpolated message.

Twelve copy-paste demos covering every status code live in
[`connectus/demo_check_auth_parity.md`](demo_check_auth_parity.md).

---

## 10. Known limitations

- **Signed-auth integrations** (HMAC / AWS SigV4 / Akamai EdgeGrid)
  are not analyzable by sentinel-grep — the secret never appears
  verbatim in the wire payload, only an HMAC of it. They short-circuit
  to `skipped_signed`. Operator must verify parity manually.
- **mTLS** is similarly unanalyzable; YML `type: 14` slot triggers
  `skipped_mtls`.
- **JS / PowerShell integrations** are not loaded by the harness;
  `ERROR_NON_PYTHON` is the only verdict.
- **No-`BaseClient` integrations** (those that use `requests`
  directly) have no `_apply_ucp_<type>` seam to mock; `ERROR_NO_BASECLIENT`.
- **OAuth2 role slot** — the role enum for `OAuth2ClientCreds` /
  `OAuth2JWT` is currently free-form, so
  [`_ucp_shape_oauth2`](check_auth_parity.py:339) picks the lex-min
  path's sentinel. Once the role enum is locked in
  [`column-schemas.md`](column-schemas.md), the selector should
  switch to a role lookup like the `Plain` / `APIKey` helpers.

---

## Appendix A — Historical design notes

The pre-2026-05 design carried these now-removed concepts:

- **`AuthDetails.config: ConfigExpression`** — a top-level expression
  field describing the relationship between profiles
  (`REQUIRED(...)` / `OPTIONAL(...)` / `CHOICE(...)` / `+`-joined
  clauses). The analyzer originally parsed it via
  `parse_config()`. Removed because the only inter-profile relation
  is exclusive-OR, fully encoded by `len(auth_types)`.
- **`AuthType.OAuth2AuthCode`** — explicit enum for browser-redirect
  Authorization Code flow. Folded into `Passthrough` because the
  user-facing config lives on the profile rather than in
  `metadata.auth.parameter`, so it has no canonical field shape.
- **`AuthType.Other`** — renamed to `Passthrough` (no back-compat
  alias).
- **`requires auth parity test` flag column** in the pipeline CSV —
  removed in 2026-05; the analyzer is now unconditional.
- **`skipped_other_type`** per-connection status — renamed to
  `skipped_passthrough` in the same revision.
- **Direct CSV lookup of `Auth Details`** — the original design had
  the analyzer read the cell straight from the workflow CSV; that
  was refactored into the `--auth-details` CLI flag so the analyzer
  is stateless and re-runnable outside the pipeline.

For the actual removed code paths, search the git history at the
parent of the 2026-05 simplification commits (the merge brought in
the new `Passthrough` enum and the schema-shape changes).

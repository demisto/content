# Per-Command Parameter Analyzer — Manual

> This file is linked from connectus-migration-SKILL.md Step 2; read it when you need the full analyzer reference (all flags, output schema, status enum, the complete decision tree, blind spots, the `--seed-param` recovery loop, runtime expectations, or non-Python handling). The SKILL.md Step 2 stub carries the canonical invocation + the operational decision-tree summary + the "err on inclusion" rule + the "payload = only `integration` + `commands`; never persist diagnostics" rule.

Use this procedure whenever you are about to populate the `Params to Commands` workflow data column (Step 2). The [`connectus/check_command_params.py`](check_command_params.py) analyzer does the heavy lifting: it runs each command in a production-equivalent Docker container, intercepts HTTP traffic via an internal capture proxy, and reports which YML configuration params each command actually consumes. The skill's job is to invoke it correctly, interpret its output, and merge its findings with a source-code review before writing the polished result to the pipeline.

## 1. When to run the analyzer

Run the analyzer for any integration that requires the `Params to Commands` column to be populated — i.e., the per-command list of YML configuration params actually consumed by each command. This is the input to Step 2 (`set-params-to-commands`).

## 2. How to invoke it

The analyzer is a self-contained script. It starts its own HTTP capture proxy internally — **the skill does not need to start any external proxy, server, or service**. The only external dependency is Docker (used by default to give each integration its production runtime environment).

Standard invocation:

```bash
python3 connectus/check_command_params.py <integration_dir> \
    --ignore-params-file connectus/default_ignore_params.txt \
    --integration-id "<Integration ID>"
```

Where `<integration_dir>` is the directory containing the integration's `.yml` and `.py` files (e.g., `Packs/QRadar/Integrations/QRadar_v3`). The positional argument MUST be the **directory**, NOT a file — passing the `.py` file directly exits with code `2`.

**You already have this directory — do NOT re-derive or search for it.** It is the `Directory:` field of `workflow_state.py files "<Integration ID>"`, and equivalently the `dirname` of `context`'s `file_paths.yml` (i.e. `file_paths.yml` minus the trailing `/<Base>.yml`). Since Step 0 already runs `context` (which returns `file_paths`), reuse that value — there is no need for a separate `files` call, a `find`/`ls`/`glob`, or a sub-agent lookup just to get the path. Example: `file_paths.yml = "Packs/AbuseDB/Integrations/AbuseDB/AbuseDB.yml"` → `<integration_dir> = "Packs/AbuseDB/Integrations/AbuseDB"`.

The `--integration-id "<Integration ID>"` flag is **strongly recommended inside the migration workflow.** When supplied, the analyzer additionally calls [`workflow_state.py auth-params <id>`](workflow_state/cli.py:1) and unions every YML param id declared in the integration's `Auth Details` cell (auth-secret params projected from `auth_types[].xsoar_param_map.keys()` — dotted leaves collapse to the segment before the first `.` — plus every `other_connection` entry) into its own ignore set. This removes the entire burden of "remembering which params already live in `Auth Details`" from the AI — those params will simply not appear in the analyzer's per-command output. When you pass `--integration-id`, you do NOT need a standalone `auth-params` call — the analyzer auto-unions that set. (`auth-params` remains available for human display only.)

Optional flags the skill should know about:

- `--commands cmd1 cmd2 ...` — analyze only specific commands instead of all of them.
- `--static-only` — skip the dynamic phase (no Docker, no proxy). Faster, but lower accuracy. Use only when Docker is unavailable.
- `--timeout SECONDS` — per-command wall-clock timeout (default 30s; the batch runner uses 300s for the whole integration).
- `--docker {auto,always,never}` — `auto` (default) uses Docker when available; `never` runs in host Python (will fail on integrations needing third-party deps); `always` requires Docker.
- `--use-integration-docker` — opt-in: instead of the pinned `demisto/py3-native` image, use the integration's own `script.dockerimage` from its YML. Use this for a targeted re-run when an integration reports `module_not_found` (see Step 1 of the decision tree in section 6 below). Falls back to `--docker-image` if the YML doesn't declare one.
- `--integration-id <id>` — OPTIONAL. When supplied, the analyzer pulls the auth-derived ignore set from [`workflow_state.py auth-params <id>`](workflow_state/cli.py:1) and unions it with the file-based ignore set, guaranteeing that any param already declared in the integration's `Auth Details` cell cannot leak into the per-command output. The analyzer logs a single-line stderr INFO with the pulled list. Inside the migration workflow, ALWAYS pass this flag — `set-params-to-commands` will reject overlap regardless, so pulling the exclusion list up front saves a round-trip. If the integration is not in the workflow CSV, or its `Auth Details` is unset, the analyzer logs a single-line stderr WARNING and proceeds with just the file-based ignore set (it is intentionally not a fatal error).
- `--no-sentinel-coercion` — disable automatic sentinel-value coercion. By default the analyzer coerces sentinels for params whose **NAME** (case-insensitive substring match) contains `thumbprint`, `certificate`, or `private_key`, replacing the generic `SENTINEL_PARAM_<name>` string with a syntactically-valid stub (40-char hex thumbprint, stub PEM cert, stub PEM private key). This prevents the cert-thumbprint-hex-validator pattern (see auth-examples.md §1.6 row #9) from killing the entire dynamic phase. Pass `--no-sentinel-coercion` for strict-sentinel debug mode.
- `--seed-param NAME=VALUE` — repeatable. Operator/AI escape hatch: provide an explicit value to seed for a specific YML param, overriding all other sources (YML default, cert coercion, generic sentinel). Use this when an integration has a param the auto-coercion didn't anticipate (e.g., a different format-validating credential, an enum-value selector that needs a specific value to traverse a code path). Values >= 4 chars long act as ad-hoc sentinels — they're grep-able in captured HTTP and the post-hoc attribution code looks for them too.
- `--seed-arg CMD:NAME=VALUE` — repeatable. The command-**argument** analogue of `--seed-param`. Seeds the value `demisto.args()` returns for argument `NAME` of command `CMD`, overriding the auto-derived value. The `CMD:` prefix scopes the override to one command, so the same arg name on different commands can differ (e.g. `--seed-arg ip:ip=1.1.1.1 --seed-arg abuseipdb-report-ip:ip=8.8.8.8`). Use when a required command argument needs a specific real value (e.g. a valid IP/CIDR) to traverse a code path that the auto-seeded `SENTINEL_ARG_<name>` doesn't satisfy. See §11 (argument seeding) below.
- `--no-seed-args` — disable automatic command-argument seeding (which is **ON by default**). With seeding on, the analyzer builds `demisto.args()` for each command from its YML `arguments` (each arg's `defaultValue`, else first `predefined` option, else a `SENTINEL_ARG_<name>` sentinel) so handlers whose YML arguments are **required positional parameters** don't crash with `TypeError: missing required positional argument` before issuing any HTTP request. Pass `--no-seed-args` only for strict/debug runs where you want the legacy empty-`args()` behavior. See §11.
- `--no-auto-retry-integration-docker` — disable the automatic retry. By default, when the FIRST command's diagnostic comes back as `module_not_found` AND the analyzer is using the default `demisto/py3-native` image, it will automatically restart the dynamic phase with `--use-integration-docker` (which uses the integration's own production image, usually with the missing package preinstalled). Pass `--no-auto-retry-integration-docker` to disable, in which case the analyzer fast-fails the remaining commands as `module_not_found` (~30s × N saved) and returns immediately.
- `--with-diagnostics` — opt-in. Emits a top-level `diagnostics` key in the stdout JSON in addition to `integration` and `commands`. **Do NOT pass this flag inside the migration workflow** — `set-params-to-commands` will reject any payload containing extra top-level keys. Only pass it for interactive / debug use when you specifically want to read per-command status / failure attribution / Hybrid narrowing signal. (See §§3a/4/5/6 below; all of that documentation applies only when `--with-diagnostics` is set.)

The script writes its result to **stdout** as a single JSON document. All progress and warnings go to **stderr**. Exit code `0` means success; `2` means bad CLI args / path; `3` means an unhandled analyzer error.

## 3. Output schema (annotated example)

> **Default payload is two keys: `integration` + `commands`.** Diagnostics are **opt-in** via `--with-diagnostics` (the analyzer flipped its default after a breaking change to prevent `diagnostics` from leaking into `Params to Commands` when stdout was piped verbatim into `set-params-to-commands`). The schema below shows the diagnostic-rich payload; with the default flags you will see only the first two keys.

```json
{
  "integration": "IBM QRadar v3",
  "commands": {
    "test-module":            ["adv_params", "fetch_interval"],
    "qradar-offenses-list":   ["adv_params", "fetch_interval"],
    "long-running-execution": [
      "adv_params", "enrichment", "events_columns", "events_limit",
      "fetch_interval", "fetch_mode", "first_fetch", "incident_type",
      "limit_assets", "mirror_options", "offenses_per_fetch",
      "query", "retry_events_fetch"
    ]
  },
  "diagnostics": {                         // ONLY present with --with-diagnostics
    "test-module": {
      "status": "param_caused_failure",
      "captured_requests": 0,
      "failure_excerpt": "integration_under_test.DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params - please make sure you entered it correctly",
      "failing_params": ["adv_params"]
    },
    "long-running-execution": {
      "status": "param_caused_failure",
      "captured_requests": 0,
      "failure_excerpt": "integration_under_test.DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params - please make sure you entered it correctly",
      "failing_params": ["adv_params"]
    }
  }
}
```

`commands` is the **finished, polished result** — these are the per-command param lists the skill writes into the pipeline data.

`diagnostics` is **internal AI signal only**, and is only present when you re-ran the analyzer with `--with-diagnostics` — see section 5 below. **In normal workflow usage you will not see the `diagnostics` block at all.** If you need the diagnostic signal (e.g., a command failed unexpectedly and you want to see the failure_excerpt), re-invoke the analyzer with `--with-diagnostics` to inspect it, then RE-INVOKE WITHOUT THE FLAG to get the clean payload to persist.

### 3a. Per-field reference

For each command, the `diagnostics[cmd]` object always has:

- **`status`** — one of `ok` / `ok_no_capture` / `param_caused_failure` / `no_data` / `timeout` / `docker_error` / `module_not_found` (see §4).
- **`captured_requests`** — int. Always present in dynamic mode. Number of HTTP requests the capture proxy observed for this command.

Optional fields, present only under specific conditions:

- **`failure_excerpt`** — string, trimmed to ≤500 chars. Present when `status` is one of the failure-bearing values (`param_caused_failure`, `no_data`, `timeout`, `docker_error`, `module_not_found`); omitted on `ok` / `ok_no_capture`.
- **`failing_params`** — list of param names. Present **only** when `status == "param_caused_failure"`. Populated by scanning the **full child stderr** for `SENTINEL_PARAM_<name>` substrings (not just the trimmed `failure_excerpt`), so a sentinel buried deep in a long traceback still gets attributed.
- **`missing_module`** — string. Present **only** when `status == "module_not_found"`; names the package the child crashed on (e.g. `"pymisp"`).
- **`scope_1_narrowed`** — `true`. Present **only when Hybrid Scope-1 narrowing actually dropped at least one param** for this command. Omitted entirely when narrowing was applied but the captured set was a superset of the static Scope-1 set (i.e. narrowing fired silently and changed nothing). **An absent field therefore does not mean narrowing was skipped** — it could also mean narrowing trivially kept everything. See §6's narrowing callout.
- **`scope_1_dropped`** — list of param names that narrowing dropped. Present iff `scope_1_narrowed` is present.
- **`limitation`** — optional string flag for known structural reasons the dynamic signal cannot fire for this integration. Currently the only documented value is `"capture_proxy_bypassed"`, attached to **every command** of any integration whose source imports `boto3`, `botocore`, or `AWSApiModule` (matched by prefix on `Import` / `ImportFrom` AST nodes). It means the capture proxy could not observe HTTP traffic, so Hybrid Scope-1 narrowing structurally cannot fire for that integration regardless of `status`. Treat the per-command list as the full static union and verify against source.

The per-param `attributions[*].by_source` map may also contain a `dynamic_access` source (confidence 0.9) — the **params-access spy** signal (the param was READ at runtime during this command's execution, above the startup baseline). See §12.

## 4. Status enum reference

| status | meaning |
|---|---|
| `ok` | Command completed (rc=0, or rc=7 with captures>0) and at least one HTTP request was captured. The param list in `commands[cmd]` is high-confidence. |
| `ok_no_capture` | Command ran cleanly (rc=0) but made no HTTP calls. Either the command genuinely needs no HTTP (rare) OR our seeded params didn't trigger any HTTP path OR the integration is in the proxy-bypass family (see `limitation: capture_proxy_bypassed`). The param list is the full static union. |
| `param_caused_failure` | Command failed AND we identified the specific params that caused the failure (their sentinels appeared anywhere in the child's stderr). Those params are pre-elevated into `commands[cmd]`. The remaining params for that command come from the static union (the integration may have bailed before reaching them). |
| `no_data` | Command failed but no specific param attribution could be made — typically the integration short-circuited with a hardcoded error (e.g. a `Client.__init__` guard) before any sentinel reached the error text. The param list is the full static union. |
| `timeout` | Command hit the per-command wall-clock timeout. The param list is the full static union. |
| `docker_error` | Docker invocation itself failed (image pull, daemon down, rc 125/126/127). The whole integration's dynamic phase is unreliable; rely on static and consider `--docker never`. |
| `module_not_found` | Child crashed with `ModuleNotFoundError`. Integration needs a third-party package not present in the runtime image. The `missing_module` field names the package. First retry with `--use-integration-docker`; if that still fails, fall back to manual source review (analogous to JS / PowerShell). |

## 5. CRITICAL — Use diagnostics for AI judgment, NEVER write them to pipeline data

> ⚠️ **The `diagnostics` field is stderr-equivalent metadata. It MUST NEVER appear in any persisted pipeline artifact (CSV, manifest, `set-params-to-commands` payload, etc.).**

It exists ONLY for the skill's internal decision-making. The skill MUST:

- Read `diagnostics` to assess confidence in each command's param list.
- Use the `failure_excerpt` and `failing_params` to investigate the integration source code when needed.
- Write **only the polished `commands` data** into the pipeline (CSV / manifest / wherever).
- **Never include `diagnostics`, `failure_excerpt`, `status`, or `captured_requests` in any persisted output.**

The pipeline data is meant to be a clean machine-readable artifact. Diagnostics are debugging context for the AI — they get consumed and discarded. When invoking `set-params-to-commands`, the JSON payload must contain only `integration` and `commands` keys (per [`column-schemas.md`](column-schemas.md)) — strip everything else.

## 6. Decision tree — what the AI does for each diagnostic

The full decision is a function of `(status, limitation)`. Walk this table per command (or per integration when the same outcome dominates):

| Diagnostic | What it means | What the AI should do |
|---|---|---|
| `status: ok` (no `limitation`) | Command ran cleanly and the proxy captured HTTP. Hybrid Scope-1 narrowing may have applied (visible only when it actually dropped something). | Trust the param list as-is. |
| `status: ok` + `limitation: capture_proxy_bypassed` | The integration ran without errors but the proxy saw nothing because the HTTP layer (boto3 / botocore / `AWSApiModule`) bypassed it. The param list is the **full static union**; Hybrid narrowing structurally cannot fire. | Treat as static-only output. Verify against source manually, especially the Scope-1 fan-out (credentials, region, etc.) that narrowing would normally trim. |
| `status: ok_no_capture` (no `limitation`) | Command completed cleanly (rc=0) but the proxy saw zero HTTP requests. Either the command is a pure local helper, or the seeded params didn't reach an HTTP path. | Verify against source: a true local helper needs no HTTP and the static union is correct; otherwise consider it under-tested and treat the list as the full static union (err on inclusion). |
| `status: ok_no_capture` + `limitation: capture_proxy_bypassed` | Integration is in the proxy-bypass family and ran cleanly. Same situation as above for the AWS family — zero captures here is structural, not signal. | Use the static union; **do not infer "no params" from zero captures**. |
| `status: param_caused_failure` | A `SENTINEL_PARAM_<name>` substring was found anywhere in the child's stderr (full-stderr scan, not just the trimmed excerpt). `failing_params` lists the suspects and they are pre-elevated into `commands[cmd]`. | Treat `failing_params` as definitely-relevant. Merge the remaining params with the static union (the integration may have bailed before reaching them). When in doubt, leave the failing params attributed to the command (err on inclusion). |
| `status: no_data` | Command failed but no sentinel could be matched — typically the integration short-circuited (e.g. a `Client.__init__` guard with a hardcoded error message) before the sentinel value reached an error path. | Cannot trust the dynamic signal. Use the full static union. Consider re-running with `--use-integration-docker` if the integration has a non-default runtime that might reach further. |
| `status: timeout` | The child process hit the per-command wall-clock timeout. | Use the full static union. Consider raising `--timeout` or re-running on a smaller `--commands` subset. |
| `status: docker_error` | Docker invocation itself failed (rc 125/126/127). | Re-run on the host (`--docker never`) or fix the docker daemon. The whole integration's dynamic phase is unreliable until then. |
| `status: module_not_found` | Child crashed with `ModuleNotFoundError`; `missing_module` names the package. | First retry with `--use-integration-docker` (uses the integration's own production image, which usually has the missing package). If that still fails, fall back to manual source review — the analyzer literally cannot run. |
| `status: no_data` across **every** command + stderr containing `Error: Odd-length string` or `non-hexadecimal` | Cert-thumbprint hex validator in `MicrosoftClient.__init__` rejected the analyzer's sentinel value before any command dispatched. Structural; affects most Microsoft cert-auth integrations. | Use the **full static union**. Do NOT retry with `--use-integration-docker` (failure is in `MicrosoftApiModule`, not in a missing package). `--ignore-params <name>` does NOT help. Manual source review is the path; or seed via `--seed-param` (see §6h). |

### 6a. Hybrid Scope-1 narrowing — what to read into the diagnostic

The analyzer applies a narrowing pass that fires only when a command's dynamic phase **captured ≥1 HTTP request AND hit ≥1 sentinel**. It intersects the static Scope-1 set (pre-dispatch + module-level fan-out shared across all commands) with the captured params. Scope-2 (per-command handler-traced params, including binding-narrowed dispatch-site reads) is preserved unchanged.

**Semantics for `scope_1_narrowed` / `scope_1_dropped`:**

- **Present** with a non-empty `scope_1_dropped` → narrowing fired AND removed at least one param. Trust the per-command list more; the dropped names are listed for transparency.
- **Absent** → ambiguous on its own. It can mean either (a) narrowing was never attempted (no captures, sentinel-less, or the integration is in the proxy-bypass family), **or** (b) narrowing fired but the captured set was a superset of Scope-1 so nothing was dropped (narrowing happened trivially). Use `status` and `limitation` together to disambiguate: if `status == "ok"` and there is no `limitation`, an absent narrowing field means "narrowing fired, nothing to drop"; otherwise it means "narrowing was not applied at all and the list is the full static union".

The remaining commands (typically ~80% per integration) receive the **full Scope-1 static union**, which can include false positives from the `Client(api_key=..., max_fetch=..., custom_credentials=...)` fan-out pattern in `main()`. When you see a column where many commands share a suspiciously-identical large param list (the fan-out signature), consult the source code and prune obvious Client-only params for commands that don't actually use them — but **continue to err on inclusion**: a real param missing silently breaks the migrated integration, while an extra param is merely cosmetic noise.

### 6b. Why Hybrid Scope-1 narrowing is retained

Even after the static analyzer was extended (helper-function recursion, alias-chain matching, nested pre-dispatch flattening, etc.), Hybrid narrowing was **kept on purpose**. It is the only mechanism that trims **module-level globals** of the CrowdStrike `PARAMS = demisto.params()` style — `collect_module_level_params` is explicitly outside the static binding-narrowing pipeline because those reads fan out to every command unconditionally. Static binding-narrowing handles the intra-`main()` `Client(api_key=params.get("apikey"))` pattern but cannot touch module-scope `CLIENT_ID = PARAMS.get("client_id")`.

Concrete justification (from [`connectus/check_command_params_validation_report.md`](check_command_params_validation_report.md:1)): on CrowdStrike Falcon, narrowing dropped 7 of 9 module-level Scope-1 params from 65 of 96 commands — every drop manually verified as a genuine false positive. Without narrowing, those 7 params would appear on every command of every CrowdStrike-style integration.

### 6c. The `capture_proxy_bypassed` family (boto3 / AWS)

`boto3` / `botocore` (and the shared `AWSApiModule` that wraps them) do not honour `HTTPS_PROXY` / `HTTP_PROXY` the way the capture proxy expects — they manage their own HTTP layer that has to be configured per-client via `Config(proxies=...)`. The analyzer detects this **statically** by walking the integration's `Import` / `ImportFrom` AST nodes for any name matching the prefixes in `_PROXY_BYPASS_MODULE_PREFIXES` (currently `boto3`, `botocore`, `AWSApiModule`). When detected, every per-command diagnostic receives `limitation: "capture_proxy_bypassed"`.

For these integrations:

- Expect `status: ok_no_capture` (or `no_data` if the sentinel trips an early validator) on every command, regardless of whether the integration actually ran successfully.
- Hybrid Scope-1 narrowing will **never** fire — `_merge_command_params()` correctly skips itself when `captured_requests == 0`, so there is no risk of accidentally narrowing with an empty captured set and zeroing out the per-command list.
- The per-command output is the **full static `scope_1 | scope_2` union** as-is. Treat AWS integrations as **static-only effectively** and verify against source.

### 6d. Patterns the static analyzer now handles correctly

The following patterns previously needed AI workaround. They are now handled inside the static phase, so **the AI should not add defensive logic for them** — trust the analyzer's static set and only intervene if a sanity-check against source disagrees.

- **Helper-function shared-client construction** (`client = build_client(args)` where `build_client` reads `demisto.params()` internally): traced via `_params_consumed_by_function` and helper recursion in `trace_params_in_function`. (AWS-EC2 pattern.)
- **`command == "X" or command == "Y"` alias chains:** matched recursively in `_if_test_matches_command` via a `BoolOp(Or)` walk. (AWS-IAM pattern.)
- **Stub `.py` files in the integration directory:** `find_integration_files` applies a deny-list (`demistomock.py`, `CommonServerUserPython.py`, etc.) and prefers the file whose stem matches the directory name or YML stem.
- **Pre-dispatch bindings nested inside `try:` / `with:` / `if:` blocks:** `_iter_pre_dispatch_stmts` flattens these so binding-narrowing fires regardless of nesting. (MDATP pattern.)
- **Named dict-dispatch tables:** any local dict can be the dispatch table, not just one literally named `commands`. (AzureKeyVault, MongoDB.)

### 6e. Decision-tree summary (operational order)

Given the analyzer's JSON for an integration, the skill should:

**Step 0** — If MOST commands have `status: "module_not_found"`, the integration depends on a third-party package not in the runtime image. First retry with `--use-integration-docker`. If still failing, **read the integration source and YML directly to write a polished result manually**, exactly as you would for a JavaScript or PowerShell integration. The `missing_module` field tells you which package was needed.

**Step 1.** If the analyzer process exited non-zero (the batch runner wraps this as `{"error": ..., "stderr": ...}` in the cell): treat as a structural failure. Read the integration source, decide manually what each command needs, write a polished result. Do NOT propagate the error into the pipeline.

**Step 2.** If `commands` is non-empty AND most commands have `status: "ok"` (no `limitation`): the analyzer's output is high-confidence. Write `commands` as-is into the pipeline data.

**Step 3.** If the integration has `limitation: "capture_proxy_bypassed"` on every command: treat the analyzer output as **static-only**. Hybrid narrowing structurally cannot fire here. Cross-check the per-command lists against source, especially for the Client fan-out pattern.

**Step 4.** If many commands have `status: "param_caused_failure"`: the failing params are already pre-elevated into `commands[cmd]`. Read the `failure_excerpt` and the integration source to confirm whether the param really applies to all commands or just to startup logic. **When in doubt, leave the param attributed to that command (err on inclusion).**

**Step 5.** If many commands have `status: "no_data"` or `status: "ok_no_capture"` (without the proxy-bypass limitation): the analyzer couldn't get a strong signal. Read the integration source and trace which params each command's handler uses. Write the resulting per-command list into the pipeline. **When in doubt, include rather than exclude.**

**Step 6.** Always sanity-check: are there commands in the YML that the analyzer missed? Are there params clearly used in a command's source code that don't appear in the analyzer's list? If yes, add them.

### 6f. Analyzer blind spot — client-side post-response params

The dynamic phase observes outbound HTTP traffic only. Params that are consumed **after** the API response — typically when building XSOAR result objects (`Common.DBotScore`, `CommandResults` with computed `outputs`, etc.) — leave no network footprint and will be missed by dynamic capture, even when the integration ran cleanly.

**Common shapes:**
- **Reputation `integrationReliability`** — passed into `Common.DBotScore(... reliability=reliability ...)` only when constructing the indicator; never sent to the API.
- **Per-indicator threshold params** (e.g. `bad`, `suspicious`, `malicious`) — used to map an API numeric score onto an XSOAR severity AFTER the API responds.
- **Output formatting toggles** — e.g. `human_readable_format`, `output_simplified`.

**Detection:** the analyzer reports `status: ok` and a list of params for the command, but a manual source-review reveals additional params consumed in the result-building code path. The fix is to **add them manually** ("err on inclusion", §7). The analyzer cannot detect this class structurally because it has no signal that the command consumed the param.

Concrete example: APIVoid's reputation commands (`apivoid-ip`, `apivoid-domain`, `apivoid-url`, plus the bare `ip`/`domain`/`url`) all read `integrationReliability` to build the DBotScore object — but the analyzer reports it on zero of them. Add it manually to all six.

### 6g. Analyzer blind spot — pre-dispatch fan-out helpers

Some integrations have a pre-dispatch helper that merges params into the per-command args dict before any handler is dispatched. The OpenAI ChatGPT v3 shape is the canonical case:

```python
def setup_args(args, params):
    for p in ("max_tokens", "temperature", "top_p"):
        args.setdefault(p, params.get(p))
    return args

def main():
    args = setup_args(demisto.args(), demisto.params())
    # ... dispatch ...
```

The analyzer's per-handler tracer sees `args.get("max_tokens")` inside the handler — looks like a pure command arg, not a param read. Static binding-narrowing doesn't fire because the params reach the handler only via the merged args dict. Dynamic only attributes when the param's value is actually consumed (e.g., `int(args["max_tokens"])`); commands that bail before that cast have no sentinel attribution.

**Detection:** look for any pre-dispatch helper in `main()` that iterates over a list of param names and writes them into the args dict. When found, **every** command receiving those merged args reads those params indirectly. Add them manually to every affected command's per-command list. The analyzer cannot detect this class structurally without modeling the args-dict mutation.

Watch also for in-place mutation patterns like `args.update({k: params.get(k) for k in BEHAVIOURAL_PARAMS})` and `args = {**args, **{k: params.get(k) for k in ...}}`.

### 6h. Recovery loop using `--seed-param`

> **Symptom that MUST trigger this loop — do NOT fall back to static-only.** When **every** command in the dynamic phase fails identically *before any HTTP request* with a credential-parse error raised from `main()` (e.g. `called return_error before any HTTP request: ... Unable to parse JSON string`), the integration is parsing/validating a credential param at startup (the classic case: a Google service-account JSON loaded via `safe_load_non_strict_json(...)` in `main()` before command dispatch). This is **not** a real param-discovery limitation and you MUST NOT silently treat the run as static-only — the dynamic signal is recoverable by seeding a structurally-valid credential value (see the `user_creds.*` example below). Static-only is the fallback only after seeding still fails to produce a parseable credential. Reach for `--seed-param` first.

When the analyzer reports `status: no_data` AND the failure_excerpt suggests a format-validator failure on a credential-shaped param that the auto-coercion didn't catch (auth-examples.md §1.6 row #9 covers the common Microsoft cert-thumbprint case), the recovery loop is:

1. Inspect the failing param's YML type and the source code's first-touch validator. Determine what shape the integration expects.
2. Re-run the analyzer with `--seed-param <name>=<plausible-value>`:
   ```bash
   python3 connectus/check_command_params.py <dir> \
       --ignore-params-file connectus/default_ignore_params.txt \
       --integration-id "<id>" \
       --seed-param my_jwt_secret='base64-encoded-stub' \
       --seed-param my_oidc_issuer='https://example.com/issuer'
   ```
3. If a different validator fires next, repeat with another `--seed-param`. The escape hatch is repeatable; each invocation can pass multiple `--seed-param` flags.
4. The seed values you supply (>= 4 chars) double as ad-hoc sentinels: they appear verbatim in any captured HTTP request, so the analyzer's post-hoc attribution can still attribute them to commands.

**Common shapes you'll need to seed:**
- JWT signing secrets: a base64-decodable random byte string ≥ 16 chars.
- OIDC issuer URLs: a full `https://...` URL that passes URL validators.
- Splunk session tokens: a 32-char hex string.
- API tokens with prefix prefixes (e.g., GitHub `ghp_...`): supply a plausible stub matching the prefix convention.

Coerced auto-defaults (cert/thumbprint/private_key) do NOT need `--seed-param` — they're already handled. Use `--seed-param` only when the auto-coercion misses a case.

**YML `type:9` credentials widgets use the dotted-leaf form.** When the integration code reads `params.get("<name>", {}).get("identifier")` / `.get("password")` (the standard XSOAR credentials-widget shape), the analyzer seeds a dict-shaped value by default. To override either leaf, use `--seed-param <name>.identifier=<value>` and/or `--seed-param <name>.password=<value>`. Each leaf can be supplied independently — omitted leaves keep their `SENTINEL_PARAM_<name>_identifier` / `SENTINEL_PARAM_<name>_password` defaults.

The common case: an integration's `Client.__init__` (or test-module path) validates the password leaf as JSON, a PEM key, or another structured format, and the generic sentinel string fails validation. Seed the password leaf with a plausible structured stub:

```bash
# Google service-account JWT — code validates user_creds.password as JSON
--seed-param 'user_creds.identifier=stub@stub.iam.gserviceaccount.com' \
--seed-param 'user_creds.password={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n","client_email":"stub@stub.iam.gserviceaccount.com",...}'
```

**Flat `--seed-param <name>=<value>` on a `type:9` credentials param is rejected with exit code 2** and an actionable error pointing at the dotted-leaf form. The reason: integration code expects `params.get(name, {}).get(...)` to return a leaf value from a dict; a flat string replacement makes the whole value a string and crashes the consumer with `AttributeError: 'str' object has no attribute 'get'`.

**Stray dotted-leaf overrides surface as `[seed] WARNING` lines** without aborting the run:
- `--seed-param ghost.password=x` where `ghost` isn't a YML param → "dotted-leaf override(s) … reference parent(s) that are not in this integration's visible YML config".
- `--seed-param api_key.identifier=x` where `api_key` is a YML `type:4` (encrypted) param, not `type:9` → "dotted-leaf override(s) … are invalid. Dotted-leaf form is only supported for YML type:9 credentials widgets".
- `--seed-param creds.weird_leaf=x` where `creds` IS type:9 but `weird_leaf` isn't `identifier`/`password` → same WARNING with `leaf 'weird_leaf' not in {'identifier', 'password'}`.

## 7. The "err on inclusion" principle

When the skill is uncertain whether a param belongs to a command, it should INCLUDE the param. The cost of a false positive (an unused param shown in the column) is much lower than a false negative (a real param missing, which would silently break the migrated integration).

Specifically: if the analyzer says param X is NOT relevant for command Y, but the skill's source-code review suggests param X IS used by Y (even indirectly), the skill should add X to Y's list.

## 8. Self-contained operation

The skill does NOT need to:

- Start the capture proxy (the analyzer starts it internally per integration on a free port).
- Manage Docker containers (the analyzer pulls images and spawns containers automatically).
- Manage temp directories (the analyzer uses ephemeral tmp dirs that auto-clean).

By default the analyzer runs the child in `demisto/py3-native:8.9.0.114862` (a single pinned image; the integration's YML `script.dockerimage` is intentionally ignored for batch reproducibility). When the analyzer reports `module_not_found` for an integration, the skill has two options:

1. **Re-run with the integration's own runtime** by adding `--use-integration-docker` to the invocation. This honours `script.dockerimage` from the integration YML, which usually has the missing third-party package (e.g. `httpx`, `pymisp`) preinstalled. Prefer this when the missing package is a standard one and the integration is not exotic — it lets the analyzer recover full dynamic signal automatically.

2. **Read the integration source manually** (the original procedure: analogous to JS / PowerShell handling). Prefer this when the per-integration image is unusually large, unavailable from the registry, or already known to break under the analyzer's bootstrap shim.

The `missing_module` field in the diagnostic names the missing package — use it to decide between (1) and (2). Switching to `--use-integration-docker` is the lower-effort path; manual source review is the safer fallback.

The skill ONLY needs to:

- Have `python3` available on the host.
- Have `docker` available on the host (for non-trivial integrations; otherwise pass `--docker never`).
- Pass [`connectus/default_ignore_params.txt`](default_ignore_params.txt) via `--ignore-params-file` to filter out auth/connection/framework noise.
- **Set `DEMISTO_SDK_LOG_FILE_PATH` to a workspace-local directory** when running in a sandboxed environment (e.g., from inside the IDEX agent). The analyzer's dynamic phase shells out to `demisto-sdk prepare-content`, which uses `loguru` to open a debug log file. By default `demisto-sdk` writes to `~/.demisto-sdk/logs/demisto_sdk_debug.log`, which is outside the workspace and triggers `PermissionError: [Errno 1] Operation not permitted` (EPERM from macOS sandboxd / TCC, not from POSIX perms) → the analyzer crashes with `DynamicPrepError: prepare-content failed: rc=1` and exits rc=3. Workaround: prepend the analyzer invocation with `DEMISTO_SDK_LOG_FILE_PATH="$PWD/.tmp_migration/sdk-logs"` (the env var is inherited by the `demisto-sdk` subprocess). Any workspace-writable directory works.

  ```bash
  DEMISTO_SDK_LOG_FILE_PATH="$PWD/.tmp_migration/sdk-logs" \
    python3 connectus/check_command_params.py <integration_dir> \
      --ignore-params-file connectus/default_ignore_params.txt \
      --integration-id "<Integration ID>"
  ```

  Same applies to any other `demisto-sdk` invocation made from the agent (Step 7 `validate`, Step 9 `pre-commit`). When in doubt, set the env var. The directory does not need to exist beforehand — `demisto-sdk` creates it on first write.

  > **Note.** The connectus analyzers (`check_auth_parity.py`, `check_command_params.py`) auto-apply this workaround when `DEMISTO_SDK_LOG_FILE_PATH` is unset: they default it to `<repo>/.tmp_migration/sdk-logs` and create the directory on demand. You only need to set the env var manually for `demisto-sdk` invocations you make YOURSELF (validate, pre-commit, update-release-notes, etc.) — the analyzer invocations are now self-fixing.

## 9. Runtime expectations

- Per-integration wall time: ~5–60 seconds (depends on number of commands + whether the integration's Docker image is already cached).
- First-time run on a host: each distinct Docker image needs a one-time pull (20–60s per image).
- Failure modes are loud: the analyzer never silently produces garbage. If something is wrong, you'll see a clear stderr message.

## 10. Non-Python integrations (JavaScript / PowerShell)

The analyzer's two phases handle non-Python integrations asymmetrically:

- **Static analysis**: graceful skip — empty static set, clear stderr log, the analyzer process still exits `0`.
- **Dynamic analysis (current)**: exits non-zero (rc=3) with empty stdout. (This asymmetry is a known limitation tracked as a future improvement — see [`check_command_params_design.md`](check_command_params_design.md:1) §"Language asymmetry".)

For the AI, **treat any JavaScript or PowerShell integration the same way you treat `module_not_found`**: ignore the analyzer's output, read the integration source + YML directly, and write a polished per-command param list manually. The batch runner surfaces the rc=3 as `{"error": ..., "stderr": ...}` in the cell — Step 1 of the decision tree (§6e above) covers this case. **Never propagate the error into the persisted pipeline data.**

## 11. Command-argument seeding (ON by default)

The dynamic phase invokes each command via `demisto.args()`. Many handlers
take their YML arguments as **required positional parameters** (e.g.
`def check_ip_command(reliability, ip, ...)` invoked as
`handler(**demisto.args())`). If `args()` returns `{}`, those handlers
crash with `TypeError: missing required positional argument` **before any
HTTP request**, so the param-flow capture sees nothing → `status: no_data`
across the integration.

**Argument seeding fixes this.** For each command, the analyzer builds the
`demisto.args()` dict from the command's YML `arguments`, with this
per-argument precedence:

1. `--seed-arg CMD:NAME=VALUE` operator override (per-command scoped).
2. YML `defaultValue` (parsed).
3. First `predefined` option (enum-style args — e.g. `true`/`false`, a format selector).
4. A grep-able `SENTINEL_ARG_<name>` sentinel.

Every declared argument gets a value, so required-positional handlers run.
Seeding is **ON by default**; pass `--no-seed-args` for the legacy
empty-`args()` behavior.

**When to use `--seed-arg`:** auto-seeding satisfies the *signature*, but a
sentinel like `SENTINEL_ARG_ip` won't pass a value-validator (e.g.
`ipaddress.ip_address(ip)`). When a command still fails on a
malformed-argument validation, re-run with a real value:
`--seed-arg ip:ip=1.1.1.1`. The `CMD:` prefix means the same arg name on
different commands can take different values.

**Note:** seeding args makes a command *run*; it does not by itself make
arg-derived params capturable. The param signal still comes from the
sentinel-on-wire scan, the params-access spy (§12), and static analysis.

## 12. Params-access spy

The sentinel-on-wire scan only detects params whose seeded **value travels
into an outgoing HTTP request**. It misses params that are read but never
sent: control-flow booleans (`if params.get("disregard_quota")`),
post-response/client-side params (`integrationReliability` used to compute
a DBot label), and short YML-default values recorded as non-traceable.

The **params-access spy** closes that gap. The analyzer replaces the child's
params dict with an instrumented `TrackingMapping` that records every key
READ at runtime (`__getitem__`, `.get()`, `__contains__`), then reports the
accessed-key set back to the parent. A spy hit folds into the per-param
`attributions[*].by_source` as the `dynamic_access` source at confidence
**0.9** — high, but below the on-wire `dynamic_capture` (1.0) gold tier, so
the verdict stays `needs_review`: **the agent should still double-check.**

### 12.1 Baseline diff (why a global read isn't tagged on every command)

A param read in module-level code or `main()` before dispatch is read on
**every** command run. To avoid tagging those on every command, the spy
computes a **baseline** = the startup "always-read" key set (test-module's
accessed set, unioned with the intersection of all commands' accessed
sets). Only keys read **above** the baseline for a given command are
elevated to `dynamic_access`. Pre-dispatch / module-import reads fall into
the baseline and stay at their existing low static tier (0.2 / 0.1).

### 12.2 Known limitation — module-level-global integrations

Integrations that read params into **module-level globals** at import time
(a very common older-XSOAR pattern), e.g.:

```python
SERVER = demisto.params().get("server")
MAX_AGE = demisto.params().get("days")
```

execute those reads on **every** child run (import precedes any command),
so they all land in the baseline → nothing is "above baseline" → the spy
elevates **nothing** for that integration. This is intentional: the
baseline correctly prevents per-command false-positives, but it also means
the spy adds no signal for the module-global pattern. **For these
integrations, fall back to source review** (the "err on inclusion"
principle, §7) — the spy is silent precisely so it never over-claims. The
spy's value is for integrations that read params **inside handlers /
helpers at call time** (especially through dynamic dispatch, `getattr`, or
helper chains deeper than `--call-graph-depth`, which static analysis can
miss).

### 12.3 Confidence tier reference (updated)

| source | confidence | meaning |
|---|---|---|
| `dynamic_capture` | 1.0 | seeded value observed on the wire (gold) |
| `handler_body` | 1.0 | direct `params.get()` in the command handler (static) |
| `dynamic_access` | **0.9** | **params-access spy: read at runtime, above baseline (needs_review — double-check)** |
| `helper_depth_1..4+` | 0.8 → 0.3 | `params.get()` reached through a helper at call-graph depth N |
| `module_const_referenced` | 0.5 | a module constant binding a param is referenced in reachable code |
| `pre_dispatch_main` | 0.2 | read in `main()` before dispatch (every command) |
| `module_const_hedged` | 0.1 | module-const reference with an uncertain static walk |

### 12.4 Presenting scores to the user (Step 2)

When you present the Step 2 `Params to Commands` payload for approval, make
the **per-param confidence explicit** so the user can see what the analyzer
proved vs. what you decided yourself. Show, per param: the **max score**
(the `rollup_confidence`), its top **source**, and whether you **added it
by source review** (analyzer score below your inclusion bar). A compact
table works well:

| Param | Max score | Top source | Decision |
|---|---|---|---|
| `disregard_quota` | 0.8 | `helper` | trust (analyzer) |
| `integrationReliability` | 0.2 | `pre_dispatch_main` | investigated — reputation post-response param |
| `days` | 0.1 | `module_const_hedged` | investigated — used in reputation handlers |

Call out explicitly which params you elevated despite a low analyzer score
(the "investigated myself" rows) and why, so the override is auditable.


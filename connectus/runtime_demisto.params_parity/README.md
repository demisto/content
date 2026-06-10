# Param Parity Test (Runtime `demisto.params()` Equivalence Gate)

This folder implements the **param parity test** — step `param parity test passes` (#11) of the ConnectUs migration workflow (see [`connectus/Readme.md`](../Readme.md) and [`connectus/connectus-migration-SKILL.md`](../connectus-migration-SKILL.md)).

## What it tests

When a content integration (e.g. [Salesforce IAM](../../Packs/Salesforce/Integrations/Salesforce_IAM/Salesforce_IAM.yml)) is migrated to a ConnectUs connector, the runtime `demisto.params()` dict the integration's Python code receives MUST be equivalent whether the instance was created via:

  * **The legacy XSOAR flow** — `PUT /settings/integration` with the YML-declared params (the **INTEGRATION side**).
  * **The new ConnectUs flow** — UCP Shell API → mirrors instance to XSOAR with connector-delivered params (the **CONNECTOR side**).

Any non-trivial difference between these two `demisto.params()` snapshots indicates a connector bug (missing field, leaking field, wrong default, broken serializer mapping). This test runs both flows end-to-end and diffs the captured dicts.

## Architecture

```
┌─────────────────────────┐                  ┌─────────────────────────┐
│  Salesforce_IAM.yml     │                  │  test_data/connectors/  │
│  (17 params declared)   │                  │     salesforce/         │
│                         │                  │  (capabilities, conf,   │
└────────────┬────────────┘                  │   connection, etc.)     │
             │                               └────────────┬────────────┘
             │ via                                        │ via
             ▼                                            ▼
   ┌──────────────────────┐                   ┌──────────────────────┐
   │ xsoar_capture.py     │                   │ ucp_capture.py       │
   │ create instance →    │                   │ port-forward → UCP   │
   │ test-module → probe  │                   │ creates instance →   │
   │ fires → return_error │                   │ mirror to XSOAR →    │
   │ payload parsed       │                   │ inject magic key →   │
   │                      │                   │ test-module → probe  │
   └──────────┬───────────┘                   └──────────┬───────────┘
              │                                          │
              │   INTEGRATION-side dict   CONNECTOR-side │
              │                                          │
              ▼                                          ▼
                ┌──────────────────────────────┐
                │ normalizers.py               │
                │ deterministic IGNORE policy: │
                │ drop type 4/9, mirror_out,   │
                │ magic key, framework noise   │
                └──────────────┬───────────────┘
                               │
                               ▼
                ┌──────────────────────────────┐
                │ diff.py                      │
                │ symmetric key-union diff +   │
                │ serializer-mapping awareness │
                └──────────────┬───────────────┘
                               │
                               ▼
                ┌──────────────────────────────┐
                │ check_param_parity.py        │
                │ orchestrator CLI:            │
                │   exit 0 on parity (pass)    │
                │   exit 1 on any failure      │
                └──────────────────────────────┘
```

## The probe

`check_param_parity.py` relies on a small probe inserted into [`Packs/Base/Scripts/CommonServerPython/CommonServerPython.py`](../../Packs/Base/Scripts/CommonServerPython/CommonServerPython.py) (lines ~13903-13955) that:

1. Detects `demisto.command() == 'test-module'` **AND** `demisto.params().get('__params_parity_dump__') == '1'`.
2. Clears `LOG.replace_strs` to neutralize `IntegrationLogger`'s over-broad substring-match auto-masker (which would otherwise replace values of `*key`-suffixed params with `<XX_REPLACED>`).
3. Emits `PARAMS_PARITY_DUMP::{"__params_parity_dump__": true, "params": <full demisto.params()>}` via `return_error()`.

The orchestrator injects `__params_parity_dump__: "1"` into both creation payloads so the probe fires reliably. Safety: the probe is wrapped in `try/except`; any failure is silently swallowed so it can never break unrelated integrations.

## Files

| File | Purpose |
|---|---|
| [`xsoar_capture.py`](xsoar_capture.py) | INTEGRATION-side capture: connect XSOAR → create instance → run test-module → parse params dump → cleanup. Top-level: `capture_xsoar_params()`. |
| [`ucp_capture.py`](ucp_capture.py) | CONNECTOR-side capture: port-forward to UCP shell pod → GET creation view → POST /instances → poll XSOAR for mirror → inject magic key → test-module → parse → cleanup. Top-level: `capture_ucp_params()`. |
| [`normalizers.py`](normalizers.py) | Deterministic IGNORE policy. Strict exact-match comparison (no value normalization in MVP). Top-level: `normalize_for_diff()`. |
| [`diff.py`](diff.py) | 5-state symmetric key-union diff engine + serializer-mapping annotations + connector-file `reason_hint` grep. Top-level: `diff_params()`. |
| [`resolver.py`](resolver.py) | Resolves `--integration-id` → connector dir/id, integration YML/brand, capabilities/profiles, and the compare/ignore policy from the pipeline CSV + connector repo. Top-level: `resolve()`; shared `slugify()`. |
| [`check_param_parity.py`](check_param_parity.py) | **Orchestrator CLI** (the main entry point; resolver-driven). |
| [`results_ledger.py`](results_ledger.py) | Phase 7 results persistence: writes the per-run envelope JSON (captures scrubbed by default) + appends a row to `results/ledger.csv`. Top-level: `write_result()`, `append_ledger()`, `result_filename()`. |
| [`tenant_lock.py`](tenant_lock.py) | Per-tenant filesystem lock (acquire/release/force-unlock; TTL/heartbeat/stale-reclaim). Keeps parallel shells from deploying to the same tenant at once. |
| [`deploy_and_test.py`](deploy_and_test.py) | Atomic wrapper the skill runs per integration: acquire lock → `deploy.py` → `check_param_parity.py` → release (try/finally). Exit codes `0/10/11/20/21/30`. |
| [`main.py`](main.py) | Thin CLI wrapper around `xsoar_capture` for ad-hoc INTEGRATION-side capture in isolation. |
| [`create_ucp_instance.py`](create_ucp_instance.py) | Thin CLI wrapper around `ucp_capture` for ad-hoc CONNECTOR-side capture in isolation (with interactive Slack-permissions reminder). |
| [`deploy.py`](deploy.py) | GitLab CI/CD helper for deploying connector content to a tenant (whole-manifest / whole-branch). |
| [`test_data/connectors/<name>/`](test_data/connectors/) | Pre-built connector YAMLs the test suite diffs against. |
| `results/` | Git-ignored Phase 7 artifacts: per-run envelope JSONs + `ledger.csv`. |
| `.locks/` | Git-ignored per-tenant lockfiles (see `tenant_lock.py`). |

## Prerequisites

1. **Root `.env`** — there is ONE unified `.env` for all connectus/UCP tooling, living at the **repo root** (`/<content-repo>/.env`), NOT in this directory. Copy the root template to the root `.env` and fill it in:
   ```bash
   cp .env.example .env   # run from the content-repo root
   ```
   The REQUIRED values are: `DEMISTO_BASE_URL`, `DEMISTO_API_KEY`, `XSIAM_AUTH_ID`, `CONNECTUS_REPO_DIR` (local clone of unified-connectors-content — used by both deploy git ops AND the resolver), `CONNECTUS_BRANCH` (the connectus-repo branch deploy.py force-pushes), `TENANT_ID` (your single tenant — one per shell; sent to the GitLab pipeline as `TENANT_IDS`), and `GITLAB_TOKEN` (scope `api`). The rest have safe defaults. ⚠️ `BASE_BRANCH` controls a `git reset --hard origin/<base>` on every deploy — it discards un-pushed local changes on `CONNECTUS_BRANCH`.

   Every script here loads this root `.env` automatically via the shared loader [`connectus/env_loader.py`](../env_loader.py) (`load_env()`), which resolves the repo root from `__file__` and loads `<repo_root>/.env` by an explicit path — so it works no matter which directory you run the tools from. **Do not** create a per-tool `.env` in this folder, and **do not** call `load_dotenv()` directly; use `load_env()`.
2. **Patched Base pack on the tenant** — the probe must be present on the tenant's `CommonServerPython` script. Upload via:
   ```bash
   demisto-sdk upload -i Packs/Base -z -mp platform
   ```
3. **Target integration installed** — for Salesforce IAM:
   ```bash
   demisto-sdk upload -i Packs/Salesforce -z -mp platform
   ```
4. **Target connector deployed to UCP** — use [`deploy.py`](deploy.py) (GitLab CI/CD path).
5. **GKE access for UCP-side capture**:
   * `gcloud` CLI authenticated (`gcloud auth login`).
   * `kubectl` on `PATH`.
   * Slack-channel permission grant for the GKE project (request via `#xdr-permissions-dev`).
6. **Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## The one command

The orchestrator is **resolver-driven**: the ONLY required input is the
integration id. Everything else — the connector dir/id, the integration
YML/brand, ALL (sub-)capabilities + profiles, and the compare/ignore policy —
is resolved at runtime from the migration pipeline CSV + the connector repo by
[`resolver.resolve()`](resolver.py). There are NO connector-specific defaults;
this is a mass-migration tool, not a single-integration POC.

```bash
cd connectus/runtime_demisto.params_parity
python check_param_parity.py --integration-id "<Integration ID>"
# e.g. python check_param_parity.py --integration-id "Salesforce IAM"
```

That's it. The orchestrator:

  1. Resolves the integration id → connector/capabilities/profiles/policy.
  2. Captures the INTEGRATION-side `demisto.params()`.
  3. Captures the CONNECTOR-side `demisto.params()`.
  4. Normalizes both with the IGNORE policy.
  5. Diffs them with serializer-mapping awareness.
  6. Prints the JSON envelope to stdout (with raw captures embedded for triage).
  7. **Persists** the run to `results/` (JSON + `ledger.csv` — see below).
  8. Exits per the exit-code contract below.

> **Prerequisite — `Connector Folder Path`.** The resolver looks up the
> connector tree from the pipeline CSV's `Connector Folder Path` column. That
> cell MUST be set (e.g. via
> `python3 connectus/workflow_state.py set-connector-path "<Integration ID>" connectors/<slug>`)
> **before** the param-parity test can run, or the resolver raises a
> `ResolverError` and the test is setup-blocked (exit `2`).

### Exit-code contract (`check_param_parity.py`)

| Exit | Meaning |
|---|---|
| `0` | **Parity pass** (`status: "pass"`, `n_fail == 0`). |
| `1` | **Parity fail** — a real diff (`MISSING`/`EXTRA`/`VALUE_MISMATCH` not downgraded by `--allow-*`). |
| `2` | **Setup-blocked** — resolver/capture failure (tenant unreachable, `Connector Folder Path` unset, handler not on disk, flow error). NOT a parity diff. |

This contract is **stable**; the Phase 7 results-persistence step never changes
it (a persistence write failure logs a warning and the exit code is unchanged).

### Useful CLI flags

The required `--integration-id` is the only input the resolver needs. The
remaining flags are OPTIONAL overrides (default `None`): pass one to pin a single
knob the resolver would otherwise supply.

| Flag | Purpose |
|---|---|
| `--integration-id <id>` | **Required.** The migration pipeline integration id (e.g. `"Salesforce IAM"`). Everything else is resolved from it. |
| `--allow-missing` | Downgrade `MISSING_IN_CONNECTOR` findings to `warn` (no exit-code 1). |
| `--allow-extra` | Same, for `EXTRA_IN_CONNECTOR`. |
| `--allow-mismatch` | Same, for `VALUE_MISMATCH`. |
| `--integration-yml <path>` | Override: pin the integration YML the resolver would supply. |
| `--integration-brand <name>` | Override: pin the brand string for the XSOAR-mirror lookup. |
| `--connector-id <id>` | Override: pin the connector id. |
| `--connector-dir <path>` | Override: pin the connector YAML directory (used for `reason_hint` attribution and serializer parsing). |
| `--no-scrub-results` | DEBUGGING ONLY: write the persisted result JSON with RAW captures (do NOT redact `demisto.params()` values). Default scrubs — see [Results & ledger](#results--ledger-phase-7). |
| `--skip-xsoar` + `--integration-capture-file <path>` | Dev convenience: re-use a previously-captured INTEGRATION-side dict from disk. |
| `--skip-ucp` + `--connector-capture-file <path>` | Same, for the CONNECTOR-side. |
| `--verbose` | Enable DEBUG logging. |

## The deploy + test wrapper (`deploy_and_test.py`)

In the migration pipeline the param-parity test never runs standalone — it runs
behind the atomic wrapper [`deploy_and_test.py`](deploy_and_test.py), which the
skill invokes ONE command per integration:

```bash
python deploy_and_test.py --integration-id "<Integration ID>"
```

The wrapper performs the whole indivisible critical section inside a
`try/finally` (the lock is ALWAYS released, even on crash):

```
acquire tenant lock → deploy.py (whole-manifest) → check_param_parity.py → release
```

### Wrapper exit-code contract

The skill branches deterministically on this contract (it does NOT re-interpret
stdout):

| Exit | Meaning | Skill action |
|---|---|---|
| `0` | Deployed + parity **passed**. | `markpass "param parity test passes"`. |
| `10` | Parity **FAILED** (real diff). | Report the mismatching params; cell stays empty. |
| `11` | Parity **BLOCKED** (setup, e.g. handler not on disk / `Connector Folder Path`/`REPO_DIR` unset). | Report the setup fix; cell stays empty. |
| `20` | **Deploy failed.** | Report the failed GitLab jobs + URL; CSV unchanged. |
| `21` | **Deploy timeout.** | Report the still-running pipeline URL; CSV unchanged. |
| `30` | Could not acquire the **tenant lock** (timeout). | Report the holder + options; NO auto-retry. |

(`check_param_parity.py`'s `0/1/2` map to the wrapper's `0/10/11`; deploy's
`1/2` map to `20/21`; lock-busy maps to `30`.)

## The per-tenant lock (`tenant_lock.py`)

Deployment is **whole-manifest**: [`deploy.py`](deploy.py) resets/force-pushes the
`xsoar` branch and triggers a GitLab skinny pipeline against the `.env`
`TENANT_IDS`. A deploy to tenant **X** clobbers whatever was on X, so two shells
deploying to the SAME tenant concurrently corrupt each other's test. The lock is
therefore **per-tenant** (keyed by the ICaaS / `TENANT_IDS` value) — not global,
not per-integration. Shells on *different* tenants run fully in parallel.

[`tenant_lock.py`](tenant_lock.py) is a filesystem lockfile under `.locks/`
(git-ignored), created atomically via `O_CREAT | O_EXCL`:

* **`acquire` BLOCKS internally** (up to `ACQUIRE_MAX_WAIT`, default 1800s) with
  poll-retry; it is NOT the AI's job to loop.
* **TTL + heartbeat** — the holder touches `heartbeat_at` every
  `HEARTBEAT_INTERVAL` (30s) so a slow-but-alive deploy isn't mistaken for dead;
  a lock whose `heartbeat_at` is older than `TTL` (1200s) is stale.
* **Stale/dead-holder reclaim** — if the holder `pid` is not alive OR the lock is
  stale, `acquire` reclaims it atomically and proceeds. A crashed holder never
  causes a timeout.
* **Owner-checked release** — `release` deletes the file iff this shell owns it
  (matching `shell_id`); also fires on `atexit` / SIGINT / SIGTERM.
* **`force-unlock --tenant X`** — manual reclaim for a known-dead holder.
* **No auto-retry on timeout** — if `acquire` times out (wrapper exit `30`), the
  skill STOPS and reports the holder + options to the user. The only retry is
  human-initiated.

## Parallel multi-shell

Multiple AI shells run the migration in parallel, each taking different
integrations — possibly on different tenants. **One tenant per shell:** each
shell sets its OWN tenant in its OWN `.env` (`TENANT_IDS`). Shells on distinct
tenants never block each other. If two shells happen to target the SAME tenant,
the per-tenant lock serializes them so they can't clobber each other's deploy
mid-test — the second shell's `acquire` blocks until the first releases.

## Results & ledger (Phase 7)

Every `check_param_parity.py` run is persisted to `results/` (git-ignored) by
[`results_ledger.py`](results_ledger.py), in ADDITION to printing the envelope to
stdout. Persistence happens BEFORE the exit code is returned and is guarded so a
write failure logs a warning but NEVER changes the exit-code contract.

```
connectus/runtime_demisto.params_parity/results/
├── ledger.csv                                                  # append-only tracking index
└── <connector-slug>__<integration-slug>__<UTC-timestamp>.json # full envelope (audit detail)
```

* **Per-run JSON** — the envelope written verbatim, e.g.
  `salesforce__salesforce-iam__20260607T170006Z.json` (timestamp is
  `YYYYMMDDTHHMMSSZ`, UTC; append-only, never overwritten). **By default the
  `captures` block is SCRUBBED**: every value under `captures.integration` /
  `captures.connector` is replaced with `"<redacted>"` (keys preserved) because
  the server may inject real tokens into `demisto.params()`. Pass
  `--no-scrub-results` to write raw captures for debugging.
* **`ledger.csv`** — one row per run; created with a header the first time.
  Columns (exact):

  | Column | Source |
  |---|---|
  | `timestamp` | the same UTC stamp used in the JSON filename |
  | `integration_id` | the `--integration-id` |
  | `connector_slug` | `slugify(connector_id)` |
  | `status` | `envelope["status"]` (`pass`/`fail`) |
  | `n_fail` | `envelope["summary"]["n_fail"]` |
  | `result_file` | the JSON filename (basename) |

The wrapper's captured output includes a `Result written: <path>` INFO line so an
operator (or the skill) can jump straight to the audit JSON. This ledger is the
parity DETAIL; the pipeline CSV ([`connectus-migration-pipeline.csv`](../connectus-migration-pipeline.csv))
still records only a single ✅ in `param parity test passes`.

## The JSON envelope (output schema)

```json
{
  "status": "pass" | "fail",

  "summary": {
    "n_total":                  <int>,    // size of (integration ∪ connector) keysets after IGNORE
    "n_ok":                     <int>,
    "n_missing_in_connector":   <int>,
    "n_extra_in_connector":     <int>,
    "n_value_mismatch":         <int>,
    "n_dropped":                <int>,    // EXTRA_IN_INTEGRATION (framework noise)
    "n_fail":                   <int>,    // total fail-verdict findings (drives "status")
    "n_warn":                   <int>     // total findings downgraded by --allow-*
  },

  "per_param": [
    {
      "name":               "<param>",
      "state":              "<one of OK | MISSING_IN_CONNECTOR | EXTRA_IN_CONNECTOR | VALUE_MISMATCH>",
      "integration_value":  <value>,        // present if INTEGRATION has the key
      "connector_value":    <value>,        // present if CONNECTOR has the key
      "verdict":            "ok" | "fail" | "warn",
      "reason_hint":        "<source-file attribution string>",   // ONLY for EXTRA_IN_CONNECTOR
      "serialized_from":    "<connector_field>",                  // ONLY when this XSOAR param is the destination of a serializer mapping
      "serialized_to":      "<xsoar_param>"                       // ONLY when this connector field is the source of a serializer mapping
    }
    // ...
  ],

  "dropped": [
    // EXTRA_IN_INTEGRATION entries — INTEGRATION-side keys not in YML
    // (XSOAR framework noise; reported but never fail the gate).
    { "name": "<param>", "integration_value": <value>, "reason": "extra_in_integration" }
  ],

  "captures": {
    // RAW demisto.params() dicts BEFORE any normalization or IGNORE filtering.
    // Always embedded for triage; lets you re-run the diff offline with different
    // policies/flags via --skip-xsoar / --skip-ucp.
    "integration": { ...full dict... },
    "connector":   { ...full dict... }
  },

  "normalizer_dropped": {
    // Keys the normalizer dropped from each side, with the reason.
    "integration": [ {"name": "...", "reason": "yml_type_ignored:9", "side": "integration"}, ... ],
    "connector":   [ {"name": "...", "reason": "name_ignored",       "side": "connector"},   ... ]
  },

  "inputs": {
    // Echo of the CLI args used so the report is reproducible.
    "integration_yml": "...",
    "integration_brand": "...",
    "connector_id": "...",
    "connector_dir": "...",
    "profile": "...",
    "capability": "...",
    "domain": "...",
    "allow_missing": false,
    "allow_extra": false,
    "allow_mismatch": false
  }
}
```

### The 6 per-param states

| State | Meaning | Fails gate? | What to do |
|---|---|---|---|
| `OK` | Same key, same value on both sides. | No | ✅ |
| `OK_IGNORED` | Key was IGNORE'd by the normalizer policy (credentials, encrypted, mirroring, framework noise, magic key). Surfaced in `per_param` for visibility with a `reason` field explaining the policy. | No | ✅ Read the `reason` to confirm the IGNORE classification is intentional. |
| `MISSING_IN_CONNECTOR` | Integration's YML declares the param; connector doesn't deliver it. | Yes (unless `--allow-missing`) | Add the param to the connector's `configurations.yaml`. |
| `EXTRA_IN_CONNECTOR` | Connector delivers a field; integration's YML doesn't declare it. | Yes (unless `--allow-extra`) | Either add it to the integration YML, add a serializer mapping that maps/drops it, or remove it from the connector. The `reason_hint` field names the connector YAML that declared the leak. |
| `VALUE_MISMATCH` | Both sides have the key but the values differ. | Yes (unless `--allow-mismatch`) | Real default-value drift or serializer bug. **If `serialized_from` is present, the value was rewritten by a serializer** — check whether the serializer is implementing the right transformation. Note: the orchestrator auto-aligns inputs across serializer mappings (see below), so most serializer-driven VALUE_MISMATCH findings are real bugs, not test-setup drift. |
| `EXTRA_IN_INTEGRATION` | INTEGRATION-side has the key, CONNECTOR-side doesn't, AND it's NOT in the integration's YML (= XSOAR framework noise). | No (reported under `dropped`) | Add to `normalizers.IGNORED_PARAM_NAMES` if it shows up consistently. |

`status: "pass"` iff `n_fail == 0`.

### Auto-aligned dummy values via serializer mappings

The point of this test is that both sides should produce the **same** `demisto.params()` dict. When the connector's `serializer.yaml` declares a mapping like:

```yaml
field_mappings:
  - id: "domain"       # connector field (source)
    field_name: "url"  # XSOAR param (destination)
```

…the orchestrator auto-derives this rule:

> "the INTEGRATION-side `url` override = the CONNECTOR-side `domain` value"

…and applies the auto-derived override when calling `capture_xsoar_params()`. So if you run `python check_param_parity.py --domain test.salesforce.com`, the INTEGRATION side will receive `url="test.salesforce.com"` (auto-aligned) instead of the default dummy `url="https://dummy.example.com"`.

This eliminates false-positive VALUE_MISMATCH findings from test-setup drift across the serializer boundary. **Any remaining VALUE_MISMATCH on a serialized field is a REAL connector bug** (e.g., the serializer is transforming the value with extra logic, or the connector isn't even running the serializer at runtime).

### Serializer-mapping annotations

The diff engine parses every `serializer.yaml` under the connector dir and exposes two annotation keys on each per_param entry:

* **`serialized_from`** — present when the entry's `name` is the **XSOAR param** that a serializer mapping fills. Tells the operator "the integration sees this value AFTER the serializer remapped it from `<connector_field>`". For example, on the Salesforce connector, the `url` entry will have `"serialized_from": "domain"` because the connector serializer maps `domain → url`.

* **`serialized_to`** — present when the entry's `name` is the **connector field** that gets remapped. Tells the operator "this connector field is renamed on the integration side, so `EXTRA_IN_CONNECTOR`/`MISSING_IN_CONNECTOR` here is EXPECTED — look at `serialized_to` for the actual XSOAR-side param".

Together these make the report self-explanatory when serializer mappings are in play.

## The deterministic IGNORE policy

Some param-name patterns are dropped from comparison *before* the diff engine ever sees them. The policy is hard-coded in [`normalizers.py`](normalizers.py):

* **YML type 9 (credentials)** — UCP doesn't deliver credentials through `demisto.params()`. Examples: `credentials`, `credentials_consumer`.
* **YML type 4 (encrypted text)** — same reason. Examples: `consumer_key`, `consumer_secret`.
* **Mirroring fields** — XSOAR-only concept, not supported on the Platform. Names: `mapper_out`, `outgoingMapperId`, `defaultMapperOut`.
* **Probe protocol** — `__params_parity_dump__` must never leak into the diff.
* **Framework noise** — `apiproxy` and similar XSOAR-runtime-injected fields.

**Strict exact-match policy:** within the MUST-COMPARE bucket, NO value normalization is applied. This means `True` (bool) vs `"true"` (string) will surface as a `VALUE_MISMATCH`. Intentional for max signal in MVP.

## Guaranteed-different dummy values (Mode A bug detection)

The INTEGRATION-side dummy generator [`xsoar_capture.generate_dummy_value_for_param()`](xsoar_capture.py) emits values that are **guaranteed to differ** from each param's YML default. Why?

**The trap:** the XSOAR server auto-injects YML default values for any param NOT delivered in the instance-creation payload. So if our INTEGRATION-side dummy = YML default, AND the connector silently forgets to deliver a param, the XSOAR server fills in the same default on the CONNECTOR side — and the diff says ✅ OK, **missing the connector bug**.

**The fix:** the generator emits guaranteed-different values:

| YML type | YML default | INTEGRATION-side dummy |
|---|---|---|
| 8 (boolean) | `"true"` | `False` |
| 8 (boolean) | `"false"` | `True` |
| 8 (boolean) | (none) | `True` |
| 0 / 4 / 12 / 13 / 16 / 17 (text-like) | anything | `"<override_<param_name>>"` |
| 9 (credentials) | n/a | structured dict with `<override_user_<name>>` / `<override_pass_<name>>` |
| 15 (single select) | one of the options | pick a DIFFERENT option |
| 16 (multi select) | empty | `[options[0]]` |
| 16 (multi select) | non-empty | `[]` |

Now, when the diff runs:
* **If the connector delivers the param correctly** → both sides see the override → `OK`.
* **If the connector forgets to deliver the param** → INTEGRATION side sees the override, CONNECTOR side sees the server-injected YML default → `VALUE_MISMATCH`. Operator immediately knows the connector is silently relying on the server-default-injection (a Mode A bug).

This is much more sensitive than "use the YML default and hope to spot a difference." Every param is actively probed.

**Caveat (Mode B not yet covered):** if both the connector AND the YML declare the same param with the SAME default, AND the connector actively delivers that default, the diff says OK. This is the desired behavior — the connector is responsibly handling the param. But if the connector and YML disagree on the default value, the diff catches it as `VALUE_MISMATCH` too (because INTEGRATION-side gets the override, CONNECTOR-side gets the connector's default — which differs from both).

## Worked example — Salesforce IAM × Salesforce connector

Running `python check_param_parity.py` against Salesforce IAM × the Salesforce connector (capability `automation-and-remediation`, profile `oauth2_client_credentials.salesforce`, domain `test.salesforce.com`) currently produces this verdict:

* **`status: "fail"`** with 4 failures across 13 total keys.
* **9 OK** matches for the boolean toggles, locale keys, and `mapper_in`.
* **2 `MISSING_IN_CONNECTOR`**: `insecure`, `proxy`. The connector's `configurations.yaml` doesn't declare these, so the integration sees them as missing keys at runtime. If the integration's HTTP client depends on them (TLS-skip, proxy routing), this is a real gap.
* **1 `EXTRA_IN_CONNECTOR`**: `instance_name`, attributed by `reason_hint` to `"from capabilities.yaml (general_configurations)"`. The connector's `capabilities.yaml` `general_configurations.instance_name` field is leaking into `demisto.params()` even though the integration YML doesn't declare it. Fix: either add a serializer rule that drops it from the params stream, or expose it as a YML param.
* **1 `VALUE_MISMATCH`**: `url`, with `"serialized_from": "domain"`. The connector's `serializer.yaml` maps `domain → url`, BUT this VALUE_MISMATCH has two contributing causes the operator should disambiguate:
   1. The INTEGRATION-side test sets `url` to `"https://dummy.example.com"` (a generated dummy URL).
   2. The CONNECTOR-side test sets `domain` to `"test.salesforce.com"` (passed via `--domain`); the serializer copies it verbatim to `url` without prepending `https://`.
   
   Either fix the serializer to add the protocol prefix, OR change the INTEGRATION-side test's dummy URL to match what the serializer would actually produce.

Use `--allow-mismatch` to downgrade the `url` finding once you've decided which behavior is correct.

## MVP scope and known limitations

* **Python only.** The probe lives in `CommonServerPython.py`. JavaScript (`commonServer.js`) and PowerShell (`commonServerPowerShell.ps1`) probes are deferred. JS/PS integrations will fail with "test-module unexpectedly returned success".
* **Single-variant capture.** Each side runs `test-module` once. No iteration over fetch/longrunning sub-cases.
* **Hard-coded Salesforce-IAM payload builder.** [`ucp_capture._build_salesforce_iam_payload()`](ucp_capture.py) is specialized for the Salesforce connector. Adding new connectors will require a new builder (or generalizing the existing one).
* **ONE capability at a time.** The MVP enables exactly one capability per UCP instance.
* **No `workflow_state.py` integration.** The orchestrator is a standalone CLI — it does NOT call `markpass` / `fail` on the migration workflow.
* **Strict exact-match values.** `True` vs `"true"`, `50` vs `"50"`, leading/trailing whitespace — all surface as `VALUE_MISMATCH`. Intentional for max signal in MVP.
* **Dummy auth only.** Both sides use dummy credentials. Auth-related bugs (token refresh, etc.) are out of scope.
* **Reason-hint heuristic.** Field-source attribution uses regex grep — accurate for standard connector layouts but may miss unusual YAML shapes.
* **Serializer-mapping parser is minimal.** It currently understands only the `field_mappings: [{id, field_name}]` shape. `computed_fields` and conditional mappings are not yet parsed; they would surface as plain `VALUE_MISMATCH` without `serialized_from` annotation.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `test-module unexpectedly returned success` | Probe didn't fire — magic key wasn't delivered to the integration container, OR the patched `CommonServerPython.py` isn't on the tenant. | Run `demisto-sdk upload -i Packs/Base -z -mp platform` again. |
| `<XX_REPLACED>` appears in captured values | The probe ran but `LOG.replace_strs = []` clear didn't take effect. | Verify the patched probe block is the latest version in `CommonServerPython.py`. |
| UCP-side capture fails at "No XSOAR mirror appeared" | UCP created the instance but it didn't mirror to XSOAR within 45s. | Check XSIAM UI for the new instance; verify `--integration-brand` matches the YML's `name` field. |
| `gcloud / kubectl` errors during port-forward | Missing GKE permissions, expired auth, or wrong `UCP_TENANT_ID`. | Re-auth `gcloud`; request permissions in `#xdr-permissions-dev`; verify `UCP_TENANT_ID` in `.env`. |
| Test takes > 2 min | Mirror polling is the slow step. | Normal — UCP→XSOAR mirroring can take 30+ seconds on a loaded dev tenant. |

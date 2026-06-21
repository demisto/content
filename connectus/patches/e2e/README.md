# connectus/patches/e2e — black-box patch E2E suite

End-to-end, **black-box** tests for the on-disk remediation patches in
`connectus/patches/`. Each patch is invoked as a real **subprocess** (via
`sys.executable`) against a **sandboxed** copy of a fixture's connector tree, and
the result is compared **semantically** to a golden `connection.yaml`. This
mirrors the proven generator harness in
`connectus_migration/e2e/e2e_helpers.py`.

> **TDD-RED:** the patch this suite targets —
> `connectus/patches/add_vault_support.py` — **does not exist yet**. The suite is
> authored red-first and **auto-activates** the moment the patch lands. See
> [TDD-red status](#tdd-red-status) below.

## `add_vault_support.py` (under test — to be implemented)

### Purpose

Retrofit already-committed connectors' `connection.yaml` so each **type-9
PASSTHROUGH** profile gains a schema-valid `vault_mappings` block — **without
regenerating** from the XSOAR YML. It must:

- support `--dry-run` (compute + report changes, write nothing);
- be **idempotent** (re-running adds nothing; detect existing `vault_mappings`
  and skip);
- **only** touch passthrough profiles — never `plain`, never `api_key`, and never
  the `vault_support` boolean.

### `vault_mappings` shape (source of truth)

Per `unified-connectors-content/schema/connection.schema.json`
(`$defs.VaultMapping` + `Profile.vault_mappings`): a profile-level array, each
item `{ id, map }` where `id` is a non-empty string and `map` is an object with
`minProperties >= 1`, `additionalProperties: false`, and properties
`user` / `password` / `sshkey` (each a non-empty string). It is placed **after**
`description`, before `metadata` — matching the existing RemoteAccess golden:

```yaml
  vault_mappings:
  - id: credentials
    map:
      user: username
      password: password
  - id: additional_password
    map:
      password: additional_password
```

## Assumed CLI flag contract

The future `add_vault_support.py` **must honour** these flags (kept consistent
with `flatten_non_type9_nesting.py`). The harness invokes:

```bash
python3 patches/add_vault_support.py \
    --connectors-dir <tmp>/connectors \   # sandbox connectors root (REQUIRED by the harness)
    [--path <connector>] \                # restrict to one connector (dir/name)
    [--pipeline-csv <input>/connectus-migration-pipeline.csv] \  # discovery CSV override
    [--dry-run] \                         # report only; write nothing; exit 0
    [<extra_args...>]                     # any case-specific passthrough flags
```

| flag               | meaning                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------- |
| `--connectors-dir` | connectors root to scan/patch (the harness always points this at the tmp sandbox).       |
| `--path`           | restrict to a single connector dir/name (same semantics as `flatten_non_type9_nesting`). |
| `--pipeline-csv`   | path to the discovery CSV (`Integration ID`, `Integration File Path`, `Connector ID`, `Connector Folder Path`, …). Lets a case wire in a fixture-local CSV instead of the repo default. |
| `--dry-run`        | compute + **report** intended changes, write nothing, exit `0`.                          |

> If the implementer chooses different discovery flags, update `build_cmd()` in
> `patch_e2e_helpers.py` and this table together.

## Fixture layout

```
patches/e2e/
  patch_e2e_helpers.py          # black-box driver (sandbox + subprocess + semantic compare)
  add_vault_support_e2e_test.py # pytest driver (parametrized over cases)
  README.md                     # this file
  fixtures/
    <case>/
      case.json                 # { description, connector?, csv?, extra_args?, expect_modified? }
      input/
        connectors/<slug>/connection.yaml                 # BEFORE (sandboxed + patched in place)
        connectors/<slug>/components/handlers/<h>/handler.yaml  # owner linkage
        connectus-migration-pipeline.csv                  # discovery CSV (optional)
      expected/
        connectors/<slug>/connection.yaml                 # AFTER (semantic golden)
```

### `case.json` keys

| key              | required | meaning                                                          |
| ---------------- | -------- | ---------------------------------------------------------------- |
| `description`    | no       | human-readable note.                                             |
| `connector`      | no       | restrict the patch to one connector (passed as `--path`).        |
| `csv`            | no       | filename of the discovery CSV inside `input/` (→ `--pipeline-csv`). |
| `extra_args`     | no       | extra CLI flags appended verbatim.                               |
| `expect_modified`| no       | whether the LIVE run is expected to change the tree (default `true`); drives the dry-run report assertion and selects the negative/scope-guard cases. |

### Cases

- **`remote_access_v2_vault_backfill`** — the passthrough profile is back-filled
  with `vault_mappings`. AFTER is byte-for-semantic-equal to the existing
  `connectus_migration/e2e/.../remote_access_v2_from_scratch` golden; BEFORE is
  that same file with the `vault_mappings` block removed (and nothing else
  changed).
- **`negative_scope_untouched`** — a connector with three **non-passthrough**
  profiles (a `plain` type-9 username/password, an `api_key` type-9 token, and an
  `api_key` profile with `vault_support: true`). AFTER == BEFORE — proving the
  scope guard leaves non-passthrough + `vault_support` profiles untouched.

## What the test asserts (acceptance criteria)

1. **LIVE run** — patched `connection.yaml` semantically equals `expected/`
   AFTER (vault_mappings injected for RemoteAccess; unchanged for the negative
   case).
2. **DRY-RUN** — the sandbox tree is byte-for-byte unchanged, yet the CLI reports
   the intended change and exits `0`.
3. **IDEMPOTENCY** — a second live run over the already-patched tree produces no
   further change (no duplicate `vault_mappings`).
4. **SCOPE GUARD** — via `negative_scope_untouched`, `plain` + `api_key` +
   `vault_support` profiles are left untouched.

Comparison is **semantic**: YAML is parsed, order-canonicalized, and the leading
`# yaml-language-server` directive (and any leading comment/blank lines) is
stripped before comparing — formatting never causes a false failure.

## Run

```bash
cd content/connectus && python3 -m pytest patches/e2e/add_vault_support_e2e_test.py -v
```

## TDD-red status

This suite is **TDD-red until `connectus/patches/add_vault_support.py` exists.**
While the patch is missing, the four acceptance-criteria tests are marked
`pytest.mark.xfail(strict=False)` — they run, the subprocess fails (no such
file), and pytest records `xfail` rather than a hard error. The two suite-sanity
tests (`test_cases_are_discovered`, `test_fixture_is_well_formed`) always run.
The instant the patch is implemented, the `xfail` marker is no longer applied and
the real criteria are enforced. **Nothing here stubs the patch** to force a pass.

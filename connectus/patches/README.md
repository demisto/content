# connectus/patches

One-off remediation scripts that repair already-generated ConnectUs manifests
on disk. Unlike the manifest generator (which produces manifests from XSOAR
integration YMLs), these patches operate directly on the committed
`unified-connectors-content/connectors/<name>/connection.yaml` files.

## `flatten_non_type9_nesting.py`

### What it fixes

The manifest generator previously nested **non-type-9** auth params into dotted
`<param>.identifier` / `<param>.password` leaves. Only XSOAR **type 9** (the
Credentials widget) may legitimately nest. Types **4** (Encrypted text), **14**
(Certificate / Key), and everything else must be **flat**.

The generator itself has since been fixed — it flattens + warns going forward
(see `connectus_migration.manifest_generator._flatten_non_type9_param_map`,
called from `build_connection_profile`). This script repairs the manifests that
were **already written to disk** by the old generator so they match what a fresh
regeneration would now produce.

### What "nested" looks like on disk

Each `profiles[]` entry carries a `metadata.xsoar.interpolation_mapping`: a
comma-joined string of `<auth_parameter>:<xsoar_path>` entries.

- A **nested** entry has a dotted `xsoar_path` — `<param>.identifier` or
  `<param>.password`.
- A **flat** entry has a bare `xsoar_path`.

The corresponding `configurations[].fields[]` ids are derived from the dotted
key (mirroring `manifest_generator._connection_field_id_from_map_key`):

| map key                                   | field id           |
| ----------------------------------------- | ------------------ |
| `<param>.identifier`                      | `<param>_username` |
| `<param>.password` (with `.identifier`)   | `<param>_password` |
| `<param>.password` (no `.identifier`)     | bare `<param>`     |

### How it decides type-9 vs not (per-profile resolution)

For each dotted leaf the script resolves the **bare param name** (segment before
the dot) to its originating XSOAR YML `configuration[].type`.

Resolution is **per profile**, not per connector folder. A shared connector
folder (e.g. `aws`, with ~30 handlers) mixes many source integrations, and the
**same param name can have different types** across them — `access_key` is
type 0 in most AWS integrations but **type 9 in `AWS-WAF`**. A naive
folder-wide merge would clobber the type and could corrupt a legitimately
type-9 profile. So each profile is mapped back to its single source
integration via the handler linkage (the same chain
`fix_connection_mask_title.py` uses):

```
components/handlers/<h>/handler.yaml
    triggering.labels.xsoar-integration-id  == the source integration
    id  "xsoar-<view_group>"                == the profile's view_group
    capabilities[].auth_options[].id        == the profile's id
```

The owning integration's YML is then located via the pipeline CSV
(`content/connectus/connectus-migration-pipeline.csv`): `Integration ID` →
`Integration File Path`. (If the handler linkage can't resolve — e.g. a
hand-authored connector — it falls back to the connector-folder CSV rows.)

Decision per param:

- **type == 9** → leave nested (correct).
- **type != 9** → **flatten** (mirror of the fixed generator).
- **type unresolved** → **skip + report** (never blindly flatten — that could
  corrupt a legitimately-nested type-9 param). Override with
  `--flatten-unresolved`.

### Flattening semantics (mirror of `_flatten_non_type9_param_map`)

- `interpolation_mapping`: the dotted `xsoar_path` is replaced with the bare
  `<param>`. When **both** `.identifier` and `.password` leaves exist for one
  param, they **collapse onto a single flat entry**; the `.password` (secret)
  leaf **wins**, so the surviving auth role is the credential role, not the
  username role.
- `configurations[].fields[]`: the `<param>_username` + `<param>_password`
  fields collapse into a single `<param>` field carrying the winning
  `metadata.auth.parameter` and `options.mask: true` (a flattened non-type-9
  param is always a secret — type 4 / 14). A lone bare-`<param>` field keeps its
  place with the same masking guarantee.

### Safety / idempotency

- Type-9 nesting is **never** touched.
- Running twice is a **no-op** (already-flat params have no dotted leaf left).
- Unrelated YAML content and key order are preserved via `ruamel.yaml`
  round-trip (falls back to PyYAML only if `ruamel` is unavailable, with reduced
  formatting fidelity).
- `--dry-run` reports what **would** change without writing anything.

### Usage

Run from anywhere (paths resolve via `CONNECTUS_REPO_DIR` / repo-root, the same
as the rest of the toolchain):

```bash
# Whole-repo dry run (recommended first):
python3 content/connectus/patches/flatten_non_type9_nesting.py --dry-run

# Whole-repo apply in place (default):
python3 content/connectus/patches/flatten_non_type9_nesting.py

# Restrict to a single connector or connection.yaml:
python3 content/connectus/patches/flatten_non_type9_nesting.py --path connectors/koi
python3 content/connectus/patches/flatten_non_type9_nesting.py --path connectors/koi/connection.yaml

# Force-flatten leaves whose origin type can't be resolved:
python3 content/connectus/patches/flatten_non_type9_nesting.py --flatten-unresolved

# Point at a non-default connectors dir:
python3 content/connectus/patches/flatten_non_type9_nesting.py --connectors-dir /path/to/unified-connectors-content/connectors
```

Flags:

- `--dry-run` — report only, never write.
- `--connectors-dir DIR` — connectors root (default:
  `$CONNECTUS_REPO_DIR/connectors`, else
  `<repo-root>/unified-connectors-content/connectors`).
- `--path PATH` (or positional) — restrict to one `connection.yaml` or one
  connector dir/name (default: scan **all** connectors).
- `--flatten-unresolved` — also flatten dotted leaves whose origin XSOAR type
  cannot be resolved (default: skip + report).

The final summary prints how many manifests were scanned, how many were (or
would be) modified, the changed connectors with the specific flattened params,
and any unresolved params it skipped.

### Tests

```bash
cd content/connectus && python3 -m pytest patches/flatten_non_type9_nesting_test.py -q
```

The tests use synthetic `connection.yaml` fixtures in temp dirs and an
**injected** `{param_name: type}` resolver (so unit tests never touch real
source YMLs). They cover: type-14 flatten, type-9 left unchanged, mixed
manifests, `.identifier`+`.password` pair collapse (secret wins), idempotency,
unresolved-skip, clean-manifest no-op, dry-run-doesn't-write, and per-profile
type scoping.

## `add_vault_support.py`

### What it does

Retrofits already-committed connectors' `connection.yaml` so each **type-9
PASSTHROUGH** profile gains a schema-valid `vault_mappings` block — **without**
regenerating from the XSOAR YML. It mirrors the generator's derivation
(`connectus_migration.manifest_generator._build_vault_mappings` +
`_VAULT_MAP_SLOT_FOR_LEAF`) but applies it to manifests already on disk.

### Derivation — from `interpolation_mapping` (standalone by design)

This patch is **standalone**: it does **not** import the generator. The
generator derives `vault_mappings` from a freshly-built `raw_param_map` while
reading the integration YML; on an **already-committed** manifest that same
information is already encoded in each profile's
`metadata.xsoar.interpolation_mapping`, so the patch reproduces the equivalent
derivation **from the profile itself**. As a result the integration YML, the
handler linkage and the pipeline CSV are **not required** to compute the result.

`interpolation_mapping` is a comma-joined string of `<role>:<xsoar_path>` entries
(the **inverse** of the generator's raw param map — role on the **left**, dotted
path on the **right**). For each entry:

- a **dotted** `xsoar_path` (`<param>.<leaf>`) is a **type-9 credential leaf**.
  Group by `<param>`; map the leaf onto a vault slot — `identifier` → `user`,
  `password` → `password` — valued by that entry's **role** (the left side).
  Out-of-scope leaves (e.g. `sshkey`) are ignored (no slot invented).
- a **flat** (non-dotted) `xsoar_path` is **not** a type-9 credential → ignored.

One entry is produced per `<param>` (`{ id, map }`, `map` with ≥1 slot). For the
RemoteAccess fixture this yields (semantically equal to the golden):

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

> **Ordering note.** Entries are emitted in the order each `<param>` first
> appears (left-to-right) in `interpolation_mapping`, so byte-for-byte the patch
> may list `additional_password` before `credentials`. The E2E comparison is
> **semantic / order-canonicalized**, so this is equivalent to the golden; the
> within-`map` slot order is normalized to `user` then `password`.

### Placement

`vault_mappings` is inserted **immediately after** the profile's `description`
key (before `metadata`) via a `ruamel.yaml` round-trip, so the rest of the file
is preserved. If there is no `description`, it falls back to after `title`, then
to before `metadata`, then append.

### Scope guard (passthrough only)

- **Only** `type: passthrough` profiles qualify. `plain`, `api_key`,
  `external_auth`, `oauth2*` are **never** touched.
- The `vault_support` boolean is **never** added, removed or altered.
- A passthrough profile with no dotted type-9 cred in its `interpolation_mapping`
  gets nothing.

### Safety / idempotency / dry-run

- A passthrough profile that **already** has `vault_mappings` is **skipped** — no
  duplicate, no reorder; re-running is a **no-op**.
- Unrelated YAML content and key order are preserved (`ruamel.yaml` round-trip;
  PyYAML fallback only if `ruamel` is unavailable, with reduced fidelity).
- `--dry-run` computes + **reports** intended changes and exits `0` without
  writing.

### CLI flag contract

```bash
python3 content/connectus/patches/add_vault_support.py \
    [--connectors-dir DIR] \   # connectors root (default: $CONNECTUS_REPO_DIR/connectors,
                               #   else <repo-root>/unified-connectors-content/connectors)
    [--path PATH] \            # one connection.yaml or connector dir/name (default: all)
    [--pipeline-csv CSV] \     # accepted for parity with flatten_non_type9_nesting.py;
                               #   NOT needed (derivation is from interpolation_mapping)
    [--dry-run]                # report only; write nothing; exit 0
```

- `--connectors-dir DIR` — connectors root to scan/patch.
- `--path PATH` (or positional) — restrict to one `connection.yaml` or connector
  dir/name.
- `--pipeline-csv CSV` — accepted (so the E2E harness's invocation never errors)
  but unused: the vault_mappings come from each profile's own
  `interpolation_mapping`, not from the integration YML.
- `--dry-run` — report only, never write.

### Usage

```bash
# Whole-repo dry run (recommended first):
python3 content/connectus/patches/add_vault_support.py --dry-run

# Whole-repo apply in place (default):
python3 content/connectus/patches/add_vault_support.py

# Restrict to a single connector or connection.yaml:
python3 content/connectus/patches/add_vault_support.py --path connectors/remoteaccess
python3 content/connectus/patches/add_vault_support.py --path connectors/remoteaccess/connection.yaml
```

### Tests

```bash
cd content/connectus && python3 -m pytest patches/e2e/add_vault_support_e2e_test.py -v
```

The black-box E2E suite invokes the patch as a real subprocess against a
sandboxed copy of each fixture and compares the result **semantically** to the
golden. It covers: live back-fill matches `expected/`, `--dry-run` writes
nothing but reports, idempotent second run, and the scope guard (plain / api_key
/ `vault_support` profiles left untouched). Contract details are in
[`e2e/README.md`](e2e/README.md).

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

## `propagate_advanced_flag.py`

### What it fixes

XSOAR integrations may declare `advanced: true` on individual
`configuration[]` params (the param then surfaces under the legacy "Advanced"
panel). The ConnectUs FieldGroup schema exposes the same boolean at the **row
level** (`general_configurations.configurations[].advanced` and equivalents),
but the manifest generator currently drops it. This patch **back-fills**
`advanced: true` onto the matching FieldGroup rows of already-committed
`configurations.yaml` and `connection.yaml` files — **without** regenerating
from the XSOAR YML.

### What it modifies

Both `configurations.yaml` and `connection.yaml` per connector. Only **rows**
are changed (either an existing row is **promoted** by getting `advanced: true`
inserted, or a mixed row is **split** into a non-advanced + advanced sibling
pair). Field ids, field titles, field options and any other field-level
properties are **never** modified. No new fields are invented; no fields are
removed.

### Where it looks

All **5** FieldGroup row-placement contexts the schema defines:

1. `configurations.yaml` → `general_configurations.configurations[]`
2. `configurations.yaml` → `configurations[].configurations[]` (per-capability)
3. `connection.yaml` → `general_configurations.configurations[]`
4. `connection.yaml` → `profiles[].configurations[]` (per-profile)
5. `capabilities.yaml` → `general_configurations.configurations[]` (legality
   pinned in code for completeness; contexts 1–4 are the actively-patched ones)

### Per-handler scoping

Each row is resolved back to its **owning** XSOAR integration(s) via the
handler linkage (`components/handlers/<h>/handler.yaml`'s
`triggering.labels.xsoar-integration-id`) and the pipeline CSV:

- **Per-capability rows** are scoped to the handler(s) whose
  `capabilities[].id` matches the row's enclosing capability id.
- **Per-profile rows** are scoped to the handler(s) whose
  `capabilities[].auth_options[].id` matches the row's enclosing profile id
  (or whose `handler.id` derives the row's `view_group`).
- **General_configurations rows** use the **union** of advanced sets across
  all handlers under the connector (because a general row belongs to the
  connector as a whole, not to any one source integration).

This is the same per-handler linkage that
`flatten_non_type9_nesting.py` uses and prevents an advanced flag from one
handler bleeding into a sibling handler's per-capability / per-profile rows.

### Mixed rows are auto-split

When a single row contains **both** advanced and non-advanced fields, the
patch splits it into two sibling rows:

- The **original** row keeps the **non-advanced** fields (and stays in place,
  preserving its key order and surrounding siblings).
- A **new sibling** row is inserted **immediately after** with
  `advanced: true` and the advanced fields.

Field order is preserved within each resulting row (relative order of the
non-advanced fields is unchanged; relative order of the advanced fields is
unchanged).

### Propagation rules on split

When splitting a mixed row, sibling properties propagate to the new advanced
row only where the FieldGroup schema permits them:

- `view_group` propagates **only** on `general_configurations` rows **AND
  only** when the connector is `grouped: true` (per
  `connector.yaml settings.grouped`). Per-capability and per-profile siblings
  inherit `view_group` from their enclosing capability / profile, so the
  schema forbids it on the row itself.
- `required_for_capabilities` propagates **only** on `general_configurations`
  rows. Per-capability and per-profile rows imply their capability, so the
  schema forbids the field there.
- `advanced: true` is legal in every context; this is the entire reason the
  patch exists.

Per-capability and per-profile split siblings therefore carry **neither**
`view_group` nor `required_for_capabilities` — only `fields` and `advanced`.

### Safety / idempotency

- `ruamel.yaml` round-trip preserves formatting, key order, quoting and
  comments (PyYAML fallback only if `ruamel` is unavailable, with reduced
  fidelity).
- A row that **already** has `advanced: true` is **skipped** — a second run is
  a **no-op**.
- The patch never invents fields, never changes field metadata, never adds
  `view_group` / `required_for_capabilities` where the original row didn't
  have one.
- When the per-row lookup returns no advanced params (handler / pipeline-CSV
  gap), the row's fields are **reported as unmatched** and the file is left
  untouched.
- `--dry-run` computes and reports intended changes and exits `0` without
  writing.

### No changes to `manifest_generator.py`

This is a **one-off, content-side** patch. The generator itself is **not**
modified — fixing the generator would not retroactively update the manifests
that were already committed by older generator versions. This patch operates
directly on those committed files.

### CLI flag contract

```bash
python3 content/connectus/patches/propagate_advanced_flag.py \
    [--connectors-dir DIR] \   # connectors root (default: $CONNECTUS_REPO_DIR/connectors,
                               #   else <repo-root>/unified-connectors-content/connectors)
    [--path PATH] \            # one connector dir/name, configurations.yaml or
                               #   connection.yaml (default: scan all connectors)
    [--pipeline-csv CSV] \     # handler-id → source-YML map
                               #   (default: <connectus>/connectus-migration-pipeline.csv)
    [--dry-run]                # report only; write nothing; exit 0
```

| Flag                | Purpose                                                              |
| ------------------- | -------------------------------------------------------------------- |
| `--dry-run`         | Report what would change; write nothing.                             |
| `--connectors-dir`  | Override the `unified-connectors-content/connectors` root.           |
| `--path` (or positional) | Restrict to one connector dir/name or one of its manifests.     |
| `--pipeline-csv`    | Override the discovery CSV used to map handler id → source YML path. |

Env var: `CONNECTUS_REPO_DIR` selects the connectors repo when
`--connectors-dir` is omitted (same convention as the other patches).

### Usage

```bash
# Whole-repo dry run (recommended first):
python3 content/connectus/patches/propagate_advanced_flag.py --dry-run

# Apply to a single connector:
python3 content/connectus/patches/propagate_advanced_flag.py --path qualys

# With an explicit env var pointing at the connectors repo:
CONNECTUS_REPO_DIR=/path/to/unified-connectors-content \
    python3 content/connectus/patches/propagate_advanced_flag.py --dry-run --path qualys
```

### Tests

```bash
cd content/connectus && python3 -m pytest \
    patches/propagate_advanced_flag_test.py \
    patches/e2e/propagate_advanced_flag_e2e_test.py -v
```

- `patches/propagate_advanced_flag_test.py` — unit tests (whole-row
  promotion, mixed-row split, idempotency, unmatched reporting, `view_group`
  + `required_for_capabilities` propagation rules across the 5 contexts,
  per-handler scoping, and both `configurations.yaml` + `connection.yaml`
  row shapes).
- `patches/e2e/propagate_advanced_flag_e2e_test.py` — black-box E2E suite
  that invokes the patch as a subprocess against a sandboxed copy of each
  fixture and compares semantically to the golden. Fixtures:
  `configurations_general_advanced`, `configurations_per_capability_advanced`,
  `connection_profile_advanced`, and `no_advanced_params_noop`.

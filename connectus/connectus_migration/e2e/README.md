# `generate_manifest` end-to-end (golden-file) tests

Black-box, on-disk tests for `manifest_generator.py`. Each test feeds the
generator real **inputs** (a content integration YML + an optional pre-existing
connectus manifest) and compares the **generated output tree** against a
checked-in **expected** golden.

## One test case == one folder

Every test case is a **single self-contained directory** under
`fixtures/<feature>/<case-name>/`. There is nothing shared between cases — the
integration(s) and the connectus manifests for a case all live inside that
case's own folder:

```
fixtures/
  serializer/                                  <- a feature group
    add_handler_shared_param_name_dedup/       <- ONE test case = ONE folder
      case.json                                # the test's CLI inputs
      input/
        integration.yml                        # the integration being generated
        connectors/<slug>/...                  # OPTIONAL pre-existing manifest
        sub_capabilities_to_licenses.json      # OPTIONAL per-case license registry
      expected/
        connectors/<slug>/...                  # expected output tree
        CODEOWNERS                             # OPTIONAL (from-scratch cases)
```

To add a test, create a **new sibling folder** with its own `case.json`,
`input/`, and `expected/`. The harness auto-discovers every folder that
contains a `case.json` and turns each into its own parametrized pytest case
(id = `<feature>/<case-name>`).

## `case.json`

```json
{
  "description": "human readable (optional)",
  "connector_title": "GitHub",
  "mapped_params": { "Automation": ["team"] },
  "auth_methods": {},
  "manual_fields": { "serializer": {} },
  "expect_failure": false,
  "expect_stderr_contains": "FileExistsError"
}
```

- `connector_title` (**required**) — passed as the CLI title.
- `mapped_params` / `auth_methods` — serialized to JSON for the CLI args.
- `manual_fields` (optional) — maps to `--manual-<key>-fields` options
  (`connector`, `handler`, `summary`, `capabilities`, `configurations`,
  `serializer`, `connection`).
- `expect_failure` / `expect_stderr_contains` (optional) — negative cases:
  assert the run exits non-zero (and, optionally, that stderr contains a marker).

## How it runs

1. Copy `input/connectors/` (if present) into a temp `connectors/` root.
2. Invoke `manifest_generator.py` as a **subprocess** with
   `--connectors-root <tmp>/connectors`. The subprocess `cwd` is the **content
   repo root** so the from-scratch path can resolve the author image (its
   recorded path is relative to the content root, e.g.
   `Packs/GitHub/Integrations/GitHub/GitHub_image.png`). The integration YML and
   connectors-root are passed as absolute paths, so `cwd` only affects image
   resolution.
   - When `input/connectors/<slug>/` exists, the generator takes its
     **add-handler-to-existing-connector** path (the author image is ignored);
     otherwise it scaffolds **from scratch** (and copies the author image, so
     the title must map to an image that exists under the content root).
   - Output is sandboxed: `--connectors-root` is explicit and the generator's
     `CODEOWNERS` write lands at `<tmp>/CODEOWNERS`, never the real repo. For
     from-scratch cases that `CODEOWNERS` is snapshotted to `expected/CODEOWNERS`.
3. Compare the produced tree to `expected/connectors/`:
   - file-set must match exactly,
   - `*.yaml` compared by parsed-content deep equality (formatting, key order,
     and the `# yaml-language-server` directive line are ignored),
   - other files (e.g. `*.svg`/`*.png`) compared by raw bytes.

## Two hard constraints (subprocess can't be monkeypatched)

1. **Author image:** `connector_title` MUST be a key in
   `connector_to_author_image.json` (the CLI looks it up unconditionally).
2. **Licenses:** every sub-capability id the run produces
   (`<capability>_<integration-id-slug>`) MUST exist in
   `sub_capabilities_to_licenses.json`, or the run raises `RuntimeError`. Pick
   integration `commonfields.id` values and `mapped_params` accordingly — **or**
   drop a per-case `input/sub_capabilities_to_licenses.json` (see below) so the
   case introduces synthetic sub-capability ids without touching the shared
   production registry.

### Per-case license registry override (optional)

When a case needs sub-capability ids that aren't in the production
`sub_capabilities_to_licenses.json`, add an `input/sub_capabilities_to_licenses.json`
to the case. When present, the harness points the generator at it (via the
`CONNECTUS_SUB_CAPABILITIES_TO_LICENSES_PATH` env var the generator honours)
instead of the shared production file — so the production registry stays
untouched. The override file must list **every** sub-capability id the run
produces for this case (e.g. `fetch-issues_<slug>`,
`threat-intelligence-and-enrichment_<slug>`, `automation-and-remediation_<slug>`).

> Tip: choosing a `connector_title` + integration ids that match a real
> already-migrated connector (e.g. title `GitHub` with ids `GitHub` /
> `GitHub IAM`) satisfies both maps for free.

## Authoring / regenerating goldens

Author `expected/` by hand (TDD) **or** snapshot it from actual output:

```bash
# from the connectus/ directory
UPDATE_GOLDEN=1 python3 -m pytest connectus_migration/e2e/manifest_generator_e2e_test.py
```

`UPDATE_GOLDEN=1` rewrites each case's `expected/connectors/` (and captures the
sandboxed `CODEOWNERS`) from the generator's real output, then **skips** instead
of asserting. **Always review the resulting diff before committing** —
regenerating blindly will happily bless bugs.

## Running

```bash
# from the connectus/ directory
python3 -m pytest connectus_migration/e2e/manifest_generator_e2e_test.py -v
```

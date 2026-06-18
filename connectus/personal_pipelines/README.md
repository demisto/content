# Personal pipelines

This folder homes **personal copies** of the ConnectUs migration pipeline CSV,
plus the extractor that creates them:
[`extract_personal_pipeline.py`](extract_personal_pipeline.py).

The bundled pipeline at
[`connectus/connectus-migration-pipeline.csv`](../connectus-migration-pipeline.csv)
is shared by everyone and must never be hand-edited row-by-row. When you want
the migration tooling to operate on **just your rows** (your assignments, a
connector you own, a few explicit integrations), extract a personal subset
here and point `CONNECTUS_PIPELINE_CSV` at it.

The extractor only ever **reads** the main CSV — it never modifies it.

## How `CONNECTUS_PIPELINE_CSV` ties in

The migration tooling resolves the pipeline CSV through the
`CONNECTUS_PIPELINE_CSV` environment variable (see
[`connectus/workflow_state/csv_io.py`](../workflow_state/csv_io.py) and the
param-parity resolver). When that variable is **set and non-empty**, the
tooling reads the file it points at instead of the bundled default. The value
is loaded from the single repo-root `.env` via `load_env()` (see the
[Environment Configuration](../Readme.md) section of the connectus Readme).

* A **relative** path resolves against the **repo root** (e.g.
  `connectus/personal_pipelines/joey-schwartz.csv`).
* An **absolute** path is used as-is. `~` is expanded.

This script does **not** edit `.env` for you — it prints the exact line to add
yourself.

## The workflow

1. **Extract** your subset:

   ```bash
   python3 connectus/personal_pipelines/extract_personal_pipeline.py --mine
   ```

2. **Add** the printed line to your repo-root `.env`:

   ```dotenv
   CONNECTUS_PIPELINE_CSV=connectus/personal_pipelines/joey-schwartz.csv
   ```

3. **Use** the tooling — `workflow_state.py` and the param-parity resolver now
   read your personal copy.

## Selectors

At least one selector is **required** (the tool copies only the rows you
select; it will not duplicate the whole pipeline). Selectors are **additive**:
the result is the union of every match, de-duplicated by `Integration ID`, in
the same order as the main file.

| Flag | Selects |
| --- | --- |
| `--mine` | rows whose `assignee` equals `git config user.name` |
| `--assignee NAME` | rows for a specific assignee (case-insensitive) |
| `--connector ID` | rows for a specific `Connector ID` (case-insensitive) |
| `--integration-id ID` | a specific `Integration ID` (case-insensitive, **repeatable**) |

### Examples

```bash
# Everything assigned to you (git user)
python3 connectus/personal_pipelines/extract_personal_pipeline.py --mine

# A specific person's rows
python3 connectus/personal_pipelines/extract_personal_pipeline.py --assignee YuvHayun

# A whole connector
python3 connectus/personal_pipelines/extract_personal_pipeline.py --connector "Cisco Security"

# Explicit integrations (repeat the flag)
python3 connectus/personal_pipelines/extract_personal_pipeline.py \
    --integration-id AMP --integration-id APIVoid

# Combine selectors — the union is taken and de-duplicated
python3 connectus/personal_pipelines/extract_personal_pipeline.py \
    --mine --connector APIVoid --name my-work
```

## Destination

* Default: `connectus/personal_pipelines/<stem>.csv`, where `<stem>` is your
  slugified git user name (e.g. `Joey Schwartz` → `joey-schwartz`), falling
  back to `personal-pipeline` when the git user is unknown.
* `--name NAME` sets the filename stem (sanitized to a safe filename) inside
  this folder.
* `--output PATH` overrides the full destination path (absolute or
  repo-root-relative). `--output` takes precedence over `--name`.

## Overwrite guard

If the destination already exists, the tool **refuses** and exits non-zero.
Pass `--force` to overwrite:

```bash
python3 connectus/personal_pipelines/extract_personal_pipeline.py --mine --force
```

## Dry run

`--dry-run` does everything except write the file. It reports the row count,
the destination it would write, and the matched `Integration ID`s:

```bash
python3 connectus/personal_pipelines/extract_personal_pipeline.py --assignee noydavidi --dry-run
```

## Resulting `.env` line

After a successful run the tool prints (and you copy-paste) something like:

```dotenv
CONNECTUS_PIPELINE_CSV=connectus/personal_pipelines/joey-schwartz.csv
```

An absolute path works too — the tool prints that form as well.

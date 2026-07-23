---
name: pci-migrate-playbook
description: Migrate a Cortex XSOAR/XSIAM playbook YAML from old Core commands (e.g. core-block-ip) to new PCI/Builtin commands (e.g. blockIPs) by driving playbooks_pci_migration/migrate_playbook.py, then reviewing and hand-fixing the residuals the script could not resolve. Use when the user asks to migrate, convert, port, or upgrade a playbook from old Core/xdr- commands to the new PCI (Builtin) commands, or mentions migrate_playbook.py / endpoint_mapping.json.
---

# 🔀 pci-migrate-playbook

Migrate a playbook from old Core commands to new PCI (`Builtin`) commands using [`migrate_playbook.py`](playbooks_pci_migration/migrate_playbook.py), then hand-fix what the script flags as `[UNMAPPABLE]`. The script is validated: drive it, do not modify it. Playbook YAML structure reference lives in [`references/playbook-structure.md`](playbooks_pci_migration/references/playbook-structure.md).

This bundle is self-contained: the script, the mapping, and the structure reference all live here, and every residual-review lookup is sourced from [`endpoint_mapping.json`](playbooks_pci_migration/endpoint_mapping.json). No PCI repo is required at runtime.

## What the script does

For each task where `task.iscommand` is true it parses `task.script` (`<brand>|||<command>`). If `<command>` matches an `old_command` in the mapping's `matched_commands` it rewrites `task.script` to `Builtin|||<newCommand>`, sets `task.brand` to `Builtin`, renames `scriptarguments` keys per `args_changes.moved`, and drops keys in `args_changes.removed`. It then rewrites every old output context path (union of each command's `output_changes.moved` + `output_changes.changed`) everywhere in the playbook: `${...}` DT expressions (incl. array-index forms), `complex` root/accessor, `conditions`, `filters`, `transformers` args, `fieldMapping` outputs, and playbook-level `inputs`/`outputs`. Output rewrites apply to any matching string regardless of `iscontext` (intentional).

## Prerequisites

1. `ruamel.yaml` installed: `pip install ruamel.yaml`.
2. A target playbook path provided by the user.
3. Mapping present at [`endpoint_mapping.json`](playbooks_pci_migration/endpoint_mapping.json) (top keys: `matched_commands`, `not_migrated`, `newly_added`, `ambiguous_matches`). The script resolves this automatically as its default; you only pass `--mapping` to override it.

## Run it

Run from the content repo root. Preview first, then apply in place (the script edits the file directly with no backup). Capture stderr so the `[UNMAPPABLE]` warnings can be reviewed:

```bash
# 1. Dry run: does everything except writing. Review the output.
python3 playbooks_pci_migration/migrate_playbook.py <playbook.yml> --dry-run 2>&1 | tee /tmp/migrate.log

# 2. Real run: edits the playbook in place.
python3 playbooks_pci_migration/migrate_playbook.py <playbook.yml> 2>&1 | tee /tmp/migrate.log
```

The default `--mapping` resolves automatically to the sibling `endpoint_mapping.json`, so it is optional. Override it only if you want a different mapping:

```bash
python3 playbooks_pci_migration/migrate_playbook.py <playbook.yml> --mapping playbooks_pci_migration/endpoint_mapping.json --dry-run
```

## Read the output

- Green summary line: tasks migrated, args renamed, args dropped, output refs rewritten, warnings count.
- Red `[UNMAPPABLE]` lines on stderr: each residual the script could not resolve. The script logs each and continues. These are the items to review by hand.

## Review and hand-fix the residuals

Work each `[UNMAPPABLE]` line case by case against the playbook YAML. Source every decision from [`endpoint_mapping.json`](playbooks_pci_migration/endpoint_mapping.json). Never invent a command or output path.

1. **not_migrated / unmatched command** (task left untouched). Look the command up in `endpoint_mapping.json` `not_migrated` (list of `{old_command, endpoint, old_source_file}`) to explain why it has no PCI replacement. Decide whether an alternate new command in `matched_commands` fits; if none does, flag to the user that the task needs a manual decision.
2. **Dropped removed arg** (key in `args_changes.removed`, dropped with its value). Decide whether the value must move to a renamed/added arg on the new command. Consult the matched entry's `args_changes.moved` / `args_changes.added` in `endpoint_mapping.json` and re-add the value under the correct new arg when an equivalent exists. If the mapping does not make the target arg unambiguous, surface the decision to the user.
3. **Removed output still referenced** (path in `output_changes.removed`, reference left intact). Consult the matched entry's `output_changes.moved` / `output_changes.changed` in `endpoint_mapping.json` to find the correct replacement path and update the reference. If no equivalent exists in the mapping, surface it to the user.
4. **One-to-many collapse** (e.g. quick-action variants collapsing to one new command). Confirm the exact `old_command` match was used. If the task used a variant not distinguished by args, verify the chosen new command is correct for that task.

### Optional PCI-repo cross-references (graceful degradation)

The mapping is the authoritative source for this skill. If you need deeper context on a new command's Go implementation or the arg/output conventions, the following live in the PCI (`core-content-module`) repo and are only consultable when that repo is also open in the workspace:

- Per-command Go source: `core-content-module/pkg/corecontent/commands/<domain>/commands.go` (the `new_source_file` field in a matched entry points here).
- Naming/arg conventions: `core-content-module/create_command.md`.
- Hard rules: `core-content-module/.roo/rules/do-and-donts.md`.

If the PCI repo is not present, do not block: make the best decision from `endpoint_mapping.json` alone and surface any remaining ambiguity to the user.

## Validate

- Confirm the playbook is still valid YAML:
  ```bash
  python3 -c "from ruamel.yaml import YAML; YAML().load(open('<playbook.yml>'))"
  ```
- Confirm no `core-`/`xdr-` command strings remain unintentionally (any that do should be a known not_migrated residual you already surfaced):
  ```bash
  grep -nE '\|\|\|(core-|xdr-)' <playbook.yml>
  ```

## Report

Give the user a concise final summary: what was auto-migrated, what was hand-fixed, and what still needs a human decision.

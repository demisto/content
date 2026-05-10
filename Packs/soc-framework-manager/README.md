# SOC Framework Pack Manager

Install and configure SOC Framework content packs directly from the XSIAM
Playground. No manual ZIP uploads, no separate REST API tooling.

## What does this pack do?

- Browses the SOC Framework pack catalog from the XSIAM Playground
- Installs and updates SOC Framework content packs as system content
- Applies integration instances, jobs, and lookup datasets from each pack's `xsoar_config.json`
- Re-runs configuration without reinstalling, for recovery or config changes
- Synchronizes the legacy `value_tags` lookup for older deployments still using it

## Quick Start

```
!SOCFWPackManager action=list
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=configure pack_id=SocFrameworkTrendMicroVisionOne
```

## Prerequisites

Before running `action=apply`, configure the **SOC Framework Pack Manager**
integration instance:

1. Navigate to **Settings** > **Configurations** > **API Keys** and create a
   Standard API key.
2. Copy the **Key**, the **Key ID**, and click **Copy URL** to capture the
   tenant Server URL.
3. Configure an instance of the **SOC Framework Pack Manager** integration
   with those three values.

Credentials are stored masked on the integration instance and are never
passed as command arguments.

## Commands

### `action=list` — Browse the catalog

```
!SOCFWPackManager action=list
!SOCFWPackManager action=list filter=crowdstrike
```

Lists all available SOC Framework packs with ID, version, and path. Use
`filter=` to narrow results.

### `action=apply` — Install or update a pack

```
!SOCFWPackManager action=apply pack_id=<pack_id>
```

Downloads the pack ZIP from GitHub Releases, installs it as system content,
then applies all configuration from the pack's `xsoar_config.json`
(integration instances, jobs, lookup datasets). Safe to re-run — existing
configuration is detected and preserved.

```
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
!SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
```

### `action=configure` — Re-run configuration only

```
!SOCFWPackManager action=configure pack_id=<pack_id>
```

Fetches `xsoar_config.json` and runs integration, job, and lookup
configuration without reinstalling the pack. Use when configuration has
changed, or to recover from a failed config step after a manual install.

### `action=sync-tags` — Update the legacy value_tags lookup

> Backward-compat action for older SOC Framework deployments. Modern
> versions use the `SOCActionTimeMap_V3` list as the time source and do
> not require this command.

```
!SOCFWPackManager action=sync-tags
!SOCFWPackManager action=sync-tags force=true
```

For deployments still running on the legacy `value_tags` lookup, this
downloads `value_tags.json` from the SOC Framework repository and updates
the `value_tags` lookup dataset, comparing a content hash against the
previously stored version. If unchanged, the upload is skipped. Version
state is stored in the `SOCFWTagsVersion` XSIAM List (visible at
**Settings** > **Advanced** > **Lists**).

## Recommended Installation Order

1. Install the base framework:

   ```
   !SOCFWPackManager action=apply pack_id=soc-optimization-unified
   ```

2. Install the NIST IR lifecycle pack:

   ```
   !SOCFWPackManager action=apply pack_id=soc-framework-nist-ir
   ```

3. Install vendor enhancement packs for your environment:

   ```
   !SOCFWPackManager action=apply pack_id=SocFrameworkMicrosoftDefender
   !SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
   !SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
   ```

> Vendor enhancement packs require the corresponding marketplace integration
> to be installed and configured in the tenant.

## Architecture

This pack ships two pieces that work together:

- **SOCFWPackManager (script)** — the user-facing entry point. Run
  `!SOCFWPackManager action=...` from the Playground. The script reads the
  pack catalog, sequences installs, and configures integration instances,
  jobs, and lookup datasets from each pack's `xsoar_config.json`.
- **SOC Framework Pack Manager (integration)** — credential storage and a
  single `socfw-install-pack` command that downloads and uploads a pack ZIP
  as system content. The integration is internal plumbing; end users do not
  call it directly.

The split exists because XSIAM integrations cannot call
`demisto.executeCommand`, so all multi-step orchestration must live in the
script. The integration handles only the work that needs raw HTTP.

## Design Principles

- **Idempotent** — all actions are safe to re-run; existing configuration
  is detected and preserved
- **Composable** — install only the packs relevant to your environment
- **Version-aware** — `apply` installs from pinned GitHub Release tags;
  `sync-tags` (legacy) tracks content hash across runs

For the full argument reference, see the per-component READMEs:

- [`Scripts/SOCFWPackManager/README.md`](Scripts/SOCFWPackManager/README.md)
- [`Integrations/SOCFWPackManager/README.md`](Integrations/SOCFWPackManager/README.md)
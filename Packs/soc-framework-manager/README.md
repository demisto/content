# SOC Framework Pack Manager

Manage SOC Framework content packs directly from the XSIAM Playground — no manual zip uploads, no REST API dependency.

---

## Quick Start

```
!SOCFWPackManager action=list
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=configure pack_id=SocFrameworkTrendMicroVisionOne
!SOCFWPackManager action=sync-tags
```

---

## Prerequisites

Before running `action=apply`, configure the **SOC Framework Pack Manager** integration instance:

1. Go to **Settings → API Keys** → create a Standard key
2. Copy the **Key**, **Key ID**, and the **API URL** (Settings → API Keys → Copy API URL)
3. Configure the integration instance with these three values

Credentials are stored masked in the integration — never passed as command arguments.

---

## Commands

### `action=list` — Browse the catalog

```
!SOCFWPackManager action=list
```

Shows all available SOC Framework packs with ID, version, and path. Use `filter=` to narrow results.

```
!SOCFWPackManager action=list filter=crowdstrike
```

---

### `action=apply` — Install or update a pack

```
!SOCFWPackManager action=apply pack_id=<pack_id>
```

Downloads the pack zip from GitHub Releases, installs it as system content, then applies all configuration from the pack's `xsoar_config.json` (integration instances, jobs, lookup datasets). Safe to re-run — existing config is detected and skipped.

**Examples:**

```
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
!SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
```

---

### `action=configure` — Re-run configuration only

```
!SOCFWPackManager action=configure pack_id=<pack_id>
```

Fetches `xsoar_config.json` and runs integration, job, and lookup configuration without reinstalling the pack. Use when configuration has changed, or to recover from a failed config step after a manual install.

```
!SOCFWPackManager action=configure pack_id=SocFrameworkMicrosoftDefender
```

---

### `action=sync-tags` — Update the value_tags lookup

```
!SOCFWPackManager action=sync-tags
```

Downloads `value_tags.json` from the SOC Framework repository and updates the `value_tags` lookup dataset. Compares a content hash against the previously stored version — if unchanged, skips the upload and reports the current version. Run after SOC Framework updates to keep the Value Metrics dashboard current.

```
!SOCFWPackManager action=sync-tags force=true   # overwrite regardless of version
```

Version state is stored in the `SOCFWTagsVersion` XSIAM List (visible at Settings → Advanced → Lists).

---

## Recommended Installation Order

1. Install the base framework:
   ```
   !SOCFWPackManager action=apply pack_id=soc-optimization-unified
   ```

2. Install the NIST IR lifecycle pack:
   ```
   !SOCFWPackManager action=apply pack_id=soc-framework-nist-ir
   ```

3. Install product enhancement packs for your environment:
   ```
   !SOCFWPackManager action=apply pack_id=SocFrameworkMicrosoftDefender
   !SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
   !SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
   ```

4. Sync the value_tags lookup:
   ```
   !SOCFWPackManager action=sync-tags
   ```

> Product enhancement packs require the corresponding Marketplace integration to be installed and configured in the tenant.

---

## Design Principles

- **No core-api-* dependency** — packs install via the XSIAM content bundle endpoint, which works on all tenants
- **Idempotent** — all actions are safe to re-run; existing config is detected and preserved
- **Composable** — install only the packs relevant to your environment
- **Version-aware** — `sync-tags` tracks content hash across runs; `apply` installs from pinned GitHub Release tags

---

For a complete argument reference, see [README_COMMANDS.md](README_COMMANDS.md).

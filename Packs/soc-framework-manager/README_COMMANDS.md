# SOCFWPackManager — Full Command Reference

All commands run from the XSIAM **Playground**.

---

## Syntax

```
!SOCFWPackManager action=<action> [arguments]
```

---

## `action` (required)

| Value | Description |
|---|---|
| `list` | Browse the SOC Framework pack catalog |
| `apply` | Install or update a pack and apply its configuration |
| `configure` | Re-run configuration only (no pack install) |
| `sync-tags` | Update the `value_tags` lookup dataset |

---

## `action=list` arguments

| Argument | Default | Description |
|---|---|---|
| `filter` | — | Case-insensitive text filter on id, display_name, path |
| `limit` | `50` | Rows per page |
| `offset` | `0` | Row offset for paging |
| `sort_by` | `id` | Column to sort: `id`, `display_name`, `version`, `visible`, `path` |
| `sort_dir` | `asc` | `asc` or `desc` |
| `fields` | `id,display_name,version,visible,path` | Columns to display (comma-separated) |
| `show_total` | `true` | Show "X-Y of Z" paging info |
| `include_hidden` | `false` | Show packs marked `visible=false` in the catalog |
| `catalog_url` | GitHub main branch | Override the `pack_catalog.json` URL |

---

## `action=apply` arguments

| Argument | Default | Description |
|---|---|---|
| `pack_id` | **required** | Pack ID from the catalog (e.g. `soc-optimization-unified`) |
| `pre_config_done` | `false` | Set to `true` to proceed past the pre-config documentation gate |
| `pre_config_gate` | `true` | Set to `false` to skip the pre-config stop entirely |
| `install_marketplace` | `true` | Install Marketplace dependencies listed in `xsoar_config.json` |
| `apply_configure` | `true` | Apply integration/job/lookup config from `xsoar_config.json` |
| `configure_integrations` | `true` | Create or update integration instances |
| `configure_jobs` | `true` | Create scheduled jobs |
| `configure_lookups` | `true` | Create and populate lookup datasets |
| `overwrite_lookup` | `false` | Overwrite existing lookup data (default: skip if data present) |
| `dry_run` | `false` | Resolve manifest and print plan without installing anything |
| `include_hidden` | `false` | Include packs marked `visible=false` |
| `include_doc_content` | `false` | Embed pre/post-config doc preview in war room output |
| `retry_sleep_seconds` | `15` | Seconds between retry attempts |
| `debug` | `false` | Enable verbose war room output |
| `catalog_url` | GitHub main branch | Override the `pack_catalog.json` URL |

---

## `action=configure` arguments

Shares all configuration arguments with `action=apply`. `pack_id` is required. No pack install is performed.

| Argument | Default | Description |
|---|---|---|
| `pack_id` | **required** | Pack to fetch `xsoar_config.json` for |
| `configure_integrations` | `true` | Create or update integration instances |
| `configure_jobs` | `true` | Create scheduled jobs |
| `configure_lookups` | `true` | Create and populate lookup datasets |
| `overwrite_lookup` | `false` | Overwrite existing lookup data |
| `debug` | `false` | Enable verbose war room output |

---

## `action=sync-tags` arguments

| Argument | Default | Description |
|---|---|---|
| `force` | `false` | Upload even if the content hash matches the stored version |
| `tags_url` | SOC Framework main branch | Override the `value_tags.json` source URL |
| `debug` | `false` | Enable verbose war room output |

### How versioning works

On each sync, the content hash of `value_tags.json` is computed and compared against the version stored in the `SOCFWTagsVersion` XSIAM List (Settings → Advanced → Lists). If the hashes match, the upload is skipped and the current version is reported. On update, the new hash and timestamp are stored.

```
!SOCFWPackManager action=sync-tags              # check and update if changed
!SOCFWPackManager action=sync-tags force=true   # always upload
```

---

## Integration Instance Setup

`action=apply` requires the **SOC Framework Pack Manager** integration instance to be configured. This stores credentials used to POST packs directly to the XSIAM content bundle endpoint — no `core-api-*` commands required.

**Setup steps:**

1. Go to **Settings → API Keys** → **New Key** → Standard
2. Copy the generated key
3. Note the **Key ID** from the ID column
4. Click **Copy API URL** — this is your Server URL
5. Configure the **SOC Framework Pack Manager** integration instance with these three values

The integration instance name must be **SOCFWPackManager** (default) for the script to locate it automatically.

---

## Notes

- `apply` and `configure` are **idempotent** — integration instances that already exist are detected and skipped rather than duplicated
- Lookup datasets with existing data are not overwritten unless `overwrite_lookup=true`
- `dry_run=true` prints the full install plan without executing anything — useful for validating pack IDs and manifest resolution before committing
- Hidden packs (`visible=false` in the catalog) are internal or deprecated packs; use `include_hidden=true` only when explicitly working with them

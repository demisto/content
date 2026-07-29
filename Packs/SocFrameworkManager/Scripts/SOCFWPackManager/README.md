SOC Framework Pack Manager — bootloader script for the SOC Framework on
XSIAM. Lists the SOC Framework pack catalog with the installed version and
update status of each pack, installs and configures packs, re-runs
configuration only, diagnoses the platform endpoints the install path depends
on, and synchronizes the `value_tags` lookup against the catalog version
metadata.

## Architecture

This script is the user-facing entry point. It depends on the **SOC
Framework Pack Manager** integration, also shipped in this pack, for
credential storage and the actual pack-install HTTP. Configure an instance
of that integration before running `action=apply`. End users should never
call the integration's `socfw-install-pack` command directly — invoke it
through this script.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | configuration, Content Management, SOC, SOC_Framework, SOC_Framework_Unified, SOCFWBootloader |
| Cortex XSIAM Version | 5.0.0 and later |

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| action | One of `list`, `apply`, `configure`, `sync-tags`, or `diagnose`. `list` shows the catalog with the installed version and update status of each pack. `apply` installs and configures a pack. `configure` re-runs configuration only (no pack install). `diagnose` probes every platform endpoint the marketplace install path depends on and reports which one fails; run it first when an install misbehaves. `sync-tags` is a backward-compat action that updates the legacy `value_tags` lookup; modern SOC Framework deployments use `SOCActionTimeMap_V3` and do not need it. |
| probe_pack | `action=diagnose` only. Pack ID used to probe the marketplace metadata and dependency endpoints. Defaults to `Whois` because it is a stock Marketplace pack present on effectively every tenant, which makes it a dependable read-only probe target. Nothing is installed or modified. Falls back to an installed pack if this one is absent. |
| upgrade_marketplace | `action=apply` only. Controls what a `marketplace_packs` entry of `latest` means. `false` (default) ensures the pack is present, leaving an already-installed pack at its current version. `true` brings each requested pack to the newest published version. Mandatory dependencies are never force-upgraded either way; they move only when a `minVersion` requires it. |
| pack_id | The pack ID from `pack_catalog.json` (for example, `soc-optimization-unified`). Required for `action=apply` and `action=configure`. |
| catalog_url | Override the catalog URL without modifying the integration instance parameters. |
| using | Integration instance name to route core-api commands through. Defaults to the active instance. |
| include_hidden | Allow installing packs where `visible=false` in the catalog. |
| dry_run | Show what would happen without installing or configuring. |
| install_marketplace | Whether to install `marketplace_packs` from `xsoar_config.json`. |
| skip_verify | Pass-through to `core-api-install-packs` for ZIP installs. |
| skip_validation | Pass-through to `core-api-install-packs` for ZIP installs. |
| apply_configure | Whether to apply the config sections from `xsoar_config.json` (instances, jobs, lookups). |
| overwrite_lookup | Overwrite the SOC Framework lookup table. Save your customizations first. |
| configure_jobs | When `action=apply`, run job configuration from `xsoar_config.json`. Ignored if `apply_configure=false`. |
| configure_integrations | When `action=apply`, create or update integration instances from `xsoar_config.json`. Ignored if `apply_configure=false`. |
| configure_lookups | When `action=apply`, create or update lookup datasets from `xsoar_config.json`. Ignored if `apply_configure=false`. |
| retry_count | Number of retry attempts for install or configure operations that fail transiently. |
| retry_sleep_seconds | Seconds to wait between retry attempts. |
| execution_timeout | Timeout in seconds for individual core-api commands invoked during configure. |
| install_timeout | Timeout in seconds for the full custom-pack install command before falling back to polling. |
| post_install_poll_seconds | After an install timeout, total seconds to poll the tenant for the pack to appear installed. |
| post_install_poll_interval_seconds | Interval in seconds between install completion polls. |
| continue_on_install_timeout | Continue with configuration steps if a custom-pack install times out and polling does not confirm installation. |
| fail_on_marketplace_errors | Raise on marketplace install errors instead of recording them and continuing. |
| debug | Verbose War Room logging and additional install detail. |
| filter | `action=list` only. Case-insensitive free-text filter applied to id, display_name, and path. |
| limit | `action=list` only. Maximum number of rows to display per page. |
| offset | `action=list` only. Row offset for paging. |
| sort_by | `action=list` only. Column to sort by. One of `id`, `display_name`, `category`, `version`, `installed`, `status`, `visible`, or `path`. Ignored for ordering between categories when `group_by_category=true`. |
| sort_dir | `action=list` only. Sort direction. `asc` or `desc`. |
| visible_only | `action=list` only. Hide packs marked `visible=false`. Implied false when `include_hidden=true`. |
| fields | `action=list` only. Comma-separated list of columns to show when `output_format=table`. Available columns are `id`, `display_name`, `category`, `version`, `installed`, `status`, `docs`, `visible`, and `path`. Unknown fields are ignored. |
| group_by_category | `action=list` only. Group packs under their catalog category, one section per category. Set to `false` for a single flat list. |
| output_format | `action=list` only. `list` renders one line per pack and is the default, because the War Room transposes single-row tables and truncates long ones. `table` renders the columns named in `fields`. |
| docs_base_url | `action=list` only. Absolute base URL of the documentation site. The catalog supplies each pack's relative `docs_path`, and this value supplies the host, so each pack ID renders as a link to its overview page. Must be absolute, otherwise the link resolves against the tenant host. Set to an empty value to disable linking. |
| show_total | `action=list` only. Display "showing X-Y of Z" paging information. |
| include_doc_content | When printing pre and post config docs, also fetch a truncated preview of the README content into the War Room output. |
| doc_content_max_chars | Maximum characters per doc preview when `include_doc_content=true`. |
| doc_content_max_lines | Maximum lines per doc preview when `include_doc_content=true`. |
| pre_config_done | Set to `true` to acknowledge pre-config docs have been completed and continue with install or configure. |
| pre_config_gate | When `true`, the script prints `pre_config_docs` and stops until `pre_config_done=true`. |
| force | `action=sync-tags` only. Update `value_tags` even if the content hash matches the current version. |
| tags_url | `action=sync-tags` only. Override the `value_tags.json` source URL. Defaults to the `soc-optimization-unified` pack on main. |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SOCFramework.PackManager.pack_id | Pack ID acted on for `action=apply` or `action=configure`. | String |
| SOCFramework.PackManager.xsoar_config_url | URL of the `xsoar_config.json` fetched for the pack. | String |
| SOCFramework.PackManager.catalog_url | URL of the pack catalog used to resolve the manifest. | String |
| SOCFramework.PackManager.Diagnose.check | `action=diagnose` only. Name of the probed check. | String |
| SOCFramework.PackManager.Diagnose.detail | `action=diagnose` only. What the probe observed. | String |
| SOCFramework.PackManager.Diagnose.endpoint | `action=diagnose` only. Platform endpoint the check exercised. | String |
| SOCFramework.PackManager.Diagnose.result | `action=diagnose` only. `pass` or `fail`. | String |
| SOCFramework.PackManager.marketplace_errors | Marketplace install errors recorded during `action=apply`. | Unknown |
| SOCFramework.PackManager.configure_summary.integrations | Integration instance configuration summary. | Unknown |
| SOCFramework.PackManager.configure_summary.jobs | Job configuration summary. | Unknown |
| SOCFramework.PackManager.configure_summary.lookups | Lookup dataset configuration summary. | Unknown |
| SOCFramework.PackManager.SyncTags.status | `action=sync-tags` result. `up_to_date` or `updated`. | String |
| SOCFramework.PackManager.SyncTags.dataset | Dataset name updated (`value_tags`). | String |
| SOCFramework.PackManager.SyncTags.version | Short hash of the `value_tags` content currently installed. | String |
| SOCFramework.PackManager.SyncTags.hash | Full content hash of the `value_tags` content currently installed. | String |
| SOCFramework.PackManager.SyncTags.rows | Number of `value_tags` rows uploaded to the dataset. | Number |
| SOCFramework.PackManager.SyncTags.updated | Whether the dataset was updated on this run. | Boolean |
| SOCFramework.PackManager.SyncTags.previous_hash | Previous content hash before this run, when applicable. | String |
| SOCFramework.PackManager.SyncTags.updated_at | ISO 8601 timestamp the `value_tags` dataset was last updated. | String |

## Command examples

#### action=list

```!SOCFWPackManager action=list```

##### Human Readable Output

> Lists the available SOC Framework packs grouped by catalog category. Each pack is prefixed with a status marker — 🔵 update available, ⚪ not installed, 🟢 up to date, 🟠 installed ahead of the catalog — followed by the pack ID, the version detail, and a link to the pack documentation. The header summarizes the counts per status.

#### action=diagnose

```!SOCFWPackManager action=diagnose```

##### Human Readable Output

> Probes each platform endpoint the marketplace install path depends on — the Core REST API instance, the installed-packs metadata endpoint, marketplace metadata resolution, and dependency lookup — and reports pass or fail per check with the endpoint exercised. Read-only; nothing is installed or modified. Run this first when an install misbehaves, to identify which endpoint is at fault before retrying.

#### action=apply

```!SOCFWPackManager action=apply pack_id=soc-optimization-unified```

##### Human Readable Output

> Streams progress to the war room as the marketplace dependencies install, the custom pack ZIP is uploaded as system content, and `xsoar_config.json` is applied.

#### action=configure

```!SOCFWPackManager action=configure pack_id=SocFrameworkTrendMicroVisionOne```

##### Human Readable Output

> Re-runs configuration only — integration instances, jobs, and lookup datasets — without reinstalling the pack.

#### action=sync-tags

```!SOCFWPackManager action=sync-tags```

##### Human Readable Output

> Backward-compat action. Updates the legacy `value_tags` lookup dataset for older deployments. Modern SOC Framework deployments use `SOCActionTimeMap_V3` and do not need this command.

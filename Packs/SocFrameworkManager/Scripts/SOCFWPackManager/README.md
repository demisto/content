The SOC Framework bootloader for Cortex XSIAM. Lists the SOC Framework pack
catalog with the installed version and update status of each pack, installs
and configures packs from xsoar_config.json, re-runs configuration only, and
diagnoses the platform endpoints the install path depends on. Also includes
sync-tags, a backward-compatible action for older SOC Framework deployments
still using the value_tags lookup; modern versions use the
SOCActionTimeMap_V3 list and do not require it.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | configuration, Content Management, SOC, SOC_Framework, SOC_Framework_Unified, SOCFWBootloader |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Sleep

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| action | The action to run. The diagnose action probes every platform endpoint the marketplace install path depends on and reports which one fails; run it first when an install misbehaves. The list action shows the catalog. The apply action installs and configures a pack. The configure action re-runs configuration only, without installing a pack. The sync-tags action is a backward-compatible action that updates the legacy value_tags lookup; modern SOC Framework deployments use SOCActionTimeMap_V3 and do not need it. |
| probe_pack | The pack ID used to probe the marketplace metadata and dependency endpoints, for the diagnose action only. Whois is a stock Marketplace pack present on effectively every tenant, which makes it a dependable read-only probe target; nothing is installed or modified. Falls back to an installed pack if this one is absent. |
| pack_id | The pack ID from pack_catalog.json \(for example, soc-optimization-unified\). Required for action=apply. |
| catalog_url | Override the catalog URL without modifying the integration instance parameters. |
| using | Integration instance name to route core-api commands through. Defaults to the active instance. |
| include_hidden | Allow installing packs where visible=false in the catalog. |
| dry_run | Show what would happen without installing or configuring. |
| install_marketplace | Whether to install marketplace_packs from xsoar_config.json. |
| skip_verify | Pass-through to core-api-install-packs for ZIP installs. |
| skip_validation | Pass-through to core-api-install-packs for ZIP installs. |
| apply_configure | Whether to apply the config sections from xsoar_config.json \(instances, jobs, lookups\). |
| overwrite_lookup | Overwrite the SOC Framework lookup table. Save your customizations first. |
| configure_jobs | When action=apply, run job configuration from xsoar_config.json. Ignored if apply_configure=false. |
| configure_integrations | When action=apply, create or update integration instances from xsoar_config.json. Ignored if apply_configure=false. |
| configure_lookups | Whether to create or update lookup datasets from xsoar_config.json, for the apply and configure actions. A pack that ships a Lookup directory already brings its dataset with it, so configuring it again is redundant. Ignored when apply_configure is false. |
| retry_count | Number of retry attempts for install or configure operations that fail transiently. |
| retry_sleep_seconds | Seconds to wait between retry attempts. |
| execution_timeout | Timeout in seconds for individual core-api commands invoked during configure. |
| install_timeout | Timeout in seconds for the full custom-pack install command before falling back to polling. |
| post_install_poll_seconds | After an install timeout, total seconds to poll the tenant for the pack to appear installed. |
| post_install_poll_interval_seconds | Interval in seconds between install completion polls. |
| continue_on_install_timeout | Continue with configuration steps if a custom-pack install times out and polling does not confirm installation. |
| upgrade_marketplace | Whether a marketplace_packs entry of "latest" brings each requested pack to the newest published version, for the apply action only. When false, an already-installed pack keeps its current version. Mandatory dependencies are never force-upgraded either way; they move only when a minVersion requires it. Upgrading resolves versions from the marketplace, which returns large responses, so it is slower. |
| fail_on_marketplace_errors | Raise on marketplace install errors instead of recording them and continuing. |
| debug | Verbose War Room logging and additional install detail. |
| filter | action=list only. Case-insensitive free-text filter applied to id, display_name, and path. |
| limit | action=list only. Maximum number of rows to display per page. |
| offset | action=list only. Row offset for paging. offset=0 shows the first page. |
| sort_by | The column to sort by, for the list action only. Ignored for ordering between categories when group_by_category is true. |
| sort_dir | action=list only. Sort direction. |
| visible_only | action=list only. Hide packs marked visible=false in the catalog. Implied false when include_hidden=true. |
| fields | The comma-separated list of columns to show, for the list action only. Available columns are id, display_name, category, version, installed, status, docs, visible and path. Unknown fields are ignored. |
| group_by_category | Whether to group packs under their catalog category, one section per category, for the list action only. When false, a single flat list is rendered. |
| docs_base_url | The absolute base URL of the documentation site, for the list action only. The catalog supplies each pack's relative documentation path and this value supplies the host, so each pack links to its overview page. Must be absolute, otherwise the link resolves against the tenant host. Set to an empty value to disable linking. |
| output_format | The output style for the list action only. The list style renders one line per pack, because the War Room transposes single-row tables and truncates long ones. The table style renders the columns named in fields. |
| show_total | action=list only. If true, displays "showing X-Y of Z" paging information. |
| include_doc_content | When printing pre_config_docs and post_config_docs, also fetch a truncated preview of the README content into the War Room output. |
| doc_content_max_chars | Maximum characters per doc preview when include_doc_content=true. |
| doc_content_max_lines | Maximum lines per doc preview when include_doc_content=true. |
| pre_config_done | Set to true to acknowledge pre-config docs have been completed and continue with install or configure. |
| pre_config_gate | When true, the script prints pre_config_docs and stops until pre_config_done=true. |
| force | action=sync-tags only. Update value_tags even if the content hash matches the current version. |
| tags_url | action=sync-tags only. Override the value_tags.json source URL. Defaults to the soc-optimization-unified pack on main. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SOCFramework.PackManager.pack_id | Pack ID acted on for action=apply or action=configure. | String |
| SOCFramework.PackManager.xsoar_config_url | URL of the xsoar_config.json fetched for the pack. | String |
| SOCFramework.PackManager.catalog_url | URL of the pack catalog used to resolve the manifest. | String |
| SOCFramework.PackManager.marketplace_errors | Marketplace install errors recorded during action=apply. | Unknown |
| SOCFramework.PackManager.configure_summary.integrations | Integration instance configuration summary \(attempted, ok, already_exists, failed\). | Unknown |
| SOCFramework.PackManager.configure_summary.jobs | Job configuration summary \(attempted, ok, failed, notes\). | Unknown |
| SOCFramework.PackManager.configure_summary.lookups | Lookup dataset configuration summary \(attempted, ok, failed\). | Unknown |
| SOCFramework.PackManager.SyncTags.status | action=sync-tags result. up_to_date or updated. | String |
| SOCFramework.PackManager.SyncTags.dataset | Dataset name updated \(value_tags\). | String |
| SOCFramework.PackManager.SyncTags.version | Short hash of the value_tags content currently installed. | String |
| SOCFramework.PackManager.SyncTags.hash | Full content hash of the value_tags content currently installed. | String |
| SOCFramework.PackManager.SyncTags.rows | Number of value_tags rows uploaded to the dataset. | Number |
| SOCFramework.PackManager.SyncTags.updated | Whether the dataset was updated on this run. | Boolean |
| SOCFramework.PackManager.SyncTags.previous_hash | Previous content hash before this run, when applicable. | String |
| SOCFramework.PackManager.SyncTags.updated_at | ISO 8601 timestamp the value_tags dataset was last updated. | String |

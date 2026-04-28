SOC Framework Pack Manager — bootloader script for the SOC Framework on XSIAM. Lists the SOC Framework pack catalog, installs and configures packs (custom ZIP or marketplace), re-runs configuration only, and synchronizes the SOCFWTagsVersion lookup against the catalog version metadata.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | |
| Cortex XSIAM Version | 5.0.0 and later |

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| action | One of `list`, `apply`, `configure`, or `sync-tags`. `list` shows the catalog. `apply` installs and configures a pack. `configure` re-runs configuration only (no pack install). `sync-tags` updates the `value_tags` lookup with version check. |
| pack\_id | The pack ID from `pack_catalog.json` (for example, `soc-optimization-unified`). Required for `apply`. |
| catalog\_url | Override the catalog URL without modifying the integration instance parameters. |
| include\_hidden | Allow installing packs where `visible=false` in the catalog. |
| dry\_run | Show what would happen without installing or configuring. |

## Outputs

The script writes progress to the war room and returns a structured result describing the pack(s) acted on, the install method used, and the configuration steps performed.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### koi-get-events

***
Gets events from KOI. This command is used for developing/debugging. Use with caution, as it can create events, leading to event duplication and exceeding API request limitations.

#### Base Command

`koi-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | The type of events to retrieve. If not specified, uses the value configured in the integration parameters. Possible values are: Alerts, Audit. Default is Alerts,Audit. | Optional |
| limit | The maximum number of events to return per type. Default is 50. | Optional |
| start_time | Filter events created at or after this time. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | Filter events created at or before this time. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| should_push_events | The flag that indicates whether to push events to Cortex XSIAM. Pushing events is supported on Cortex XSIAM only. When set to false, or on non-XSIAM platforms, events are displayed without being pushed. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KOI.Event.id | String | The unique identifier of the event. |
| KOI.Event.source_log_type | String | The source log type of the event (Alerts or Audit). |
| KOI.Event._time | Date | The timestamp of the event in ISO 8601 format. |
| KOI.Event.created_at | Date | The creation time of the event (audit logs). |

#### Human Readable Output

>### KOI Events
>
>|id|source_log_type|_time|severity|status|
>|---|---|---|---|---|
>| alert-001 | Alerts | 2024-01-01T00:00:00Z | high | open |
>| audit-001 | Audit | 2024-01-01T00:00:00Z | | |

### koi-blocklist-get

***
Retrieves all items in the blocklist.

#### Base Command

`koi-blocklist-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Blocklist.item_id | String | The unique identifier of the blocklist item. |
| Koi.Blocklist.item_name | String | The name of the blocklist item. |
| Koi.Blocklist.item_display_name | String | The display name of the blocklist item. |
| Koi.Blocklist.marketplace | String | The marketplace of the blocklist item \(e.g., vscode\). |
| Koi.Blocklist.publisher_name | String | The publisher name of the blocklist item. |
| Koi.Blocklist.package_name | String | The package name of the blocklist item. |
| Koi.Blocklist.notes | String | Notes associated with the blocklist item. |
| Koi.Blocklist.created_by | String | The user who created the blocklist item. |
| Koi.Blocklist.created_at | Date | The creation time of the blocklist item in ISO 8601 format. |

#### Command example

```!koi-blocklist-get```

#### Human Readable Output

>### KOI Blocklist
>
>|Item Id|Item Name|Item Display Name|Marketplace|Publisher Name|Package Name|Notes|Created By|Created At|
>|---|---|---|---|---|---|---|---|---|
>| mal-001 | Bad Extension | Malicious Extension | chrome_web_store | Suspicious Publisher | bad-package | Known malware distribution | security@example.com | 2025-05-01T09:15:00.000Z |
>| mal-002 | Risky Plugin | Risky Plugin | vscode | Unknown Publisher | risky-plugin | Data exfiltration risk | admin@example.com | 2025-05-02T14:30:00.000Z |

### koi-allowlist-get

***
Retrieves all items in the allowlist.

#### Base Command

`koi-allowlist-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Allowlist.item_id | String | The unique identifier of the allowlist item. |
| Koi.Allowlist.item_name | String | The name of the allowlist item. |
| Koi.Allowlist.item_display_name | String | The display name of the allowlist item. |
| Koi.Allowlist.marketplace | String | The marketplace of the allowlist item \(e.g., vscode\). |
| Koi.Allowlist.publisher_name | String | The publisher name of the allowlist item. |
| Koi.Allowlist.package_name | String | The package name of the allowlist item. |
| Koi.Allowlist.notes | String | Notes associated with the allowlist item. |
| Koi.Allowlist.created_by | String | The user who created the allowlist item. |
| Koi.Allowlist.created_at | Date | The creation time of the allowlist item in ISO 8601 format. |

#### Command example

```!koi-allowlist-get```

#### Human Readable Output

>### KOI Allowlist
>
>|Item Id|Item Name|Item Display Name|Marketplace|Publisher Name|Package Name|Notes|Created By|Created At|
>|---|---|---|---|---|---|---|---|---|
>| ext-123 | My Extension | My Extension Display Name | vscode | My Publisher | my-package | Approved for development purposes | admin@example.com | 2025-04-23T17:22:24.023Z |
>| ext-456 | Another Ext | Another Extension | chrome | Another Publisher | another-package | Approved by security team | user@example.com | 2025-04-24T10:00:00.000Z |

### koi-inventory-search

***
Searches inventory items using advanced query builder filters. Provide a filter via the 'filter_json' argument (inline JSON string) or the 'filter_raw_json_entry_id' argument (War Room file entry ID). At least one filter source must be provided.

#### Base Command

`koi-inventory-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_json | Advanced filter using query builder syntax as a JSON string. Either the 'filter_json' or the 'filter_raw_json_entry_id' argument must be provided. | Optional |
| filter_raw_json_entry_id | War Room entry ID of a JSON file containing the filter object. Takes priority over the 'filter_json' argument when both are provided. | Optional |
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the 'limit' argument. | Optional |
| page_size | Number of results per page (default: 50, max: 500). Used in single-page mode with the 'page' argument. | Optional |
| limit | Maximum total number of inventory items to return (default: 50, max: 1000). When provided without the 'page' argument, auto-paginates to collect up to this many items. Default is 50. | Optional |
| sort_by | Column to sort by. Possible values are: first_seen, last_seen, item_display_name, item_id, version, marketplace, endpoint_count, risk, risk_level, status, installs_count, released_at, publisher_name. Default is first_seen. | Optional |
| sort_direction | Sort direction. Possible values are: asc, desc. Default is desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Inventory.item_id | String | The unique identifier of the inventory item. |
| Koi.Inventory.item_display_name | String | The display name of the inventory item. |
| Koi.Inventory.marketplace | String | The marketplace source of the item. |
| Koi.Inventory.platforms | Unknown | List of platforms where the item is installed. |
| Koi.Inventory.publisher_name | String | The publisher name of the item. |
| Koi.Inventory.risk | Number | The numeric risk score of the item. |
| Koi.Inventory.risk_level | String | The risk level classification of the item. |
| Koi.Inventory.version | String | The version of the item. |
| Koi.Inventory.status | String | The governance status of the item. |
| Koi.Inventory.endpoint_count | Number | The number of endpoints where the item is installed. |
| Koi.Inventory.installs_count | Number | The total number of installs for the item. |
| Koi.Inventory.first_seen | Date | The date the item was first seen in ISO 8601 format. |
| Koi.Inventory.last_seen | Date | The date the item was last seen in ISO 8601 format. |
| Koi.Inventory.last_used | Date | The date the item was last used in ISO 8601 format. |
| Koi.Inventory.installation_method | String | The method used to install the item. |
| Koi.Inventory.short_description | String | A short description of the item. |
| Koi.Inventory.is_first_party | Boolean | Whether the item is a first-party item. |
| Koi.Inventory.is_signed | Boolean | Whether the item is signed. |
| Koi.Inventory.categories | Unknown | List of categories the item belongs to. |
| Koi.Inventory.findings | Unknown | List of findings associated with the item. |
| Koi.Inventory.governed_details | Unknown | Governance policy details for the item. |
| Koi.Inventory.released_at | Date | The release date of the item. Format: YYYY-MM-DD \(e.g., 2023-01-15\). |
| Koi.Inventory.brew_category_koi | String | The Homebrew package category \(Koi classification\). |
| Koi.Inventory.browser_category_koi | String | The browser extension category \(Koi classification\). |
| Koi.Inventory.chocolatey_category_koi | String | The Chocolatey package category \(Koi classification\). |
| Koi.Inventory.ide_category_koi | String | The IDE extension category \(Koi classification\). |
| Koi.Inventory.software_category_koi | String | The software category \(Koi classification\). |

#### Command example

```!koi-inventory-search filter_json="{\"field\":\"risk_level\",\"operator\":\"eq\",\"value\":\"high\"}" limit=50```

#### Human Readable Output

>### KOI Inventory Search
>
>|Item Id|Item Display Name|Marketplace|Platforms|Publisher Name|Risk|Risk Level|Version|Status|Endpoint Count|Installs Count|Installation Method|Is First Party|Is Signed|First Seen|Last Seen|Last Used|Released At|Short Description|Categories|Findings|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| abc123 | React Developer Tools | chrome_web_store | chrome, edge | Meta | 5 | high | 1.0.0 | APPROVED | 42 | 1000000 | marketplace | false | true | 2024-01-01T10:00:00Z | 2024-10-15T10:00:00Z | 2025-06-15T10:00:00Z | 2023-01-15 | React debugging tools | Developer Tools | malware, permissions |

### koi-policy-list

***
Retrieves a list of all policies. Use the 'page' and 'page_size' arguments to fetch a specific page, or use the 'limit' argument to auto-paginate and collect up to the specified number of policies. If the 'page' argument is provided, the 'limit' argument is ignored.

#### Base Command

`koi-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the 'limit' argument. | Optional |
| page_size | Number of results per page (default: 50, max: 500). Used only in single-page mode together with the 'page' argument. | Optional |
| limit | Maximum total number of policies to return (default: 50, max: 1000). When provided without the 'page' argument, auto-paginates to collect up to this many policies. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Policy.id | Number | The unique identifier of the policy. |
| Koi.Policy.name | String | The name of the policy. |
| Koi.Policy.description | String | The description of the policy. |
| Koi.Policy.action | String | The action taken by the policy \(e.g., block\). |
| Koi.Policy.enabled | Boolean | Whether the policy is enabled. |
| Koi.Policy.group_ids | Unknown | List of group IDs associated with the policy. |
| Koi.Policy.creator_fullname | String | The full name of the policy creator. |
| Koi.Policy.created_at | Date | The creation time of the policy in ISO 8601 format. |
| Koi.Policy.updated_at | Date | The last update time of the policy in ISO 8601 format. |

#### Command example

```!koi-policy-list limit=50```

#### Human Readable Output

>### KOI Policies
>
>|Id|Name|Description|Action|Enabled|Group Ids|Creator Fullname|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 1 | My Policy | This policy blocks high-risk extensions | block | true | 1, 2, 3 | John Doe | 2025-04-23T17:22:24.023Z | 2025-04-23T17:22:24.023Z |
>| 2 | Allow Policy | This policy allows approved extensions | allow | false | 4 | Jane Smith | 2025-04-24T10:00:00.000Z | 2025-04-24T12:30:00.000Z |

### koi-inventory-item-get

***
Retrieves comprehensive details for a specific software item, extension, or package using its unique identifier, marketplace, and version.

#### Base Command

`koi-inventory-item-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Unique identifier for the item. | Required | 
| marketplace | The marketplace where the item is hosted. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Required | 
| version | The specific version of the item to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Inventory.item_id | String | The unique identifier of the inventory item. | 
| Koi.Inventory.item_display_name | String | The display name of the inventory item. | 
| Koi.Inventory.marketplace | String | The marketplace source of the item. | 
| Koi.Inventory.platforms | Unknown | List of platforms where the item is installed. | 
| Koi.Inventory.publisher_name | String | The publisher name of the item. | 
| Koi.Inventory.risk | Number | The numeric risk score of the item. | 
| Koi.Inventory.risk_level | String | The risk level classification of the item. | 
| Koi.Inventory.version | String | The version of the item. | 
| Koi.Inventory.status | String | The governance status of the item. | 
| Koi.Inventory.endpoint_count | Number | The number of endpoints where the item is installed. | 
| Koi.Inventory.installs_count | Number | The total number of installs for the item. | 
| Koi.Inventory.installation_method | String | The method used to install the item. | 
| Koi.Inventory.is_first_party | Boolean | Whether the item is a first-party item. | 
| Koi.Inventory.is_signed | Boolean | Whether the item is signed. | 
| Koi.Inventory.first_seen | Date | The date the item was first seen in ISO 8601 format. | 
| Koi.Inventory.last_seen | Date | The date the item was last seen in ISO 8601 format. | 
| Koi.Inventory.last_used | Date | The date the item was last used in ISO 8601 format. | 
| Koi.Inventory.released_at | Date | The release date of the item. Format: YYYY-MM-DD \(e.g., 2023-01-15\). | 
| Koi.Inventory.short_description | String | A short description of the item. | 
| Koi.Inventory.categories | Unknown | List of categories the item belongs to. | 
| Koi.Inventory.findings | Unknown | List of findings associated with the item including severity and evidence. | 
| Koi.Inventory.governed_details | Unknown | Governance policy details for the item. | 
| Koi.Inventory.brew_category_koi | String | The Homebrew package category \(Koi classification\). | 
| Koi.Inventory.browser_category_koi | String | The browser extension category \(Koi classification\). | 
| Koi.Inventory.chocolatey_category_koi | String | The Chocolatey package category \(Koi classification\). | 
| Koi.Inventory.ide_category_koi | String | The IDE extension category \(Koi classification\). | 
| Koi.Inventory.software_category_koi | String | The software category \(Koi classification\). | 

### koi-blocklist-items-add

***
Adds one or more items to the global blocklist. Provide either 'item_id' and 'marketplace' for a single item, or 'items_list_raw_json_entry_id' for bulk addition from a JSON file.

#### Base Command

`koi-blocklist-items-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to add to the blocklist. Required when not using items_list_raw_json_entry_id. | Optional | 
| marketplace | The source marketplace of the item. Required when not using items_list_raw_json_entry_id. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Optional | 
| created_by | Email of the user who created this entry. | Optional | 
| notes | Additional notes or justification for blocking the item. | Optional | 
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to add. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, item_id and marketplace arguments are ignored. | Optional | 

#### Context Output

There is no context output for this command.
### koi-policy-status-update

***
Enables or disables a policy by ID.

#### Base Command

`koi-policy-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the policy to update. | Required |
| enabled | Whether to enable (true) or disable (false) the policy. Possible values are: true, false. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Policy.id | Number | The unique identifier of the policy. |
| Koi.Policy.name | String | The name of the policy. |
| Koi.Policy.description | String | The description of the policy. |
| Koi.Policy.action | String | The action taken by the policy \(e.g., block\). |
| Koi.Policy.enabled | Boolean | Whether the policy is enabled. |
| Koi.Policy.group_ids | Unknown | List of group IDs associated with the policy. |
| Koi.Policy.creator_fullname | String | The full name of the policy creator. |
| Koi.Policy.created_at | Date | The creation time of the policy in ISO 8601 format. |
| Koi.Policy.updated_at | Date | The last update time of the policy in ISO 8601 format. |

#### Command example

```!koi-policy-status-update policy_id=1 enabled=true```

#### Human Readable Output

>### KOI Policy Updated
>
>|Id|Name|Description|Action|Enabled|Group Ids|Creator Fullname|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 1 | My Policy | This policy blocks high-risk extensions | block | true | 1, 2, 3 | John Doe | 2025-04-23T17:22:24.023Z | 2025-04-23T17:22:24.023Z |

### koi-inventory-list

***
Retrieves a paginated list of items installed across your organization's endpoints. Supports extensive filtering by marketplace, platform, risk level, publisher, and specific categories.

#### Base Command

`koi-inventory-list`

### koi-inventory-list

***
Retrieves a paginated list of items installed across your organization's endpoints. Supports extensive filtering by marketplace, platform, risk level, publisher, and specific categories.

#### Base Command

`koi-inventory-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the limit argument. | Optional | 
| page_size | Number of results per page (default: 50, max: 500). Used in single-page mode with the page argument. | Optional | 
| limit | Maximum total number of inventory items to return (default: 50, max: 1000). When provided without page, auto-paginates to collect up to this many items. Default is 50. | Optional | 
| brew_category_koi | Filter by Homebrew package category (Koi classification). | Optional | 
| browser_category_koi | Filter by browser extension category (Koi classification). | Optional | 
| chocolatey_category_koi | Filter by Chocolatey package category (Koi classification). | Optional | 
| device_id | Filter devices by device ID. | Optional | 
| finding_id | Filter devices by finding ID. | Optional | 
| first_seen | Filter by first seen date (items first seen on or after this date). ISO 8601 format (e.g., "2024-01-01T00:00:00Z"). | Optional | 
| ide_category_koi | Filter by IDE extension category (Koi classification). | Optional | 
| installation_method | Filter by installation method. Possible values are: marketplace, manual, built_in, side_loaded. | Optional | 
| item_display_name | Filter by item display name. Performs case-insensitive partial match. | Optional | 
| item_id | Filter by item ID. | Optional | 
| marketplace | Filter by marketplace. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Optional | 
| platform | Filter by platform. Possible values are: antigravity, aqua, arc, brave, brew, chatgpt_atlas, chocolatey, chrome, chromium, claude, clion, codex, comet, cursor, datagrip, dataspell, dia, edge, excel, firefox, fleet, goland, hugging_face, intellij_community, intellij, kiro, mac, npm, notepad++, opera, outlook, phpstorm, powerpoint, prisma_access_browser, pycharm, pypi, rider, rubymine, rustrover, vscode, webstorm, windsurf, word, windows, writerside. | Optional | 
| publisher_name | Filter by publisher name. Performs case-insensitive partial match. | Optional | 
| risk_level | Filter by risk level. Possible values are: low, medium, high, critical, pending. | Optional | 
| software_category_koi | Filter by software category (Koi classification). | Optional | 
| sort_by | Column to sort by. Possible values are: first_seen, last_seen, item_display_name, item_id, version, marketplace, endpoint_count, risk, risk_level, status, installs_count, released_at, publisher_name. Default is first_seen. | Optional | 
| sort_direction | Sort direction. Possible values are: asc, desc. | Optional | 
| view | Filter by predefined view (marketplace group). Possible values are: agentic_ai, ai_models, code_packages, extensions, os_packages, software. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Inventory.item_id | String | The unique identifier of the inventory item. | 
| Koi.Inventory.item_display_name | String | The display name of the inventory item. | 
| Koi.Inventory.marketplace | String | The marketplace source of the item. | 
| Koi.Inventory.platforms | Unknown | List of platforms where the item is installed. | 
| Koi.Inventory.publisher_name | String | The publisher name of the item. | 
| Koi.Inventory.risk | Number | The numeric risk score of the item. | 
| Koi.Inventory.risk_level | String | The risk level classification of the item. | 
| Koi.Inventory.version | String | The version of the item. | 
| Koi.Inventory.status | String | The governance status of the item. | 
| Koi.Inventory.endpoint_count | Number | The number of endpoints where the item is installed. | 
| Koi.Inventory.installs_count | Number | The total number of installs for the item. | 
| Koi.Inventory.first_seen | Date | The date the item was first seen in ISO 8601 format. | 
| Koi.Inventory.last_seen | Date | The date the item was last seen in ISO 8601 format. | 
| Koi.Inventory.last_used | Date | The date the item was last used in ISO 8601 format. | 
| Koi.Inventory.installation_method | String | The method used to install the item. | 
| Koi.Inventory.short_description | String | A short description of the item. | 
| Koi.Inventory.is_first_party | Boolean | Whether the item is a first-party item. | 
| Koi.Inventory.is_signed | Boolean | Whether the item is signed. | 
| Koi.Inventory.categories | Unknown | List of categories the item belongs to. | 
| Koi.Inventory.findings | Unknown | List of findings associated with the item. | 
| Koi.Inventory.governed_details | Unknown | Governance policy details for the item. | 
| Koi.Inventory.released_at | Date | The release date of the item. Format: YYYY-MM-DD \(e.g., 2023-01-15\). | 
| Koi.Inventory.brew_category_koi | String | The Homebrew package category \(Koi classification\). | 
| Koi.Inventory.browser_category_koi | String | The browser extension category \(Koi classification\). | 
| Koi.Inventory.chocolatey_category_koi | String | The Chocolatey package category \(Koi classification\). | 
| Koi.Inventory.ide_category_koi | String | The IDE extension category \(Koi classification\). | 
| Koi.Inventory.software_category_koi | String | The software category \(Koi classification\). | 

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Unique identifier for the item. | Required |
| marketplace | The marketplace where the item is hosted. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Required |
| version | The specific version of the item. | Required |
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the 'limit' argument. | Optional |
| page_size | Number of results per page (default: 50, max: 500). Used in single-page mode with the 'page' argument. | Optional |
| limit | Maximum total number of endpoints to return (default: 50, max: 1000). When provided without the 'page' argument, auto-paginates to collect up to this many endpoints. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Inventory.Endpoint.id | String | The unique identifier of the endpoint device. |
| Koi.Inventory.Endpoint.hostname | String | The hostname of the endpoint. |
| Koi.Inventory.Endpoint.os | String | The operating system of the endpoint. |
| Koi.Inventory.Endpoint.platform | String | The platform where the item is installed on this endpoint. |
| Koi.Inventory.Endpoint.serial | String | The serial number of the endpoint device. |
| Koi.Inventory.Endpoint.last_logged_on_user | String | The last logged on user of the endpoint. |
| Koi.Inventory.Endpoint.activation_status | String | The activation status of the endpoint. |
| Koi.Inventory.Endpoint.path | String | The installation path of the item on the endpoint. |
| Koi.Inventory.Endpoint.first_seen | Date | The date the item was first seen on this endpoint in ISO 8601 format. |
| Koi.Inventory.Endpoint.last_seen | Date | The date the item was last seen on this endpoint in ISO 8601 format. |
### koi-inventory-item-endpoints-list

***
Retrieves a paginated list of endpoints that have a specific item installed.

#### Base Command

`koi-inventory-item-endpoints-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Unique identifier for the item. | Required | 
| marketplace | The marketplace where the item is hosted. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Required | 
| version | The specific version of the item. | Required | 
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the limit argument. | Optional | 
| page_size | Number of results per page (default: 50, max: 500). Used in single-page mode with the page argument. | Optional | 
| limit | Maximum total number of endpoints to return (default: 50, max: 1000). When provided without page, auto-paginates to collect up to this many endpoints. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Inventory.Endpoint.id | String | The unique identifier of the endpoint device. | 
| Koi.Inventory.Endpoint.hostname | String | The hostname of the endpoint. | 
| Koi.Inventory.Endpoint.os | String | The operating system of the endpoint. | 
| Koi.Inventory.Endpoint.platform | String | The platform where the item is installed on this endpoint. | 
| Koi.Inventory.Endpoint.serial | String | The serial number of the endpoint device. | 
| Koi.Inventory.Endpoint.last_logged_on_user | String | The last logged on user of the endpoint. | 
| Koi.Inventory.Endpoint.activation_status | String | The activation status of the endpoint. | 
| Koi.Inventory.Endpoint.path | String | The installation path of the item on the endpoint. | 
| Koi.Inventory.Endpoint.first_seen | Date | The date the item was first seen on this endpoint in ISO 8601 format. | 
| Koi.Inventory.Endpoint.last_seen | Date | The date the item was last seen on this endpoint in ISO 8601 format. | 

| --- | --- | --- |
| item_id | The ID of the item to remove from the allowlist. Required when not using items_list_raw_json_entry_id. | Optional | 
| marketplace | The source marketplace of the item. Required when not using items_list_raw_json_entry_id. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Optional | 
| created_by | Email of the user who created this entry. | Optional | 
| notes | Additional notes about the removal. | Optional | 
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to remove. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, item_id and marketplace arguments are ignored. | Optional | 

#### Context Output

There is no context output for this command.
### koi-allowlist-items-add

***
Adds one or more items to the global allowlist. Provide either the 'item_id' and 'marketplace' arguments for a single item, or the 'items_list_raw_json_entry_id' argument for bulk addition from a JSON file.

#### Base Command

`koi-allowlist-items-add`

### koi-allowlist-items-add

***
Adds one or more items to the global allowlist. Provide either 'item_id' and 'marketplace' for a single item, or 'items_list_raw_json_entry_id' for bulk addition from a JSON file.

#### Base Command

`koi-allowlist-items-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to add to the allowlist. Required when not using items_list_raw_json_entry_id. | Optional | 
| marketplace | The source marketplace of the item. Required when not using items_list_raw_json_entry_id. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Optional | 
| created_by | Email of the user who created this entry. | Optional | 
| notes | Additional notes about the entry. | Optional | 
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to add. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, item_id and marketplace arguments are ignored. | Optional | 

#### Context Output

There is no context output for this command.
### koi-group-device-remove

***
Removes a device from a specified group.

#### Base Command

`koi-group-device-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group. | Required | 
| device_id | The ID of the device to remove. | Required | 

#### Context Output

There is no context output for this command.
### koi-agent-activity-events-list

***
Retrieves a list of agent activity events within a time window (max 24 hours).

#### Base Command

`koi-agent-activity-events-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_at_gte | Start of time window (ISO 8601 or relative, e.g. "1 hour ago"). Maximum 24-hour window. | Required | 
| created_at_lte | End of time window (ISO 8601 or relative, e.g. "now"). Maximum 24-hour window. | Required | 
| session_id | Filter by session ID. | Optional | 
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the limit argument. | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of events to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.AgentActivityEvent.id | String | The unique identifier of the event. | 
| Koi.AgentActivityEvent.session_id | String | The session ID associated with the event. | 
| Koi.AgentActivityEvent.created_at | Date | The timestamp when the event was created. | 
| Koi.AgentActivityEvent.event_type | String | The type of event. | 

### koi-runtime-policy-list

***
Retrieves a list of agent runtime policies.

#### Base Command

`koi-runtime-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of policies to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.RuntimePolicy.id | String | The unique identifier of the runtime policy. | 
| Koi.RuntimePolicy.display_name | String | The display name of the policy. | 
| Koi.RuntimePolicy.description | String | The description of the policy. | 
| Koi.RuntimePolicy.enforcement_mode | String | The enforcement mode \(block or ask\). | 
| Koi.RuntimePolicy.enabled | Boolean | Whether the policy is enabled. | 
| Koi.RuntimePolicy.agents | Unknown | The agents this policy applies to. | 
| Koi.RuntimePolicy.rules | Unknown | The rules for this policy. | 
| Koi.RuntimePolicy.group_ids | Unknown | The group IDs this policy applies to. | 
| Koi.RuntimePolicy.created_at | Date | The creation timestamp. | 
| Koi.RuntimePolicy.updated_at | Date | The last update timestamp. | 

### koi-approval-request-approve

***
Approves a pending approval request.

#### Base Command

`koi-approval-request-approve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_request_id | The ID of the approval request to approve. | Required | 
| approved_by | The email of the user who approved the request. | Optional | 

#### Context Output

There is no context output for this command.
### koi-private-item-list

***
Retrieves a list of all private items.

#### Base Command

`koi-private-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.PrivateItem.id | String | The unique identifier of the private item. | 
| Koi.PrivateItem.name | String | The name of the private item. | 
| Koi.PrivateItem.marketplace | String | The marketplace. | 
| Koi.PrivateItem.created_by | String | The creator of the private item. | 
| Koi.PrivateItem.created_at | Date | The creation timestamp. | 

### koi-user-list

***
Retrieves a list of all users.

#### Base Command

`koi-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.User.id | String | The unique identifier of the user. | 
| Koi.User.email | String | The user email. | 
| Koi.User.role | String | The user role. | 
| Koi.User.created_at | Date | The user creation timestamp. | 

### koi-approval-request-create

***
Creates a new approval request for an item.

#### Base Command

`koi-approval-request-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item. | Required | 
| marketplace | The marketplace of the item. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Required | 
| platform | The platform of the item. | Required | 
| justification | The justification for the approval request. | Required | 
| requested_by | The email of the requester. | Required | 
| version | The version of the item. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.ApprovalRequest.id | String | The unique identifier of the approval request. | 
| Koi.ApprovalRequest.item_id | String | The item ID. | 
| Koi.ApprovalRequest.name | String | The name of the item. | 
| Koi.ApprovalRequest.marketplace | String | The marketplace. | 
| Koi.ApprovalRequest.platform | String | The platform. | 
| Koi.ApprovalRequest.approval_status | String | The approval status. | 
| Koi.ApprovalRequest.requested_by | String | The email of the requester. | 
| Koi.ApprovalRequest.created_at | Date | The creation timestamp. | 

### koi-finding-customize-risk

***
Customizes the risk level for a specific finding.

#### Base Command

`koi-finding-customize-risk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_id | The ID of the finding to customize risk for. | Required | 
| risk | The risk level to set, between 0 and 10. | Required | 

#### Context Output

There is no context output for this command.
### koi-private-item-details-get

***
Retrieves full scan details for a private item.

#### Base Command

`koi-private-item-details-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the private item. | Required | 
| version | The version to retrieve details for. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.PrivateItem.id | String | The unique identifier of the private item. | 
| Koi.PrivateItem.name | String | The name of the private item. | 
| Koi.PrivateItem.marketplace | String | The marketplace. | 
| Koi.PrivateItem.risk | Number | The risk score. | 
| Koi.PrivateItem.risk_level | String | The risk level. | 
| Koi.PrivateItem.findings | Unknown | The findings for this item. | 

### koi-report-create

***
Creates an async report. Use koi-report-status-get to check status and get download URL.

#### Base Command

`koi-report-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_type | The type of report to generate. Possible values are: inventory_by_extension, inventory_by_instance, agent_activity_logs. | Required | 
| filters | Optional JSON object of filters to apply to the report. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Report.id | String | The unique identifier of the report. | 
| Koi.Report.report_type | String | The type of the report. | 
| Koi.Report.status | String | The report generation status. | 

### koi-device-inventory-get

***
Retrieves the inventory of software installed on a specific device.

#### Base Command

`koi-device-inventory-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 
| finding_id | Filter by finding ID. | Optional | 
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of items to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.DeviceInventory.item_id | String | The item ID. | 
| Koi.DeviceInventory.item_display_name | String | The display name of the item. | 
| Koi.DeviceInventory.marketplace | String | The marketplace. | 
| Koi.DeviceInventory.risk_level | String | The risk level. | 
| Koi.DeviceInventory.version | String | The version. | 

### koi-runtime-policy-delete

***
Deletes an agent runtime policy by ID.

#### Base Command

`koi-runtime-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the runtime policy to delete. | Required | 

#### Context Output

There is no context output for this command.
### koi-agent-activity-sessions-list

***
Retrieves a list of agent activity sessions within a time window (max 30 days).

#### Base Command

`koi-agent-activity-sessions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_at_gte | Start of time window (ISO 8601 or relative). Maximum 30-day window. | Required | 
| created_at_lte | End of time window (ISO 8601 or relative). Maximum 30-day window. | Required | 
| agent | Filter by AI agent name. | Optional | 
| host | Filter by host. | Optional | 
| model | Filter by model. | Optional | 
| user_email | Filter by user email. | Optional | 
| verdict | Filter by verdict. | Optional | 
| mcp | Filter by MCP. | Optional | 
| skill | Filter by skill. | Optional | 
| action | Filter by action. | Optional | 
| governed_by | Filter by governance policy. | Optional | 
| filter | Additional filter string. | Optional | 
| sort_by | Column to sort by. | Optional | 
| sort_direction | Sort direction. Possible values are: asc, desc. | Optional | 
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of sessions to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.AgentActivitySession.id | String | The unique identifier of the session. | 
| Koi.AgentActivitySession.agent | String | The AI agent name. | 
| Koi.AgentActivitySession.host | String | The host. | 
| Koi.AgentActivitySession.model | String | The model used. | 
| Koi.AgentActivitySession.user_email | String | The user email. | 
| Koi.AgentActivitySession.verdict | String | The session verdict. | 
| Koi.AgentActivitySession.created_at | Date | The session creation timestamp. | 

### koi-group-list

***
Retrieves a list of all device groups with device details.

#### Base Command

`koi-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of groups to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Group.id | Number | The unique identifier of the group. | 
| Koi.Group.name | String | The group name. | 
| Koi.Group.created_at | Date | The group creation timestamp. | 
| Koi.Group.devices | Unknown | The devices in the group. | 

### koi-report-status-get

***
Retrieves the status of an async report. Returns download URL when completed.

#### Base Command

`koi-report-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Report.id | String | The unique identifier of the report. | 
| Koi.Report.report_type | String | The type of the report. | 
| Koi.Report.status | String | The report generation status \(e.g. pending, completed, failed\). | 
| Koi.Report.download_url | String | The download URL for the completed report. | 
| Koi.Report.created_at | Date | The creation timestamp. | 

### koi-remediation-dismiss

***
Dismisses one or more remediations.

#### Base Command

`koi-remediation-dismiss`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| items | JSON array of items to dismiss. Each item must include item_id, platform, version, and device_id. Example: [{"item_id": "abc", "platform": "chrome", "version": "1.0", "device_id": "dev1"}]. | Required | 
| dismissed_by | The email of the user dismissing the remediations. | Optional | 

#### Context Output

There is no context output for this command.
### koi-device-archive

***
Archives a device by ID.

#### Base Command

`koi-device-archive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device to archive. | Required | 
| archived_by_user_email | The email of the user performing the archive. | Required | 

#### Context Output

There is no context output for this command.
### koi-runtime-policy-get

***
Retrieves a single agent runtime policy by ID.

#### Base Command

`koi-runtime-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the runtime policy. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.RuntimePolicy.id | String | The unique identifier of the runtime policy. | 
| Koi.RuntimePolicy.display_name | String | The display name of the policy. | 
| Koi.RuntimePolicy.description | String | The description of the policy. | 
| Koi.RuntimePolicy.enforcement_mode | String | The enforcement mode \(block or ask\). | 
| Koi.RuntimePolicy.enabled | Boolean | Whether the policy is enabled. | 
| Koi.RuntimePolicy.agents | Unknown | The agents this policy applies to. | 
| Koi.RuntimePolicy.rules | Unknown | The rules for this policy. | 
| Koi.RuntimePolicy.group_ids | Unknown | The group IDs this policy applies to. | 
| Koi.RuntimePolicy.created_at | Date | The creation timestamp. | 
| Koi.RuntimePolicy.updated_at | Date | The last update timestamp. | 

### koi-user-delete

***
Deletes a user by ID.

#### Base Command

`koi-user-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to delete. | Required | 

#### Context Output

There is no context output for this command.
### koi-group-device-add

***
Adds a device to a specified group.

#### Base Command

`koi-group-device-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group. | Required | 
| device_id | The ID of the device to add. | Required | 

#### Context Output

There is no context output for this command.
### koi-koidex-fetch

***
Triggers a Koidex fetch for one or more items to update their risk data.

#### Base Command

`koi-koidex-fetch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| items | JSON array of items to fetch. Each item must include item_id or name, and marketplace or platform. Example: [{"item_id": "abc", "marketplace": "npm", "version": "1.0.0"}]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.KoidexFetch.status | String | The status of the fetch operation. | 

### koi-koidex-risk-report-get

***
Retrieves the Koidex risk report for a specific item.

#### Base Command

`koi-koidex-risk-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item. | Required | 
| marketplace | The marketplace of the item. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Required | 
| version | The version of the item. If omitted, returns the latest version. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.KoidexRiskReport.item_id | String | The item ID. | 
| Koi.KoidexRiskReport.marketplace | String | The marketplace. | 
| Koi.KoidexRiskReport.risk | Number | The risk score. | 
| Koi.KoidexRiskReport.risk_level | String | The risk level. | 
| Koi.KoidexRiskReport.findings | Unknown | The findings for this item. | 

### koi-group-create

***
Creates a new device group. Maximum 9 groups per customer.

#### Base Command

`koi-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the group to create. | Required | 
| device_ids | Comma-separated list of device IDs to add to the group. | Optional | 
| creator | Identifier to attribute as the creator (e.g. email or service name). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Group.id | Number | The unique identifier of the created group. | 
| Koi.Group.name | String | The group name. | 
| Koi.Group.created_at | Date | The group creation timestamp. | 
| Koi.Group.devices | Unknown | The devices in the group. | 

### koi-approval-request-list

***
Retrieves a list of approval requests with optional filters.

#### Base Command

`koi-approval-request-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_status | Filter by approval status. Possible values are: pending, approved, rejected. | Optional | 
| marketplace | Filter by marketplace. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Optional | 
| requested_by | Filter by requester email. | Optional | 
| created_at_gte | Filter by request date greater than or equal to (ISO 8601 or relative). | Optional | 
| created_at_lte | Filter by request date less than or equal to (ISO 8601 or relative). | Optional | 
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of requests to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.ApprovalRequest.id | String | The unique identifier of the approval request. | 
| Koi.ApprovalRequest.item_id | String | The item ID. | 
| Koi.ApprovalRequest.name | String | The name of the item. | 
| Koi.ApprovalRequest.marketplace | String | The marketplace. | 
| Koi.ApprovalRequest.platform | String | The platform. | 
| Koi.ApprovalRequest.approval_status | String | The approval status \(pending, approved, rejected\). | 
| Koi.ApprovalRequest.requested_by | String | The email of the requester. | 
| Koi.ApprovalRequest.justification | String | The justification for the request. | 
| Koi.ApprovalRequest.reject_reason | String | The reason for rejection. | 
| Koi.ApprovalRequest.version | String | The version of the item. | 
| Koi.ApprovalRequest.publisher_name | String | The publisher name. | 
| Koi.ApprovalRequest.created_at | Date | The date when the request was created. | 
| Koi.ApprovalRequest.updated_at | Date | The date when the request was last updated. | 
| Koi.ApprovalRequest.resolved_at | Date | The date when the request was resolved. | 

### koi-remediation-submit

***
Submits remediations for one or more items on specific devices.

#### Base Command

`koi-remediation-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| items | JSON array of remediation items. Each item must include item_id, platform, version, and device_ids array. Example: [{"item_id": "abc", "platform": "chrome", "version": "1.0", "device_ids": ["dev1"]}]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Remediation.id | String | The unique identifier of the submitted remediation. | 
| Koi.Remediation.status | String | The remediation status. | 

### koi-koidex-search

***
Searches for items in the Koidex marketplace catalog.

#### Base Command

`koi-koidex-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| marketplace | The marketplace to search in. Possible values are: binaries, bitbucket, chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github, github_mcp_registry, gitlab, homebrew, hugging_face, jetbrains, linux, mac, mcp_registry, notepad++, npm, office_add_ins, ollama, open_vsx_registry, pypi, skill, visual_studio, vscode, windows, windsurf. | Required | 
| search_term | The search term to look for. | Required | 
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of results to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.KoidexSearch.item_id | String | The item ID. | 
| Koi.KoidexSearch.name | String | The item name. | 
| Koi.KoidexSearch.marketplace | String | The marketplace. | 
| Koi.KoidexSearch.publisher_name | String | The publisher name. | 
| Koi.KoidexSearch.risk | Number | The risk score. | 
| Koi.KoidexSearch.risk_level | String | The risk level. | 

### koi-remediation-list

***
Retrieves a list of remediations with optional filters.

#### Base Command

`koi-remediation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Filter by hostname. | Optional | 
| platform | Filter by platform. | Optional | 
| risk_level | Filter by risk level. | Optional | 
| status | Filter by remediation status. | Optional | 
| reason | Filter by reason. | Optional | 
| sort_by | Column to sort by. | Optional | 
| sort_direction | Sort direction. Possible values are: asc, desc. | Optional | 
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of remediations to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Remediation.id | String | The unique identifier of the remediation. | 
| Koi.Remediation.item_id | String | The item ID. | 
| Koi.Remediation.hostname | String | The hostname. | 
| Koi.Remediation.platform | String | The platform. | 
| Koi.Remediation.status | String | The remediation status. | 
| Koi.Remediation.risk_level | String | The risk level. | 
| Koi.Remediation.reason | String | The reason. | 
| Koi.Remediation.created_at | Date | The creation timestamp. | 

### koi-private-item-upload

***
Uploads a private item for scanning.

#### Base Command

`koi-private-item-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file to upload. | Required | 
| created_by | The email of the user uploading the item. | Required | 
| marketplace | The marketplace for the private item. Possible values are: chrome_web_store, skill. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.PrivateItem.id | String | The unique identifier of the uploaded private item. | 
| Koi.PrivateItem.name | String | The name of the uploaded item. | 
| Koi.PrivateItem.marketplace | String | The marketplace. | 
| Koi.PrivateItem.created_by | String | The creator. | 

### koi-runtime-policy-update

***
Updates an existing agent runtime policy. Only provided fields are updated.

#### Base Command

`koi-runtime-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the runtime policy to update. | Required | 
| display_name | The new display name. | Optional | 
| enforcement_mode | The new enforcement mode. Possible values are: block, ask. | Optional | 
| agents | Comma-separated list of agent names. | Optional | 
| rules | JSON array of rule objects. | Optional | 
| enabled | Whether the policy is enabled. Possible values are: true, false. | Optional | 
| description | The new description. | Optional | 
| group_ids | Comma-separated list of group IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.RuntimePolicy.id | String | The unique identifier of the runtime policy. | 
| Koi.RuntimePolicy.display_name | String | The display name of the policy. | 
| Koi.RuntimePolicy.enforcement_mode | String | The enforcement mode. | 
| Koi.RuntimePolicy.enabled | Boolean | Whether the policy is enabled. | 
| Koi.RuntimePolicy.updated_at | Date | The last update timestamp. | 

### koi-finding-list

***
Retrieves a paginated list of all finding definitions.

#### Base Command

`koi-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of findings to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Finding.id | String | The unique identifier of the finding. | 
| Koi.Finding.name | String | The name of the finding. | 
| Koi.Finding.description | String | The description of the finding. | 
| Koi.Finding.risk | Number | The risk level of the finding \(0-10\). | 

### koi-runtime-policy-create

***
Creates a new agent runtime policy.

#### Base Command

`koi-runtime-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The display name of the policy. | Required | 
| enforcement_mode | The enforcement mode. Possible values are: block, ask. | Required | 
| agents | Comma-separated list of agent names this policy applies to. | Required | 
| rules | JSON array of rule objects for the policy. | Required | 
| enabled | Whether the policy is enabled. Possible values are: true, false. Default is true. | Optional | 
| description | The description of the policy. | Optional | 
| group_ids | Comma-separated list of group IDs this policy applies to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.RuntimePolicy.id | String | The unique identifier of the created runtime policy. | 
| Koi.RuntimePolicy.display_name | String | The display name of the policy. | 
| Koi.RuntimePolicy.enforcement_mode | String | The enforcement mode. | 
| Koi.RuntimePolicy.enabled | Boolean | Whether the policy is enabled. | 
| Koi.RuntimePolicy.created_at | Date | The creation timestamp. | 

### koi-user-create

***
Creates a new user.

#### Base Command

`koi-user-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email of the user to create. | Required | 
| role | The role to assign to the user. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.User.id | String | The unique identifier of the created user. | 
| Koi.User.email | String | The user email. | 
| Koi.User.role | String | The user role. | 
| Koi.User.created_at | Date | The creation timestamp. | 

### koi-approval-request-reject

***
Rejects a pending approval request.

#### Base Command

`koi-approval-request-reject`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_request_id | The ID of the approval request to reject. | Required | 
| rejected_by | The email of the user who rejected the request. | Optional | 
| reason | The reason for rejecting the approval request. | Optional | 

#### Context Output

There is no context output for this command.
### koi-group-update

***
Updates the name of an existing device group.

#### Base Command

`koi-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to update. | Required | 
| name | The new name for the group. | Required | 

#### Context Output

There is no context output for this command.
### koi-device-list

***
Retrieves a list of devices with optional filters.

#### Base Command

`koi-device-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Filter by device status. | Optional | 
| last_seen_gte | Filter by last seen date greater than or equal to (ISO 8601 or relative). | Optional | 
| last_seen_lte | Filter by last seen date less than or equal to (ISO 8601 or relative). | Optional | 
| page | Page number for pagination (1-based). | Optional | 
| page_size | Number of results per page (default: 50, max: 500). | Optional | 
| limit | Maximum total number of devices to return (default: 50, max: 1000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Koi.Device.id | String | The unique identifier of the device. | 
| Koi.Device.hostname | String | The hostname of the device. | 
| Koi.Device.os | String | The operating system. | 
| Koi.Device.platform | String | The platform. | 
| Koi.Device.status | String | The device status. | 
| Koi.Device.last_seen | Date | The last seen timestamp. | 
| Koi.Device.serial | String | The serial number. | 


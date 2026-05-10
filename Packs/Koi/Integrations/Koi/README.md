## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### koi-get-events

***
Gets events from KOI. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

#### Base Command

`koi-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | The type of events to retrieve. If not specified, uses the value configured in the integration parameters. Possible values are: Alerts, Audit. Default is Alerts,Audit. | Optional |
| limit | The maximum number of events to return per type. Default is 50. | Optional |
| start_time | Filter events created at or after this time. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | Filter events created at or before this time. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| should_push_events | If true, the command creates events in XSIAM; otherwise, it only displays them. Possible values are: true, false. Default is false. | Optional |

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
| marketplace | The marketplace where the item is hosted. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Required |
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

#### Command example

```!koi-inventory-item-get item_id=example-extension marketplace=vscode```

#### Human Readable Output

>### KOI Inventory Item
>
>|Item Id|Item Display Name|Marketplace|Platforms|Publisher Name|Risk|Risk Level|Version|Status|Endpoint Count|Installs Count|Installation Method|Is First Party|Is Signed|First Seen|Last Seen|Last Used|Released At|Short Description|Categories|Findings|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| abc123 | React Developer Tools | chrome_web_store | chrome, edge | Meta | 5 | high | 1.0.0 | Allowed | 42 | 1000000 | marketplace | false | true | 2024-01-01T10:00:00Z | 2024-10-15T10:00:00Z | 2025-06-15T10:00:00Z | 2023-01-15 | React debugging tools | Developer Tools | {'description': 'This item contains malware', 'evidence': {}, 'finding_id': 'malware_detected', 'finding_name': 'Malware Detected', 'severity': 'critical'} |

### koi-blocklist-items-add

***
Adds one or more items to the global blocklist. Provide either the 'item_id' and 'marketplace' arguments for a single item, or the 'items_list_raw_json_entry_id' argument for bulk addition from a JSON file.

#### Base Command

`koi-blocklist-items-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to add to the blocklist. Required when not using the 'items_list_raw_json_entry_id' argument. | Optional |
| marketplace | The source marketplace of the item. Required when not using the 'items_list_raw_json_entry_id' argument. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Optional |
| created_by | Email of the user who created this entry. | Optional |
| notes | Additional notes or justification for blocking the item. | Optional |
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to add. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, the 'item_id' and 'marketplace' arguments are ignored. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!koi-blocklist-items-add item_id=malicious-ext marketplace=chrome_web_store notes="Blocked due to security risk"```

#### Human Readable Output

>Blocklist item 'malicious-ext' (marketplace: chrome_web_store) was added successfully.

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

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination (1-based). When provided, fetches a single page and ignores the 'limit' argument. | Optional |
| page_size | Number of results per page (default: 50, max: 500). Used in single-page mode with the 'page' argument. | Optional |
| limit | Maximum total number of inventory items to return (default: 50, max: 1000). When provided without the 'page' argument, auto-paginates to collect up to this many items. Default is 50. | Optional |
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
| marketplace | Filter by marketplace. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Optional |
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

#### Command example

```!koi-inventory-list limit=50 marketplace=vscode sort_by=first_seen sort_direction=desc```

#### Human Readable Output

>### KOI Inventory
>
>|Item Id|Item Display Name|Marketplace|Platforms|Publisher Name|Risk|Risk Level|Version|Status|Endpoint Count|Installs Count|Installation Method|Is First Party|Is Signed|First Seen|Last Seen|Last Used|Released At|Short Description|Categories|Findings|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| abc123 | React Developer Tools | chrome_web_store | chrome, edge | Meta | 5 | high | 1.0.0 | APPROVED | 42 | 1000000 | marketplace | false | true | 2024-01-01T10:00:00Z | 2024-10-15T10:00:00Z | 2025-06-15T10:00:00Z | 2023-01-15 | React debugging tools | Developer Tools | malware, permissions |
>| def456 | Prettier - Code formatter | vscode | vscode | Prettier | 2 | low | 10.1.0 | APPROVED | 15 | 500000 | manual | true | true | 2024-03-10T08:30:00Z | 2024-11-01T14:00:00Z |  | 2022-06-01 | Code formatter using prettier | Productivity |  |

### koi-inventory-item-endpoints-list

***
Retrieves a paginated list of endpoints that have a specific item installed.

#### Base Command

`koi-inventory-item-endpoints-list`

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

#### Command example

```!koi-inventory-item-endpoints-list item_id=example-extension marketplace=vscode limit=50```

#### Human Readable Output

>### KOI Inventory Item Endpoints
>
>|Id|Hostname|Os|Platform|Serial|Last Logged On User|Activation Status|Path|First Seen|Last Seen|
>|---|---|---|---|---|---|---|---|---|---|
>| device-123 | laptop-01 | windows | chrome | ABC123XYZ | john.doe | enabled | /Applications/Google Chrome.app/Contents/Extensions/abc123 | 2024-01-01T10:00:00Z | 2024-10-15T10:00:00Z |
>| device-456 | desktop-02 | macos | chrome | DEF456UVW | jane.smith | enabled | /Users/jane/Library/Application Support/Google/Chrome/Extensions/abc123 | 2024-02-15T08:30:00Z | 2024-11-01T14:00:00Z |

### koi-blocklist-items-remove

***
Removes one or more items from the global blocklist. Provide either the 'item_id' and 'marketplace' arguments for a single item, or the 'items_list_raw_json_entry_id' argument for bulk removal from a JSON file.

#### Base Command

`koi-blocklist-items-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to remove from the blocklist. Required when not using the 'items_list_raw_json_entry_id' argument. | Optional |
| marketplace | The source marketplace of the item. Required when not using the 'items_list_raw_json_entry_id' argument. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Optional |
| created_by | Email of the user who created this entry. | Optional |
| notes | Additional notes about the removal. | Optional |
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to remove. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, the 'item_id' and 'marketplace' arguments are ignored. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!koi-blocklist-items-remove item_id=malicious-ext marketplace=chrome_web_store```

#### Human Readable Output

>Blocklist item 'malicious-ext' (marketplace: chrome_web_store) was removed successfully.

### koi-allowlist-items-remove

***
Removes one or more items from the global allowlist. Provide either the 'item_id' and 'marketplace' arguments for a single item, or the 'items_list_raw_json_entry_id' argument for bulk removal from a JSON file.

#### Base Command

`koi-allowlist-items-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to remove from the allowlist. Required when not using the 'items_list_raw_json_entry_id' argument. | Optional |
| marketplace | The source marketplace of the item. Required when not using the 'items_list_raw_json_entry_id' argument. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Optional |
| created_by | Email of the user who created this entry. | Optional |
| notes | Additional notes about the removal. | Optional |
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to remove. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, the 'item_id' and 'marketplace' arguments are ignored. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!koi-allowlist-items-remove item_id=example-extension marketplace=vscode```

#### Human Readable Output

>Allowlist item 'example-extension' (marketplace: vscode) was removed successfully.

### koi-allowlist-items-add

***
Adds one or more items to the global allowlist. Provide either the 'item_id' and 'marketplace' arguments for a single item, or the 'items_list_raw_json_entry_id' argument for bulk addition from a JSON file.

#### Base Command

`koi-allowlist-items-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The ID of the item to add to the allowlist. Required when not using the 'items_list_raw_json_entry_id' argument. | Optional |
| marketplace | The source marketplace of the item. Required when not using the 'items_list_raw_json_entry_id' argument. Possible values are: chocolatey, chrome_web_store, claude_desktop_extensions, cursor, docker, edge_add_ons, firefox_add_ons, github_mcp_registry, homebrew, hugging_face, jetbrains, linux, mac, notepad++, npm, office_add_ins, open_vsx_registry, pypi, visual_studio, vscode, windows, windsurf. | Optional |
| created_by | Email of the user who created this entry. | Optional |
| notes | Additional notes about the entry. | Optional |
| items_list_raw_json_entry_id | War Room entry ID of a JSON file containing a list of items to add. Each item must have "item_id" and "marketplace" fields. Optional fields: "created_by", "notes". When provided, the 'item_id' and 'marketplace' arguments are ignored. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!koi-allowlist-items-add item_id=example-extension marketplace=vscode notes="Approved by security team"```

#### Human Readable Output

>Allowlist item 'example-extension' (marketplace: vscode) was added successfully.

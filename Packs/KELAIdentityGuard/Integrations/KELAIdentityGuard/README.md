# KELA Identity Guard

Search KELA Identity Guard incidents: compromised credentials detected on infostealer-infected
machines (bots), leaked credential lists, data breaches and cybercrime chatter; bot-market alerts
(bots/webmails offered for sale); and compromised session-cookie incidents. Includes fetch-incidents
to automatically mirror all three sources into Cortex XSOAR, each independently toggleable.

This integration was integrated and tested with the Identity Guard module of the KELA platform
(`bots-client-api` v1).

## Configure KELA Identity Guard in Cortex XSOAR

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the KELA API (`https://api.ke-la.com/bots-client-api/v1`). | True |
| API Key | Your KELA Identity Guard API token. | True |
| Default Workspace ID | Used when a command is called without an explicit `workspace_id` argument. Required for fetch-incidents. | False |
| Fetch incidents | Whether to fetch KELA Identity Guard incidents as Cortex XSOAR incidents. | False |
| Incident type | The incident type to classify fetched incidents as. | False |
| Maximum number of incidents per fetch (per source) | Cap on the number of incidents pulled per source, per fetch cycle. | False |
| First fetch time | How far back to look on the very first fetch, e.g. `3 days`. Applies to all enabled sources. | False |
| Minimum severity to fetch | Only fetch incidents/cookie incidents at or above this severity. Doesn't apply to bot-market alerts (no severity field in the API). | False |
| Fetch bot-market alerts | Include bot-market alerts in the automatic fetch. Uncheck to exclude this source. | False |
| Fetch compromised session-cookie incidents | Include cookie incidents in the automatic fetch. Uncheck to exclude this source. | False |
| Trust any certificate (not secure) | Skip TLS certificate validation. | False |
| Use system proxy settings | Route requests through the configured system proxy. | False |

The interval between fetch cycles is Cortex XSOAR's built-in "Incidents Fetch Interval" setting on
the instance (not configured in this pack).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### kela-identityguard-search-incidents

***
Search Identity Guard incidents for a workspace, with rich filtering, sorting and pagination.

#### Base Command

`kela-identityguard-search-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | Workspace ID to search. Defaults to the instance's Default Workspace ID. | Optional |
| search_term | Free-text search term. | Optional |
| severity | Filter by severity (low/medium/high/critical). | Optional |
| status | Filter by resolution status (RESOLVED/UNRESOLVED). | Optional |
| source_types | Comma-separated source types (infectedBots, credentialsLists). | Optional |
| source_category | Comma-separated source categories (infostealers, dataBreaches, chatters). | Optional |
| archived | Comma-separated archived-state filter (archived/unarchived). | Optional |
| deleted | Only return deleted/non-deleted incidents. | Optional |
| created_date_start / created_date_end | Created-date range. | Optional |
| updated_date_start / updated_date_end | Updated-date range. | Optional |
| sort_by | Field to sort by (createdDate/updatedDate/sourceDate). | Optional |
| order | Sort order (asc/desc). | Optional |
| limit | Page size. Default is 50. | Optional |
| offset | Pagination offset. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.IdentityGuard.Incident.incidentId | String | The incident ID. |
| KELA.IdentityGuard.Incident.severity | String | The incident severity. |
| KELA.IdentityGuard.Incident.status | String | The incident status. |
| KELA.IdentityGuard.Incident.sourceType | String | The source type. |
| KELA.IdentityGuard.Incident.accountUserName | String | The compromised username, if any. |
| KELA.IdentityGuard.Incident.accountServiceHostname | String | The targeted service hostname, if any. |
| KELA.IdentityGuard.Incident.botIp | String | The IP address of the infected machine, if any. |

#### Command Example

```
!kela-identityguard-search-incidents workspace_id=1234 severity=critical status=UNRESOLVED limit=20
```

### kela-identityguard-search-bot-markets

***
Search Identity Guard bot-market alerts (bots/webmails offered for sale) for a workspace.

#### Base Command

`kela-identityguard-search-bot-markets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | Workspace ID to search. Defaults to the instance's Default Workspace ID. | Optional |
| search_term | Free-text search term. | Optional |
| statuses | Comma-separated takedown request statuses (pending, takedown, canceled, failed, untagged). | Optional |
| availability_issues | Comma-separated availability issues (notAvailable, available, untagged). | Optional |
| incident_status | Comma-separated incident statuses (unresolved, resolved). | Optional |
| services | Comma-separated marketplace names (e.g. RussianMarket). | Optional |
| is_archived / is_deleted | Filter by archived/deleted state. | Optional |
| sort_by | Field to sort by (createdDate/updatedDate/postedDate). | Optional |
| order | Sort order (asc/desc). | Optional |
| limit / offset | Page size / pagination offset. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.IdentityGuard.BotMarket.alertId | String | The bot-market alert ID. |
| KELA.IdentityGuard.BotMarket.marketName | String | The marketplace name (e.g. "RussianMarket"). |
| KELA.IdentityGuard.BotMarket.requestStatus | String | The takedown request status. |
| KELA.IdentityGuard.BotMarket.availabilityStatus | String | The availability status. |
| KELA.IdentityGuard.BotMarket.price | String | The listed price. |
| KELA.IdentityGuard.BotMarket.postedDate | Date | When the item was posted for sale. |

#### Command Example

```
!kela-identityguard-search-bot-markets workspace_id=1234 statuses=pending
```

### kela-identityguard-search-cookie-incidents

***
Search Identity Guard compromised session-cookie incidents for a workspace. Requires the "cookies"
permission on Identity Guard.

#### Base Command

`kela-identityguard-search-cookie-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | Workspace ID to search. Defaults to the instance's Default Workspace ID. | Optional |
| search_term | Free-text search term. | Optional |
| severity | Filter by severity (CRITICAL/NON_CRITICAL). | Optional |
| status | Filter by resolution status (RESOLVED/UNRESOLVED). | Optional |
| cookie_category | Comma-separated cookie categories. | Optional |
| service_hostname | Comma-separated service hostnames. | Optional |
| geographies | Comma-separated geographies. | Optional |
| incident_hash / session_hash | Filter by a specific incident/session hash. | Optional |
| linked_usernames | Only return incidents linked to usernames. | Optional |
| archived | Filter by archived state. | Optional |
| sort_by | Field to sort by (createdDate/sourceDate/updatedDate). | Optional |
| order | Sort order (asc/desc). | Optional |
| limit / offset | Page size / pagination offset. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.IdentityGuard.CookieIncident.incidentId | String | The cookie incident ID. |
| KELA.IdentityGuard.CookieIncident.severity | String | The severity (critical/non-critical). |
| KELA.IdentityGuard.CookieIncident.status | String | The status. |
| KELA.IdentityGuard.CookieIncident.cookieCategory | String | The cookie category/categories. |
| KELA.IdentityGuard.CookieIncident.botCountry | String | The country of the infected machine. |

#### Command Example

```
!kela-identityguard-search-cookie-incidents workspace_id=1234 severity=CRITICAL status=UNRESOLVED
```

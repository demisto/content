PiHole v6 integration using the new REST API. PiHole is a network-level advertisement and Internet tracker blocking application which acts as a DNS sinkhole and optionally a DHCP server, intended for use on a private network.
This integration was integrated and tested with PiHole v6.0 API.

## Configure PiHole v6 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://192.168.1.25\) | True |
| password | PiHole admin password for API authentication | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pihole-get-summary

***
Get overview of PiHole activity including query stats, client counts, and gravity info.

#### Base Command

`pihole-get-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Summary.queries | Unknown | Query statistics including total, blocked, cached, forwarded counts. |
| PiHoleV6.Summary.clients | Unknown | Client statistics. |
| PiHoleV6.Summary.gravity | Unknown | Gravity list statistics. |

### pihole-get-top-domains

***
Get top permitted or blocked domains.

#### Base Command

`pihole-get-top-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| count | Number of top domains to return. Default is 10. | Optional |
| blocked | If true, return top blocked domains instead of top permitted domains. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.TopDomains.domains | Unknown | Array of top domains with counts. |
| PiHoleV6.TopDomains.total_queries | Number | Total number of queries. |

### pihole-get-top-clients

***
Get top clients by query count.

#### Base Command

`pihole-get-top-clients`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| count | Number of top clients to return. Default is 10. | Optional |
| blocked | If true, return top blocked clients instead of top active clients. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.TopClients.clients | Unknown | Array of top clients with counts. |
| PiHoleV6.TopClients.total_queries | Number | Total number of queries. |

### pihole-get-upstreams

***
Get metrics about upstream DNS destinations.

#### Base Command

`pihole-get-upstreams`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Upstreams.upstreams | Unknown | Array of upstream destinations with query counts and response times. |
| PiHoleV6.Upstreams.forwarded_queries | Number | Number of forwarded queries. |

### pihole-get-query-types

***
Get breakdown of DNS query types.

#### Base Command

`pihole-get-query-types`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.QueryTypes.types | Unknown | Query type counts \(A, AAAA, MX, etc\). |

### pihole-get-recent-blocked

***
Get most recently blocked domain(s).

#### Base Command

`pihole-get-recent-blocked`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| count | Number of recently blocked domains to return. Default is 1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.RecentBlocked.blocked | Unknown | List of recently blocked domains. |

### pihole-get-history

***
Get activity graph data (queries over time).

#### Base Command

`pihole-get-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.History.history | Unknown | Activity over time data with timestamps, total, cached, blocked, forwarded counts. |

### pihole-get-history-clients

***
Get per-client activity graph data.

#### Base Command

`pihole-get-history-clients`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| N | Maximum number of clients to return. 0 returns all. Default is 20. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.HistoryClients.clients | Unknown | Client information with query counts. |
| PiHoleV6.HistoryClients.history | Unknown | Per-client activity over time. |

### pihole-get-queries

***
Get DNS query log with optional filtering.

#### Base Command

`pihole-get-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| length | Number of queries to return. Default is 100. | Optional |
| domain | Filter by domain \(wildcards supported\). | Optional |
| client_ip | Filter by client IP \(wildcards supported\). | Optional |
| client_name | Filter by client hostname \(wildcards supported\). | Optional |
| upstream | Filter by upstream server. | Optional |
| type | Filter by query type \(A, AAAA, etc\). | Optional |
| status | Filter by status \(GRAVITY, FORWARDED, CACHE, etc\). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Queries.queries | Unknown | Array of DNS query records. |
| PiHoleV6.Queries.recordsTotal | Number | Total number of available queries. |

### pihole-get-blocking-status

***
Get current PiHole blocking status.

#### Base Command

`pihole-get-blocking-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Blocking.blocking | String | Current blocking status \(enabled/disabled\). |
| PiHoleV6.Blocking.timer | Number | Remaining seconds until blocking mode changes automatically. Null if permanent. |

### pihole-set-blocking

***
Enable or disable PiHole blocking, optionally with a timer.

#### Base Command

`pihole-set-blocking`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| blocking | Enable or disable blocking. Possible values are: true, false. | Required |
| timer | Seconds until blocking mode automatically reverts. Leave empty for permanent change. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Blocking.blocking | String | New blocking status. |
| PiHoleV6.Blocking.timer | Number | Timer value if set. |

### pihole-get-domains

***
Get domains from allow/deny lists. Filter by type and kind.

#### Base Command

`pihole-get-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Domain type filter. Possible values are: allow, deny. | Optional |
| kind | Domain kind filter. Possible values are: exact, regex. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Domains.domains | Unknown | Array of domain entries. |

### pihole-add-domain

***
Add a domain to allow/deny list.

#### Base Command

`pihole-add-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Domain type. Possible values are: allow, deny. | Required |
| kind | Domain kind. Possible values are: exact, regex. | Required |
| domain | Domain to add. | Required |
| comment | Optional comment. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Domains.domains | Unknown | Added domain details. |

### pihole-delete-domain

***
Delete a domain from allow/deny list.

#### Base Command

`pihole-delete-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Domain type. Possible values are: allow, deny. | Required |
| kind | Domain kind. Possible values are: exact, regex. | Required |
| domain | Domain to delete. | Required |

#### Context Output

There is no context output for this command.

### pihole-get-version

***
Get PiHole component versions.

#### Base Command

`pihole-get-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Version | Unknown | Version information for all PiHole components. |

### pihole-get-system-info

***
Get system information from PiHole host.

#### Base Command

`pihole-get-system-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.SystemInfo | Unknown | System information \(CPU, memory, disk, uptime, etc\). |

### pihole-get-ftl-info

***
Get FTL (Faster Than Light) engine information.

#### Base Command

`pihole-get-ftl-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.FTLInfo | Unknown | FTL engine information. |

### pihole-get-host-info

***
Get host information.

#### Base Command

`pihole-get-host-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.HostInfo | Unknown | Host information. |

### pihole-get-sensors

***
Get sensor information from PiHole host.

#### Base Command

`pihole-get-sensors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Sensors | Unknown | Sensor readings \(temperature, etc\). |

### pihole-run-gravity

***
Update PiHole gravity (pull latest adlists).

#### Base Command

`pihole-run-gravity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Gravity.output | String | Gravity update output. |

### pihole-restart-dns

***
Restart the pihole-FTL DNS service.

#### Base Command

`pihole-restart-dns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.RestartDNS | Unknown | Restart result. |

### pihole-flush-logs

***
Flush DNS logs and purge last 24 hours from database.

#### Base Command

`pihole-flush-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.FlushLogs | Unknown | Flush result. |

### pihole-flush-network

***
Flush the network table (remove all known devices and addresses).

#### Base Command

`pihole-flush-network`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.FlushNetwork | Unknown | Flush result. |

### pihole-get-network-devices

***
Get network devices known to PiHole.

#### Base Command

`pihole-get-network-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.NetworkDevices | Unknown | Network device information. |

### pihole-get-network-gateway

***
Get network gateway information.

#### Base Command

`pihole-get-network-gateway`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Gateway | Unknown | Gateway information. |

### pihole-search-domain

***
Search for a domain across all PiHole lists and configuration.

#### Base Command

`pihole-search-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to search for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Search | Unknown | Search results showing where the domain appears in PiHole configuration. |

### pihole-get-dhcp-leases

***
Get current DHCP leases.

#### Base Command

`pihole-get-dhcp-leases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.DHCPLeases | Unknown | DHCP lease information. |

### pihole-get-groups

***
Get all groups.

#### Base Command

`pihole-get-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Groups | Unknown | Group information. |

### pihole-add-group

***
Create a new group.

#### Base Command

`pihole-add-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Group name. | Required |
| comment | Optional comment. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Groups | Unknown | Created group details. |

### pihole-delete-group

***
Delete a group.

#### Base Command

`pihole-delete-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Group name to delete. | Required |

#### Context Output

There is no context output for this command.

### pihole-get-lists

***
Get all configured adlists.

#### Base Command

`pihole-get-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Lists | Unknown | Adlist information. |

### pihole-add-list

***
Add a new adlist.

#### Base Command

`pihole-add-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | URL of the adlist to add. | Required |
| comment | Optional comment. | Optional |
| enabled | Whether the list should be enabled. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHoleV6.Lists | Unknown | Added list details. |

### pihole-delete-list

***
Delete an adlist.

#### Base Command

`pihole-delete-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | URL of the adlist to delete. | Required |

#### Context Output

There is no context output for this command.

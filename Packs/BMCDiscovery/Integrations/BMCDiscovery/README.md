BMC Discovery is a SaaS-based, cloud-native discovery and dependency modeling system that provides instant visibility into hardware, software, and service dependencies across multi-cloud, hybrid, and on-premises environments.
This integration was integrated and tested with BMC Discovery v.22.1.

## Configure BMC Discovery Integration in Cortex


| **Parameter**                      | **Description**               | **Required** |
| ---------------------------------- | ----------------------------- | ------------ |
| Server URL                         | BMC Discovery URL             | True         |
| API Token                          | BMC Discovery user API token* | True         |
| Use system proxy settings          |                               | False        |
| Trust any certificate (not secure) |                               | False        |

* The BMC Discovery user must have the following permissions: **admin, api-access, discovery, system**


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### bmc-discovery-scan-status-list

Get status of all currently running scans (runs) or a specific scan (run)

Base Command

`bmc-discovery-scan-status-list`

#### Input

| **Argument Name** | **Description**             | **Required** |
| ----------------- | --------------------------- | ------------ |
| run_id            | ID of a specific scan (run) | Optional     |

#### Context Output

| **Path**                                                      | **Type** | **Description**                           |
|---------------------------------------------------------------|----------|-------------------------------------------|
| BmcDiscovery.Scan.Status.uuid                                 | String   | Scan UUID                                 |
| BmcDiscovery.Scan.Status.blocked                              | Boolean  | Is blocked                                |
| BmcDiscovery.Scan.Status.done                                 | Number   | Number of scanned hosts                   |
| BmcDiscovery.Scan.Status.total                                | Number   | Number of hosts to scan                   |
| BmcDiscovery.Scan.Status.finished                             | Boolean  | Is finished                               |
| BmcDiscovery.Scan.Status.label                                | String   | Scan name                                 |
| BmcDiscovery.Scan.Status.scan_kind                            | String   | IP/Cloud/API                              |
| BmcDiscovery.Scan.Status.scan_level                           | String   | Full discovery/Sweep scan                 |
| BmcDiscovery.Scan.Status.scan_type                            | String   | Snapshot/scheduled                        |
| BmcDiscovery.Scan.Status.user                                 | String   | Initiating user                           |
| BmcDiscovery.Scan.Status.valid_ranges                         | String   | IP ranges to scan                         |
| BmcDiscovery.Scan.Status.cancelled                            | String   | Is canceled                               |
| BmcDiscovery.Scan.Status.key                                  | String   | Scan key                                  |
| BmcDiscovery.Scan.Status.outpost_id                           | String   | Outpost id                                |
| BmcDiscovery.Scan.Status.scope                                | String   | Scan scope                                |
| BmcDiscovery.Scan.Status.scan_params.provider                 | String   | Scan provider                             |
| BmcDiscovery.Scan.Status.scan_options.NO_PING                 | Boolean  | Is NO-PING option set                     |
| BmcDiscovery.Scan.Status.scan_options.SESSION_LOGGING         | Boolean  | Is SESSION_LOGGING option set             |
| BmcDiscovery.Scan.Status.scan_options.SKIP_IMPLICIT_SCANS     | Boolean  | Is SKIP_IMPLICIT_SCANS option set         |
| BmcDiscovery.Scan.Status.scan_options.MAX_START_SSM_SESSIONS  | Boolean  | Is MAX_START_SSM_SESSIONS option set      |
| BmcDiscovery.Scan.Status.scan_options.MAX_ACTIVE_SSM_SESSIONS | Boolean  | Is MAX_ACTIVE_SSM_SESSIONS option set     |
| BmcDiscovery.Scan.Status.scanning                             | Number   | Number of entities in scanning status     |
| BmcDiscovery.Scan.Status.pre_scanning                         | Number   | Number of entities in pre_scanning status |
| BmcDiscovery.Scan.Status.starttime                            | Date     | Scan start time                           |
| BmcDiscovery.Scan.Status.waiting                              | Number   | Number of entities in waiting status      |
| BmcDiscovery.Scan.Status.uri                                  | String   | Scan URI                                  |
| BmcDiscovery.Scan.Status.inferred                             | String   | Scan inferred URI                         |
| BmcDiscovery.Scan.Status.results                              | String   | Scan results URI                          |
| BmcDiscovery.Scan.Status.consolidating                        | Boolean  | Is consolidating                          |
| BmcDiscovery.Scan.Status.consolidation_source                 | String   | Consolidation source                      |

***
#### bmc-discovery-scan-create

Create a new snapshot scan (run)

Base Command

`bmc-discovery-scan-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| label             | Scan (run) name | Yes          |
| ranges            | IP range        | Yes          |

**Note**: The following run parameters are predefined: 
- Kind = IP
- Level = Full Discovery
- Type = Snapshot

#### Context Output

| **Path**                      | **Type** | **Description** |
|-------------------------------|----------|-----------------|
| BmcDiscovery.Scan.Create.url  | String   | New scan URI    |
| BmcDiscovery.Scan.Create.uuid | String   | New scan UUID   |

***
#### bmc-discovery-scan-summary

Retrieve scan (run) results summary

Base Command

`bmc-discovery-scan-summary`

#### Input

| **Argument Name** | **Description**   | **Required** |
| ----------------- | ----------------- | ------------ |
| run_id            | An ID of the scan | Yes          |

**Note**: The following run parameters are predefined: 
- Kind = IP
- Level = Full Discovery
- Type = Snapshot

#### Context Output

| **Path**                             | **Type** | **Description**                         |
|--------------------------------------|----------|-----------------------------------------|
| BmcDiscovery.Scan.Summary.Success    | Number   | Number of successfully scanned entities |
| BmcDiscovery.Scan.Summary.Skipped    | Number   | Number of skipped entities              |
| BmcDiscovery.Scan.Summary.NoAccess   | Number   | Number of entities with no access       |
| BmcDiscovery.Scan.Summary.NoResponse | Number   | Number of entities with no response     |
| BmcDiscovery.Scan.Summary.Error      | Number   | Number of entities in error             |
| BmcDiscovery.Scan.Summary.Dropped    | Number   | Number of dropped entities              |

***
#### bmc-discovery-scan-stop

Cancel a currently running scan

Base Command

`bmc-discovery-scan-stop`

#### Input

| **Argument Name** | **Description**   | **Required** |
| ----------------- | ----------------- | ------------ |
| run_id            | An ID of the scan | Yes          |

**Note**: The following run parameters are predefined: 
- Kind = IP
- Level = Full Discovery
- Type = Snapshot

#### Context Output

| **Path**                            | **Type** | **Description**    |
|-------------------------------------|----------|--------------------|
| BmcDiscovery.Scan.Stop.cancelled    | Boolean  | Scan cancel status |

***
#### bmc-discovery-scan-results-list

Get a list of hosts by specific result type

Base Command

`bmc-discovery-scan-results-list`

#### Input

| **Argument Name** | **Description**                                                             | **Required** |
|-------------------|-----------------------------------------------------------------------------|--------------|
| run_id            |                                                                             | Yes          |
| result_type       | "Available options: Success, Skipped, NoAccess, NoResponse, Error, Dropped" | Yes          |
| offset            | Search results offset                                                       | Optional     |
| limit             | Search results limit                                                        | Optional     |
| results_id        | Search results id                                                           | Optional     |

#### Context Output

| **Path**                             | **Type** | **Description**                    |
|--------------------------------------|----------|------------------------------------|
| BmcDiscovery.Scan.Result.count       | Number   | Number of hosts of the result type |
| BmcDiscovery.Scan.Result.kind        | String   | Result kind type                   |
| BmcDiscovery.Scan.Result.next_offset | Number   | Next offset to be used             |
| BmcDiscovery.Scan.Result.offset      | Number   | Current offset value               |
| BmcDiscovery.Scan.Result.results_id  | String   | Current result id                  |
| BmcDiscovery.Scan.Result.results     | Unknown  | The actual scan result data        |

***
#### bmc-discovery-search

Search for a node by IP address or hostname

Base Command

`bmc-discovery-search`

#### Input

| **Argument name** | **Description**                                      | **Required**  |
|-------------------|------------------------------------------------------|---------------|
| ip                | IP address                                           | Optional      | 
| hostname          | Hostname                                             | Optional      |
| kind              | "Node kind (Host, NetWorkDevice, SNMPManagedDevice)" | Single Select |
| name              | Search name                                          | Optional      |

#### Context Output

| **Path**                  | **Type** | **Description**            |
|---------------------------|----------|----------------------------|
| BmcDiscovery.Search.count | Number   | Number of returned results |
| BmcDiscovery.Search.data  | Unknown  | Search results             |
| BmcDiscovery.Search.name  | String   | Name of the search         |

***
#### bmc-discovery-search-custom

Run a user defined query

Base Command

`bmc-discovery-search-custom`

#### Input

| **Argument name** | **Description**       | **Required**  |
|-------------------|-----------------------|---------------|
| query             | Full search query*    | Yes           | 
| offset            | Search results offset | Optional      |
| limit             | Search resuluts limit | Optional      |
| results_id        | Search results id     | Optional      |

*See the [documentation for reference](https://docs.bmc.com/docs/discovery/113/using-the-query-language-788111625.html)

#### Context Output

| **Path**                  | **Type** | **Description**            |
|---------------------------|----------|----------------------------|
| BmcDiscovery.Search.count | Number   | Number of returned results |
| BmcDiscovery.Search.data  | Unknown  | Search results             |
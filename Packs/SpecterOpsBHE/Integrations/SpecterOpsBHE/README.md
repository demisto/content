This integration enables automated retrieval of attack path findings from BloodHound into Cortex XSOAR, streamlining incident creation and investigation.
This integration was integrated and tested with version xx of SpecterOpsBHE.

## Configure SpecterOpsBHE in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| BloodHound Enterprise Domain | BloodHound Enterprise Domain URL | True |
| Token ID | BloodHound Enterprise API token ID | True |
| Token Key | BloodHound Enterprise API token key | True |
| Password |  | True |
| Proxy URL |  | False |
| Proxy URL Username |  | False |
| Proxy URL Password |  | False |
| Password |  | False |
| Finding Environment | The environment from which to fetch attack paths. Default is all. | False |
| Finding Category | The category of attack paths to fetch. Default is all. | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval | The interval for fetching attack paths | False |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bhe-object-id-get

***
Fetches the object ID using the object name.

#### Base Command

`bhe-object-id-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_names | The object name associated with object ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpecterOpsBHE.Object.Status | string | The status of the object ID lookup \(success or error\). |
| SpecterOpsBHE.Object.Message | string | The message describing the result of the lookup. |
| SpecterOpsBHE.Object.ObjectID | string | The unique object ID of the found object. |
|  SpecterOpsBHE.Object.ObjectName | string | The name of the object that was searched. |

### bhe-asset-info-get

***
Fetches asset information using the object ID.

#### Base Command

`bhe-asset-info-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | The object ID to fetch asset information. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpecterOpsBHE.Asset.Status | string | The status of the asset information fetch \(success or error\). |
| SpecterOpsBHE.Asset.Message | string | The message describing the result of the asset information fetch. |
| SpecterOpsBHE.Asset.ObjectID | string | The object ID for which asset information was fetched. |
| SpecterOpsBHE.Asset.Data | unknown | The raw asset data containing all asset information fields \(name, type, objectid, domain, enabled, email, and other properties\). |

### bhe-path-exist

***
Checks if a path exists between the two nodes.

#### Base Command

`bhe-path-exist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_principal | The start node. | Optional |
| to_principal | The end node. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpecterOpsBHE.Path.FromPrincipal | String | The start node \(from principal\) used in the path check. |
| SpecterOpsBHE.Path.ToPrincipal | String | The end node \(to principal\) used in the path check. |
| SpecterOpsBHE.Path.Status | String | The status of the path check \(success or error\). |
| SpecterOpsBHE.Path.Message | String | The message describing the result of the path check. |
| SpecterOpsBHE.Path.Data | Boolean | Whether a path exists between the nodes \(True or False\). |

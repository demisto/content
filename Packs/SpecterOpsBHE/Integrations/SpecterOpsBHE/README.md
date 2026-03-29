This integration enables automated retrieval of attack path findings from BloodHound into Cortex XSOAR, streamlining incident creation and investigation.
This integration was integrated and tested with version 1.0.0 of SpecterOpsBHE.

## Configure SpecterOpsBHE in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| BloodHound Enterprise Domain | BloodHound Enterprise Domain URL | True |
| Token ID | BloodHound Enterprise API token ID | True |
| Token Key | BloodHound Enterprise API token key | True |
| Proxy URL | Proxy server url  | False |
| Proxy URL Username | Proxy server url username | False |
| Proxy URL Password | Proxy server url password | False |
| Finding Environment | The environment from which to fetch attack paths. Default is all. | False |
| Finding Category | The category of attack paths to fetch. Default is all. | False |
| Fetch incidents | Enable automatic fetching of attack path findings from BloodHound Enterprise. | False |
| Incidents Fetch Interval | The interval for fetching attack paths | False |
| Incident type | The incident type to assign to fetched attack path findings. Recommended: SpecterOpsBHE Attack Path. | False |

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

#### Command Example

!bhe-object-id-get object_names="OBJECTNAME@example.com"

#### Human Readable Output

| **Object Name** | **Status** | **Message** | **Object ID** |
| --- | --- | --- | --- |
| OBJECTNAME@example.com | success | Object ID found. | 12345678-1234-1234-1234-123456789abc |

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
| SpecterOpsBHE.Asset.Data | json | The raw asset data containing all asset information fields \(name, type, objectid, domain, enabled, email, and other properties\). |

#### Command Example

!bhe-asset-info-get object_ids="12345678-1234-1234-1234-123456789abc,87654321-4321-4321-4321-cba987654321"

#### Human Readable Output

| **Object ID** | **Status** | **Message** | **Raw Data** |
| --- | --- | --- | --- |
| 12345678-1234-1234-1234-123456789abc | success | Asset information retrieved successfully. | \{<br>&emsp;"name": "OBJECTNAME@example.com",<br>&emsp;"type": "User",<br>&emsp;"objectid": "12345678-1234-1234-1234-123456789abc",<br>&emsp;"domain": "example.com",<br>&emsp;"enabled": true<br>\} |

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
| SpecterOpsBHE.Path.FromPrincipal | string | The start node \(from principal\) used in the path check. |
| SpecterOpsBHE.Path.ToPrincipal | string | The end node \(to principal\) used in the path check. |
| SpecterOpsBHE.Path.Status | string | The status of the path check \(success or error\). |
| SpecterOpsBHE.Path.Message | string | The message describing the result of the path check. |
| SpecterOpsBHE.Path.Data | Boolean | Whether a path exists between the nodes \(True or False\). |

#### Command Example

!bhe-path-exist from_principal="12345678-1234-1234-1234-123456789abc" to_principal="87654321-4321-4321-4321-cba987654321"

#### Human Readable Output

| **From Principal** | **To Principal** | **Status** | **Message** | **Path Exists** |
| --- | --- | --- | --- | --- |
| 12345678-1234-1234-1234-123456789abc | 87654321-4321-4321-4321-cba987654321 | success | Path exists between nodes. | True |

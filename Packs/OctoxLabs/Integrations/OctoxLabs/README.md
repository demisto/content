Octox Labs Cyber Security Asset Management platform
This integration was integrated and tested with version 3.3.0 of OctoxLabs

## Configure OctoxLabs on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OctoxLabs.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | IP | Your Octox Labs Platform IP | True |
    | API Key | Your Octox Labs API Key. \(https://github.com/octoxlabs/py-octoxlabs\#getting-started\) | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### octoxlabs-get-adapters

***
Fetch octoxlabs all adapters

#### Base Command

`octoxlabs-get-adapters`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Adapters.count | Number | Adapters count |
| OctoxLabs.Adapters.results.id | Number | Adapter id |
| OctoxLabs.Adapters.results.name | String | Adapter name |
| OctoxLabs.Adapters.results.slug | String | Adapter slug |
| OctoxLabs.Adapters.results.description | String | Adapter description |
| OctoxLabs.Adapters.results.groups | Unknown | List&lt;string&gt; Adapter groups |
| OctoxLabs.Adapters.results.beta | Boolean | Adapter is beta? |
| OctoxLabs.Adapters.results.status | Number | Adapter status |
| OctoxLabs.Adapters.results.hr_status | String | Adapter human readable status |

### octoxlabs-get-connections

***
Fetch octoxlabs connections

#### Base Command

`octoxlabs-get-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Connections.count | Number | Connections count |
| OctoxLabs.Connections.results.id | Number | Connection id |
| OctoxLabs.Connections.results.adapter_id | Number | Connection adapter id |
| OctoxLabs.Connections.results.adapter_name | String | Connection adapter name |
| OctoxLabs.Connections.results.name | String | Connection name |
| OctoxLabs.Connections.results.status | Boolean | Connection status |
| OctoxLabs.Connections.results.description | String | Connection description |
| OctoxLabs.Connections.results.enabled | Boolean | Connection is enabled? |

### octoxlabs-get-discoveries

***
Fetch octoxlabs discoveries

#### Base Command

`octoxlabs-get-discoveries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Discoveries.count | Number | Total discovery count |
| OctoxLabs.Discoveries.results.id | Number | Discovery id |
| OctoxLabs.Discoveries.results.start_time | String | Discovery start time |
| OctoxLabs.Discoveries.results.end_time | String | Discovery end time |
| OctoxLabs.Discoveries.results.status | Number | Discovery status |
| OctoxLabs.Discoveries.results.hr_status | String | Discovery human readable status |
| OctoxLabs.Discoveries.results.progress | Number | Discovery progress |

### octoxlabs-get-last-discovery

***
Get last success discovery

#### Base Command

`octoxlabs-get-last-discovery`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Discovery.id | Number | Last discovery id |
| OctoxLabs.Discovery.start_time | String | Last discovery start time |
| OctoxLabs.Discovery.end_time | String | Last discovery end time |
| OctoxLabs.Discovery.status | Number | Last discovery status |
| OctoxLabs.Discovery.hr_status | String | Last discovery human readable status |
| OctoxLabs.Discovery.progress | Number | Last discovery progress |

### octoxlabs-search-devices

***
Search in your devices

#### Base Command

`octoxlabs-search-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional |
| fields | Fields. | Optional |
| page | Page. | Optional |
| size | Size. | Optional |
| discovery_id | Specific Discovery Id. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Devices.count | Number | Total devices count |
| OctoxLabs.Devices.results | Unknown | List&lt;Dict&gt; Device information |

### octoxlabs-get-device

***
Fetch your device

#### Base Command

`octoxlabs-get-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Your device hostname. | Required |
| discovery_id | Your device at specific discovery. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Device | Unknown | &lt;Dict&gt; Octoxlabs Device |

### octoxlabs-get-queries

***
Fetch your queries

#### Base Command

`octoxlabs-get-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Query list page. | Optional |
| search | Search text. | Optional |
| size | Query list size. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Queries.count | Number | Queries count |
| OctoxLabs.Queries.results.id | Number | Query id |
| OctoxLabs.Queries.results.name | String | Query name |
| OctoxLabs.Queries.results.text | String | Query text |
| OctoxLabs.Queries.results.tags | Unknown | List&lt;str&gt; Query tags |
| OctoxLabs.Queries.results.count | Number | Query device count |
| OctoxLabs.Queries.results.is_public | Boolean | Query is public? |
| OctoxLabs.Queries.results.created_at | String | Query created at |
| OctoxLabs.Queries.results.updated_at | String | Query updated at |
| OctoxLabs.Queries.results.username | String | Query creator |
| OctoxLabs.Queries.results.is_temporary | Boolean | Query is temporary |

### octoxlabs-get-query-by-id

***
Fetch your queries by id

#### Base Command

`octoxlabs-get-query-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | Query id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Queries.results.id | Number | Query id |
| OctoxLabs.Queries.results.name | String | Query name |
| OctoxLabs.Queries.results.text | String | Query text |
| OctoxLabs.Queries.results.tags | Unknown | List&lt;str&gt; Query tags |
| OctoxLabs.Queries.results.count | Number | Query device count |
| OctoxLabs.Queries.results.is_public | Boolean | Query is public? |
| OctoxLabs.Queries.results.created_at | String | Query created at |
| OctoxLabs.Queries.results.updated_at | String | Query updated at |
| OctoxLabs.Queries.results.username | String | Query creator |
| OctoxLabs.Queries.results.is_temporary | Boolean | Query is temporary |

### octoxlabs-get-query-by-name

***
Fetch your queries by id

#### Base Command

`octoxlabs-get-query-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_name | Query name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Queries.results.id | Number | Query id |
| OctoxLabs.Queries.results.name | String | Query name |
| OctoxLabs.Queries.results.text | String | Query text |
| OctoxLabs.Queries.results.tags | Unknown | List&lt;str&gt; Query tags |
| OctoxLabs.Queries.results.count | Number | Query device count |
| OctoxLabs.Queries.results.is_public | Boolean | Query is public? |
| OctoxLabs.Queries.results.created_at | String | Query created at |
| OctoxLabs.Queries.results.updated_at | String | Query updated at |
| OctoxLabs.Queries.results.username | String | Query creator |
| OctoxLabs.Queries.results.is_temporary | Boolean | Query is temporary |

## Overview
---
Use this integration to pull incidents and supporting information from your Coralogix account and tag interesting points in time from Cortex XSOAR.

## Use Cases
---
1. Configure your Coralogix account as a full fledged SIEM solution by using any of its available integrations and tools and streamline the process of security incident handling by using Cortex XSOAR's playbooks to automatically pull the incidents from Coralogix and handle them by any of the other Cortex XSOAR integrations.
2. Use supporting data from Coralogix while you prepare the security incident report directly from the war room in Cortex XSOAR.
3. Automatically tag the timestamps in Coralogix at which point a security incident was detected by any of the other Cortex XSOAR integrations.

## Configure Coralogix on Cortex XSOAR
---
1. Navigate to __Marketplace__.
2. Search for Coralogix.
3. Click on __Install__ on the top right corner and then on __Install__ at the bottom right corner.
4. Once it is installed, click on __Settings__ > __Integrations__ and then on __Add instance__ on the right-hand side and fill in the following parameters:

| **Parameter Name** | **Description** | **Required** | **Default Value** |
| --- | --- | --- | --- |
| Fetches incidents | Whether or not to fetch incidents via this integration | No | Do not fetch |
| Coralogix WebAPI Endpoint URL | The Coralogix WebAPI URL | **Yes** (Don't change it unless instructed to do so by Coralogix personnel) | `https://webapi.coralogix.com` |
| Private Key | Your Coralogix account private key | **Yes** | N/A |
| Application Name (for tags) | The Coralogix application name that will be assigned to the tags created by this instance | **Yes** | Cortex XSOAR |
| Subsystem Name (for tags) | The Coralogix subsystem name that will  be assigned to the tags created by this instance | **Yes** | Cortex XSOAR |
| Coralogix ES-API Endpoint URL | The Coralogix ES-API URL | **Yes** | `https://coralogix-esapi.coralogix.com:9443` |
| Basic incidents query | The Lucene query for fetching incidents. If not specified, will return Coralogix alerts that were sent to the Demisto webhook | No | N/A |
| Incidents Application Name | Limits the incidents query to only return incidents of a specific application name | No | N/A |
| Incidents Severity | Limits the incidents query to only return incidents of a specific severity | No | N/A |
| incidents Name Field | The Coralogix field value that should be used as the incident's name. If not specified, the integration will use the "alert_name" field | No | N/A |
| Incidents first fetch days | The number of days to look back for incidents | No | 3 |
| Maximum number of incidents to fetch at a single call | Maximum number of incidents to retrieve at each call to Coralogix | No | 50 |

## Commands
---
You can execute the following commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. `coralogix-search`
2. `coralogix-tag`

### 1. coralogix-search
---
Returns logs from your Coralogix account according to the specified Lucene query

##### Base Command

`coralogix-search`
##### Input

| **Argument Name** | **Description** | **Required** | **Default** |
| --- | --- | --- | --- |
| query | The Lucene query to run | **Yes** | N/A |
| app_name | A Coralogix application name to filter results by | No | `empty` |
| subsystem_name | A Coralogix subsystem name to filte results by | No | `empty` |
| severity | A Coralogix severity name to filter results by | No | `empty` |
| since_timestamp | The timestamp in the format of YYYY-MM-DD (e.g 1978-03-31T23:59:59) from which you would like to start the search | No | `empty` |
| to_timestamp | The timestamp in the format of YYYY-MM-DD (e.g 1978-03-31T23:59:59) that will be the upper boundary of the search timespan | No | 'now' | 
| max_items_to_retrieve | Maximum number of log entries to retrieve from Coralogix | No | 50 |

##### Command Examples
```!coralogix-search query="security.rcode_name:\"NXDOMAIN\"" using="Coralogix_instance_1"```  
```!coralogix-search query="security.rcode_name:\"NXDOMAIN\"" max_items_to_retrieve="100" since_timestamp="2020-12-31T23:59:59" using="Coralogix_instance_1"```

##### Output

| **coralogix.timestamp** | **coralogix.metadata.applicationName** | **coralogix.metadata.subsystemName** | **security.source_ip** | **security.destination_ip** | **security.event_type** | **security.source_port** | **security.destination_port** | **security.protocol** | **security.query** | **security.query_type_name** | ... |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2020-08-27T02:39:35.886Z | test-sta | test-sta | 172.31.7.153 | 172.31.0.2 | bro_dns | 33161 | 53 | udp | upload.wikimedia.org.ncsa.uiuc.edu | A | ... |
| 2020-08-27T02:52:35.699Z | test-sta | test-sta | 172.31.7.153 | 172.31.0.2 | bro_dns | 44618 | 53 | udp | www.googgle.com | AAAA | ... |


### 2. coralogix-tag
---
Allows you to tag an interesting point in time in Coralogix from Cortex XSOAR

##### Base Command

`coralogix-tag`
##### Input

| **Argument Name** | **Description** | **Required** | **Default** |
| --- | --- | --- | --- |
| name | The name of the tag that will be created in Coralogix | Yes | N/A |
| timestamp | The timestamp at which the tag will be created in Coralogix | No | Defaults to the current timestamp |
| icon_url | A URL to an icon file (JPG or PNG) that will be displayed as the tag at Coralogix. Can be up to 50KB in size | No | Defaults to a lightning icon | 

##### Command Example
```!coralogix-tag name="Data leak started"```

##### Output
```
Tag added successfully
```

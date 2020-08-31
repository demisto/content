## Overview
---
Use this integration to pull incidents and supporting information from your Coralogix account and tag interesting points in time from Cortex XSOAR.

## Use Cases
---
1. Configure your Coralogix account as a full fledged SIEM solution by using any of its available integrations and tools and streamline the process of security incidents handling by using Cortex XSOAR's playbooks to automatically pull the incidents from Coralogix and handle them by any of the other Cortex XSOAR integrations.
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
| Name | The name of the Coralogix integration instance (Can be any name you like) | **Yes** | N/A |
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


## Commands
---
You can execute the following commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. `clx_search`
2. `clx_tag`

### 1. clx_search
---
Returns logs from your Coralogix account by the specified Lucene query

##### Base Command

`clx_search`
##### Input

| **Argument Name** | **Description** | **Required** | **Default** |
| --- | --- | --- | --- |
| query | The Lucene query to run | **Yes** | N/A |
| app_name | A Coralogix application name to filter results by | No | `empty` |
| subsystem_name | A Coralogix subsystem name to filte results by | No | `empty` |
| severity | A Coralogix severity name to filter results by | No | `empty` |
| as_table | A true/false value indicating whether or not to return the search results as a table or as a JSON | No | false |
| exclude | A list of columns (comma separated) to exclude from the results table | No | `empty` | 

##### Command Example
```!cgx_search query="security.rcode_name:\"NXDOMAIN\"" exclude="security.message" as_table="true" using="Coralogix_instance_1"```

##### Context Example

| **@timestamp** | **@version** | **coralogix.branchId** | **coralogix.jsonUuid** | **coralogix.logId** | **coralogix.metadata.applicationName** | **coralogix.metadata.category** | **coralogix.metadata.className** | **coralogix.metadata.companyId** | **coralogix.metadata.computerName** | ... |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2020-08-27T02:39:35.886Z | 1 | 96225e09-a943-cf51-a6e1-4a4784052280 | 11993062-5fce-fbfd-b01a-7d93d3e14c65 | de998f70-0c34-48a8-90f9-f90cb36f30f0 | SchalotteTest | CORALOGIX |  | 6665 | ba3c90e19695 | ... |
| 2020-08-27T02:52:35.699Z | 1 | 96225e09-a943-cf51-a6e1-4a4784052280 | 11993062-5fce-fbfd-b01a-7d93d3e14c65 | 680fedc8-b24a-4a5d-a83a-87edd331c4b6 | SchalotteTest | CORALOGIX |  | 6665 | ba3c90e19695 | ... |


### 2. clx_tag
---
Allows you to tag an interesting point in time in Coralogix from Cortex XSOAR

##### Base Command

`clx_tag`
##### Input

| **Argument Name** | **Description** | **Required** | **Default** |
| --- | --- | --- | --- |
| name | The name of the tag that will be created in Coralogix | Yes | N/A |
| timestamp | The timestamp at which the tag will be created in Coralogix | No | Defaults to the current timestamp |
| icon_url | A URL to an icon file (JPG or PNG) that will be displayed as the tag at Coralogix. Can be up to 50KB in size | No | Defaults to a lightning icon | 

##### Command Example
```!clx_tag name="Data leak started"```

##### Output
```
{
    "application_name": "Demisto",
    "avatar": "/assets/deployment-icons/event.png",
    "company_id": 6665,
    "created_at": "2020-09-09T09:48:43.511Z",
    "id": 1206745,
    "subsystem_name": "Demisto",
    "tagTypeId": 4,
    "tag_status": "SUCCESSFUL",
    "tag_timestamp": 1599644923510,
    "tag_type": {
        "id": 4,
        "type": "CUSTOM_EVENT"
    },
    "tag_type_id": 4,
    "text_key": "Custom tag",
    "text_value": "Data leak started",
    "updated_at": "2020-09-09T09:48:43.511Z"
}
```

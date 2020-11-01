Fetch offenses as incidents and search QRadar.
This integration was integrated and tested with version 7.3.2 of QRadar.


## Configure QRadar v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QRadar v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. `https://8.8.8.8`) | True |
| credentials | Username / API Key \(see '?'\) | False |
| query | Query to fetch offenses | False |
| offenses_per_fetch | Number of offenses to pull per API call \(max 50\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| Long running instance | Fetches incidents | False |
| incidentType | Incident type | False |
| full_enrich | Full Incident Enrichment | False |
| longRunning | Long running instance | False |
| events_columns | Event columns to return from the events query | False |
| fetch_mode | Fetch mode | True |
| events_limit | Max number of events per incident | False |
| adv_params | Advanced Parameters | False |

4. Click **Test** to validate the URLs, token, and connection.

## Troubleshooting Performance Issues
In some cases, you might encounter performance issues when running QRadar AQL queries from Demisto. This issue is caused by QRadar API limitations. We recommend that you test the QRadar API performance by running several cURL scripts.
#### 1. Creating a search
Run the following command to use the QRadar API to create a new search.Save the QUERY ID that is attached to the response for the next step.
```
curl -H "SEC: <API KEY>" -X POST <QRADAR INSTANCE>/api/ariel/searches?query_expression=<QUERY IN URL SAFE ENCODING>
```
#### 2. Check if the search status is Complete or Executing
Use the following command to use the QRadar API to check the query status (EXECUTE, COMPLETED, or ERROR).
```
curl -H "SEC: <API KEY>" -X GET <QRADAR INSTANCE>/api/ariel/searches?<QUERY ID>
```

## Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key (see '?')` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.

## Fetch incidents
To start fetching incidents, enable the parameter `Long running instance` - this will start a long running process that'll fetch incidents periodically.
Depending on the system load, **the initial fetch might take a long time**.

#### Field (Schema) Mapping
The scheme is divided to 4 sections. Offense (root), Events: Builtins, Events: Custom Fields, and Assets.
For more details, see the [Classification & Mapping documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/incidents/classification-and-mapping/create-a-mapper.html).

#### Query to fetch offenses
You can apply additional (optional) filters for the fetch-incident query using the `Query to fetch offenses` integration parameter. For more information on how to use the filter syntax, see the [QRadar filter documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) and [QRadar offense documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.2/com.ibm.qradar.doc/11.0--siem-offenses-GET.html).
* Incident IP Enrichment - When enabled, fetched incidents IP values (local source addresses and local destination addresses) will be fetched from QRadar instead of their ID values.
* Incident Asset Enrichment - When enabled, fetched offenses will also contain correlated assets.

#### Reset the "last run" timestamp
To reset fetch incidents, run `qradar-reset-last-run` - this will reset the fetch to its initial state (will try to fetch first available offense).

## Required Permissions
* Assets - Vulnerability Management *or* Assets
* Domains - Admin
* Offenses (Manage Closing Reason) - Manage Offense Closing Reasons
* Offenses (Assign Offenses to Users) - Assign Offenses to Users
* Offenses (Read) - Offenses
* References (Create/Update) - admin
* References (Read) - View Reference Data

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qradar-offenses
***
Gets offenses from QRadar

#### Base Command

`qradar-offenses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Query to filter offenses. For reference please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-GET.html | Optional | 
| range | Range of results to return. e.g.: 0-20 | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.ID | number | The ID of the offense. | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The local destination addresses that are associated with the offense. If your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destination that are associated with the offesne. If this value is greater than 0 that means your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.OffenseType | string | The offense type \(due to API limitations if username and password were not provided, this value will be the id of offense type\) | 


#### Command Example
```!qradar-offenses range=0-1 filter="follow_up=false"```

#### Context Example
```
{
    "QRadar": {
        "Offense": [
            {
                "Description": "Outbound port scan\n",
                "DestinationAddress": [
                    "8.8.8.8,
                ],
                "EventCount": 22,
                "Followup": false,
                "ID": 477,
                "LastUpdatedTime": "2020-08-04T08:37:49.416000Z",
                "Magnitude": 2,
                "OffenseType": "Source IP",
                "RemoteDestinationCount": 4,
                "SourceAddress": [
                    "8.8.8.8
                ],
                "StartTime": "2020-08-04T08:34:21.690000Z"
            },
            {
                "Description": "Multiple Login Failures for the Same User\n preceded by DJM\n preceded by Port Scan detected\n containing Failure Audit: An account failed to log on\n",
                "DestinationAddress": [
                    "8.8.8.8
                ],
                "EventCount": 15,
                "Followup": false,
                "ID": 476,
                "LastUpdatedTime": "2020-08-04T08:37:57.209000Z",
                "Magnitude": 1,
                "OffenseType": "Username",
                "RemoteDestinationCount": 0,
                "SourceAddress": [
                    "8.8.8.8
                ],
                "StartTime": "2020-08-04T08:36:57.209000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### QRadar offenses
>|ID|Description|Followup|SourceAddress|DestinationAddress|RemoteDestinationCount|StartTime|EventCount|Magnitude|LastUpdatedTime|OffenseType|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 477 | Outbound port scan<br/> | false | 8.8.8.8| 8.8.8.8<br/>8.8.8.8<br/>8.8.8.8| 4 | 2020-08-04T08:34:21.690000Z | 22 | 2 | 2020-08-04T08:37:49.416000Z | Source IP |
>| 476 | Multiple Login Failures for the Same User<br/> preceded by DJM<br/> preceded by Port Scan detected<br/> containing Failure Audit: An account failed to log on<br/> | false | ::1,<br/>8.8.8.8| 8.8.8.8| 0 | 2020-08-04T08:36:57.209000Z | 15 | 1 | 2020-08-04T08:37:57.209000Z | Username |


### qradar-offense-by-id
***
Gets offense with matching offense ID from qradar


#### Base Command

`qradar-offense-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | Offense ID | Required | 
| filter | Query to filter offense. For refernce please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-GET.html | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Credibility | number | The credibility of the offense | 
| QRadar.Offense.Relevance | number | The relevance of the offense | 
| QRadar.Offense.Severity | number | The severity of the offense | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The local destination addresses that are associated with the offense. If your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destination that are associated with the offesne. If this value is greater than 0 that means your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type | 
| QRadar.Offense.Protected | boolean | Is the offense protected | 


#### Command Example
```!qradar-offense-by-id offense_id=450```

#### Context Example
```
{
    "QRadar": {
        "Offense": {
            "Categories": [
                "Firewall Session Closed",
                "Host Port Scan"
            ],
            "Credibility": 3,
            "Description": "Outbound port scan\n",
            "DestinationAddress": [
                "8.8.8.8
            ],
            "DestinationHostname": [
                "Net-10-172-192.Net_10_0_0_0"
            ],
            "EventCount": 5,
            "FlowCount": 0,
            "Followup": false,
            "ID": 450,
            "LastUpdatedTime": "2020-07-22T14:45:39.082000Z",
            "Magnitude": 2,
            "OffenseSource": "8.8.8.8,
            "OffenseType": "Source IP",
            "Protected": false,
            "Relevance": 0,
            "RemoteDestinationCount": 0,
            "Severity": 5,
            "SourceAddress": [
                "8.8.8.8
            ],
            "StartTime": "2020-07-22T14:40:43.870000Z",
            "Status": "OPEN"
        }
    }
}
```

#### Human Readable Output

>### QRadar Offenses
>|Categories|Credibility|Description|DestinationAddress|DestinationHostname|EventCount|FlowCount|Followup|ID|LastUpdatedTime|Magnitude|OffenseSource|OffenseType|Protected|Relevance|RemoteDestinationCount|Severity|SourceAddress|StartTime|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Firewall Session Closed,<br/>Host Port Scan | 3 | Outbound port scan<br/> | 8.8.8.8| Net-10-172-192.Net_10_0_0_0 | 5 | 0 | false | 450 | 2020-07-22T14:45:39.082000Z | 2 | 8.8.8.8| Source IP | false | 0 | 0 | 5 | 8.8.8.8| 2020-07-22T14:40:43.870000Z | OPEN |


### qradar-searches
***
Searches in QRadar using AQL. It is highly recommended to use the playbook 'QRadarFullSearch' instead of this command - it will execute the search, and will return the result.


#### Base Command

`qradar-searches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_expression | The query expressions in AQL (for more information about Ariel Query Language please review "https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.0/com.ibm.qradar.doc/c_aql_intro.html") | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.ID | number | Search ID | 
| QRadar.Search.Status | string | The status of the search. | 


#### Command Example
```!qradar-searches query_expression="SELECT sourceip AS 'MY Source IPs' FROM events"```

#### Context Example
```
{
    "QRadar": {
        "Search": {
            "ID": "ddd8ef78-4bff-4453-ab10-24f0fe1fa763",
            "Status": "WAIT"
        }
    }
}
```

#### Human Readable Output

>### QRadar Search
>|ID|Status|
>|---|---|
>| ddd8ef78-4bff-4453-ab10-24f0fe1fa763 | WAIT |


### qradar-get-search
***
Gets a specific search id and status


#### Base Command

`qradar-get-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The search id | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.ID | number | Search ID | 
| QRadar.Search.Status | string | The status of the search. | 


#### Command Example
```!qradar-get-search search_id=6212b614-074e-41c1-8fcf-1492834576b8```

#### Context Example
```
{
    "QRadar": {
        "Search": {
            "ID": "6212b614-074e-41c1-8fcf-1492834576b8",
            "Status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### QRadar Search Info
>|ID|Status|
>|---|---|
>| 6212b614-074e-41c1-8fcf-1492834576b8 | COMPLETED |


### qradar-get-search-results
***
Gets search results


#### Base Command

`qradar-get-search-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The search id | Required | 
| range | Range of results to return. e.g.: 0-20 | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 
| output_path | Replaces the default context output path for the query result (QRadar.Search.Result). e.g. for output_path=QRadar.Correlations the result will be under the key "QRadar.Correlations" in the context data. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Result | Unknown | The result of the search | 


#### Command Example
```!qradar-get-search-results search_id=6212b614-074e-41c1-8fcf-1492834576b8```

#### Context Example
```
{
    "QRadar": {
        "Search": {
            "Result": {
                "events": [
                    {
                        "MY Source IPs": "8.8.8.8
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### QRadar Search Results from events
>|MY Source IPs|
>|---|
>| 8.8.8.8|



### qradar-update-offense
***
Update an offense


#### Base Command

`qradar-update-offense`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to update | Required | 
| protected | Set to true to protect the offense | Optional | 
| follow_up | Set to true to set the follow up flag on the offense | Optional | 
| status | The new status for the offense | Optional | 
| closing_reason_id | The id of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default  closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation | Optional | 
| closing_reason_name | The name of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default  closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation | Optional | 
| assigned_to | A user to assign the offense to | Optional | 
| fields | Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. Please consult - https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-POST.html | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Credibility | number | The credibility of the offense | 
| QRadar.Offense.Relevance | number | The relevance of the offense | 
| QRadar.Offense.Severity | number | The severity of the offense | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The destination addresses that are associated with the offense. | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type | 
| QRadar.Offense.Protected | boolean | Is the offense protected | 


#### Command Example
```!qradar-update-offense offense_id=450 protected=false```

#### Context Example
```
{
    "QRadar": {
        "Offense": {
            "Categories": [
                "Firewall Session Closed",
                "Host Port Scan"
            ],
            "Credibility": 3,
            "Description": "Outbound port scan\n",
            "DestinationAddress": [
                "8.8.8.8
            ],
            "DestinationHostname": [
                "Net-10-172-192.Net_10_0_0_0"
            ],
            "EventCount": 5,
            "FlowCount": 0,
            "Followup": false,
            "ID": 450,
            "LastUpdatedTime": "2020-07-22T14:45:39.082000Z",
            "Magnitude": 2,
            "OffenseSource": "8.8.8.8,
            "OffenseType": "Source IP",
            "Protected": false,
            "Relevance": 0,
            "RemoteDestinationCount": 0,
            "Severity": 5,
            "SourceAddress": [
                "8.8.8.8
            ],
            "StartTime": "2020-07-22T14:40:43.870000Z",
            "Status": "OPEN"
        }
    }
}
```

#### Human Readable Output

>### QRadar Offense
>|Categories|Credibility|Description|DestinationAddress|DestinationHostname|EventCount|FlowCount|Followup|ID|LastUpdatedTime|Magnitude|OffenseSource|OffenseType|Protected|Relevance|RemoteDestinationCount|Severity|SourceAddress|StartTime|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Firewall Session Closed,<br/>Host Port Scan | 3 | Outbound port scan<br/> | 8.8.8.8| Net-10-172-192.Net_10_0_0_0 | 5 | 0 | false | 450 | 2020-07-22T14:45:39.082000Z | 2 | 8.8.8.8| Source IP | false | 0 | 0 | 5 | 8.8.8.8| 2020-07-22T14:40:43.870000Z | OPEN |


### qradar-get-assets
***
List all assets found in the model


#### Base Command

`qradar-get-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Query to filter assets. For refernce please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--asset_model-assets-GET.html | Optional | 
| range | Range of results to return. e.g.: 0-20 | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Assets.ID | number | The ID of the asset | 
| Endpoint.IPAddress | Unknown | IP address of the asset | 
| QRadar.Assets.Name.Value | string | Name of the asset | 
| Endpoint.OS | number | Asset OS | 
| QRadar.Assets.AggregatedCVSSScore.Value | number | CVSSScore | 
| QRadar.Assets.AggregatedCVSSScore.LastUser | string | Last user who updated the Aggregated CVSS Score | 
| QRadar.Assets.Weight.Value | number | Asset weight | 
| QRadar.Assets.Weight.LastUser | string | Last user who updated the weight | 
| QRadar.Assets.Name.LastUser | string | Last user who updated the name | 


#### Command Example
```!qradar-get-assets range=0-1```

#### Context Example
```
{
    "Endpoint": {
        "IPAddress": [
            "8.8.8.8,
            "8.8.8.8
        ]
    },
    "QRadar": {
        "Asset": [
            {
                "ID": 1914,
                "Name": {
                    "LastUser": "IDENTITY:0",
                    "Property Name": "Name",
                    "Value": "ec2-54-245-171-52.us-west-2.compute.amazonaws.com"
                }
            },
            {
                "ID": 1928,
                "Name": {
                    "LastUser": "IDENTITY:0",
                    "Property Name": "Name",
                    "Value": "ec2-44-234-115-112.us-west-2.compute.amazonaws.com"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### QRadar Assets
>### Asset(ID:1914)
>|LastUser|Property Name|Value|
>|---|---|---|
>| IDENTITY:0 | Name | ec2-54-245-171-52.us-west-2.compute.amazonaws.com |
>### Asset(ID:1928)
>|LastUser|Property Name|Value|
>|---|---|---|
>| IDENTITY:0 | Name | ec2-44-234-115-112.us-west-2.compute.amazonaws.com |
>### Endpoint
>|IPAddress|
>|---|
>| 8.8.8.8<br/>8.8.8.8|


### qradar-get-asset-by-id
***
Retrieves the asset by id


#### Base Command

`qradar-get-asset-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the requested asset. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Assets.ID | number | The ID of the asset. | 
| Endpoint.MACAddress | Unknown | Asset MAC address. | 
| Endpoint.IPAddress | Unknown | It's in ip_addresses - value | 
| QRadar.Assets.ComplianceNotes.Value | string | Compliance notes | 
| QRadar.Assets.CompliancePlan.Value | string | Compliance plan | 
| QRadar.Assets.CollateralDamagePotential.Value | Unknown | Collateral damage potential | 
| QRadar.Assets.AggregatedCVSSScore.Value | number | CVSSScore | 
| QRadar.Assets.Name.Value | string | Name of the asset | 
| QRadar.Assets.GroupName | string | Name of the asset's group | 
| Endpoint.Domain | Unknown | DNS name | 
| Endpoint.OS | Unknown | Asset OS | 
| QRadar.Assets.Weight.Value | number | Asset weight | 
| QRadar.Assets.Vulnerabilities.Value | Unknown | Vulnerabilities | 
| QRadar.Assets.Location | string | Location. | 
| QRadar.Assets.Description | string | The asset description. | 
| QRadar.Assets.SwitchID | number | Switch ID | 
| QRadar.Assets.SwitchPort | number | Switch port. | 
| QRadar.Assets.Name.LastUser | string | Last user who updated the name | 
| QRadar.Assets.AggregatedCVSSScore.LastUser | string | Last user who updated the Aggregated CVSS Score | 
| QRadar.Assets.Weight.LastUser | string | Last user who updated the weight | 
| QRadar.Assets.ComplianceNotes.LastUser | string | Last user who updated the compliance notes | 
| QRadar.Assets.CompliancePlan.LastUser | string | Last user who updated the compliance plan | 
| QRadar.Assets.CollateralDamagePotential.LastUser | string | Last user who updated the collateral damage potential | 
| QRadar.Assets.Vulnerabilities.LastUser | string | Last user who updated the vulnerabilities | 


#### Command Example
```!qradar-get-asset-by-id asset_id=1928```

#### Context Example
```
{
    "Endpoint": {
        "IPAddress": [
            "8.8.8.8
        ],
        "MACAddress": [
            "Unknown NIC"
        ]
    },
    "QRadar": {
        "Asset": {
            "ID": 1928,
            "Name": {
                "LastUser": "IDENTITY:0",
                "Property Name": "Name",
                "Value": "ec2-44-234-115-112.us-west-2.compute.amazonaws.com"
            }
        }
    }
}
```

#### Human Readable Output

>### QRadar Asset
>### Asset(ID:1928)
>|LastUser|Property Name|Value|
>|---|---|---|
>| IDENTITY:0 | Name | ec2-44-234-115-112.us-west-2.compute.amazonaws.com |
>### Endpoint
>|IPAddress|MACAddress|
>|---|---|
>| 8.8.8.8| Unknown NIC |


### qradar-get-closing-reasons
***
Get closing reasons


#### Base Command

`qradar-get-closing-reasons`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_reserved | If true, reserved closing reasons are included in the response | Optional | 
| include_deleted | If true, deleted closing reasons are included in the response | Optional | 
| filter | Query to filter results. For refernce please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offense_closing_reasons-GET.html | Optional | 
| range | Range of results to return. e.g.: 0-20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.ClosingReasons.ID | number | Closing reason ID | 
| QRadar.Offense.ClosingReasons.Name | string | Closing reason name | 


#### Command Example
```!qradar-get-closing-reasons include_reserved=false```

#### Context Example
```
{
    "QRadar": {
        "Offense": {
            "ClosingReasons": [
                {
                    "ID": 2,
                    "IsDeleted": false,
                    "IsReserved": false,
                    "Name": "False-Positive, Tuned"
                },
                {
                    "ID": 1,
                    "IsDeleted": false,
                    "IsReserved": false,
                    "Name": "Non-Issue"
                },
                {
                    "ID": 3,
                    "IsDeleted": false,
                    "IsReserved": false,
                    "Name": "Policy Violation"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Offense Closing Reasons
>|ID|Name|IsReserved|IsDeleted|
>|---|---|---|---|
>| 2 | False-Positive, Tuned | false | false |
>| 1 | Non-Issue | false | false |
>| 3 | Policy Violation | false | false |


### qradar-create-note
***
Create a note on an offense


#### Base Command

`qradar-create-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to add the note to | Required | 
| note_text | The note text | Required | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-POST.html | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.ID | number | Note ID | 
| QRadar.Note.Text | string | Note text | 
| QRadar.Note.CreateTime | date | The creation time of the note | 
| QRadar.Note.CreatedBy | string | The user who created the note | 


#### Command Example
```!qradar-create-note offense_id=450 note_text="XSOAR has the best documentation!"```

#### Context Example
```
{
    "QRadar": {
        "Note": {
            "CreateTime": "2020-09-02T08:12:47.314000Z",
            "CreatedBy": "API_user: admin",
            "ID": 1238,
            "Text": "XSOAR has the best documentation!"
        }
    }
}
```

#### Human Readable Output

>### QRadar Note
>|CreateTime|CreatedBy|ID|Text|
>|---|---|---|---|
>| 2020-09-02T08:12:47.314000Z | API_user: admin | 1238 | XSOAR has the best documentation! |


### qradar-get-note
***
Retrieve a note for an offense


#### Base Command

`qradar-get-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve the note from | Required | 
| note_id | The note ID | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.ID | number | Note ID | 
| QRadar.Note.Text | string | Note text | 
| QRadar.Note.CreateTime | date | The creation time of the note | 
| QRadar.Note.CreatedBy | string | The user who created the note | 


#### Command Example
```!qradar-get-note offense_id=450 note_id=1232```

#### Context Example
```
{
    "QRadar": {
        "Note": {
            "CreateTime": "2020-09-02T06:39:24.601000Z",
            "CreatedBy": "API_user: admin",
            "ID": 1232,
            "Text": "XSOAR has the best documentation!"
        }
    }
}
```

#### Human Readable Output

>### QRadar note for offense: 450
>|CreateTime|CreatedBy|ID|Text|
>|---|---|---|---|
>| 2020-09-02T06:39:24.601000Z | API_user: admin | 1232 | XSOAR has the best documentation! |


### qradar-get-reference-by-name
***
Information about the reference set that had data added or updated. This returns information set but not the contained data. This feature is supported from version 8.1 and upward.


#### Base Command

`qradar-get-reference-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the requestered reference. | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers) | Optional | 
| date_value | If set to true will try to convert the data values to ISO-8601 string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeToLive | string | Reference time to live. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 
| QRadar.Reference.Data | Unknown | Reference set items | 


#### Command Example
```!qradar-get-reference-by-name ref_name=Date date_value=True```

#### Context Example
```
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2020-09-02T08:12:49.020000Z",
            "ElementType": "DATE",
            "Name": "Date",
            "NumberOfElements": 0,
            "TimeoutType": "UNKNOWN"
        }
    }
}
```

#### Human Readable Output

>### QRadar References
>|CreationTime|ElementType|Name|NumberOfElements|TimeoutType|
>|---|---|---|---|---|
>| 2020-09-02T08:12:49.020000Z | DATE | Date | 0 | UNKNOWN |


### qradar-create-reference-set
***
Creates a new reference set. If the provided name is already in use, this command will fail


#### Base Command

`qradar-create-reference-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | Reference name to be created | Required | 
| element_type | The element type for the values allowed in the reference set. The allowed values are: ALN (alphanumeric), ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric), PORT (port number) or DATE. Note that date values need to be represented in milliseconds since the Unix Epoch January 1st 1970. | Required | 
| timeout_type | The allowed values are "FIRST_SEEN", LAST_SEEN and UNKNOWN. The default value is UNKNOWN. | Optional | 
| time_to_live | The time to live interval, for example: "1 month" or "5 minutes" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.CreationTime | date | Creation time of the reference set. | 
| QRadar.Reference.ElementType | string | The element type for the values allowed in the reference set. The allowed values are: ALN \(alphanumeric\), ALNIC \(alphanumeric ignore case\), IP \(IP address\), NUM \(numeric\), PORT \(port number\) or DATE. | 
| QRadar.Reference.Name | string | Name of the reference set. | 
| QRadar.Reference.NumberOfElements | number | Number of elements in the created reference set. | 
| QRadar.Reference.TimeoutType | string | Timeout type of the reference. The allowed values are FIRST_SEEN, LAST_SEEN and UNKNOWN. | 


#### Command Example
```!qradar-create-reference-set ref_name=Date element_type=DATE```

#### Context Example
```
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2020-09-02T08:12:49.020000Z",
            "ElementType": "DATE",
            "Name": "Date",
            "NumberOfElements": 0,
            "TimeoutType": "UNKNOWN"
        }
    }
}
```

#### Human Readable Output

>### QRadar References
>|CreationTime|ElementType|Name|NumberOfElements|TimeoutType|
>|---|---|---|---|---|
>| 2020-09-02T08:12:49.020000Z | DATE | Date | 0 | UNKNOWN |


### qradar-delete-reference-set
***
Deletes a reference set corresponding to the name provided.


#### Base Command

`qradar-delete-reference-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of reference set to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!qradar-delete-reference-set ref_name=Date```

#### Context Example
```
{}
```

#### Human Readable Output

>Reference Data Deletion Task for 'Date' was initiated. Reference set 'Date' should be deleted shortly.

### qradar-create-reference-set-value
***
Add or update a value in a reference set.


#### Base Command

`qradar-create-reference-set-value`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. | Required | 
| value | The value/s to add or update in the reference set. Note: Date values must be represented in epoch in reference sets (milliseconds since the Unix Epoch January 1st 1970). If 'date_value' is set to 'True', then the argument will be converted from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. | Required | 
| source | An indication of where the data originated. The default value is 'reference data api'. | Optional | 
| date_value | If set to True will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 


#### Command Example
```!qradar-create-reference-set-value ref_name=Date value=2018-11-27T11:34:23.110000Z date_value=True```

#### Context Example
```
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2020-09-02T08:12:49.020000Z",
            "ElementType": "DATE",
            "Name": "Date",
            "NumberOfElements": 1,
            "TimeoutType": "UNKNOWN"
        }
    }
}
```

#### Human Readable Output

>### Element value was updated successfully in reference set:
>|CreationTime|ElementType|Name|NumberOfElements|TimeoutType|
>|---|---|---|---|---|
>| 2020-09-02T08:12:49.020000Z | DATE | Date | 1 | UNKNOWN |


### qradar-update-reference-set-value
***
Adds or updates a value in a reference set.


#### Base Command

`qradar-update-reference-set-value`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. | Required | 
| value |  A comma-separated list of values to add or update in the reference set. Date values must be represented in milliseconds since the Unix Epoch January 1st 1970. | Required | 
| source | An indication of where the data originated. The default value is 'reference data api'. | Optional | 
| date_value | If set to True will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 


#### Command Example
```!qradar-update-reference-set-value ref_name="Documentation Reference" value="Important information" source="Documentation"```

#### Context Example
```
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2020-09-02T06:45:52.294000Z",
            "ElementType": "ALNIC",
            "Name": "Documentation Reference",
            "NumberOfElements": 1,
            "TimeoutType": "UNKNOWN"
        }
    }
}
```

#### Human Readable Output

>### Element value was updated successfully in reference set:
>|CreationTime|ElementType|Name|NumberOfElements|TimeoutType|
>|---|---|---|---|---|
>| 2020-09-02T06:45:52.294000Z | ALNIC | Documentation Reference | 1 | UNKNOWN |


### qradar-delete-reference-set-value
***
Deletes a value in a reference set.


#### Base Command

`qradar-delete-reference-set-value`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to remove a value from. | Required | 
| value | The value to remove from the reference set. | Required | 
| date_value | If set to True will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 


#### Command Example
```!qradar-delete-reference-set-value ref_name=Date value=1543318463000```

#### Context Example
```
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2020-09-02T08:12:49.020000Z",
            "ElementType": "DATE",
            "Name": "Date",
            "NumberOfElements": 0,
            "TimeoutType": "UNKNOWN"
        }
    }
}
```

#### Human Readable Output

>### Element value was deleted successfully in reference set:
>|CreationTime|ElementType|Name|NumberOfElements|TimeoutType|
>|---|---|---|---|---|
>| 2020-09-02T08:12:49.020000Z | DATE | Date | 0 | UNKNOWN |


### qradar-get-domains
***
Retrieve all Domains


#### Base Command

`qradar-get-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html | Optional | 
| range | Number of results in return | Optional | 
| filter | Query to filter offenses | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Domains.AssetScannerIDs | Number | Array of Asset Scanner IDs. | 
| QRadar.Domains.CustomProperties | String | Custom properties of the domain. | 
| QRadar.Domains.Deleted | Boolean | Indicates if the domain is deleted. | 
| QRadar.Domains.Description | String | Description of the domain. | 
| QRadar.Domains.EventCollectorIDs | Number | Array of Event Collector IDs. | 
| QRadar.Domains.FlowCollectorIDs | Number | Array of Flow Collector IDs. | 
| QRadar.Domains.FlowSourceIDs | Number | Array of Flow Source IDs. | 
| QRadar.Domains.ID | Number | ID of the domain. | 
| QRadar.Domains.LogSourceGroupIDs | Number | Array of Log Source Group IDs. | 
| QRadar.Domains.LogSourceIDs | Number | Array of Log Source IDs. | 
| QRadar.Domains.Name | String | Name of the Domain. | 
| QRadar.Domains.QVMScannerIDs | Number | Array of QVM Scanner IDs. | 
| QRadar.Domains.TenantID | Number | ID of the Domain tenant. | 


#### Command Example
```!qradar-get-domains```

#### Context Example
```
{
    "QRadar": {
        "Domains": [
            {
                "Deleted": false,
                "ID": 0,
                "TenantID": 0
            },
            {
                "Deleted": true,
                "ID": 1,
                "Name": "QRadarWhiteListIP",
                "TenantID": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Domains Found
>|AssetScannerIDs|CustomProperties|Deleted|Description|EventCollectorIDs|FlowCollectorIDs|FlowSourceIDs|ID|LogSourceGroupIDs|LogSourceIDs|Name|QVMScannerIDs|TenantID|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | false |  |  |  |  | 0 |  |  |  |  | 0 |
>|  |  | true |  |  |  |  | 1 |  |  | QRadarWhiteListIP |  | 0 |


### qradar-get-domain-by-id
***
Retrieves Domain information By ID


#### Base Command

`qradar-get-domain-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the domain | Required | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Domains.AssetScannerIDs | Number | Array of Asset Scanner IDs. | 
| QRadar.Domains.CustomProperties | String | Custom properties of the domain. | 
| QRadar.Domains.Deleted | Boolean | Indicates if the domain is deleted. | 
| QRadar.Domains.Description | String | Description of the domain. | 
| QRadar.Domains.EventCollectorIDs | Number | Array of Event Collector IDs. | 
| QRadar.Domains.FlowCollectorIDs | Number | Array of Flow Collector IDs. | 
| QRadar.Domains.FlowSourceIDs | Number | Array of Flow Source IDs. | 
| QRadar.Domains.ID | Number | ID of the domain. | 
| QRadar.Domains.LogSourceGroupIDs | Number | Array of Log Source Group IDs. | 
| QRadar.Domains.LogSourceIDs | Number | Array of Log Source IDs. | 
| QRadar.Domains.Name | String | Name of the Domain. | 
| QRadar.Domains.QVMScannerIDs | Number | Array of QVM Scanner IDs. | 
| QRadar.Domains.TenantID | Number | ID of the Domain tenant. | 


#### Command Example
```!qradar-get-domain-by-id id=0```

#### Context Example
```
{
    "QRadar": {
        "Domains": {
            "Deleted": false,
            "ID": 0,
            "TenantID": 0
        }
    }
}
```

#### Human Readable Output

>### Domains Found
>|Deleted|ID|TenantID|
>|---|---|---|
>| false | 0 | 0 |


### qradar-upload-indicators
***
Uploads indicators from Demisto to Qradar.


#### Base Command

`qradar-upload-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. To create a new reference set, you need to set the element type. | Required | 
| element_type | The element type for the values premitted in the reference set. Only required when creating a new reference set. The valid values are: ALN (alphanumeric), ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric), PORT (port number) or DATE. Note that date values need to be represented in milliseconds since the Unix Epoch January 1st 1970. | Optional | 
| timeout_type | The timeout_type can be "FIRST_SEEN", "LAST_SEEN", or "UNKNOWN". The default value is UNKNOWN. Only required for creating a new refernce set. | Optional | 
| time_to_live | The time to live interval, for example: "1 month" or "5 minutes". Only required when creating a new reference set. | Optional | 
| query | The query for getting indicators. | Required | 
| limit | The maximum number of indicators to return. The default value is 1000. | Optional | 
| page | The page from which to get the indicators | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!qradar-upload-indicators query=type:IP ref_name="XSOAR IP Indicators"```

#### Context Example
```
{}
```

#### Human Readable Output

>### reference set XSOAR IP Indicators was updated
>|Name|ElementType|TimeoutType|CreationTime|NumberOfElements|
>|---|---|---|---|---|
>| XSOAR IP Indicators | ALNIC | UNKNOWN | 2020-09-02T06:59:41.266000Z | 276 |
>### Indicators list
>|Value|Type|
>|---|---|
>| 8.8.8.8| IP |

### qradar-reset-last-run
***
Reset fetch incidents last run value, which resets the fetch to its initial fetch state (will try to fetch first available offense).


#### Base Command

`qradar-reset-last-run`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!qradar-reset-last-run```

#### Context Example
```
{}
```

#### Human Readable Output

>fetch-incidents was reset successfully.

### get-mapping-fields
***
Returns the list of fields for an incident type. This command is for debugging purposes.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### qradar-get-custom-properties
***
Retrieves a list of event regex properties.


#### Base Command

`qradar-get-custom-properties`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of regex event properties to fetch. Default is 25. | Optional | 
| field_name | A comma-separated list of names of exact properties to search for. | Optional | 
| fields | A comma-separated list of fields that specifies the fields returned by the command output. When not given, will return all. Options are identifier, name, id, locale, datetime_format, description, username, property_type, auto_discovered, use_for_rule_engine. | Optional | 
| like_name | A comma-separated names of a  properties to search for. Case insensitive. | Optional | 
| filter | This parameter is used to restrict the elements in a list base on the contents of various fields. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Properties.auto_discovered | Number | The flag to indicate if the event regex property is generated by custom properties discovery engine. | 
| QRadar.Properties.creation_date | Date | The date when the event regex property was created. | 
| QRadar.Properties.datetime_format | String | The date/time pattern that the event regex property matches. | 
| QRadar.Properties.description | String | The description of the event regex property. | 
| QRadar.Properties.id | Number | The sequence ID of the event regex property. | 
| QRadar.Properties.identifier | String | The ID of the event regex property. | 
| QRadar.Properties.locale | String | The language tag of the locale that the Property matches. | 
| QRadar.Properties.modification_date | Date | The date when the event regex property was last modified. | 
| QRadar.Properties.name | String | The name of the event regex property. | 
| QRadar.Properties.property_type | String | The property type \(STRING, NUMERIC, IP, PORT, TIME\) of event regex property. | 
| QRadar.Properties.use_for_rule_engine | Number | The flag to indicate if the event regex property is parsed when the event is received. | 
| QRadar.Properties.username | String | The owner of the event regex property. | 


#### Command Example
```!qradar-get-custom-properties field_name="AVT-App-Name" like_name="rule" limit=2```

#### Context Example
```
{
    "QRadar": {
        "Properties": [
            {
                "auto_discovered": false,
                "creation_date": "2012-07-04 17:05:02",
                "datetime_format": null,
                "description": "",
                "id": 213,
                "identifier": "DEFAULT_ACF2_RULE_KEY",
                "locale": null,
                "modification_date": "2012-07-04 17:05:02",
                "name": "ACF2 rule key",
                "property_type": "string",
                "use_for_rule_engine": true,
                "username": "admin"
            },
            {
                "auto_discovered": false,
                "creation_date": "2012-07-04 17:05:02",
                "datetime_format": null,
                "description": "Rule name why Parity Agent blocked an access to a file.",
                "id": 222,
                "identifier": "DEFAULT_RULE_NAME",
                "locale": null,
                "modification_date": "2012-07-04 17:05:02",
                "name": "Rule Name",
                "property_type": "string",
                "use_for_rule_engine": true,
                "username": "admin"
            }
        ]
    }
}
```

#### Human Readable Output

>### QRadar: Custom Properties:
>|auto_discovered|creation_date|description|id|identifier|modification_date|name|property_type|use_for_rule_engine|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | 2012-07-04 17:05:02 |  | 213 | DEFAULT_ACF2_RULE_KEY | 2012-07-04 17:05:02 | ACF2 rule key | string | true | admin |
>| false | 2012-07-04 17:05:02 | Rule name why Parity Agent blocked an access to a file. | 222 | DEFAULT_RULE_NAME | 2012-07-04 17:05:02 | Rule Name | string | true | admin |


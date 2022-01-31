IBM QRadar SIEM helps security teams accurately detect and prioritize threats across the enterprise, supports API versions 10.1 and above. Provides intelligent insights that enable teams to respond quickly to reduce the impact of incidents.
This integration was integrated and tested with API versions 10.1-14.0 on QRadar platform 7.4.1.
## Configure QRadar v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QRadar v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | \(e.g., https://192.168.0.1\) | True |
    | Username |  | True |
    | QRadar API Version | API version of QRadar \(e.g., '12.0'\). Minimum API version is 10.1. | True |
    | Incident Type |  | False |
    | Fetch mode |  | True |
    | Number of offenses to pull per API call (max 50) |  | False |
    | Query to fetch offenses | Define a query to determine which offenses to fetch. E.g., "severity &amp;gt;= 4 AND id &amp;gt; 5 AND status=OPEN". | False |
    | Incidents Enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. | True |
    | Event fields to return from the events query (WARNING: This parameter is correlated to the incoming mapper and changing the values may adversely affect mapping). | The parameter uses the AQL SELECT syntax. For more information, see: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.4/com.ibm.qradar.doc/c_aql_intro.html | False |
    | Mirroring Options | How mirroring from QRadar to Cortex XSOAR should be done. | False |
    | Close Mirrored XSOAR Incident | When selected, closing the QRadar offense is mirrored in Cortex XSOAR. | False |
    | The number of incoming incidents to mirror each time | Maximum number of incoming incidents to mirror each time. | False |
    | Advanced Parameters | Comma-separated configuration for advanced parameter values. E.g., EVENTS_INTERVAL_SECS=20,FETCH_SLEEP=5 | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Required Permissions
| Component | Permission |
| --- | --- |
| Assets | Vulnerability Management *or* Assets |
| Domains | Admin |
| Offenses (Manage Closing Reason) | Manage Offense Closing Reasons |
| Offenses (Assign Offenses to Users) | Assign Offenses to Users |
| Offenses (Read) | Offenses |
| References (Create/Update) | Admin |
| References (Read) | View Reference Data |
## Mapping limitations for XSOAR versions below 6.0.0
The *Pull from instance* option to create a new mapper is not supported in XSOAR versions below 6.0.0. 
## Creating classifier using *Pull from instance* feature
QRadar fetches incidents using a long-running execution. As a result, when you select the *Pull from instance* option to pull incidents from the QRadar service to create a classifier, it does not fetch offenses in real time, but uses samples to support the *Pull from instance* feature. This results in seeing the latest sample stored, and not the latest offense that was fetched.  
## Important note regarding the *Query to fetch offenses* parameter
The *Query to fetch offenses* feature enables you to define a specific query for offenses to be retrieved, e.g., **'status = OPEN and id = 5'**. The QRadar integration keeps track of IDs that have already been fetched in order to avoid duplicate fetching. 
If you change the *Query to fetch offenses* value, it will not re-fetch offenses that have already been fetched. To re-fetch those offences, run the ***qradar-reset-last-run*** command. However, note that the list of QRadar IDs that had already been fetched will be reset and duplicate offenses could be re-fetched, depending on the user query.
## Migration from QRadar v2 to QRadar v3
Every command and playbook that runs in QRadar v2 also runs in QRadar v3. No adjustments are required.
## Additions and changes between QRadar v3 and QRadar v2
### New commands
- ***qradar-rule-groups-list***
- ***qradar-searches-list***
- ***qradar-geolocations-for-ip***
- ***qradar-log-sources-list***
### Command name changes
| QRadar v2 command | QRadar V3 command | Notes
| --- | --- | --- |
| qradar-offenses | qradar-offenses-list | |
| qradar-offense-by-id | qradar-offenses-list | Specify the *offense_id* argument in the command.  |
| qradar-update-offense | qradar-offense-update | |
| qradar-get-closing-reasons | qradar-closing-reasons | |
| qradar-get-note | qradar-offense-notes-list | |
| qradar-create-note | qradar-offense-note-create | |
| qradar-get-assets | qradar-assets-list | |
| qradar-get-asset-by-id | qradar-assets-list | Specify the *asset_id* argument in the command. | |
| qradar-searches | qradar-search-create | |
| qradar-get-search | qradar-search-status-get | | 
| qradar-get-search-results | qradar-search-results-get | | 
| qradar-get-reference-by-name | qradar-reference-sets-list |  Specify the *ref_name* argument in the command. | |
| qradar-create-reference-set | qradar-reference-set-create | | 
| qradar-delete-reference-set | qradar-reference-set-delete | |
| qradar-create-reference-set-value | qradar-reference-set-value-upsert | |
| qradar-update-reference-set-value | qradar-reference-set-value-upsert |  | 
| qradar-delete-reference-set-value |  qradar-reference-set-value-delete | | 
| qradar-get-domains | qradar-domains-list |  | 
| qradar-domains-list | qradar-get-domain-by-id | Specify the *domain_id* argument in the command. |  |
## Mirroring
This integration supports in mirroring from QRadar offenses to XSOAR.
* When a field of an offense is updated in QRadar services, it is mirrored in XSOAR.
### Mirroring events
* Mirroring events from QRadar to XSOAR is supported via **Mirror Offense and Events** option.
* Events will only be mirrored in the incoming direction.
* Mirroring events will only work when the **Long running instance** parameter is enabled.
* Filtering events via *events_limit* and *events_columns* options for mirrored incidents will be the same as in the fetched incidents.
* The integration will always mirror the events that occurred first in each offense.

For further information about mirroring configurations, see [here](https://xsoar.pan.dev/docs/integrations/mirroring_integration).
### Use API token instead of Username and Password
- In the **Username / API Key** field, type **_api_token_key**.  
- In the **Password** field, type your API token.
## Choose your API version
1. Visit the [QRadar API versions page](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_getting_started.html) for a full list of available API versions according to the QRadar version.
2. Choose one of the API versions listed under **Supported REST API versions** column in the line corresponding to your QRadar version.

Note: If you're uncertain which API version to use, it is recommended to use the latest API version listed in the **Supported REST API versions** column in the line corresponding to your QRadar version.
## View your QRadar version
1. Enter QRadar service.
2. Click the **Menu** toolbar. A scrolling toolbar will appear.
3. Click **About**. A new window will appear with the details of your QRadar version.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qradar-offenses-list
***
Gets offenses from QRadar.


#### Base Command

`qradar-offenses-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve its details. Specify offense_id to get details about a specific offense. | Optional | 
| enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. Possible values are: IPs, IPs And Assets, None. Default is None. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query to filter offenses, e.g., "severity &gt;= 4 AND id &gt; 5 AND status=OPEN". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,severity,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Description | String | Description of the offense. | 
| QRadar.Offense.Rules.id | Number | The ID of the rule. | 
| QRadar.Offense.Rules.type | String | The type of the rule. | 
| QRadar.Offense.Rules.name | String | The name of the rule. | 
| QRadar.Offense.EventCount | Number | Number of events that are associated with the offense. | 
| QRadar.Offense.FlowCount | Number | Number of flows that are associated with the offense. | 
| QRadar.Offense.AssignedTo | String | The user to whom the offense is assigned. | 
| QRadar.Offense.Followup | Boolean | Whether the offense is marked for follow-up. | 
| QRadar.Offense.SourceAddress | Number | Source addresses \(IPs if IPs enrich have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Protected | Boolean | Whether the offense is protected. | 
| QRadar.Offense.ClosingUser | String | The user who closed the offense. | 
| QRadar.Offense.DestinationHostname | String | Destination networks that are associated with the offense. | 
| QRadar.Offense.CloseTime | Date | Time when the offense was closed. | 
| QRadar.Offense.RemoteDestinationCount | Number | Number of remote destinations that are associated with the offense. | 
| QRadar.Offense.StartTime | Date | Date of the earliest item that contributed to the offense. | 
| QRadar.Offense.Magnitude | Number | Magnitude of the offense. | 
| QRadar.Offense.LastUpdatedTime | String | Date of the most recent item that contributed to the offense. | 
| QRadar.Offense.Credibility | Number | Credibility of the offense. | 
| QRadar.Offense.ID | Number | ID of the offense. | 
| QRadar.Offense.Categories | String | Event categories that are associated with the offense. | 
| QRadar.Offense.Severity | Number | Severity of the offense. | 
| QRadar.Offense.ClosingReason | String | Reason the offense was closed. | 
| QRadar.Offense.OffenseType | String | Type of the offense. | 
| QRadar.Offense.Relevance | Number | Relevance of the offense. | 
| QRadar.Offense.OffenseSource | String | Source of the offense. | 
| QRadar.Offense.DestinationAddress | Number | Destination addresses \(IPs if IPs enrichment have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Status | String | Status of the offense. Possible values: "OPEN", "HIDDEN", "CLOSED". | 
| QRadar.Offense.LinkToOffense | String | Link to the URL containing information about the offense. | 
| QRadar.Offense.Assets | String | Assets correlated to the offense, if enrichment was requested. | 



#### Command Example
```!qradar-offenses-list enrichment=IPs filter="status=OPEN" range=0-2```

#### Context Example
```json
{
    "QRadar": {
        "Offense": [
            {
                "Categories": [
                    "Session Closed"
                ],
                "Credibility": 2,
                "Description": "Session Closed\n",
                "DestinationAddress": [
                    "192.168.1.3"
                ],
                "DestinationHostname": [
                    "Net-10-172-192.Net_192_168_1_3"
                ],
                "EventCount": 1,
                "FlowCount": 0,
                "Followup": true,
                "ID": 16,
                "LastUpdatedTime": "2021-02-15T14:24:11.536000+00:00",
                "LinkToOffense": "https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=16",
                "Magnitude": 1,
                "OffenseSource": "192.168.1.3",
                "OffenseType": "Source IP",
                "Protected": false,
                "Relevance": 0,
                "RemoteDestinationCount": 0,
                "Rules": [
                    {
                        "id": 100405,
                        "name": "Fake port scan",
                        "type": "CRE_RULE"
                    }
                ],
                "Severity": 2,
                "SourceAddress": [
                    "192.168.1.3"
                ],
                "StartTime": "2021-02-15T14:24:11.536000+00:00",
                "Status": "OPEN"
            },
            {
                "Categories": [
                    "User Login Failure",
                    "General Authentication Failed"
                ],
                "Credibility": 2,
                "Description": "Multiple Login Failures for the Same User\n containing Failure Audit: The domain controller failed to validate the credentials for an account\n",
                "DestinationAddress": [
                    "192.168.1.3"
                ],
                "DestinationHostname": [
                    "Net-10-172-192.Net_192_168_1_3"
                ],
                "EventCount": 15,
                "FlowCount": 0,
                "Followup": false,
                "ID": 15,
                "LastUpdatedTime": "2021-02-15T13:21:46.948000+00:00",
                "LinkToOffense": "https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=15",
                "Magnitude": 1,
                "OffenseSource": "yarden",
                "OffenseType": "Username",
                "Protected": false,
                "Relevance": 0,
                "RemoteDestinationCount": 0,
                "Rules": [
                    {
                        "id": 100056,
                        "name": "Multiple Login Failures for Single Username",
                        "type": "CRE_RULE"
                    }
                ],
                "Severity": 3,
                "SourceAddress": [
                    "192.168.1.3",
                    "::1"
                ],
                "StartTime": "2021-02-15T13:21:36.537000+00:00",
                "Status": "OPEN"
            },
            {
                "Categories": [
                    "User Login Success",
                    "Session Opened",
                    "Session Closed"
                ],
                "Credibility": 2,
                "Description": "User Login Success\n and Session Opened\n and Session Closed\n",
                "DestinationAddress": [
                    "192.168.1.3"
                ],
                "DestinationHostname": [
                    "Net-10-172-192.Net_192_168_1_3"
                ],
                "EventCount": 5,
                "FlowCount": 0,
                "Followup": false,
                "ID": 14,
                "LastUpdatedTime": "2021-02-04T22:29:30.742000+00:00",
                "LinkToOffense": "https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14",
                "Magnitude": 1,
                "OffenseSource": "192.168.1.3",
                "OffenseType": "Source IP",
                "Protected": false,
                "Relevance": 0,
                "RemoteDestinationCount": 0,
                "Rules": [
                    {
                        "id": 100405,
                        "name": "Fake port scan",
                        "type": "CRE_RULE"
                    }
                ],
                "Severity": 1,
                "SourceAddress": [
                    "192.168.1.3"
                ],
                "StartTime": "2021-02-04T12:19:54.402000+00:00",
                "Status": "OPEN"
            }
        ]
    }
}
```

#### Human Readable Output

>### Offenses List
>|ID|Description|OffenseType|Status|Severity|LastUpdatedTime|EventCount|Categories|Protected|Relevance|LinkToOffense|OffenseSource|DestinationAddress|Rules|Magnitude|SourceAddress|DestinationHostname|Credibility|Followup|RemoteDestinationCount|FlowCount|StartTime|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 16 | Session Closed<br/> | Source IP | OPEN | 2 | 2021-02-15T14:24:11.536000+00:00 | 1 | Session Closed | false | 0 | https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=16 | 192.168.1.3 | 192.168.1.3 | {'id': 100405, 'type': 'CRE_RULE', 'name': 'Fake port scan'} | 1 | 192.168.1.3 | Net-10-172-192.Net_192_168_1_3 | 2 | true | 0 | 0 | 2021-02-15T14:24:11.536000+00:00 |
>| 15 | Multiple Login Failures for the Same User<br/> containing Failure Audit: The domain controller failed to validate the credentials for an account<br/> | Username | OPEN | 3 | 2021-02-15T13:21:46.948000+00:00 | 15 | User Login Failure,<br/>General Authentication Failed | false | 0 | https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=15 | yarden | 192.168.1.3 | {'id': 100056, 'type': 'CRE_RULE', 'name': 'Multiple Login Failures for Single Username'} | 1 | 192.168.1.3,<br/>::1 | Net-10-172-192.Net_192_168_1_3 | 2 | false | 0 | 0 | 2021-02-15T13:21:36.537000+00:00 |
>| 14 | User Login Success<br/> and Session Opened<br/> and Session Closed<br/> | Source IP | OPEN | 1 | 2021-02-04T22:29:30.742000+00:00 | 5 | User Login Success,<br/>Session Opened,<br/>Session Closed | false | 0 | https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14 | 192.168.1.3 | 192.168.1.3 | {'id': 100405, 'type': 'CRE_RULE', 'name': 'Fake port scan'} | 1 | 192.168.1.3 | Net-10-172-192.Net_192_168_1_3 | 2 | false | 0 | 0 | 2021-02-04T12:19:54.402000+00:00 |


### qradar-offense-update
***
Update an offense.


#### Base Command

`qradar-offense-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to update. | Required | 
| enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. Possible values are: IPs, IPs And Assets, None. Default is None. | Optional | 
| protected | Whether the offense should be protected. Possible values are: true, false. | Optional | 
| follow_up | Whether the offense should be marked for follow-up. Possible values are: true, false. | Optional | 
| status | The new status for the offense. When the status of an offense is set to CLOSED, a valid closing_reason_id must be provided. To hide an offense, use the HIDDEN status. To show a previously hidden offense, use the OPEN status. Possible values are: OPEN, HIDDEN, CLOSED. | Optional | 
| closing_reason_id | The ID of a closing reason. You must provide a valid closing_reason_id when you close an offense. For a full list of closing reason IDs, use the 'qradar-closing-reasons' command. | Optional | 
| assigned_to | User to assign the offense to. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,severity,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-offense_id-POST.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Description | String | Description of the offense. | 
| QRadar.Offense.Rules.id | Number | The ID of the rule. | 
| QRadar.Offense.Rules.type | String | The type of the rule. | 
| QRadar.Offense.Rules.name | String | The name of the rule. | 
| QRadar.Offense.EventCount | Number | Number of events that are associated with the offense. | 
| QRadar.Offense.FlowCount | Number | Number of flows that are associated with the offense. | 
| QRadar.Offense.AssignedTo | String | The user to whom the offense is assigned. | 
| QRadar.Offense.Followup | Boolean | Whether the offense is marked for follow-up. | 
| QRadar.Offense.SourceAddress | Number | Source addresses \(IPs if IPs enrich have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Protected | Boolean | Whether the offense is protected. | 
| QRadar.Offense.ClosingUser | String | The user who closed the offense. | 
| QRadar.Offense.DestinationHostname | String | Destination networks that are associated with the offense. | 
| QRadar.Offense.CloseTime | Date | Time when the offense was closed. | 
| QRadar.Offense.RemoteDestinationCount | Number | Number of remote destinations that are associated with the offense. | 
| QRadar.Offense.StartTime | Date | Date of the earliest item that contributed to the offense. | 
| QRadar.Offense.Magnitude | Number | Magnitude of the offense. | 
| QRadar.Offense.LastUpdatedTime | String | Date of the most recent item that contributed to the offense. | 
| QRadar.Offense.Credibility | Number | Credibility of the offense. | 
| QRadar.Offense.ID | Number | ID of the offense. | 
| QRadar.Offense.Categories | String | Event categories that are associated with the offense. | 
| QRadar.Offense.Severity | Number | Severity of the offense. | 
| QRadar.Offense.ClosingReason | String | Reason the offense was closed. | 
| QRadar.Offense.OffenseType | String | Type of the offense. | 
| QRadar.Offense.Relevance | Number | Relevance of the offense. | 
| QRadar.Offense.OffenseSource | String | Source of the offense. | 
| QRadar.Offense.DestinationAddress | Number | Destination addresses \(IPs if IPs enrichment have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Status | String | Status of the offense. Possible values: "OPEN", "HIDDEN", "CLOSED". | 
| QRadar.Offense.LinkToOffense | String | Link to the URL containing information about the offense. | 
| QRadar.Offense.Assets | String | Assets correlated to the offense, if enrichment was requested. | 



#### Command Example
```!qradar-offense-update offense_id=6 assigned_to=demisto enrichment="IPs And Assets" follow_up=true status=OPEN protected=false```

#### Context Example
```json
{
    "QRadar": {
        "Offense": {
            "AssignedTo": "demisto",
            "Categories": [
                "Host Port Scan",
                "Access Permitted"
            ],
            "Credibility": 3,
            "Description": "Fake port scan\n",
            "DestinationAddress": [
                "192.168.1.3"
            ],
            "DestinationHostname": [
                "Net-10-172-192.Net_192_168_1_3"
            ],
            "EventCount": 6553,
            "FlowCount": 0,
            "Followup": true,
            "ID": 6,
            "LastUpdatedTime": "2021-03-02T13:38:32.438000+00:00",
            "LinkToOffense": "https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=6",
            "Magnitude": 6,
            "OffenseSource": "192.168.1.3",
            "OffenseType": "Source IP",
            "Protected": false,
            "Relevance": 5,
            "RemoteDestinationCount": 0,
            "Rules": [
                {
                    "id": 100405,
                    "name": "Fake port scan",
                    "type": "CRE_RULE"
                }
            ],
            "Severity": 9,
            "SourceAddress": [
                "192.168.1.3"
            ],
            "StartTime": "2020-11-10T22:24:23.603000+00:00",
            "Status": "OPEN"
        }
    }
}
```

#### Human Readable Output

>### offense Update
>|ID|Description|OffenseType|Status|Severity|SourceAddress|Relevance|LastUpdatedTime|OffenseSource|Magnitude|Followup|Rules|DestinationAddress|DestinationHostname|Categories|RemoteDestinationCount|Credibility|FlowCount|EventCount|AssignedTo|Protected|StartTime|LinkToOffense|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 6 | Fake port scan<br/> | Source IP | OPEN | 9 | 192.168.1.3 | 5 | 2021-03-02T13:38:32.438000+00:00 | 192.168.1.3 | 6 | true | {'id': 100405, 'type': 'CRE_RULE', 'name': 'Fake port scan'} | 192.168.1.3 | Net-10-172-192.Net_192_168_1_3 | Host Port Scan,<br/>Access Permitted | 0 | 3 | 0 | 6553 | demisto | false | 2020-11-10T22:24:23.603000+00:00 | https://192.168.0.1/api/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=6 |


### qradar-closing-reasons
***
Retrieves a list of offense closing reasons.


#### Base Command

`qradar-closing-reasons`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| closing_reason_id | The closing reason ID for which to retrieve its details. Specify closing_reason_id to get details about a specific closing reason. | Optional | 
| include_reserved | If true, reserved closing reasons are included in the response. Possible values are: true, false. Default is false. | Optional | 
| include_deleted | If true, deleted closing reasons are included in the response. Possible values are: true, false. Default is false. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query to filter closing reasons, e.g. "id &gt; 5". For reference see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offense_closing_reasons-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.ClosingReasons.IsDeleted | Boolean | Whether the closing reason is deleted. Deleted closing reasons cannot be used to close an offense. | 
| QRadar.Offense.ClosingReasons.IsReserved | Boolean | Whether the closing reason is reserved. Reserved closing reasons cannot be used to close an offense. | 
| QRadar.Offense.ClosingReasons.Name | String | Name of the closing reason. | 
| QRadar.Offense.ClosingReasons.ID | Number | ID of the closing reason. | 


#### Command Example
```!qradar-closing-reasons include_deleted=true include_reserved=true```

#### Context Example
```json
{
    "QRadar": {
        "ClosingReason": [
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
            },
            {
                "ID": 4,
                "IsDeleted": false,
                "IsReserved": true,
                "Name": "System Change (Upgrade, Reset, etc.)"
            }
        ]
    }
}
```

#### Human Readable Output

>### Closing Reasons
>|ID|Name|IsDeleted|IsReserved|
>|---|---|---|---|
>| 2 | False-Positive, Tuned | false | false |
>| 1 | Non-Issue | false | false |
>| 3 | Policy Violation | false | false |
>| 4 | System Change (Upgrade, Reset, etc.) | false | true |


### qradar-offense-notes-list
***
Retrieves a list of notes for an offense.


#### Base Command

`qradar-offense-notes-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve the notes for. | Required | 
| note_id | The note ID for which to retrieve its details. Specify note_id to get details about a specific note. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query to filter offense notes, e.g., "username=admin". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "username,note_text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-offense_id-notes-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.Text | String | The text of the note. | 
| QRadar.Note.CreateTime | Date | Creation date of the note. | 
| QRadar.Note.ID | Number | ID of the note. | 
| QRadar.Note.CreatedBy | String | The user who created the note. | 


#### Command Example
```!qradar-offense-notes-list offense_id=6 filter="username='API_user: demisto'" range=0-1```

#### Context Example
```json
{
    "QRadar": {
        "Note": [
            {
                "CreateTime": "2021-03-03T08:32:46.467000+00:00",
                "CreatedBy": "API_user: demisto",
                "ID": 12,
                "Text": "Note Regarding The Offense"
            },
            {
                "CreateTime": "2021-03-01T16:49:33.691000+00:00",
                "CreatedBy": "API_user: demisto",
                "ID": 10,
                "Text": "Note Regarding The Offense"
            }
        ]
    }
}
```

#### Human Readable Output

>### Offense Notes List For Offense ID 6
>|ID|Text|CreatedBy|CreateTime|
>|---|---|---|---|
>| 12 | Note Regarding The Offense | API_user: demisto | 2021-03-03T08:32:46.467000+00:00 |
>| 10 | Note Regarding The Offense | API_user: demisto | 2021-03-01T16:49:33.691000+00:00 |


### qradar-offense-note-create
***
Creates a note on an offense.


#### Base Command

`qradar-offense-note-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to add the note to. | Required | 
| note_text | The text of the note. | Required | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "username,note_text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-offense_id-notes-POST.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.Text | String | The text of the note. | 
| QRadar.Note.CreateTime | Date | Creation date of the note. | 
| QRadar.Note.ID | Number | ID of the note. | 
| QRadar.Note.CreatedBy | String | The user who created the note. | 


#### Command Example
```!qradar-offense-note-create note_text="Note Regarding The Offense" offense_id=6```

#### Context Example
```json
{
    "QRadar": {
        "Note": {
            "CreateTime": "2021-03-03T08:35:52.908000+00:00",
            "CreatedBy": "API_user: demisto",
            "ID": 13,
            "Text": "Note Regarding The Offense"
        }
    }
}
```

#### Human Readable Output

>### Create Note
>|ID|Text|CreatedBy|CreateTime|
>|---|---|---|---|
>| 13 | Note Regarding The Offense | API_user: demisto | 2021-03-03T08:35:52.908000+00:00 |


### qradar-rules-list
***
Retrieves a list of rules.


#### Base Command

`qradar-rules-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID for which to retrieve its details. Specify rule_id to get details about a specific rule. | Optional | 
| rule_type | Retrieves rules corresponding to the specified rule type. Possible values are: EVENT, FLOW, COMMON, USER. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter rules, e.g., "type=EVENT". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "owner,identifier,origin". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi150.doc/15.0--analytics-rules-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Rule.Owner | String | Owner of the rule. | 
| QRadar.Rule.BaseHostID | Number | ID of the host from which the rule's base capacity was determined. | 
| QRadar.Rule.CapacityTimestamp | Number | Date when the rule's capacity values were last updated. | 
| QRadar.Rule.Origin | String | Origin of the rule. Possible values: "SYSTEM", "OVERRIDE", "USER". | 
| QRadar.Rule.CreationDate | Date | Date when rule was created. | 
| QRadar.Rule.Type | String | Type of the rule. Possible values: "EVENT", "FLOW", "COMMON", "USER". | 
| QRadar.Rule.Enabled | Boolean | Whether rule is enabled. | 
| QRadar.Rule.ModificationDate | Date | Date when the rule was last modified. | 
| QRadar.Rule.Name | String | Name of the rule. | 
| QRadar.Rule.AverageCapacity | Number | Moving average capacity in EPS of the rule across all hosts. | 
| QRadar.Rule.ID | Number | ID of the rule. | 
| QRadar.Rule.BaseCapacity | Number | Base capacity of the rule in events per second. | 


#### Command Example
```!qradar-rules-list rule_type=COMMON```

#### Context Example
```json
{
    "QRadar": {
        "Rule": [
            {
                "AverageCapacity": 0,
                "BaseCapacity": 0,
                "BaseHostID": 0,
                "CapacityTimestamp": 0,
                "CreationDate": "2007-10-14T20:12:00.374000+00:00",
                "Enabled": true,
                "ID": 100057,
                "ModificationDate": "2020-10-18T19:40:21.886000+00:00",
                "Name": "Login Successful After Scan Attempt",
                "Origin": "SYSTEM",
                "Owner": "admin",
                "Type": "COMMON"
            },
            {
                "AverageCapacity": 0,
                "BaseCapacity": 0,
                "BaseHostID": 0,
                "CapacityTimestamp": 0,
                "CreationDate": "2006-03-27T10:54:12.077000+00:00",
                "Enabled": false,
                "ID": 100091,
                "ModificationDate": "2020-10-18T19:40:19.334000+00:00",
                "Name": "Botnet: Potential Botnet Connection (DNS)",
                "Origin": "SYSTEM",
                "Owner": "admin",
                "Type": "COMMON"
            },
            {
                "AverageCapacity": 0,
                "BaseCapacity": 0,
                "BaseHostID": 0,
                "CapacityTimestamp": 0,
                "CreationDate": "2005-12-22T00:54:48.708000+00:00",
                "Enabled": true,
                "ID": 100098,
                "ModificationDate": "2020-10-18T19:40:21.421000+00:00",
                "Name": "Host Port Scan Detected by Remote Host",
                "Origin": "SYSTEM",
                "Owner": "admin",
                "Type": "COMMON"
            }
        ]
    }
}
```

#### Human Readable Output

>### Rules List
>|ID|Name|Type|CapacityTimestamp|Owner|Enabled|BaseCapacity|Origin|AverageCapacity|ModificationDate|CreationDate|BaseHostID|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100057 | Login Successful After Scan Attempt | COMMON | 0 | admin | true | 0 | SYSTEM | 0 | 2020-10-18T19:40:21.886000+00:00 | 2007-10-14T20:12:00.374000+00:00 | 0 |
>| 100091 | Botnet: Potential Botnet Connection (DNS) | COMMON | 0 | admin | false | 0 | SYSTEM | 0 | 2020-10-18T19:40:19.334000+00:00 | 2006-03-27T10:54:12.077000+00:00 | 0 |
>| 100098 | Host Port Scan Detected by Remote Host | COMMON | 0 | admin | true | 0 | SYSTEM | 0 | 2020-10-18T19:40:21.421000+00:00 | 2005-12-22T00:54:48.708000+00:00 | 0 |

### qradar-rule-groups-list
***
Retrieves a list of the rule groups.


#### Base Command

`qradar-rule-groups-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_group_id | The rule group ID for which to retrieve its details. Specify rule_group_id to get details about a specific rule group. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter rules, e.g., "id &gt;= 125". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "owner,parent_id". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--analytics-rule_groups-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.RuleGroup.Owner | String | Owner of the group. | 
| QRadar.RuleGroup.ModifiedTime | Date | Date since the group was last modified. | 
| QRadar.RuleGroup.Level | Number | Depth of the group in the group hierarchy. | 
| QRadar.RuleGroup.Name | String | Name of the group. | 
| QRadar.RuleGroup.Description | String | Description of the group. | 
| QRadar.RuleGroup.ID | Number | ID of the group. | 
| QRadar.RuleGroup.ChildItems | String | Child items of the group. | 
| QRadar.RuleGroup.ChildGroups | Number | Child group IDs. | 
| QRadar.RuleGroup.Type | String | The type of the group. | 
| QRadar.RuleGroup.ParentID | Number | ID of the parent group. | 


#### Command Example
```!qradar-rule-groups-list```

#### Context Example
```json
{
    "QRadar": {
        "RuleGroup": [
            {
                "ChildItems": [
                    "1607",
                    "1608",
                    "1609",
                    "1610",
                    "1611",
                    "1612",
                    "1613",
                    "1614",
                    "1615",
                    "1616",
                    "1617",
                    "1618",
                    "100039",
                    "100041",
                    "100037",
                    "100040",
                    "100038",
                    "100035",
                    "100036",
                    "100044",
                    "100034",
                    "100042",
                    "100045",
                    "100043"
                ],
                "Description": "Rules focused on detection of suspicious asset reconciliation behavior.",
                "ID": 125,
                "Level": 2,
                "ModifiedTime": "2014-01-06T15:23:26.060000+00:00",
                "Name": "Asset Reconciliation Exclusion",
                "Owner": "admin",
                "ParentID": 3,
                "Type": "RULE_GROUP"
            },
            {
                "ChildItems": [
                    "1209",
                    "1210",
                    "100237",
                    "100238"
                ],
                "Description": "Sample rules for building email and other responses based on a rule.",
                "ID": 100,
                "Level": 1,
                "ModifiedTime": "2020-10-18T19:10:24.297000+00:00",
                "Name": "Response",
                "Owner": "admin",
                "ParentID": 3,
                "Type": "RULE_GROUP"
            },
            {
                "ChildItems": [
                    "1219",
                    "1265",
                    "1335",
                    "1410",
                    "1411",
                    "1412",
                    "1431",
                    "1443",
                    "1460",
                    "1461",
                    "1471",
                    "1481",
                    "1509",
                    "1552",
                    "1566",
                    "100287",
                    "100001",
                    "100033",
                    "100003"
                ],
                "Description": "Rules based on log source and event anomalies such as high event rates or excessive connections.",
                "ID": 101,
                "Level": 1,
                "ModifiedTime": "2020-10-18T19:10:24.297000+00:00",
                "Name": "Anomaly",
                "Owner": "admin",
                "ParentID": 3,
                "Type": "RULE_GROUP"
            }
        ]
    }
}
```

#### Human Readable Output

>### Rules Group List
>|ID|Name|Description|Owner|ChildGroups|Level|ParentID|Type|ChildItems|ModifiedTime|
>|---|---|---|---|---|---|---|---|---|---|
>| 125 | Asset Reconciliation Exclusion | Rules focused on detection of suspicious asset reconciliation behavior. | admin |  | 2 | 3 | RULE_GROUP | 1607,<br/>1608,<br/>1609,<br/>1610,<br/>1611,<br/>1612,<br/>1613,<br/>1614,<br/>1615,<br/>1616,<br/>1617,<br/>1618,<br/>100039,<br/>100041,<br/>100037,<br/>100040,<br/>100038,<br/>100035,<br/>100036,<br/>100044,<br/>100034,<br/>100042,<br/>100045,<br/>100043 | 2014-01-06T15:23:26.060000+00:00 |
>| 100 | Response | Sample rules for building email and other responses based on a rule. | admin |  | 1 | 3 | RULE_GROUP | 1209,<br/>1210,<br/>100237,<br/>100238 | 2020-10-18T19:10:24.297000+00:00 |
>| 101 | Anomaly | Rules based on log source and event anomalies such as high event rates or excessive connections. | admin |  | 1 | 3 | RULE_GROUP | 1219,<br/>1265,<br/>1335,<br/>1410,<br/>1411,<br/>1412,<br/>1431,<br/>1443,<br/>1460,<br/>1461,<br/>1471,<br/>1481,<br/>1509,<br/>1552,<br/>1566,<br/>100287,<br/>100001,<br/>100033,<br/>100003 | 2020-10-18T19:10:24.297000+00:00 |

### qradar-assets-list
***
Retrieves assets list.


#### Base Command

`qradar-assets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID for which to retrieve its details. Specify asset_id to get details about a specific asset. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter assets, e.g., "domain_id=0". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,interfaces,users,properties". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--asset_model-assets-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Domain | String | DNS name. | 
| Endpoint.OS | String | Asset operating system. | 
| Endpoint.MACAddress | String | Asset MAC address. | 
| Endpoint.IPAddress | Unknown | IP addresses of the endpoint. | 
| QRadar.Asset.Interfaces.id | Number | ID of the interface. | 
| QRadar.Asset.Interfaces.mac_address | String | MAC address of the interface. Null if unknown. | 
| QRadar.Asset.Interfaces.ip_addresses.id | Number | ID of the interface. | 
| QRadar.Asset.Interfaces.ip_addresses.network_id | Number | Network ID of the network the IP belongs to. | 
| QRadar.Asset.Interfaces.ip_addresses.value | String | The IP address. | 
| QRadar.Asset.Interfaces.ip_addresses.type | String | Type of IP address. Possible values: "IPV4", "IPV6". | 
| QRadar.Asset.Interfaces.ip_addresses.created | Date | Date when the IP address was created. | 
| QRadar.Asset.Interfaces.ip_addresses.first_seen_scanner | Date | Date when the IP address was first seen during a vulnerability scan. | 
| QRadar.Asset.Interfaces.ip_addresses.first_seen_profiler | Date | Date when the IP address was first seen in event or flow traffic. | 
| QRadar.Asset.Interfaces.ip_addresses.last_seen_scanner | Date | Date when the IP address was most recently seen during a vulnerability scan. | 
| QRadar.Asset.Interfaces.ip_addresses.last_seen_profiler | Date | Date when the IP address was most recently seen in event or flow traffic. | 
| QRadar.Asset.Products.id | Number | The ID of this software product instance in QRadar's asset model. | 
| QRadar.Asset.Products.product_variant_id | Number | The ID of this software product variant in QRadar's catalog of products. | 
| QRadar.Asset.Products.first_seen_scanner | Date | Date when the product was first seen during a vulnerability scan. | 
| QRadar.Asset.Products.first_seen_profiler | Date | Date when the product was first seen in event or flow traffic. | 
| QRadar.Asset.Products.last_seen_scanner | Date | Date when the product was most recently seen seen during a vulnerability scan. | 
| QRadar.Asset.Products.last_seen_profiler | Date | Date when the product was most recently seen in event or flow traffic. | 
| QRadar.Asset.VulnerabilityCount | Number | The total number of vulnerabilities associated with this asset. | 
| QRadar.Asset.RiskScoreSum | Number | The sum of the CVSS scores of the vulnerabilities on this asset. | 
| QRadar.Asset.Hostnames.last_seen_profiler | Date | Date when the host was most recently seen in event or flow traffic. | 
| QRadar.Asset.Hostnames.created | Date | Date when the host was created. | 
| QRadar.Asset.Hostnames.last_seen_scanner | Date | Date when the host was most recently seen during a vulnerability scan. | 
| QRadar.Asset.Hostnames.name | String | Name of the host. | 
| QRadar.Asset.Hostnames.first_seen_scanner | Date | Date when the host was first seen during a vulnerability scan. | 
| QRadar.Asset.Hostnames.id | Number | ID of the host. | 
| QRadar.Asset.Hostnames.type | String | Type of the host. Possible values: "DNS", "NETBIOS", "NETBIOSGROUP". | 
| QRadar.Asset.Hostnames.first_seen_profiler | Date | Date when the host was first seen in event or flow traffic. | 
| QRadar.Asset.ID | Number | ID of the asset. | 
| QRadar.Asset.Users.last_seen_profiler | Date | Date when the user was most recently seen in event or flow traffic. | 
| QRadar.Asset.Users.last_seen_scanner | Date | Date when the user was most recently seen during a vulnerability scan. | 
| QRadar.Asset.Users.first_seen_scanner | Date | Date when the user was first seen during a vulnerability scan. | 
| QRadar.Asset.Users.id | Number | ID of the user. | 
| QRadar.Asset.Users.first_seen_profiler | Date | Date when the user was first seen in event or flow traffic. | 
| QRadar.Asset.Users.username | String | Name of the user. | 
| QRadar.Asset.DomainID | Number | ID of the domain this asset belongs to. | 
| QRadar.Asset.Properties.last_reported | Date | Date when the property was last updated. | 
| QRadar.Asset.Properties.name | String | Name of the property. | 
| QRadar.Asset.Properties.type_id | Number | Type ID of the property. | 
| QRadar.Asset.Properties.id | Number | ID of the property. | 
| QRadar.Asset.Properties.last_reported_by | String | The source of the most recent update to this property. | 
| QRadar.Asset.Properties.value | String | Property value. | 


#### Command Example
```!qradar-assets-list filter="id<1100" range=0-2```

#### Context Example
```json
{
    "QRadar": {
        "Asset": [
            {
                "DomainID": 0,
                "Hostnames": [
                    {
                        "created": "2021-02-02T19:05:12.138000+00:00",
                        "first_seen_profiler": "2021-02-02T19:05:12.138000+00:00",
                        "id": 1007,
                        "last_seen_profiler": "2021-02-15T13:20:23.530000+00:00",
                        "name": "HOST1233X11",
                        "type": "NETBIOS"
                    }
                ],
                "ID": 1007,
                "Properties": [
                    {
                        "id": 1006,
                        "last_reported": "2021-02-02T19:05:12.643000+00:00",
                        "last_reported_by": "IDENTITY:112",
                        "name": "Unified Name",
                        "type_id": 1002,
                        "value": "HOST1233X11"
                    }
                ],
                "RiskScoreSum": 0,
                "Users": [
                    {
                        "first_seen_profiler": "2021-02-02T19:05:12.138000+00:00",
                        "id": 1007,
                        "last_seen_profiler": "2021-02-15T13:20:23.530000+00:00",
                        "username": "Administrator"
                    }
                ],
                "VulnerabilityCount": 0
            },
            {
                "DomainID": 0,
                "Hostnames": [
                    {
                        "created": "2021-02-02T19:05:12.139000+00:00",
                        "first_seen_profiler": "2021-02-02T19:05:12.139000+00:00",
                        "id": 1008,
                        "last_seen_profiler": "2021-02-15T13:20:23.532000+00:00",
                        "name": "-",
                        "type": "NETBIOS"
                    }
                ],
                "ID": 1008,
                "Properties": [
                    {
                        "id": 1007,
                        "last_reported": "2021-02-02T19:05:12.645000+00:00",
                        "last_reported_by": "IDENTITY:112",
                        "name": "Unified Name",
                        "type_id": 1002,
                        "value": "-"
                    }
                ],
                "RiskScoreSum": 0,
                "Users": [
                    {
                        "first_seen_profiler": "2021-02-02T19:05:12.139000+00:00",
                        "id": 1008,
                        "last_seen_profiler": "2021-02-15T13:20:23.532000+00:00",
                        "username": "DWM-3"
                    }
                ],
                "VulnerabilityCount": 0
            },
            {
                "DomainID": 0,
                "Hostnames": [
                    {
                        "created": "2021-02-02T19:05:12.140000+00:00",
                        "first_seen_profiler": "2021-02-02T19:05:12.140000+00:00",
                        "id": 1009,
                        "last_seen_profiler": "2021-02-15T13:20:23.532000+00:00",
                        "name": "EC2AMAZ-ETKN6IA",
                        "type": "NETBIOS"
                    }
                ],
                "ID": 1009,
                "Properties": [
                    {
                        "id": 1008,
                        "last_reported": "2021-02-02T19:05:12.646000+00:00",
                        "last_reported_by": "IDENTITY:112",
                        "name": "Unified Name",
                        "type_id": 1002,
                        "value": "EC2AMAZ-ETKN6IA"
                    }
                ],
                "RiskScoreSum": 0,
                "Users": [
                    {
                        "first_seen_profiler": "2021-02-02T19:05:12.140000+00:00",
                        "id": 1009,
                        "last_seen_profiler": "2021-02-15T13:20:23.532000+00:00",
                        "username": "Administrator"
                    }
                ],
                "VulnerabilityCount": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Assets List
>|DomainID|Hostnames|ID|Properties|RiskScoreSum|Users|VulnerabilityCount|
>|---|---|---|---|---|---|---|
>| 0 | {'last_seen_profiler': '2021-02-15T13:20:23.530000+00:00', 'created': '2021-02-02T19:05:12.138000+00:00', 'name': 'HOST1233X11', 'id': 1007, 'type': 'NETBIOS', 'first_seen_profiler': '2021-02-02T19:05:12.138000+00:00'} | 1007 | {'last_reported': '2021-02-02T19:05:12.643000+00:00', 'name': 'Unified Name', 'type_id': 1002, 'id': 1006, 'last_reported_by': 'IDENTITY:112', 'value': 'HOST1233X11'} | 0.0 | {'last_seen_profiler': '2021-02-15T13:20:23.530000+00:00', 'id': 1007, 'first_seen_profiler': '2021-02-02T19:05:12.138000+00:00', 'username': 'Administrator'} | 0 |
>| 0 | {'last_seen_profiler': '2021-02-15T13:20:23.532000+00:00', 'created': '2021-02-02T19:05:12.139000+00:00', 'name': '-', 'id': 1008, 'type': 'NETBIOS', 'first_seen_profiler': '2021-02-02T19:05:12.139000+00:00'} | 1008 | {'last_reported': '2021-02-02T19:05:12.645000+00:00', 'name': 'Unified Name', 'type_id': 1002, 'id': 1007, 'last_reported_by': 'IDENTITY:112', 'value': '-'} | 0.0 | {'last_seen_profiler': '2021-02-15T13:20:23.532000+00:00', 'id': 1008, 'first_seen_profiler': '2021-02-02T19:05:12.139000+00:00', 'username': 'DWM-3'} | 0 |
>| 0 | {'last_seen_profiler': '2021-02-15T13:20:23.532000+00:00', 'created': '2021-02-02T19:05:12.140000+00:00', 'name': 'EC2AMAZ-ETKN6IA', 'id': 1009, 'type': 'NETBIOS', 'first_seen_profiler': '2021-02-02T19:05:12.140000+00:00'} | 1009 | {'last_reported': '2021-02-02T19:05:12.646000+00:00', 'name': 'Unified Name', 'type_id': 1002, 'id': 1008, 'last_reported_by': 'IDENTITY:112', 'value': 'EC2AMAZ-ETKN6IA'} | 0.0 | {'last_seen_profiler': '2021-02-15T13:20:23.532000+00:00', 'id': 1009, 'first_seen_profiler': '2021-02-02T19:05:12.140000+00:00', 'username': 'Administrator'} | 0 |


### qradar-saved-searches-list
***
Retrieves a list of Ariel saved searches.


#### Base Command

`qradar-saved-searches-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| saved_search_id | The saved search ID for which to retrieve its details. Specify saved_search_id to get details about a specific saved search. | Optional | 
| timeout | Number of seconds until timeout for the specified command. Default is 35. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter saved searches, e.g., "database=EVENTS and is_dashboard=true". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,owner,description". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--ariel-saved_searches-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SavedSearch.Owner | String | Owner of the saved search. | 
| QRadar.SavedSearch.Description | String | Description of the saved search. | 
| QRadar.SavedSearch.CreationDate | Date | Date when saved search was created. | 
| QRadar.SavedSearch.UID | String | UID of the saved search. | 
| QRadar.SavedSearch.Database | String | The database of the Ariel saved search, events, or flows. | 
| QRadar.SavedSearch.QuickSearch | Boolean | Whether the saved search is a quick search. | 
| QRadar.SavedSearch.Name | String | Name of the saved search. | 
| QRadar.SavedSearch.ModifiedDate | Date | Date when the saved search was most recently modified. | 
| QRadar.SavedSearch.ID | Number | ID of the saved search. | 
| QRadar.SavedSearch.AQL | String | The AQL query. | 
| QRadar.SavedSearch.IsShared | Boolean | Whether the saved search is shared with other users. | 


#### Command Example
```!qradar-saved-searches-list range=0-1```

#### Context Example
```json
{
    "QRadar": {
        "SavedSearch": [
            {
                "AQL": "SELECT \"destinationPort\" AS 'Destination Port', UniqueCount(\"sourceIP\") AS 'Source IP (Unique Count)', UniqueCount(\"destinationIP\") AS 'Destination IP (Unique Count)', UniqueCount(qid) AS 'Event Name (Unique Count)', UniqueCount(logSourceId) AS 'Log Source (Unique Count)', UniqueCount(category) AS 'Low Level Category (Unique Count)', UniqueCount(\"protocolId\") AS 'Protocol (Unique Count)', UniqueCount(\"userName\") AS 'Username (Unique Count)', MAX(\"magnitude\") AS 'Magnitude (Maximum)', SUM(\"eventCount\") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( (\"creEventList\"='100120') or (\"creEventList\"='100122') or (\"creEventList\"='100135') AND \"eventDirection\"='R2L' ) GROUP BY \"destinationPort\" order by \"Event Count (Sum)\" desc last 6 hours",
                "CreationDate": "2010-08-04T19:44:51.630000+00:00",
                "Database": "EVENTS",
                "Description": "",
                "ID": 2776,
                "IsShared": true,
                "ModifiedDate": "2020-10-18T19:39:16.160000+00:00",
                "Name": "Remote Recon and Scanning Activity by Destination Port",
                "Owner": "admin",
                "QuickSearch": true,
                "UID": "0d3cc801-52c3-4dbd-a43c-320cca195adc"
            },
            {
                "AQL": "SELECT \"flowBias\" AS 'Flow Bias', UniqueCount(\"sourceIP\") AS 'Source IP (Unique Count)', UniqueCount(\"destinationIP\") AS 'Destination IP (Unique Count)', UniqueCount(\"destinationPort\") AS 'Destination Port (Unique Count)', UniqueCount(APPLICATIONNAME(applicationid)) AS 'Application (Unique Count)', UniqueCount(\"protocolId\") AS 'Protocol (Unique Count)', SUM(\"sourceBytes\") AS 'Source Bytes (Sum)', SUM(\"destinationBytes\") AS 'Destination Bytes (Sum)', SUM((SourceBytes + DestinationBytes)) AS 'Total Bytes (Sum)', SUM(\"sourcePackets\") AS 'Source Packets (Sum)', SUM(\"destinationPackets\") AS 'Destination Packets (Sum)', SUM((SourcePackets + DestinationPackets)) AS 'Total Packets (Sum)', COUNT(*) AS 'Count' from flows where ( ( (\"flowDirection\"='L2R') or (\"flowDirection\"='R2L') or (\"flowDirection\"='R2R') AND \"endTime\">='1284540300000' ) AND \"endTime\"<='1284561900000' ) GROUP BY \"flowBias\" order by \"Total Bytes (Sum)\" desc last 6 hours",
                "CreationDate": "2010-07-22T17:33:06.761000+00:00",
                "Database": "FLOWS",
                "Description": "",
                "ID": 2792,
                "IsShared": true,
                "ModifiedDate": "2020-10-18T19:39:16.043000+00:00",
                "Name": "Flow Bias",
                "Owner": "admin",
                "QuickSearch": true,
                "UID": "0fe9b644-2660-4465-a2a5-ccaf7c167b1f"
            }
        ]
    }
}
```

#### Human Readable Output

>### Saved Searches List
>|ID|Name|ModifiedDate|Owner|AQL|IsShared|UID|Database|QuickSearch|CreationDate|
>|---|---|---|---|---|---|---|---|---|---|
>| 2776 | Remote Recon and Scanning Activity by Destination Port | 2020-10-18T19:39:16.160000+00:00 | admin | SELECT "destinationPort" AS 'Destination Port', UniqueCount("sourceIP") AS 'Source IP (Unique Count)', UniqueCount("destinationIP") AS 'Destination IP (Unique Count)', UniqueCount(qid) AS 'Event Name (Unique Count)', UniqueCount(logSourceId) AS 'Log Source (Unique Count)', UniqueCount(category) AS 'Low Level Category (Unique Count)', UniqueCount("protocolId") AS 'Protocol (Unique Count)', UniqueCount("userName") AS 'Username (Unique Count)', MAX("magnitude") AS 'Magnitude (Maximum)', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( ("creEventList"='100120') or ("creEventList"='100122') or ("creEventList"='100135') AND "eventDirection"='R2L' ) GROUP BY "destinationPort" order by "Event Count (Sum)" desc last 6 hours | true | 0d3cc801-52c3-4dbd-a43c-320cca195adc | EVENTS | true | 2010-08-04T19:44:51.630000+00:00 |
>| 2792 | Flow Bias | 2020-10-18T19:39:16.043000+00:00 | admin | SELECT "flowBias" AS 'Flow Bias', UniqueCount("sourceIP") AS 'Source IP (Unique Count)', UniqueCount("destinationIP") AS 'Destination IP (Unique Count)', UniqueCount("destinationPort") AS 'Destination Port (Unique Count)', UniqueCount(APPLICATIONNAME(applicationid)) AS 'Application (Unique Count)', UniqueCount("protocolId") AS 'Protocol (Unique Count)', SUM("sourceBytes") AS 'Source Bytes (Sum)', SUM("destinationBytes") AS 'Destination Bytes (Sum)', SUM((SourceBytes + DestinationBytes)) AS 'Total Bytes (Sum)', SUM("sourcePackets") AS 'Source Packets (Sum)', SUM("destinationPackets") AS 'Destination Packets (Sum)', SUM((SourcePackets + DestinationPackets)) AS 'Total Packets (Sum)', COUNT(*) AS 'Count' from flows where ( ( ("flowDirection"='L2R') or ("flowDirection"='R2L') or ("flowDirection"='R2R') AND "endTime">='1284540300000' ) AND "endTime"<='1284561900000' ) GROUP BY "flowBias" order by "Total Bytes (Sum)" desc last 6 hours | true | 0fe9b644-2660-4465-a2a5-ccaf7c167b1f | FLOWS | true | 2010-07-22T17:33:06.761000+00:00 |


### qradar-searches-list
***
Retrieves the list of Ariel searches IDs. Search status and results can be polled by sending the search ID to the 'qradar-search-status-get' and 'qradar-search-results-get' commands.


#### Base Command

`qradar-searches-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SearchID.SearchID | String | ID of the search. | 


#### Command Example
```!qradar-searches-list```

#### Context Example
```json
{
    "QRadar": {
        "SearchID": [
            {
                "SearchID": "a0dc7945-9e5b-4637-b4b9-024844a9d209"
            },
            {
                "SearchID": "8081d060-9ee0-4d03-810c-d730ffb885be"
            },
            {
                "SearchID": "37e58ffa-8e4d-48eb-b9d3-c4ff673b99e3"
            },
            {
                "SearchID": "8c5517d0-b37f-45f7-b2e0-5b496d644991"
            },
            {
                "SearchID": "63710473-4a8a-4d2e-b346-9cac9db59ab7"
            },
            {
                "SearchID": "c39e4674-97c3-4123-b439-934f6ac7b5fd"
            },
            {
                "SearchID": "3753e94a-1b3b-4fc6-b923-ec0d04769f2b"
            },
            {
                "SearchID": "b01c9d11-02d0-4693-8df9-70883d6c9b65"
            },
            {
                "SearchID": "10120fba-56f5-4c5c-ab55-cb79bb9890d2"
            },
            {
                "SearchID": "4ef25d6f-e19a-4bef-9a29-dfd5d29aaeae"
            },
            {
                "SearchID": "94f4fecb-114a-41d5-a636-c1bcec09e9ca"
            },
            {
                "SearchID": "0044ffa4-850f-47ed-b79c-1ac298a8a4e3"
            },
            {
                "SearchID": "4e2e81e2-9565-444f-8e06-5aecc0cb156c"
            },
            {
                "SearchID": "2768aca6-52ff-45a0-8343-7470afe1ec54"
            },
            {
                "SearchID": "20b09e0a-1df1-452b-8284-49cc66ea6b32"
            },
            {
                "SearchID": "8c0b8293-7257-450d-92fd-f8701dbde9f3"
            },
            {
                "SearchID": "52bcd78c-cf23-4ad9-beba-aac80e7880da"
            },
            {
                "SearchID": "814b79c1-515a-4a54-90d7-cb0c5a7920c1"
            },
            {
                "SearchID": "f19a88bb-2da7-40d2-8f26-77eac3f84e7d"
            },
            {
                "SearchID": "14478391-2a3c-45f1-910e-3373addd7efe"
            },
            {
                "SearchID": "98176f19-0a4c-454a-8275-ba72f9ffcc0f"
            },
            {
                "SearchID": "12a7d8f0-851d-4b85-9246-c9b0f9239b96"
            },
            {
                "SearchID": "b301b7a3-a524-4870-ac9c-471b907055e6"
            },
            {
                "SearchID": "681c44d1-962c-4fcd-9b7a-53873741e658"
            },
            {
                "SearchID": "800b8bd4-fa8f-48b3-ad6c-3343e65c6613"
            },
            {
                "SearchID": "9322aa46-e30e-41d8-8df6-640fe8a8386b"
            },
            {
                "SearchID": "254c810b-7e29-4e39-b49d-ab4c07bbe4f4"
            },
            {
                "SearchID": "d3190c66-ed5e-4fca-99f8-50a95f498739"
            },
            {
                "SearchID": "f04eabee-aebd-4a46-b76c-dceb80d022ee"
            },
            {
                "SearchID": "6b97b870-f65f-47b0-8179-8d63eb38b3e9"
            },
            {
                "SearchID": "b836df2c-b963-4bb9-9373-7d1bc8b8cdfe"
            },
            {
                "SearchID": "1e4124e6-39a7-42c8-a4db-460aa8304fbd"
            },
            {
                "SearchID": "fa98cf29-1356-48c1-9b3d-36d9bd6cbf34"
            },
            {
                "SearchID": "fd0f3871-1737-4148-93c9-29b11acf57d4"
            },
            {
                "SearchID": "dac2ae5a-26c6-4242-8743-978e20d07325"
            },
            {
                "SearchID": "1fc95e9b-1779-4a2f-a06a-70781b2e0575"
            },
            {
                "SearchID": "94bc9927-4eab-4709-a3e4-df844205d669"
            },
            {
                "SearchID": "df7e25af-a602-42c1-b917-123718d187a2"
            },
            {
                "SearchID": "dece365c-a76b-4774-bd8b-668907a28d27"
            },
            {
                "SearchID": "fc37e5a1-2ea1-4e68-8b71-968f7df91aef"
            },
            {
                "SearchID": "1d021ac3-8e64-4094-99f6-d7db0d04a59a"
            },
            {
                "SearchID": "df9a8e6a-1c9e-4274-9af5-ae09dfc1b7c0"
            },
            {
                "SearchID": "2476a797-ff1b-41c4-9b03-898f1cb4802a"
            },
            {
                "SearchID": "4dfd311b-7190-43b5-9fc1-60bb5382b670"
            },
            {
                "SearchID": "bbde3030-465f-4528-be91-ad69393064fa"
            },
            {
                "SearchID": "678c257f-a3ad-4341-9192-ad6346ea899e"
            },
            {
                "SearchID": "ca6ccbeb-b9fb-4f4a-bdec-ae1323da5d41"
            },
            {
                "SearchID": "9aa18e0a-73b5-4ae7-9cb5-1d40dc9ace7c"
            },
            {
                "SearchID": "dc27202b-5484-41d6-b095-bd9a31b852e3"
            },
            {
                "SearchID": "484a28cf-a984-4e3a-9fd4-0c8f490c7e23"
            }
        ]
    }
}
```

#### Human Readable Output

>### Search ID List
>|SearchID|
>|---|
>| a0dc7945-9e5b-4637-b4b9-024844a9d209 |
>| 8081d060-9ee0-4d03-810c-d730ffb885be |
>| 37e58ffa-8e4d-48eb-b9d3-c4ff673b99e3 |
>| 8c5517d0-b37f-45f7-b2e0-5b496d644991 |
>| 63710473-4a8a-4d2e-b346-9cac9db59ab7 |
>| c39e4674-97c3-4123-b439-934f6ac7b5fd |
>| 3753e94a-1b3b-4fc6-b923-ec0d04769f2b |
>| b01c9d11-02d0-4693-8df9-70883d6c9b65 |
>| 10120fba-56f5-4c5c-ab55-cb79bb9890d2 |
>| 4ef25d6f-e19a-4bef-9a29-dfd5d29aaeae |
>| 94f4fecb-114a-41d5-a636-c1bcec09e9ca |
>| 0044ffa4-850f-47ed-b79c-1ac298a8a4e3 |
>| 4e2e81e2-9565-444f-8e06-5aecc0cb156c |
>| 2768aca6-52ff-45a0-8343-7470afe1ec54 |
>| 20b09e0a-1df1-452b-8284-49cc66ea6b32 |
>| 8c0b8293-7257-450d-92fd-f8701dbde9f3 |
>| 52bcd78c-cf23-4ad9-beba-aac80e7880da |
>| 814b79c1-515a-4a54-90d7-cb0c5a7920c1 |
>| f19a88bb-2da7-40d2-8f26-77eac3f84e7d |
>| 14478391-2a3c-45f1-910e-3373addd7efe |
>| 98176f19-0a4c-454a-8275-ba72f9ffcc0f |
>| 12a7d8f0-851d-4b85-9246-c9b0f9239b96 |
>| b301b7a3-a524-4870-ac9c-471b907055e6 |
>| 681c44d1-962c-4fcd-9b7a-53873741e658 |
>| 800b8bd4-fa8f-48b3-ad6c-3343e65c6613 |
>| 9322aa46-e30e-41d8-8df6-640fe8a8386b |
>| 254c810b-7e29-4e39-b49d-ab4c07bbe4f4 |
>| d3190c66-ed5e-4fca-99f8-50a95f498739 |
>| f04eabee-aebd-4a46-b76c-dceb80d022ee |
>| 6b97b870-f65f-47b0-8179-8d63eb38b3e9 |
>| b836df2c-b963-4bb9-9373-7d1bc8b8cdfe |
>| 1e4124e6-39a7-42c8-a4db-460aa8304fbd |
>| fa98cf29-1356-48c1-9b3d-36d9bd6cbf34 |
>| fd0f3871-1737-4148-93c9-29b11acf57d4 |
>| dac2ae5a-26c6-4242-8743-978e20d07325 |
>| 1fc95e9b-1779-4a2f-a06a-70781b2e0575 |
>| 94bc9927-4eab-4709-a3e4-df844205d669 |
>| df7e25af-a602-42c1-b917-123718d187a2 |
>| dece365c-a76b-4774-bd8b-668907a28d27 |
>| fc37e5a1-2ea1-4e68-8b71-968f7df91aef |
>| 1d021ac3-8e64-4094-99f6-d7db0d04a59a |
>| df9a8e6a-1c9e-4274-9af5-ae09dfc1b7c0 |
>| 2476a797-ff1b-41c4-9b03-898f1cb4802a |
>| 4dfd311b-7190-43b5-9fc1-60bb5382b670 |
>| bbde3030-465f-4528-be91-ad69393064fa |
>| 678c257f-a3ad-4341-9192-ad6346ea899e |
>| ca6ccbeb-b9fb-4f4a-bdec-ae1323da5d41 |
>| 9aa18e0a-73b5-4ae7-9cb5-1d40dc9ace7c |
>| dc27202b-5484-41d6-b095-bd9a31b852e3 |
>| 484a28cf-a984-4e3a-9fd4-0c8f490c7e23 |


### qradar-search-create
***
Creates a new asynchronous Ariel search. Returns the search ID. Search status and results can be polled by sending the search ID to the 'qradar-search-status-get' and 'qradar-search-results-get' commands. Accepts SELECT query expressions only.


#### Base Command

`qradar-search-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_expression | The AQL query to execute. Mutually exclusive with saved_search_id. | Optional | 
| saved_search_id | Saved search ID to execute. Mutually exclusive with query_expression. Saved search ID is the 'id' field returned by the 'qradar-saved-searches-list' command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Status | String | Status of the newly created search. | 
| QRadar.Search.ID | String | ID of the newly created search. | 


#### Command Example
```!qradar-search-create query_expression="""SELECT "destinationPort" AS 'Destination Port', UniqueCount("sourceIP") AS 'Source IP (Unique Count)', UniqueCount("destinationIP") AS 'Destination IP (Unique Count)', UniqueCount(qid) AS 'Event Name (Unique Count)', UniqueCount(logSourceId) AS 'Log Source (Unique Count)', UniqueCount(category) AS 'Low Level Category (Unique Count)', UniqueCount("protocolId") AS 'Protocol (Unique Count)', UniqueCount("userName") AS 'Username (Unique Count)', MAX("magnitude") AS 'Magnitude (Maximum)', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( ("creEventList"='100120') or ("creEventList"='100122') or ("creEventList"='100135') AND "eventDirection"='R2L' ) GROUP BY "destinationPort" order by "Event Count (Sum)" desc last 6 hours"""```

#### Context Example
```json
{
    "QRadar": {
        "Search": {
            "ID": "a1ecef62-5d18-4a84-ba1d-b6c2645e419b",
            "Status": "WAIT"
        }
    }
}
```

#### Human Readable Output

>### Create Search
>|ID|Status|
>|---|---|
>| a1ecef62-5d18-4a84-ba1d-b6c2645e419b | WAIT |


### qradar-search-status-get
***
Retrieves status information for a search, based on the search ID.


#### Base Command

`qradar-search-status-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The identifier for an Ariel search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Status | String | Status of the search. | 
| QRadar.Search.ID | String | ID of the search. | 


#### Command Example
```!qradar-search-status-get search_id=e69df023-fff8-4d8c-a3b3-04d2b4b4af8a```

#### Context Example
```json
{
    "QRadar": {
        "Search": {
            "ID": "e69df023-fff8-4d8c-a3b3-04d2b4b4af8a",
            "Status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### Search Status For Search ID e69df023-fff8-4d8c-a3b3-04d2b4b4af8a
>|ID|Status|
>|---|---|
>| e69df023-fff8-4d8c-a3b3-04d2b4b4af8a | COMPLETED |


### qradar-search-results-get
***
Retrieves search results.


#### Base Command

`qradar-search-results-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The identifier for an Ariel search. | Required | 
| output_path | Replaces the default context output path for the query result (QRadar.Search.Result). E.g., for output_path=QRadar.Correlations, the result will be under the 'QRadar.Correlations' key in the context data. | Optional | 
| range | Range of events to return. (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Result | Unknown | The result of the search. | 


#### Command Example
```!qradar-search-results-get search_id=e69df023-fff8-4d8c-a3b3-04d2b4b4af8a range=0-3```

#### Context Example
```json
{
    "QRadar": {
        "SearchResult": [
        {
            "Destination Port": 5123,
            "Source IP (Unique Count)": 1.0,
            "Destination IP (Unique Count)": 1.0,
            "Event Name (Unique Count)": 1.0,
            "Log Source (Unique Count)": 1.0,
            "Low Level Category (Unique Count)": 1.0,
            "Protocol (Unique Count)": 1.0,
            "Username (Unique Count)": 0.0,
            "Magnitude (Maximum)": 9.0,
            "Event Count (Sum)": 3.0,
            "Count": 3.0
        },
        {
            "Destination Port": 52310,
            "Source IP (Unique Count)": 1.0,
            "Destination IP (Unique Count)": 1.0,
            "Event Name (Unique Count)": 1.0,
            "Log Source (Unique Count)": 1.0,
            "Low Level Category (Unique Count)": 1.0,
            "Protocol (Unique Count)": 1.0,
            "Username (Unique Count)": 0.0,
            "Magnitude (Maximum)": 9.0,
            "Event Count (Sum)": 1.0,
            "Count": 1.0
        },
        {
            "Destination Port": 54131,
            "Source IP (Unique Count)": 1.0,
            "Destination IP (Unique Count)": 1.0,
            "Event Name (Unique Count)": 1.0,
            "Log Source (Unique Count)": 1.0,
            "Low Level Category (Unique Count)": 1.0,
            "Protocol (Unique Count)": 1.0,
            "Username (Unique Count)": 0.0,
            "Magnitude (Maximum)": 9.0,
            "Event Count (Sum)": 1.0,
            "Count": 1.0
        },
        {
            "Destination Port": 51263,
            "Source IP (Unique Count)": 1.0,
            "Destination IP (Unique Count)": 1.0,
            "Event Name (Unique Count)": 1.0,
            "Log Source (Unique Count)": 1.0,
            "Low Level Category (Unique Count)": 1.0,
            "Protocol (Unique Count)": 1.0,
            "Username (Unique Count)": 0.0,
            "Magnitude (Maximum)": 9.0,
            "Event Count (Sum)": 1.0,
            "Count": 1.0
        }
        ]
    }
}
```

#### Human Readable Output

>### Search Results For Search ID e69df023-fff8-4d8c-a3b3-04d2b4b4af8a
>|Count|Destination IP (Unique Count)|Destination Port|Event Count (Sum)|Event Name (Unique Count)|Log Source (Unique Count)|Low Level Category (Unique Count)|Magnitude (Maximum)|Protocol (Unique Count)|Source IP (Unique Count)|Username (Unique Count)|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 3.0 | 1.0 | 5123 | 3.0 | 1.0 | 1.0 | 1.0 | 9.0 | 1.0 | 1.0 | 0.0 |
>| 1.0 | 1.0 | 52310 | 1.0 | 1.0 | 1.0 | 1.0 | 9.0 | 1.0 | 1.0 | 0.0 |
>| 1.0 | 1.0 | 54131 | 1.0 | 1.0 | 1.0 | 1.0 | 9.0 | 1.0 | 1.0 | 0.0 |
>| 1.0 | 1.0 | 51263 | 1.0 | 1.0 | 1.0 | 1.0 | 9.0 | 1.0 | 1.0 | 0.0 |


### qradar-reference-sets-list
***
Retrieves a list of reference sets.


#### Base Command

`qradar-reference-sets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The reference name of the reference set for which to retrieve its details. Specify ref_name to get details about a specific reference set. | Optional | 
| date_value | If set to true will try to convert the data values to ISO-8601 string. Possible values are: True, False. Default is False. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter reference sets, e.g., "timeout_type=FIRST_SEEN". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-sets-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 


#### Command Example
```!qradar-reference-sets-list filter="timeout_type=FIRST_SEEN"```

#### Context Example
```json
{
    "QRadar": {
        "Reference": [
            {
                "CreationTime": "2015-08-27T19:29:30.114000+00:00",
                "ElementType": "IP",
                "Name": "Mail Servers",
                "NumberOfElements": 8,
                "TimeoutType": "FIRST_SEEN"
            },
            {
                "CreationTime": "2015-08-27T19:30:46.455000+00:00",
                "ElementType": "IP",
                "Name": "Web Servers",
                "NumberOfElements": 0,
                "TimeoutType": "FIRST_SEEN"
            },
            {
                "CreationTime": "2015-08-27T19:28:55.265000+00:00",
                "ElementType": "IP",
                "Name": "DNS Servers",
                "NumberOfElements": 0,
                "TimeoutType": "FIRST_SEEN"
            }
        ]
    }
}
```

#### Human Readable Output

>### Reference Sets List
>|Name|ElementType|TimeToLive|TimeoutType|NumberOfElements|CreationTime|
>|---|---|---|---|---|---|
>| Mail Servers | IP |  | FIRST_SEEN | 8 | 2015-08-27T19:29:30.114000+00:00 |
>| Web Servers | IP |  | FIRST_SEEN | 0 | 2015-08-27T19:30:46.455000+00:00 |
>| DNS Servers | IP |  | FIRST_SEEN | 0 | 2015-08-27T19:28:55.265000+00:00 |

### qradar-reference-set-create
***
Creates a new reference set.


#### Base Command

`qradar-reference-set-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to be created. Reference names can be found by 'Name' field in 'qradar-reference-sets-list' command. | Required | 
| element_type | The element type for the values allowed in the reference set. Possible values are: ALN, ALNIC, NUM, IP, PORT, DATE. | Required | 
| timeout_type | Indicates if the time_to_live interval is based on when the data was first seen or last seen. Possible values are: FIRST_SEEN, LAST_SEEN, UNKNOWN. Default is UNKNOWN. | Optional | 
| time_to_live | The time to live interval, time range. for example: '1 month' or '5 minutes'. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-sets-POST.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 


#### Command Example
```!qradar-reference-set-create element_type=IP ref_name="Malicious IPs" time_to_live="1 year" timeout_type=FIRST_SEEN```

#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2021-03-03T08:36:41.077000+00:00",
            "ElementType": "IP",
            "Name": "Malicious IPs",
            "NumberOfElements": 0,
            "TimeToLive": "1 years 0 mons 0 days 0 hours 0 mins 0.00 secs",
            "TimeoutType": "FIRST_SEEN"
        }
    }
}
```

#### Human Readable Output

>### Reference Set Create
>|Name|ElementType|TimeToLive|TimeoutType|NumberOfElements|CreationTime|
>|---|---|---|---|---|---|
>| Malicious IPs | IP | 1 years 0 mons 0 days 0 hours 0 mins 0.00 secs | FIRST_SEEN | 0 | 2021-03-03T08:36:41.077000+00:00 |


### qradar-reference-set-delete
***
Removes a reference set or purges its contents.


#### Base Command

`qradar-reference-set-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to be deleted. Reference names can be found by 'Name' field in 'qradar-reference-sets-list' command. | Required | 
| purge_only | Indicates if the reference set should have its contents purged (true), keeping the reference set structure. If the value is 'false', or not specified the reference set is removed completely. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!qradar-reference-set-delete ref_name="Malicious IPs"```

#### Human Readable Output

>### Reference Malicious IPs Was Asked To Be Deleted. Current Deletion Status: QUEUED

### qradar-reference-set-value-upsert
***
Adds or updates an element in a reference set.


#### Base Command

`qradar-reference-set-value-upsert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update an element in. Reference names can be found by the 'Name' field in the 'qradar-reference-sets-list' command. | Required | 
| value | Comma-separated list of the values to add or update in the reference set. If the values are dates, the supported date formats are: epoch, ISO, and time range (&lt;number&gt; &lt;time unit&gt;', e.g., 12 hours, 7 days.). | Required | 
| source | An indication of where the data originated. Default is reference data api. | Optional | 
| date_value | True if the specified value  type was date. Possible values are: true, false. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-sets-name-POST.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 


#### Command Example
```!qradar-reference-set-value-upsert ref_name="Malicious IPs" value="1.2.3.4,1.2.3.5,192.168.1.3"```

#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2021-03-03T08:36:41.077000+00:00",
            "ElementType": "IP",
            "Name": "Malicious IPs",
            "NumberOfElements": 3,
            "TimeToLive": "1 years 0 mons 0 days 0 hours 0 mins 0.00 secs",
            "TimeoutType": "FIRST_SEEN"
        }
    }
}
```

#### Human Readable Output

>### Reference Update Create
>|Name|ElementType|TimeToLive|TimeoutType|NumberOfElements|CreationTime|
>|---|---|---|---|---|---|
>| Malicious IPs | IP | 1 years 0 mons 0 days 0 hours 0 mins 0.00 secs | FIRST_SEEN | 3 | 2021-03-03T08:36:41.077000+00:00 |


### qradar-reference-set-value-delete
***
Removes a value from a reference set.


#### Base Command

`qradar-reference-set-value-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set from which to remove a value. Reference names can be found by the 'Name' field in the 'qradar-reference-sets-list' command. | Required | 
| value | The value to remove from the reference set. If the specified value is date, the supported date formats are: epoch, ISO, and time range (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days.). | Required | 
| date_value | True if the specified value type was date. Possible values are: True, False. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!qradar-reference-set-value-delete ref_name="Malicious IPs" value="1.2.3.4"```

#### Human Readable Output

>### value: 1.2.3.4 of reference: Malicious IPs was deleted successfully

### qradar-domains-list
***
Gets the list of domains. You must have System Administrator or Security Administrator permissions to call this endpoint if you are trying to retrieve the details of all domains. You can retrieve details of domains that are assigned to your Security Profile without having the System Administrator or Security Administrator permissions. If you do not have the System Administrator or Security Administrator permissions, then for each domain assigned to your security profile you can only view the values for the ID and name fields. All other values return null.


#### Base Command

`qradar-domains-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The domain ID from which to retrieve its details. Specify domain_id to get details about a specific domain. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter domains, e.g., "id &gt; 3". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--config-domain_management-domains-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Domains.AssetScannerIDs | Number | Asset scanner IDs that are associated with the domain. | 
| QRadar.Domains.CustomProperties | Unknown | Custom properties of the domain. | 
| QRadar.Domains.Deleted | Boolean | Whether the domain has been deleted. | 
| QRadar.Domains.Description | String | Description of the domain. | 
| QRadar.Domains.EventCollectorIDs | Number | Event collector IDs that are assigned to this domain. | 
| QRadar.Domains.FlowCollectorIDs | Number | Flow collector IDs that are assigned to this domain. | 
| QRadar.Domains.FlowSourceIDs | Number | Flow source IDs that are assigned to this domain. | 
| QRadar.Domains.ID | Number | ID of the domain. | 
| QRadar.Domains.LogSourceGroupIDs | Number | Log source group IDs that are assigned to this domain. | 
| QRadar.Domains.LogSourceIDs | Number | Log source IDs that are assigned to this domain. | 
| QRadar.Domains.Name | String | Name of the domain. | 
| QRadar.Domains.QVMScannerIDs | Number | QVM scanner IDs that are assigned to this domain. | 
| QRadar.Domains.TenantID | Number | ID of the tenant that this domain belongs to. | 


#### Command Example
```!qradar-domains-list```

#### Context Example
```json
{
    "QRadar": {
        "Domains": {
            "Deleted": false,
            "Description": "",
            "ID": 0,
            "Name": "",
            "TenantID": 0
        }
    }
}
```

#### Human Readable Output

>### Domains List
>|Deleted|ID|TenantID|
>|---|---|---|
>| false | 0 | 0 |


### qradar-indicators-upload
***
Uploads indicators to QRadar.


#### Base Command

`qradar-indicators-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of set to add or update data in. Reference names can be found by the 'Name' field in the 'qradar-reference-sets-list' command. | Required | 
| query | The query for getting indicators from Cortex XSOAR. | Optional | 
| limit | The maximum number of indicators to fetch from Cortex XSOAR. Default is 50. | Optional | 
| page | The page from which to get the indicators. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-maps-bulk_load-name-POST.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 


#### Command Example
```!qradar-indicators-upload ref_name="Mail Servers" limit=2 query="type:IP"```

#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "creation_time": "2015-08-27T19:29:30.114000+00:00",
            "element_type": "IP",
            "name": "Mail Servers",
            "number_of_elements": 8,
            "timeout_type": "FIRST_SEEN"
        }
    }
}
```

#### Human Readable Output

>### Indicators Upload For Reference Set Mail Servers
>|creation_time|element_type|name|number_of_elements|timeout_type|
>|---|---|---|---|---|
>| 2015-08-27T19:29:30.114000+00:00 | IP | Mail Servers | 8 | FIRST_SEEN |
>
>### Indicators Uploaded
>|Indicator Type|Indicator Value|
>|---|---|
>| IP | 1.2.3.4 |
>| IP | 192.168.1.3 |


### qradar-geolocations-for-ip
***
Retrieves the MaxMind GeoIP data for the specified IP address.


#### Base Command

`qradar-geolocations-for-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma-separated list of IPs from which to retrieve their geolocation. | Required | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "continent,ip_address". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--services-geolocations-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.GeoForIP.CityName | String | Name of the city that is associated with the IP address. | 
| QRadar.GeoForIP.ContinentName | String | Name of the continent that is associated with the IP address. | 
| QRadar.GeoForIP.LocationAccuracyRadius | Number | The approximate accuracy radius in kilometers around the latitude and longitude for the IP address. | 
| QRadar.GeoForIP.LocationAverageIncome | Number | The average income associated with the IP address. | 
| QRadar.GeoForIP.LocationLatitude | Number | The approximate latitude of the location associated with the IP address. | 
| QRadar.GeoForIP.LocationTimezone | String | Timezone of the location. | 
| QRadar.GeoForIP.LocationLongitude | Number | The approximate longitude of the location associated with the IP address. | 
| QRadar.GeoForIP.LocationMetroCode | Number | The metro code associated with the IP address. These are only available for IP addresses in the US. Returns the same metro codes as the Google AdWords API. | 
| QRadar.GeoForIP.LocationPopulationDensity | Number | The estimated number of people per square kilometer. | 
| QRadar.GeoForIP.PhysicalCountryIsoCode | String | ISO code of country where MaxMind believes the end user is located. | 
| QRadar.GeoForIP.PhysicalCountryName | String | Name of country where MaxMind believes the end user is located. | 
| QRadar.GeoForIP.RegisteredCountryIsoCode | String | ISO code of the country that the ISP has registered the IP address. | 
| QRadar.GeoForIP.RegisteredCountryName | String | Name of the country that the ISP has registered the IP address. | 
| QRadar.GeoForIP.RepresentedCountryIsoCode | String | ISO code of the country that is represented by users of the IP address. | 
| QRadar.GeoForIP.RepresentedCountryName | String | Name of the country that is represented by users of the IP address. | 
| QRadar.GeoForIP.RepresentedCountryConfidence | Number | Value between 0-100 that represents MaxMind's confidence that the represented country is correct. | 
| QRadar.GeoForIP.IPAddress | String | IP address to look up. | 
| QRadar.GeoForIP.Traits.autonomous_system_number | Number | The autonomous system number associated with the IP address. | 
| QRadar.GeoForIP.Traits.autonomous_system_organization | String | The organization associated with the registered autonomous system number for the IP address. | 
| QRadar.GeoForIP.Traits.domain | String | The second level domain associated with the IP address. | 
| QRadar.GeoForIP.Traits.internet_service_provider | String | The name of the internet service provider associated with the IP address. | 
| QRadar.GeoForIP.Traits.organization | String | The name of the organization associated with the IP address. | 
| QRadar.GeoForIP.Traits.user_type | String | The user type associated with the IP address. | 
| QRadar.GeoForIP.Coordinates | Number | Latitude and longitude by MaxMind. | 
| QRadar.GeoForIP.PostalCode | String | The postal code associated with the IP address. | 
| QRadar.GeoForIP.PostalCodeConfidence | Number | Value between 0-100 that represents MaxMind's confidence that the postal code is correct. | 


#### Command Example
```!qradar-geolocations-for-ip ip="1.2.3.4,1.2.3.5" range=0-1```

#### Context Example
```json
{
    "QRadar": {
        "GeoForIP": [
            {
                "CityName": "Mukilteo",
                "ContinentName": "NorthAmerica",
                "Coordinates": [
                    47.913,
                    -122.3042
                ],
                "IPAddress": "1.2.3.4",
                "LocationAccuracyRadius": 1000,
                "LocationLatitude": 47.913,
                "LocationLongitude": -122.3042,
                "LocationMetroCode": 819,
                "LocationTimezone": "America/Los_Angeles",
                "PhysicalCountryIsoCode": "US",
                "PhysicalCountryName": "United States",
                "PostalCode": "98275",
                "RegisteredCountryIsoCode": "US",
                "RegisteredCountryName": "United States"
            },
            {
                "CityName": "Mukilteo",
                "ContinentName": "NorthAmerica",
                "Coordinates": [
                    47.913,
                    -122.3042
                ],
                "IPAddress": "1.2.3.5",
                "LocationAccuracyRadius": 1000,
                "LocationLatitude": 47.913,
                "LocationLongitude": -122.3042,
                "LocationMetroCode": 819,
                "LocationTimezone": "America/Los_Angeles",
                "PhysicalCountryIsoCode": "US",
                "PhysicalCountryName": "United States",
                "PostalCode": "98275",
                "RegisteredCountryIsoCode": "US",
                "RegisteredCountryName": "United States"
            }
        ]
    }
}
```

#### Human Readable Output

>### Geolocation For IP
>|CityName|ContinentName|Coordinates|IPAddress|LocationAccuracyRadius|LocationLatitude|LocationLongitude|LocationMetroCode|LocationTimezone|PhysicalCountryIsoCode|PhysicalCountryName|PostalCode|RegisteredCountryIsoCode|RegisteredCountryName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Mukilteo | NorthAmerica | 47.913,<br/>-122.3042 | 1.2.3.4 | 1000 | 47.913 | -122.3042 | 819 | America/Los_Angeles | US | United States | 98275 | US | United States |
>| Mukilteo | NorthAmerica | 47.913,<br/>-122.3042 | 1.2.3.5 | 1000 | 47.913 | -122.3042 | 819 | America/Los_Angeles | US | United States | 98275 | US | United States |


### qradar-log-sources-list
***
Retrieves a list of log sources.


#### Base Command

`qradar-log-sources-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qrd_encryption_password | The password to use for encrypting the sensitive data of this endpoint. If password was not given, random password will be generated. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter log sources, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--config-event_sources-log_source_management-log_sources-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSource.SendingIP | String | IP of the system which the log source is associated with, or fed by. | 
| QRadar.LogSource.Internal | Boolean | Whether log source is internal. | 
| QRadar.LogSource.ProtocolParameters | Unknown | Protocol parameters. | 
| QRadar.LogSource.Description | String | Description of the log source. | 
| QRadar.LogSource.Enabled | Boolean | Whether log source is enabled. | 
| QRadar.LogSource.GroupIDs | Number | Log source group IDs. | 
| QRadar.LogSource.Credibility | Number | Credibility of the log source. | 
| QRadar.LogSource.ID | Number | ID of the log source. | 
| QRadar.LogSource.ProtocolTypeID | Number | Protocol type used by log source. | 
| QRadar.LogSource.CreationDate | Date | Date when log source was created. | 
| QRadar.LogSource.Name | String | Name of the log source. | 
| QRadar.LogSource.AutoDiscovered | Boolean | Whether log source was auto discovered. | 
| QRadar.LogSource.ModifiedDate | Date | Date when log source was last modified. | 
| QRadar.LogSource.TypeID | Number | The log source type. | 
| QRadar.LogSource.LastEventTime | Date | Date when the last event was received by the log source. | 
| QRadar.LogSource.Gateway | Boolean | Whether log source is configured as a gateway. | 
| QRadar.LogSource.Status | Unknown | Status of the log source. | 


#### Command Example
```!qradar-log-sources-list qrd_encryption_algorithm=AES128```

#### Context Example
```json
{
    "QRadar": {
        "LogSource": [
            {
                "AutoDiscovered": false,
                "CreationDate": "2020-10-18T19:40:19.701000+00:00",
                "Credibility": 10,
                "Description": "Anomaly Detection Engine",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 66,
                "Internal": true,
                "LastEventTime": "1970-01-01T00:00:00+00:00",
                "ModifiedDate": "2020-10-18T19:40:19.701000+00:00",
                "Name": "Anomaly Detection Engine-2 :: ip-192.168.1.3",
                "ProtocolParameters": [
                    {
                        "id": 0,
                        "name": "identifier",
                        "value": "127.0.0.1"
                    },
                    {
                        "id": 1,
                        "name": "incomingPayloadEncoding",
                        "value": "UTF-8"
                    }
                ],
                "ProtocolTypeID": 0,
                "Status": {
                    "last_updated": 0,
                    "status": "NA"
                },
                "TypeID": 207
            },
            {
                "AutoDiscovered": false,
                "CreationDate": "2020-10-18T19:40:19.705000+00:00",
                "Credibility": 10,
                "Description": "Search Results",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 68,
                "Internal": true,
                "LastEventTime": "2020-10-18T20:44:40.857000+00:00",
                "ModifiedDate": "2020-10-18T19:40:19.705000+00:00",
                "Name": "Search Results-2 :: ip-192.168.1.3",
                "ProtocolParameters": [
                    {
                        "id": 0,
                        "name": "identifier",
                        "value": "127.0.0.1"
                    },
                    {
                        "id": 1,
                        "name": "incomingPayloadEncoding",
                        "value": "UTF-8"
                    }
                ],
                "ProtocolTypeID": 0,
                "Status": {
                    "last_updated": 0,
                    "messages": [
                        {
                            "severity": "ERROR",
                            "text": "Events have not been received from this Log Source in over 720 minutes."
                        }
                    ],
                    "status": "ERROR"
                },
                "TypeID": 355
            },
            {
                "AutoDiscovered": false,
                "CreationDate": "2020-10-18T19:40:19.703000+00:00",
                "Credibility": 10,
                "Description": "Asset Profiler",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 67,
                "Internal": true,
                "LastEventTime": "2021-03-02T13:51:53.892000+00:00",
                "ModifiedDate": "2020-10-18T19:40:19.703000+00:00",
                "Name": "Asset Profiler-2 :: ip-192.168.1.3",
                "ProtocolParameters": [
                    {
                        "id": 0,
                        "name": "identifier",
                        "value": "127.0.0.1"
                    },
                    {
                        "id": 1,
                        "name": "incomingPayloadEncoding",
                        "value": "UTF-8"
                    }
                ],
                "ProtocolTypeID": 0,
                "Status": {
                    "last_updated": 0,
                    "messages": [
                        {
                            "severity": "ERROR",
                            "text": "Events have not been received from this Log Source in over 720 minutes."
                        }
                    ],
                    "status": "ERROR"
                },
                "TypeID": 267
            }
        ]
    }
}
```

#### Human Readable Output

>### Log Sources List
>|ID|Name|Description|SendingIP|LastEventTime|CreationDate|ProtocolParameters|TypeID|Internal|Gateway|ProtocolTypeID|Status|GroupIDs|Credibility|AutoDiscovered|ModifiedDate|Enabled|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 66 | Anomaly Detection Engine-2 :: ip-192.168.1.3 | Anomaly Detection Engine |  | 1970-01-01T00:00:00+00:00 | 2020-10-18T19:40:19.701000+00:00 | {'name': 'identifier', 'id': 0, 'value': '127.0.0.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | 207 | true | false | 0 | last_updated: 0<br/>status: NA | 0 | 10 | false | 2020-10-18T19:40:19.701000+00:00 | true |
>| 68 | Search Results-2 :: ip-192.168.1.3 | Search Results |  | 2020-10-18T20:44:40.857000+00:00 | 2020-10-18T19:40:19.705000+00:00 | {'name': 'identifier', 'id': 0, 'value': '127.0.0.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | 355 | true | false | 0 | last_updated: 0<br/>messages: {'severity': 'ERROR', 'text': 'Events have not been received from this Log Source in over 720 minutes.'}<br/>status: ERROR | 0 | 10 | false | 2020-10-18T19:40:19.705000+00:00 | true |
>| 67 | Asset Profiler-2 :: ip-192.168.1.3 | Asset Profiler |  | 2021-03-02T13:51:53.892000+00:00 | 2020-10-18T19:40:19.703000+00:00 | {'name': 'identifier', 'id': 0, 'value': '127.0.0.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | 267 | true | false | 0 | last_updated: 0<br/>messages: {'severity': 'ERROR', 'text': 'Events have not been received from this Log Source in over 720 minutes.'}<br/>status: ERROR | 0 | 10 | false | 2020-10-18T19:40:19.703000+00:00 | true |

### qradar-get-custom-properties
***
Retrieves a list of event regex properties.


#### Base Command

`qradar-get-custom-properties`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field_name | A comma-separated list of names of the exact properties to search for. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter regex properties, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,gateway". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--config-event_sources-custom_properties-regex_properties-GET.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Properties.identifier | String | ID of the event regex property. | 
| QRadar.Properties.modification_date | Date | Date when the event regex property was last updated. | 
| QRadar.Properties.datetime_format | String | Date/time pattern that the event regex property matches. | 
| QRadar.Properties.property_type | String | Property type. Possible values: "STRING", "NUMERIC", "IP", "PORT", "TIME". | 
| QRadar.Properties.name | String | Name of the event regex property. | 
| QRadar.Properties.auto_discovered | Boolean | Whether the event regex property was auto discovered. | 
| QRadar.Properties.description | String | Description of the event regex property. | 
| QRadar.Properties.id | Number | ID of the event regex property. | 
| QRadar.Properties.use_for_rule_engine | Boolean | Whether the event regex property is parsed when the event is received. | 
| QRadar.Properties.creation_date | Date | Date when the event regex property was created. | 
| QRadar.Properties.locale | String | Language tag of what locale the property matches. | 
| QRadar.Properties.username | String | The owner of the event regex property. | 


#### Command Example
```!qradar-get-custom-properties filter="id between 90 and 100" range=1-1231```

#### Context Example
```json
{
    "QRadar": {
        "Properties": [
            {
                "auto_discovered": false,
                "creation_date": "2008-09-13T00:52:08.857000+00:00",
                "description": "Default custom extraction of the duration in minutes from DSM payload.",
                "id": 98,
                "identifier": "DEFAULTCUSTOMEVENT3",
                "modification_date": "2008-09-13T00:52:08.857000+00:00",
                "name": "Duration_Minutes",
                "property_type": "numeric",
                "use_for_rule_engine": false,
                "username": "admin"
            },
            {
                "auto_discovered": false,
                "creation_date": "2008-09-13T00:52:08.857000+00:00",
                "description": "Default custom extraction of the duration in seconds from DSM payload.",
                "id": 99,
                "identifier": "DEFAULTCUSTOMEVENT4",
                "modification_date": "2008-09-13T00:52:08.857000+00:00",
                "name": "Duration_Seconds",
                "property_type": "numeric",
                "use_for_rule_engine": false,
                "username": "admin"
            },
            {
                "auto_discovered": false,
                "creation_date": "2008-09-13T00:52:08.857000+00:00",
                "description": "Default custom extraction of realm from DSM payload.",
                "id": 100,
                "identifier": "DEFAULTCUSTOMEVENT5",
                "modification_date": "2008-09-13T00:52:08.857000+00:00",
                "name": "Realm",
                "property_type": "string",
                "use_for_rule_engine": false,
                "username": "admin"
            },
            {
                "auto_discovered": false,
                "creation_date": "2008-09-13T00:52:08.857000+00:00",
                "description": "Default custom extraction of role from DSM payload.",
                "id": 96,
                "identifier": "DEFAULTCUSTOMEVENT1",
                "modification_date": "2008-09-13T00:52:08.857000+00:00",
                "name": "Role",
                "property_type": "string",
                "use_for_rule_engine": false,
                "username": "admin"
            }
        ]
    }
}
```

#### Human Readable Output

>### Custom Properties
>|auto_discovered|creation_date|description|id|identifier|modification_date|name|property_type|use_for_rule_engine|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | 2008-09-13T00:52:08.857000+00:00 | Default custom extraction of the duration in minutes from DSM payload. | 98 | DEFAULTCUSTOMEVENT3 | 2008-09-13T00:52:08.857000+00:00 | Duration_Minutes | numeric | false | admin |
>| false | 2008-09-13T00:52:08.857000+00:00 | Default custom extraction of the duration in seconds from DSM payload. | 99 | DEFAULTCUSTOMEVENT4 | 2008-09-13T00:52:08.857000+00:00 | Duration_Seconds | numeric | false | admin |
>| false | 2008-09-13T00:52:08.857000+00:00 | Default custom extraction of realm from DSM payload. | 100 | DEFAULTCUSTOMEVENT5 | 2008-09-13T00:52:08.857000+00:00 | Realm | string | false | admin |
>| false | 2008-09-13T00:52:08.857000+00:00 | Default custom extraction of role from DSM payload. | 96 | DEFAULTCUSTOMEVENT1 | 2008-09-13T00:52:08.857000+00:00 | Role | string | false | admin |


### qradar-reset-last-run
***
Resets the fetch incidents last run value, which resets the fetch to its initial fetch state. (Will try to fetch the first available offense).
**Please Note**: It is recommended to *disable* and then *enable* the QRadar instance for the reset to take effect immediately.

#### Base Command

`qradar-reset-last-run`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!qradar-reset-last-run```

#### Human Readable Output

>fetch-incidents was reset successfully.


### qradar-ips-source-get
***
Get Source IPs


#### Base Command

`qradar-ips-source-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_ip | Comma separated list. Source IPs to retrieve their data, E.g "192.168.0.1,192.160.0.2". | Optional | 
| filter | Query to filter IPs. E.g, filter=`source_ip="192.168.0.1"`. For reference please consult: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the ones specified. Use this argument to specify which fields should be returned in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/docs/en/qradar-common?topic=endpoints-get-siemsource-addresses | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SourceIP.ID | Number | The ID of the destination address. | 
| QRadar.SourceIP.DomainID | String | The ID of associated domain. | 
| QRadar.SourceIP.EventFlowCount | Number | The number of events and flows that are associated with the destination address. | 
| QRadar.SourceIP.FirstEventFlowSeen | Date | Date when the first event or flow was seen. | 
| QRadar.SourceIP.LastEventFlowSeen | Date | Date when the last event or flow was seen. | 
| QRadar.SourceIP.SourceIP | String | The IP address. | 
| QRadar.SourceIP.Magnitude | Number | The magnitude of the destination address. | 
| QRadar.SourceIP.Network | String | The network of the destination address. | 
| QRadar.SourceIP.OffenseIDs | Unknown | List of offense IDs the destination address is part of. | 
| QRadar.SourceIP.LocalDestinationAddressIDs | Unknown | List of local destination address IDs associated with the source address. | 


#### Command Example
```!qradar-ips-source-get filter=`source_ip="172.42.18.211"` range=0-2```

#### Context Example
```json
{
    "QRadar": {
        "SourceIP": {
            "DomainID": 0,
            "EventFlowCount": 1081,
            "FirstEventFlowSeen": "2021-03-31T10:02:25.972000+00:00",
            "ID": 1,
            "LastEventFlowSeen": "2021-08-14T09:59:52.596000+00:00",
            "LocalDestinationAddressIDs": [
                1,
                2,
                3,
                4,
                5
            ],
            "Magnitude": 0,
            "Network": "Net-10-172-192.Net_172_16_0_0",
            "OffenseIDs": [
                1,
                4,
                5,
                9,
                10,
                11
            ],
            "SourceIP": "172.42.18.211"
        }
    }
}
```

#### Human Readable Output

>### Source IPs
>|DomainID|EventFlowCount|FirstEventFlowSeen|ID|LastEventFlowSeen|LocalDestinationAddressIDs|Magnitude|Network|OffenseIDs|SourceIP|
>|---|---|---|---|---|---|---|---|---|---|
>| 0 | 1081 | 2021-03-31T10:02:25.972000+00:00 | 1 | 2021-08-14T09:59:52.596000+00:00 | 1,<br/>2,<br/>3,<br/>4,<br/>5 | 0 | Net-10-172-192.Net_172_16_0_0 | 1,<br/>4,<br/>5,<br/>9,<br/>10,<br/>11,<br/>12,<br/>13,<br/>14,<br/>15,<br/>16,<br/>17,<br/>18,<br/>19,<br/>20,<br/>21,<br/>22,<br/>23,<br/>24,<br/>25,<br/>27,<br/>28,<br/>29,<br/>30,<br/>31,<br/>32,<br/>33,<br/>34,<br/>35,<br/>36,<br/>37,<br/>38,<br/>39,<br/>40,<br/>41,<br/>42 | 172.42.18.211 |


### qradar-ips-local-destination-get
***
Get Source IPs


#### Base Command

`qradar-ips-local-destination-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_destination_ip | Comma separated list. Local destination IPs to retrieve their data, E.g "192.168.0.1,192.160.0.2". | Optional | 
| filter | If used, will filter all fields except for the ones specified. Use this argument to specify which fields should be returned in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/docs/en/qradar-common?topic=endpoints-get-siemlocal-destination-addresses | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/docs/en/qradar-common?topic=endpoints-get-siemlocal-destination-addresses. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LocalDestinationIP.ID | Number | The ID of the destination address. | 
| QRadar.LocalDestinationIP.DomainID | String | The ID of associated domain. | 
| QRadar.LocalDestinationIP.EventFlowCount | Number | The number of events and flows that are associated with the destination address. | 
| QRadar.LocalDestinationIP.FirstEventFlowSeen | Date | Date when the first event or flow was seen. | 
| QRadar.LocalDestinationIP.LastEventFlowSeen | Date | Date when the last event or flow was seen. | 
| QRadar.LocalDestinationIP.LocalDestinationIP | String | The IP address. | 
| QRadar.LocalDestinationIP.Magnitude | Number | The magnitude of the destination address. | 
| QRadar.LocalDestinationIP.Network | String | The network of the destination address. | 
| QRadar.LocalDestinationIP.OffenseIDs | Unknown | List of offense IDs the destination address is part of. | 
| QRadar.LocalDestinationIP.SourceAddressIDs | Unknown | List of source address IDs associated with the destination address. | 


#### Command Example
```!qradar-ips-local-destination-get filter=`local_destination_ip="172.42.18.211"````

#### Context Example
```json
{
    "QRadar": {
        "LocalDestinationIP": {
            "DomainID": 0,
            "EventFlowCount": 1635,
            "FirstEventFlowSeen": "2021-03-31T10:02:25.965000+00:00",
            "ID": 1,
            "LastEventFlowSeen": "2021-08-14T09:59:52.596000+00:00",
            "LocalDestinationIP": "172.42.18.211",
            "Magnitude": 0,
            "Network": "Net-10-172-192.Net_172_16_0_0",
            "OffenseIDs": [
                1,
                4,
                5
            ],
            "SourceAddressIDs": [
                1,
                2
            ]
        }
    }
}
```

#### Human Readable Output

>### Local Destination IPs
>|DomainID|EventFlowCount|FirstEventFlowSeen|ID|LastEventFlowSeen|LocalDestinationIP|Magnitude|Network|OffenseIDs|SourceAddressIDs|
>|---|---|---|---|---|---|---|---|---|---|
>| 0 | 1635 | 2021-03-31T10:02:25.965000+00:00 | 1 | 2021-08-14T09:59:52.596000+00:00 | 172.42.18.211 | 0 | Net-10-172-192.Net_172_16_0_0 | 1,<br/>4,<br/>5,<br/>9,<br/>10,<br/>11,<br/>12,<br/>13,<br/>14,<br/>15,<br/>16,<br/>17,<br/>18,<br/>19,<br/>20,<br/>21,<br/>22,<br/>23,<br/>24,<br/>25,<br/>26,<br/>27,<br/>28,<br/>29,<br/>30,<br/>31,<br/>32,<br/>33,<br/>34,<br/>35,<br/>36,<br/>37,<br/>38,<br/>39,<br/>40,<br/>41,<br/>42 | 1,<br/>2 |

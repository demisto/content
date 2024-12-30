IBM QRadar SIEM helps security teams accurately detect and prioritize threats across the enterprise, supports API versions 10.1 and above. Provides intelligent insights that enable teams to respond quickly to reduce the impact of incidents.
This integration was integrated and tested with version 14-20 of QRadar v3

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure IBM QRadar v3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | -- | --- |
| Server URL | \(e.g., https://1.1.1.1\) | True |
| Username |  | True |
| Password |  | True |
| QRadar API Version | API version of QRadar \(e.g., '12.0'\). Minimum API version is 10.1. | True |
| Incident Type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | if no offenses are found within the range of first fetch, will be set to fetch the earliest offense. | False |
| Fetch mode |  | True |
| Retry events fetch | Whenever enabled, the integration retries to fetch all events if the number of events fetched is less than \`event_count\`. Default number of tries is 3, but can be configured via the Advanced Parameter: EVENTS_SEARCH_TRIES. e.g EVENTS_SEARCH_TRIES=5 | False |
| Maximum number of events per incident. | The maximal amount of events to pull per incident. | False |
| Number of offenses to pull per API call (max 50) | In case of mirroring with events, this value will be used for mirroring API calls as well, and it is advised to have a small value. | False |
| Query to fetch offenses. | Define a query to determine which offenses to fetch. E.g., "severity &gt;= 4 AND id &gt; 5". | False |
| Incidents Enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. | True |
| Event fields to return from the events query (WARNING: This parameter is correlated to the incoming mapper and changing the values may adversely affect mapping). | The parameter uses the AQL SELECT syntax. For more information, see: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.4/com.ibm.qradar.doc/c_aql_intro.html | False |
| Mirroring Options | How mirroring from QRadar to Cortex XSOAR should be done, available from QRadar 7.3.3 Fix Pack 3. For further explanation on how to check your QRadar version, see the integration documentation at https://xsoar.pan.dev. | False |
| Close Mirrored XSOAR Incident | When selected, closing the QRadar offense is mirrored in Cortex XSOAR. | False |
| The number of incoming incidents to mirror each time | Maximum number of incoming incidents to mirror each time. | False |
| Advanced Parameters | Comma-separated configuration for advanced parameter values. E.g., EVENTS_INTERVAL_SECS=20,FETCH_SLEEP=5 | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Timeout for http-requests | The timeout of the HTTP requests sent to the Qradar API (in seconds). If no value is provided, the timeout will be set to 60 seconds. | False |
| Fetch Incidents Interval | The fetch interval between before each fetch-incidents execution. (seconds) | False |

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
## Mapping Limitation for Cortex XSOAR Versions below 6.0.0
The *Pull from instance* option to create a new mapper is not supported in Cortex XSOAR versions below 6.0.0. 

## Creating a Classifier Using the *Pull from instance* Parameter
QRadar fetches incidents using a long-running execution, not in real time. Therefore, *Pull from instance* pulls incidents from the QRadar service to create a classifier using samples, not real time data. This results in seeing the latest sample stored, and not the latest offense that was fetched.  

## Important Note Regarding the *Query to fetch offenses* Parameter
The *Query to fetch offenses* feature enables defining a specific query for offenses to be retrieved, e.g., **'status = OPEN and id = 5'**. The QRadar integration keeps track of IDs that have already been fetched in order to avoid duplicate fetching.   
If you change the *Query to fetch offenses* value, it will not re-fetch offenses that have already been fetched. To re-fetch those offenses, run the ***qradar-reset-last-run*** command.  
**Note:**  
The list of QRadar IDs that were already fetched will be reset and duplicate offenses could be re-fetched, depending on the user query.  
## Migration from QRadar v2 to QRadar v3
Every command and playbook that runs in QRadar v2 also runs in QRadar v3. No adjustments are required.
### Additions and Changes from QRadar v2 to QRadar v3
### New Commands
- ***qradar-rule-groups-list***
- ***qradar-searches-list***
- ***qradar-geolocations-for-ip***
- ***qradar-log-sources-list***
- ***qradar-upload-indicators***
- ***get-modified-remote-data***

### Command Name Changes
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
| qradar-get-domain-by-id| qradar-domains-list | Specify the *domain_id* argument in the command. |  |


## Mirroring
This integration supports in mirroring from QRadar offenses to Cortex XSOAR.  
When a field of an offense is updated in QRadar services, the update is mirrored in Cortex XSOAR.
### Mirroring Events
* Mirroring events from QRadar to Cortex XSOAR is supported via the **Mirror Offense and Events** option.
* Events will only be mirrored in the incoming direction.
* Mirroring events will only work when the **Long running instance** parameter is enabled.
* Filtering events using the  *events_limit* and *events_columns* options for mirrored incidents will be the same as in the fetched incidents.
* The integration will always mirror the events that occurred first in each offense.

For more information about mirroring configurations, see [here](https://xsoar.pan.dev/docs/integrations/mirroring_integration).  

## Use the API Token Instead of Username and Password
- In the **Username / API Key** field, type **_api_token_key**.  
- In the **Password** field, type your API token.
## Choose Your API Version
1. Visit the [QRadar API versions page](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_getting_started.html) for a full list of available API versions according to the QRadar version.
2. Choose one of the API versions listed under the **Supported REST API versions** column in the line corresponding to your QRadar version.

**Note:**  
If you're uncertain which API version to use, it is recommended to use the latest API version listed in the **Supported REST API versions** column in the line corresponding to your QRadar version.
## View Your QRadar Version
1. Enter QRadar service.
2. Click the **Menu** toolbar. A scrolling toolbar will appear.
3. Click **About**. A new window will appear with the details of your QRadar version.

## Troubleshooting

When *Fetch with events* is configured, the integration will fetch the offense events from `QRadar`.
Nevertheless, some events may not be available when trying to fetch them during an incident creation. If **Retry events fetch** is enabled, the integration tries to fetch more events when the number fetched is less than the expected `event_count`. In the default setting, the integration will try 3 times, with a wait time of 100 seconds between retries.
In order to change the default values, configure the following **Advanced Parameters** in the instance configuration:
```
EVENTS_SEARCH_TRIES=<amount of tries for events search> (default 3),EVENTS_SEARCH_RETRY_SECONDS=<amount of seconds to wait between tries> (default 100),EVENTS_POLLING_TRIES=<number of times to poll for one search> (default 10),
```
It is recommended to enable [mirroring](#mirroring-events), as it should fetch previously missed events when the offense is updated.
Alternatively, the [retrieve events command](#qradar-search-retrieve-events) can be used to retrieve the `events` immediately.
If the command takes too long to finish executing, try setting the `interval_in_seconds` to a lower value (down to a minimum of 10 seconds).


### API Call Metrics

This feature collects metadata on QRadar API calls and their success status.

API Call metrics are not available for long-running commands such as `fetch incidents`.

API Metrics are shown in the built-in **API Execution Metrics** dashboard, and are available to use in custom widgets.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,severity,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-offenses-GET.html. | Optional | 

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

#### Command example
```!qradar-offenses-list enrichment=IPs filter="status=OPEN" range=0-2```
#### Context Example
```json
{
    "QRadar": {
        "Offense": [
            {
                "AssignedTo": "admin",
                "Categories": [
                    "Information",
                    "Suspicious Activity",
                    "Process Creation Success",
                    "Suspicious Windows Events",
                    "User Login Attempt",
                    "Misc Login Succeeded",
                    "Virtual Machine Creation Attempt",
                    "Read Activity Attempted",
                    "Object Download Attempt"
                ],
                "Credibility": 4,
                "Description": "Detected A Successful Login From Different Geographies For the Same Username - AWSCloud (Exp Center)\n preceded by An AWS API Has Been Invoked From Kali - AWSCloud (Exp Center)\n preceded by Microsoft Word Launc\n preceded by Detected a Massive Creation of EC2 Instances - AWSCloud (Exp Center)\n containing Mail Server Info Message\n",
                "DestinationAddress": [
                    "1.1.1.1",
                    "1.1.1.1"
                ],
                "DestinationHostname": [
                    "other",
                    "Net-10-172-192.Net_192_168_0_0"
                ],
                "EventCount": 35651,
                "FlowCount": 0,
                "Followup": true,
                "ID": 14,
                "LastUpdatedTime": "2023-07-26T15:31:11.839000+00:00",
                "LinkToOffense": "https://ec2.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14",
                "Magnitude": 4,
                "OffenseSource": "userD",
                "OffenseType": "Username",
                "Protected": false,
                "Relevance": 0,
                "RemoteDestinationCount": 1,
                "Rules": [
                    {
                        "id": 102539,
                        "name": "EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender",
                        "type": "CRE_RULE"
                    },
                    {
                        "id": 102589,
                        "name": "EC: AWS Cloud - Microsoft Word Launched a Command Shell",
                        "type": "CRE_RULE"
                    },
                    {
                        "id": 102639,
                        "name": "EC: AWS Cloud - Detected A Successful Login From Different Geographies For the Same Username",
                        "type": "CRE_RULE"
                    },
                    {
                        "id": 102389,
                        "name": "EC: AWS Cloud - An AWS API Has Been Invoked From Kali",
                        "type": "CRE_RULE"
                    },
                    {
                        "id": 102439,
                        "name": "EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket",
                        "type": "CRE_RULE"
                    },
                    {
                        "id": 102489,
                        "name": "EC: AWS Cloud - Detected a Massive Creation of EC2 Instances",
                        "type": "CRE_RULE"
                    }
                ],
                "Severity": 10,
                "SourceAddress": [
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1"
                ],
                "StartTime": "2023-07-26T14:31:13.387000+00:00",
                "Status": "OPEN"
            },
            {
                "Categories": [
                    "Mail",
                    "System Failure"
                ],
                "Credibility": 2,
                "Description": "Flow Source/Interface Stopped Sending Flows\n",
                "DestinationAddress": [
                    "1.1.1.1"
                ],
                "DestinationHostname": [
                    "Net-10-172-192.Net_10_0_0_0"
                ],
                "EventCount": 2,
                "FlowCount": 6026,
                "Followup": true,
                "ID": 13,
                "LastUpdatedTime": "2023-06-12T08:49:50.145000+00:00",
                "LinkToOffense": "https://ec2.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=13",
                "Magnitude": 1,
                "OffenseSource": "Flow Source Stopped Sending Flows",
                "OffenseType": "Rule",
                "Protected": true,
                "Relevance": 0,
                "RemoteDestinationCount": 0,
                "Rules": [
                    {
                        "id": 100270,
                        "name": "Flow Source Stopped Sending Flows",
                        "type": "CRE_RULE"
                    }
                ],
                "Severity": 1,
                "SourceAddress": [
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1"
                ],
                "StartTime": "2023-06-12T08:19:02.020000+00:00",
                "Status": "OPEN"
            },
            {
                "Categories": [
                    "User Activity"
                ],
                "Credibility": 3,
                "Description": "User Account Created and Used and Deleted within a short time frame (Exp Center)\n",
                "DestinationAddress": [
                    "1.1.1.1"
                ],
                "DestinationHostname": [
                    "Net-10-172-192.Net_172_16_0_0"
                ],
                "EventCount": 8,
                "FlowCount": 0,
                "Followup": true,
                "ID": 12,
                "LastUpdatedTime": "2023-06-12T08:17:33.008000+00:00",
                "LinkToOffense": "https://ec2.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=12",
                "Magnitude": 2,
                "OffenseSource": "badadmin",
                "OffenseType": "Username",
                "Protected": true,
                "Relevance": 0,
                "RemoteDestinationCount": 0,
                "Rules": [
                    {
                        "id": 102989,
                        "name": "EC: User Account Created and Used and Removed",
                        "type": "CRE_RULE"
                    }
                ],
                "Severity": 5,
                "SourceAddress": [
                    "1.1.1.1"
                ],
                "StartTime": "2023-06-12T08:15:54.740000+00:00",
                "Status": "OPEN"
            }
        ]
    }
}
```

#### Human Readable Output

>### Offenses List
>|ID|Description|OffenseType|Status|Severity|DestinationHostname|LastUpdatedTime|Credibility|Rules|SourceAddress|AssignedTo|OffenseSource|Followup|EventCount|StartTime|FlowCount|DestinationAddress|LinkToOffense|RemoteDestinationCount|Relevance|Categories|Magnitude|Protected|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 14 | Detected A Successful Login From Different Geographies For the Same Username - AWSCloud (Exp Center)<br/> preceded by An AWS API Has Been Invoked From Kali - AWSCloud (Exp Center)<br/> preceded by Microsoft Word Launc<br/> preceded by Detected a Massive Creation of EC2 Instances - AWSCloud (Exp Center)<br/> containing Mail Server Info Message<br/> | Username | OPEN | 10 | other,<br/>Net-10-172-192.Net_192_168_0_0 | 2023-07-26T15:31:11.839000+00:00 | 4 | {'id': 102539, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender'},<br/>{'id': 102589, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Microsoft Word Launched a Command Shell'},<br/>{'id': 102639, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected A Successful Login From Different Geographies For the Same Username'},<br/>{'id': 102389, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - An AWS API Has Been Invoked From Kali'},<br/>{'id': 102439, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket'},<br/>{'id': 102489, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected a Massive Creation of EC2 Instances'} | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | admin | userD | true | 35651 | 2023-07-26T14:31:13.387000+00:00 | 0 | 1.1.1.1,<br/>1.1.1.1 | https://ec2.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14 | 1 | 0 | Information,<br/>Suspicious Activity,<br/>Process Creation Success,<br/>Suspicious Windows Events,<br/>User Login Attempt,<br/>Misc Login Succeeded,<br/>Virtual Machine Creation Attempt,<br/>Read Activity Attempted,<br/>Object Download Attempt | 4 | false |
>| 13 | Flow Source/Interface Stopped Sending Flows<br/> | Rule | OPEN | 1 | Net-10-172-192.Net_10_0_0_0 | 2023-06-12T08:49:50.145000+00:00 | 2 | {'id': 100270, 'type': 'CRE_RULE', 'name': 'Flow Source Stopped Sending Flows'} | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 |  | Flow Source Stopped Sending Flows | true | 2 | 2023-06-12T08:19:02.020000+00:00 | 6026 | 1.1.1.1 | https://ec2-1.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=13 | 0 | 0 | Mail,<br/>System Failure | 1 | true |
>| 12 | User Account Created and Used and Deleted within a short time frame (Exp Center)<br/> | Username | OPEN | 5 | Net-10-172-192.Net_172_16_0_0 | 2023-06-12T08:17:33.008000+00:00 | 3 | {'id': 102989, 'type': 'CRE_RULE', 'name': 'EC: User Account Created and Used and Removed'} | 1.1.1.1 |  | badadmin | true | 8 | 2023-06-12T08:15:54.740000+00:00 | 0 | 1.1.1.1 | https://ec2-3.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=12 | 0 | 0 | User Activity | 2 | true |


### qradar-offense-update

***
Updates an offense.

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
| closing_reason_name | The name of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation. | Optional | 
| assigned_to | User to assign the offense to. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,severity,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-offenses-offense_id-POST.html. | Optional | 

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

#### Command example
```!qradar-offense-update offense_id=14 assigned_to=admin enrichment="IPs And Assets" follow_up=true status=OPEN protected=false```
#### Context Example
```json
{
    "QRadar": {
        "Offense": {
            "AssignedTo": "admin",
            "Categories": [
                "Information",
                "Suspicious Activity",
                "Process Creation Success",
                "Suspicious Windows Events",
                "User Login Attempt",
                "Misc Login Succeeded",
                "Virtual Machine Creation Attempt",
                "Read Activity Attempted",
                "Object Download Attempt"
            ],
            "Credibility": 4,
            "Description": "Detected A Successful Login From Different Geographies For the Same Username - AWSCloud (Exp Center)\n preceded by An AWS API Has Been Invoked From Kali - AWSCloud (Exp Center)\n preceded by Microsoft Word Launc\n preceded by Detected a Massive Creation of EC2 Instances - AWSCloud (Exp Center)\n containing Mail Server Info Message\n",
            "DestinationAddress": [
                "1.1.1.1",
                "1.1.1.1"
            ],
            "DestinationHostname": [
                "other",
                "Net-10-172-192.Net_192_168_0_0"
            ],
            "EventCount": 35651,
            "FlowCount": 0,
            "Followup": true,
            "ID": 14,
            "LastUpdatedTime": "2023-07-26T15:31:11.839000+00:00",
            "LinkToOffense": "https://ec2-1.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14",
            "Magnitude": 4,
            "OffenseSource": "userD",
            "OffenseType": "Username",
            "Protected": false,
            "Relevance": 0,
            "RemoteDestinationCount": 1,
            "Rules": [
                {
                    "id": 102539,
                    "name": "EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender",
                    "type": "CRE_RULE"
                },
                {
                    "id": 102589,
                    "name": "EC: AWS Cloud - Microsoft Word Launched a Command Shell",
                    "type": "CRE_RULE"
                },
                {
                    "id": 102639,
                    "name": "EC: AWS Cloud - Detected A Successful Login From Different Geographies For the Same Username",
                    "type": "CRE_RULE"
                },
                {
                    "id": 102389,
                    "name": "EC: AWS Cloud - An AWS API Has Been Invoked From Kali",
                    "type": "CRE_RULE"
                },
                {
                    "id": 102439,
                    "name": "EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket",
                    "type": "CRE_RULE"
                },
                {
                    "id": 102489,
                    "name": "EC: AWS Cloud - Detected a Massive Creation of EC2 Instances",
                    "type": "CRE_RULE"
                }
            ],
            "Severity": 10,
            "SourceAddress": [
                "1.1.1.1",
                "1.1.1.1",
                "1.1.1.1",
                "1.1.1.1"
            ],
            "StartTime": "2023-07-26T14:31:13.387000+00:00",
            "Status": "OPEN"
        }
    }
}
```

#### Human Readable Output

>### offense Update
>|ID|Description|OffenseType|Status|Severity|DestinationHostname|LastUpdatedTime|Credibility|Rules|SourceAddress|AssignedTo|OffenseSource|Followup|EventCount|StartTime|FlowCount|DestinationAddress|LinkToOffense|RemoteDestinationCount|Relevance|Categories|Magnitude|Protected|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 14 | Detected A Successful Login From Different Geographies For the Same Username - AWSCloud (Exp Center)<br/> preceded by An AWS API Has Been Invoked From Kali - AWSCloud (Exp Center)<br/> preceded by Microsoft Word Launc<br/> preceded by Detected a Massive Creation of EC2 Instances - AWSCloud (Exp Center)<br/> containing Mail Server Info Message<br/> | Username | OPEN | 10 | other,<br/>Net-10-172-192.Net_192_168_0_0 | 2023-07-26T15:31:11.839000+00:00 | 4 | {'id': 102539, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender'},<br/>{'id': 102589, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Microsoft Word Launched a Command Shell'},<br/>{'id': 102639, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected A Successful Login From Different Geographies For the Same Username'},<br/>{'id': 102389, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - An AWS API Has Been Invoked From Kali'},<br/>{'id': 102439, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket'},<br/>{'id': 102489, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected a Massive Creation of EC2 Instances'} | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | admin | userD | true | 35651 | 2023-07-26T14:31:13.387000+00:00 | 0 | 1.1.1.1,<br/>1.1.1.1 | https://ec2-1.eu.compute-1.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14 | 1 | 0 | Information,<br/>Suspicious Activity,<br/>Process Creation Success,<br/>Suspicious Windows Events,<br/>User Login Attempt,<br/>Misc Login Succeeded,<br/>Virtual Machine Creation Attempt,<br/>Read Activity Attempted,<br/>Object Download Attempt | 4 | false |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-offense_closing_reasons-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.ClosingReasons.IsDeleted | Boolean | Whether the closing reason is deleted. Deleted closing reasons cannot be used to close an offense. | 
| QRadar.Offense.ClosingReasons.IsReserved | Boolean | Whether the closing reason is reserved. Reserved closing reasons cannot be used to close an offense. | 
| QRadar.Offense.ClosingReasons.Name | String | Name of the closing reason. | 
| QRadar.Offense.ClosingReasons.ID | Number | ID of the closing reason. | 

#### Command example
```!qradar-closing-reasons include_deleted=true include_reserved=true```
#### Context Example
```json
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
}
```

#### Human Readable Output

>### Closing Reasons
>|ID|Name|IsReserved|IsDeleted|
>|---|---|---|---|
>| 2 | False-Positive, Tuned | false | false |
>| 1 | Non-Issue | false | false |
>| 3 | Policy Violation | false | false |
>| 4 | System Change (Upgrade, Reset, etc.) | true | false |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "username,note_text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-offenses-offense_id-notes-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.Text | String | The text of the note. | 
| QRadar.Note.CreateTime | Date | Creation date of the note. | 
| QRadar.Note.ID | Number | ID of the note. | 
| QRadar.Note.CreatedBy | String | The user who created the note. | 

#### Command example
```!qradar-offense-notes-list offense_id=14 filter="username='API_user: admin'" range=0-1```
#### Context Example
```json
{
    "QRadar": {
        "Note": [
            {
                "CreateTime": "2023-07-27T13:58:46.428000+00:00",
                "CreatedBy": "API_user: admin",
                "ID": 53,
                "Text": "Note Regarding The Offense"
            },
            {
                "CreateTime": "2023-08-02T08:23:05.473000+00:00",
                "CreatedBy": "API_user: admin",
                "ID": 60,
                "Text": "Note Regarding The Offense"
            }
        ]
    }
}
```

#### Human Readable Output

>### Offense Notes List For Offense ID 14
>|ID|Text|CreatedBy|CreateTime|
>|---|---|---|---|
>| 53 | Note Regarding The Offense | API_user: admin | 2023-07-27T13:58:46.428000+00:00 |
>| 60 | Note Regarding The Offense | API_user: admin | 2023-08-02T08:23:05.473000+00:00 |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "username,note_text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-offenses-offense_id-notes-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.Text | String | The text of the note. | 
| QRadar.Note.CreateTime | Date | Creation date of the note. | 
| QRadar.Note.ID | Number | ID of the note. | 
| QRadar.Note.CreatedBy | String | The user who created the note. | 

#### Command example
```!qradar-offense-note-create note_text="Note Regarding The Offense" offense_id=14```
#### Context Example
```json
{
    "QRadar": {
        "Note": {
            "CreateTime": "2023-08-02T08:39:15.813000+00:00",
            "CreatedBy": "API_user: admin",
            "ID": 65,
            "Text": "Note Regarding The Offense"
        }
    }
}
```

#### Human Readable Output

>### Create Note
>|ID|Text|CreatedBy|CreateTime|
>|---|---|---|---|
>| 65 | Note Regarding The Offense | API_user: admin | 2023-08-02T08:39:15.813000+00:00 |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "owner,identifier,origin". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--analytics-rules-GET.html. | Optional | 

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

#### Command example
```!qradar-rules-list rule_type=COMMON range=0-2```
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
                "ID": 100068,
                "ModificationDate": "2022-11-21T18:44:32.696000+00:00",
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
                "ID": 100102,
                "ModificationDate": "2023-02-23T14:12:52.067000+00:00",
                "Name": "Potential Botnet Connection (DNS)",
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
                "ID": 100109,
                "ModificationDate": "2023-02-23T14:12:49.992000+00:00",
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
>|ID|Name|Type|Enabled|BaseHostID|Origin|ModificationDate|CreationDate|BaseCapacity|AverageCapacity|Owner|CapacityTimestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100068 | Login Successful After Scan Attempt | COMMON | true | 0 | SYSTEM | 2022-11-21T18:44:32.696000+00:00 | 2007-10-14T20:12:00.374000+00:00 | 0 | 0 | admin | 0 |
>| 100102 | Potential Botnet Connection (DNS) | COMMON | false | 0 | SYSTEM | 2023-02-23T14:12:52.067000+00:00 | 2006-03-27T10:54:12.077000+00:00 | 0 | 0 | admin | 0 |
>| 100109 | Host Port Scan Detected by Remote Host | COMMON | true | 0 | SYSTEM | 2023-02-23T14:12:49.992000+00:00 | 2005-12-22T00:54:48.708000+00:00 | 0 | 0 | admin | 0 |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "owner,parent_id". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--analytics-rule_groups-GET.html. | Optional | 

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

#### Command example
```!qradar-rule-groups-list range=0-2```
#### Context Example
```json
{
    "QRadar": {
        "RuleGroup": [
            {
                "ChildItems": [
                    "100045",
                    "100046",
                    "100047",
                    "100048",
                    "100049",
                    "100050",
                    "100051",
                    "100052",
                    "100053",
                    "100054",
                    "100055",
                    "100056",
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
                    "1618"
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
                    "100057",
                    "100059"
                ],
                "Description": "Rules that indicate post-intrusion access activity",
                "ID": 100020,
                "Level": 2,
                "ModifiedTime": "2015-07-08T20:14:12.250000+00:00",
                "Name": "Horizontal Movement",
                "Owner": "admin",
                "ParentID": 3,
                "Type": "RULE_GROUP"
            },
            {
                "ChildItems": [
                    "100001",
                    "100003",
                    "100044",
                    "100323",
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
                    "1566"
                ],
                "Description": "Rules based on log source and event anomalies such as high event rates or excessive connections.",
                "ID": 101,
                "Level": 1,
                "ModifiedTime": "2010-08-21T11:48:27.850000+00:00",
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
>|ID|Name|Description|Owner|ModifiedTime|ParentID|Type|ChildItems|Level|
>|---|---|---|---|---|---|---|---|---|
>| 125 | Asset Reconciliation Exclusion | Rules focused on detection of suspicious asset reconciliation behavior. | admin | 2014-01-06T15:23:26.060000+00:00 | 3 | RULE_GROUP | 100045,<br/>100046,<br/>100047,<br/>100048,<br/>100049,<br/>100050,<br/>100051,<br/>100052,<br/>100053,<br/>100054,<br/>100055,<br/>100056,<br/>1607,<br/>1608,<br/>1609,<br/>1610,<br/>1611,<br/>1612,<br/>1613,<br/>1614,<br/>1615,<br/>1616,<br/>1617,<br/>1618 | 2 |
>| 100020 | Horizontal Movement | Rules that indicate post-intrusion access activity | admin | 2015-07-08T20:14:12.250000+00:00 | 3 | RULE_GROUP | 100057,<br/>100059 | 2 |
>| 101 | Anomaly | Rules based on log source and event anomalies such as high event rates or excessive connections. | admin | 2010-08-21T11:48:27.850000+00:00 | 3 | RULE_GROUP | 100001,<br/>100003,<br/>100044,<br/>100323,<br/>1219,<br/>1265,<br/>1335,<br/>1410,<br/>1411,<br/>1412,<br/>1431,<br/>1443,<br/>1460,<br/>1461,<br/>1471,<br/>1481,<br/>1509,<br/>1552,<br/>1566 | 1 |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,interfaces,users,properties". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--asset_model-assets-GET.html. | Optional | 

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

#### Command example
```!qradar-assets-list filter="id<1100" range=0-2```
#### Context Example
```json
{
    "Endpoint": [
        {
            "IPAddress": [
                "1.1.1.1"
            ]
        }
    ],
    "QRadar": {
        "Asset": {
            "DomainID": 0,
            "ID": 1003,
            "Interfaces": [
                {
                    "created": "2023-07-26T14:32:01.789000+00:00",
                    "id": 1003,
                    "ip_addresses": [
                        {
                            "created": "2023-07-26T14:32:01.789000+00:00",
                            "id": 1003,
                            "network_id": 2,
                            "type": "IPV4",
                            "value": "1.1.1.1"
                        }
                    ]
                }
            ],
            "Properties": [
                {
                    "id": 1020,
                    "last_reported": "2023-07-26T14:32:01.802000+00:00",
                    "last_reported_by": "USER:admin",
                    "name": "Unified Name",
                    "type_id": 1002,
                    "value": "1.1.1.1"
                }
            ],
            "RiskScoreSum": 0,
            "VulnerabilityCount": 0
        }
    }
}
```

#### Human Readable Output

>### Assets List
>|DomainID|ID|Interfaces|Properties|RiskScoreSum|VulnerabilityCount|
>|---|---|---|---|---|---|
>| 0 | 1003 | {'created': '2023-07-26T14:32:01.789000+00:00', 'ip_addresses': [{'created': '2023-07-26T14:32:01.789000+00:00', 'network_id': 2, 'id': 1003, 'type': 'IPV4', 'value': '1.1.1.1'}], 'id': 1003} | {'last_reported': '2023-07-26T14:32:01.802000+00:00', 'name': 'Unified Name', 'type_id': 1002, 'id': 1020, 'last_reported_by': 'USER:admin', 'value': '1.1.1.1'} | 0.0 | 0 |
>### Endpoints
>|IPAddress|
>|---|
>| 1.1.1.1 |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,owner,description". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--ariel-saved_searches-GET.html. | Optional | 

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

#### Command example
```!qradar-saved-searches-list range=0-1```
#### Context Example
```json
{
    "QRadar": {
        "SavedSearch": [
            {
                "AQL": "select QIDNAME(qid) as 'Event Name',logsourcename(logSourceId) as 'Log Source',\"eventCount\" as 'Event Count',\"startTime\" as 'Time',categoryname(category) as 'Low Level Category',\"sourceIP\" as 'Source IP',\"sourcePort\" as 'Source Port',\"destinationIP\" as 'Destination IP',\"destinationPort\" as 'Destination Port',\"userName\" as 'Username',\"magnitude\" as 'Magnitude' from events where \"Experience Center\" ilike '%AWSCloud%' order by \"startTime\" desc LIMIT 1000 start '2023-08-02 08:34' stop '2023-08-02 08:39'",
                "CreationDate": "2019-04-02T17:39:08.493000+00:00",
                "Database": "EVENTS",
                "Description": "",
                "ID": 2817,
                "IsShared": false,
                "ModifiedDate": "2023-02-23T14:12:52.611000+00:00",
                "Name": "EC: AWS Cloud Attack Events",
                "Owner": "admin",
                "QuickSearch": false,
                "UID": "0144c7d8-a3fe-47c1-b16b-12721a34077e"
            },
            {
                "AQL": "select * from flows where destinationport = '445' and (FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%70 00 73 00 65 00 78 00 65 00 63 00 73 00 76 00 63 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%50 00 53 00 45 00 58 00 45 00 53 00 56 00 43 00 2e 00 45 00 58 00 45%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%73 00 76 00 63 00 63 00 74 00 6c 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%5c 00 61 00 64 00 6d 00 69 00 6e 00 24 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%ff 53 4d 42 72 00 00 00 00 18 07 c0%') last 24 HOURS",
                "CreationDate": "2017-07-02T18:11:44.984000+00:00",
                "Database": "FLOWS",
                "Description": "",
                "ID": 2835,
                "IsShared": true,
                "ModifiedDate": "2023-03-05T13:34:00.352000+00:00",
                "Name": "Potential Ransomware (Suspicious activity, Possible Petya, NotPetya)",
                "Owner": "admin",
                "QuickSearch": false,
                "UID": "0791701a-80e3-4a1c-b11f-7bc943b96bf6"
            }
        ]
    }
}
```

#### Human Readable Output

>### Saved Searches List
>|ID|Name|IsShared|AQL|UID|QuickSearch|ModifiedDate|CreationDate|Database|Owner|
>|---|---|---|---|---|---|---|---|---|---|
>| 2817 | EC: AWS Cloud Attack Events | false | select QIDNAME(qid) as 'Event Name',logsourcename(logSourceId) as 'Log Source',"eventCount" as 'Event Count',"startTime" as 'Time',categoryname(category) as 'Low Level Category',"sourceIP" as 'Source IP',"sourcePort" as 'Source Port',"destinationIP" as 'Destination IP',"destinationPort" as 'Destination Port',"userName" as 'Username',"magnitude" as 'Magnitude' from events where "Experience Center" ilike '%AWSCloud%' order by "startTime" desc LIMIT 1000 start '2023-08-02 08:34' stop '2023-08-02 08:39' | 0144c7d8-a3fe-47c1-b16b-12721a34077e | false | 2023-02-23T14:12:52.611000+00:00 | 2019-04-02T17:39:08.493000+00:00 | EVENTS | admin |
>| 2835 | Potential Ransomware (Suspicious activity, Possible Petya, NotPetya) | true | select * from flows where destinationport = '445' and (FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%70 00 73 00 65 00 78 00 65 00 63 00 73 00 76 00 63 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%50 00 53 00 45 00 58 00 45 00 53 00 56 00 43 00 2e 00 45 00 58 00 45%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%73 00 76 00 63 00 63 00 74 00 6c 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%5c 00 61 00 64 00 6d 00 69 00 6e 00 24 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%ff 53 4d 42 72 00 00 00 00 18 07 c0%') last 24 HOURS | 0791701a-80e3-4a1c-b11f-7bc943b96bf6 | false | 2023-03-05T13:34:00.352000+00:00 | 2017-07-02T18:11:44.984000+00:00 | FLOWS | admin |


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

#### Command example
```!qradar-searches-list```
#### Context Example
```json
{
    "QRadar": {
        "SearchID": [
            {
                "SearchID": "111e7107-48da-4645-8c2c-a8285d113eac"
            },
            {
                "SearchID": "4ad8f58f-d63b-4555-9d5e-62529e6ac089"
            },
            {
                "SearchID": "909075e0-b450-400c-b641-dd04e46b65bf"
            },
            {
                "SearchID": "f6387ac3-342a-41e7-bcd4-14fe5525dc5c"
            },
            {
                "SearchID": "e15caa93-a01f-49f4-b6be-5c666b0e08c7"
            },
            {
                "SearchID": "36ad7331-149d-4419-947d-ff0d3dd23cf1"
            },
            {
                "SearchID": "a893fc4f-f405-4cb2-a6c3-698dfad6045d"
            },
            {
                "SearchID": "47f40fcd-b7fd-48d7-abbc-05fb447acee2"
            },
            {
                "SearchID": "8967788b-f746-4e5b-9174-c145196eddb1"
            },
            {
                "SearchID": "1d743e24-a524-417f-9747-c967e0328b48"
            },
            {
                "SearchID": "be14bcb5-363e-4547-9b7f-923578a16ae6"
            },
            {
                "SearchID": "a4f4d846-9057-41ae-b558-0dd47134a72a"
            },
            {
                "SearchID": "2c98e5f6-4988-4fe3-bbac-43acbbfaaea2"
            },
            {
                "SearchID": "7e4bd0cf-b04e-446f-ba94-16e1811740e9"
            },
            {
                "SearchID": "76e9ed8a-4f59-42ad-8135-9b1781568935"
            },
            {
                "SearchID": "04e953e2-153a-488b-9a53-8701d16431c4"
            },
            {
                "SearchID": "cd44255c-0496-4663-a6ac-9662ad4a13ef"
            },
            {
                "SearchID": "92e5d6ec-1c60-4c7b-ad97-7610c1e7ed90"
            },
            {
                "SearchID": "8ded0056-8853-443f-9f99-3fff30c08cd6"
            },
            {
                "SearchID": "5ced0d93-4237-461a-ba12-6513d5674fb0"
            },
            {
                "SearchID": "1de985b2-2d45-4d0e-ac86-d25c5b7d8803"
            },
            {
                "SearchID": "b19000dd-1eda-4b85-a45e-334478f0755f"
            },
            {
                "SearchID": "ae52c4d7-689f-4274-8f74-6de74bd3652c"
            },
            {
                "SearchID": "70fe39d6-4e8e-4c48-8207-12d5930544f4"
            },
            {
                "SearchID": "011e1de5-c985-462a-8252-e291acaed012"
            },
            {
                "SearchID": "174d5a7c-b004-4b9c-96fb-868c043daa3c"
            },
            {
                "SearchID": "12b576a1-410e-4c46-bd95-61b2bebb4ceb"
            },
            {
                "SearchID": "8f1b645a-6f81-43fc-86f3-23c2213359b6"
            },
            {
                "SearchID": "12463d5a-4d2c-4c5b-9640-88e4cdee245c"
            },
            {
                "SearchID": "e1d2697f-4c40-46d0-b8b3-90a51e732814"
            },
            {
                "SearchID": "e9dea979-039c-409a-8a60-fe1fe44fa3c2"
            },
            {
                "SearchID": "66ca4a44-a3ac-482b-9d7a-300d621eb8a9"
            },
            {
                "SearchID": "a42ef950-fd27-42c9-af3d-8d466bf73d5d"
            },
            {
                "SearchID": "73ee61f0-c480-4145-a00b-d8c3a55de791"
            },
            {
                "SearchID": "e73b8002-b47d-4fb3-9dae-34a99dd21943"
            },
            {
                "SearchID": "5b812a3b-624d-4cf7-a2ed-f2d1f469b0a4"
            },
            {
                "SearchID": "4f6e37db-8c4f-4e2f-9b27-b8ae68d0c38b"
            },
            {
                "SearchID": "df9cf783-d706-46ed-8be7-680a0830d3eb"
            },
            {
                "SearchID": "d2aa7f7c-dbf4-405f-9652-b6bb776164f0"
            },
            {
                "SearchID": "de72022b-8070-4151-a826-16eb913db2cd"
            },
            {
                "SearchID": "32501bb7-22b8-4d79-aa7b-0b565c4bd806"
            },
            {
                "SearchID": "f89f3515-6d27-4616-a1bb-7dc008aa1562"
            },
            {
                "SearchID": "1ba37caf-c969-43fa-b037-6c164535b512"
            },
            {
                "SearchID": "78b709c4-8037-43dc-8bf0-dfd94629674f"
            },
            {
                "SearchID": "88096e2b-4feb-4071-807e-96e3dfc080ff"
            },
            {
                "SearchID": "1a7576fc-2cc1-41c6-85b6-3728d4d44f3d"
            },
            {
                "SearchID": "b4414e3b-b5ec-4cc8-9db2-35a7a2057e46"
            },
            {
                "SearchID": "c6a82de6-cfef-444e-9b0f-b124b5599b7b"
            },
            {
                "SearchID": "185971cc-ebbb-453d-b826-bffc59836be1"
            },
            {
                "SearchID": "2a45ec38-d060-4aae-9a9c-730f49966fdc"
            }
        ]
    }
}
```

#### Human Readable Output

>### Search ID List
>|SearchID|
>|---|
>| 111e7107-48da-4645-8c2c-a8285d113eac |
>| 4ad8f58f-d63b-4555-9d5e-62529e6ac089 |
>| 909075e0-b450-400c-b641-dd04e46b65bf |
>| f6387ac3-342a-41e7-bcd4-14fe5525dc5c |
>| e15caa93-a01f-49f4-b6be-5c666b0e08c7 |
>| 36ad7331-149d-4419-947d-ff0d3dd23cf1 |
>| a893fc4f-f405-4cb2-a6c3-698dfad6045d |
>| 47f40fcd-b7fd-48d7-abbc-05fb447acee2 |
>| 8967788b-f746-4e5b-9174-c145196eddb1 |
>| 1d743e24-a524-417f-9747-c967e0328b48 |
>| be14bcb5-363e-4547-9b7f-923578a16ae6 |
>| a4f4d846-9057-41ae-b558-0dd47134a72a |
>| 2c98e5f6-4988-4fe3-bbac-43acbbfaaea2 |
>| 7e4bd0cf-b04e-446f-ba94-16e1811740e9 |
>| 76e9ed8a-4f59-42ad-8135-9b1781568935 |
>| 04e953e2-153a-488b-9a53-8701d16431c4 |
>| cd44255c-0496-4663-a6ac-9662ad4a13ef |
>| 92e5d6ec-1c60-4c7b-ad97-7610c1e7ed90 |
>| 8ded0056-8853-443f-9f99-3fff30c08cd6 |
>| 5ced0d93-4237-461a-ba12-6513d5674fb0 |
>| 1de985b2-2d45-4d0e-ac86-d25c5b7d8803 |
>| b19000dd-1eda-4b85-a45e-334478f0755f |
>| ae52c4d7-689f-4274-8f74-6de74bd3652c |
>| 70fe39d6-4e8e-4c48-8207-12d5930544f4 |
>| 011e1de5-c985-462a-8252-e291acaed012 |
>| 174d5a7c-b004-4b9c-96fb-868c043daa3c |
>| 12b576a1-410e-4c46-bd95-61b2bebb4ceb |
>| 8f1b645a-6f81-43fc-86f3-23c2213359b6 |
>| 12463d5a-4d2c-4c5b-9640-88e4cdee245c |
>| e1d2697f-4c40-46d0-b8b3-90a51e732814 |
>| e9dea979-039c-409a-8a60-fe1fe44fa3c2 |
>| 66ca4a44-a3ac-482b-9d7a-300d621eb8a9 |
>| a42ef950-fd27-42c9-af3d-8d466bf73d5d |
>| 73ee61f0-c480-4145-a00b-d8c3a55de791 |
>| e73b8002-b47d-4fb3-9dae-34a99dd21943 |
>| 5b812a3b-624d-4cf7-a2ed-f2d1f469b0a4 |
>| 4f6e37db-8c4f-4e2f-9b27-b8ae68d0c38b |
>| df9cf783-d706-46ed-8be7-680a0830d3eb |
>| d2aa7f7c-dbf4-405f-9652-b6bb776164f0 |
>| de72022b-8070-4151-a826-16eb913db2cd |
>| 32501bb7-22b8-4d79-aa7b-0b565c4bd806 |
>| f89f3515-6d27-4616-a1bb-7dc008aa1562 |
>| 1ba37caf-c969-43fa-b037-6c164535b512 |
>| 78b709c4-8037-43dc-8bf0-dfd94629674f |
>| 88096e2b-4feb-4071-807e-96e3dfc080ff |
>| 1a7576fc-2cc1-41c6-85b6-3728d4d44f3d |
>| b4414e3b-b5ec-4cc8-9db2-35a7a2057e46 |
>| c6a82de6-cfef-444e-9b0f-b124b5599b7b |
>| 185971cc-ebbb-453d-b826-bffc59836be1 |
>| 2a45ec38-d060-4aae-9a9c-730f49966fdc |


### qradar-search-create

***
Creates a new asynchronous Ariel search. Returns the search ID. Search status and results can be polled by sending the search ID to the 'qradar-search-status-get' and 'qradar-search-results-get' commands. Accepts SELECT query expressions only.

#### Base Command

`qradar-search-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to retrieve. Mutually exclusive with query_expression and saved_search_id. | Optional | 
| events_limit | The number of events to return. Mutually exclusive with query_expression and saved_search_id. | Optional | 
| events_columns | Comma separated list of columns to return. Mutually exclusive with query_expression and saved_search_id. | Optional | 
| fetch_mode | The mode to use when fetching events. Mutually exclusive with query_expression and saved_search_id. Possible values are: Fetch With All Events, Fetch Correlation Events Only. | Optional | 
| start_time | The start time of the search. | Optional | 
| query_expression | The AQL query to execute. Mutually exclusive with all other arguments. | Optional | 
| saved_search_id | Saved search ID to execute. Mutually exclusive with all other arguments. Saved search ID is the 'id' field returned by the 'qradar-saved-searches-list' command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Status | String | Status of the newly created search. | 
| QRadar.Search.ID | String | ID of the newly created search. | 

#### Command example
```!qradar-search-create query_expression="""SELECT "destinationPort" AS 'Destination Port', UniqueCount("sourceIP") AS 'Source IP (Unique Count)', UniqueCount("destinationIP") AS 'Destination IP (Unique Count)', UniqueCount(qid) AS 'Event Name (Unique Count)', UniqueCount(logSourceId) AS 'Log Source (Unique Count)', UniqueCount(category) AS 'Low Level Category (Unique Count)', UniqueCount("protocolId") AS 'Protocol (Unique Count)', UniqueCount("userName") AS 'Username (Unique Count)', MAX("magnitude") AS 'Magnitude (Maximum)', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( ("creEventList"='100120') or ("creEventList"='100122') or ("creEventList"='100135') AND "eventDirection"='R2L' ) GROUP BY "destinationPort" order by "Event Count (Sum)" desc last 6 hours"""```
#### Context Example
```json
{
    "QRadar": {
        "Search": {
            "ID": "68d4e4e6-f512-4171-b130-d671334cb47d",
            "Status": "WAIT"
        }
    }
}
```

#### Human Readable Output

>### Create Search
>|ID|Status|
>|---|---|
>| 68d4e4e6-f512-4171-b130-d671334cb47d | WAIT |


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

### qradar-search-delete

***
Deleted search from Qradar, based on the search ID.

#### Base Command

`qradar-search-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The identifier for an Ariel search. | Required | 


### qradar-reference-sets-list

### qradar-search-cancel

***
Cancelled search in QRadar based on search_id.

#### Base Command

`qradar-search-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The identifier for an Ariel search. | Required | 


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--reference_data-sets-GET.html. | Optional | 

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

#### Command example
```!qradar-reference-sets-list filter="timeout_type=FIRST_SEEN" range=0-2```
#### Context Example
```json
{
    "QRadar": {
        "Reference": [
            {
                "CreationTime": "2015-08-27T17:15:40.583000+00:00",
                "ElementType": "IP",
                "Name": "Critical Assets",
                "NumberOfElements": 0,
                "TimeoutType": "FIRST_SEEN"
            },
            {
                "CreationTime": "2017-10-25T16:31:15.992000+00:00",
                "ElementType": "ALNIC",
                "Name": "BadRabbit_FileHash",
                "NumberOfElements": 6,
                "TimeoutType": "FIRST_SEEN"
            },
            {
                "CreationTime": "2022-10-03T10:38:51.140000+00:00",
                "ElementType": "IP",
                "Name": "Windows RCE IPs",
                "NumberOfElements": 19,
                "TimeoutType": "FIRST_SEEN"
            }
        ]
    }
}
```

#### Human Readable Output

>### Reference Sets List
>|Name|ElementType|TimeoutType|CreationTime|NumberOfElements|
>|---|---|---|---|---|
>| Critical Assets | IP | FIRST_SEEN | 2015-08-27T17:15:40.583000+00:00 | 0 |
>| BadRabbit_FileHash | ALNIC | FIRST_SEEN | 2017-10-25T16:31:15.992000+00:00 | 6 |
>| Windows RCE IPs | IP | FIRST_SEEN | 2022-10-03T10:38:51.140000+00:00 | 19 |


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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--reference_data-sets-POST.html. | Optional | 

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

#### Command example
```!qradar-reference-set-create element_type=IP ref_name="Malicious IPs" time_to_live="1 year" timeout_type=FIRST_SEEN```
#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2023-08-02T08:39:30.887000+00:00",
            "ElementType": "IP",
            "Name": "Malicious IPs",
            "NumberOfElements": 0,
            "TimeToLive": "1 years 0 mons 0 days 0 hours 0 mins 0.0 secs",
            "TimeoutType": "FIRST_SEEN"
        }
    }
}
```

#### Human Readable Output

>### Reference Set Create
>|Name|ElementType|TimeToLive|TimeoutType|CreationTime|NumberOfElements|
>|---|---|---|---|---|---|
>| Malicious IPs | IP | 1 years 0 mons 0 days 0 hours 0 mins 0.0 secs | FIRST_SEEN | 2023-08-02T08:39:30.887000+00:00 | 0 |


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
#### Command example
```!qradar-reference-set-delete ref_name="Malicious IPs"```
#### Human Readable Output

>Request to delete reference Malicious IPs was submitted. Current deletion status: QUEUED

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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--reference_data-sets-name-POST.html. | Optional | 
| quiet_mode | If true, does not output the updated reference set data. This argument helps avoid large outputs when the reference set is large. Possible values are: true, false. | Optional | 

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

#### Command example
```!qradar-reference-set-value-upsert ref_name="Malicious IPs" value="1.1.1.1,1.1.1.1,1.1.1.1"```
#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "CreationTime": "2023-08-02T08:39:30.887000+00:00",
            "Data": [
                {
                    "first_seen": 1690965572017,
                    "last_seen": 1690965572017,
                    "source": "reference data api",
                    "value": "1.1.1.1"
                },
                {
                    "first_seen": 1690965572017,
                    "last_seen": 1690965572017,
                    "source": "reference data api",
                    "value": "1.1.1.1"
                },
                {
                    "first_seen": 1690965572017,
                    "last_seen": 1690965572017,
                    "source": "reference data api",
                    "value": "1.1.1.1"
                }
            ],
            "ElementType": "IP",
            "Name": "Malicious IPs",
            "NumberOfElements": 3,
            "TimeToLive": "1 years 0 mons 0 days 0 hours 0 mins 0.0 secs",
            "TimeoutType": "FIRST_SEEN"
        }
    }
}
```

#### Human Readable Output

>### Reference Update Create
>|CreationTime|Data|ElementType|Name|NumberOfElements|TimeToLive|TimeoutType|
>|---|---|---|---|---|---|---|
>| 2023-08-02T08:39:30.887000+00:00 | {'last_seen': 1690965572017, 'first_seen': 1690965572017, 'source': 'reference data api', 'value': '1.1.1.1'},<br/>{'last_seen': 1690965572017, 'first_seen': 1690965572017, 'source': 'reference data api', 'value': '1.1.1.1'},<br/>{'last_seen': 1690965572017, 'first_seen': 1690965572017, 'source': 'reference data api', 'value': '1.1.1.1'} | IP | Malicious IPs | 3 | 1 years 0 mons 0 days 0 hours 0 mins 0.0 secs | FIRST_SEEN |


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
#### Command example
```!qradar-reference-set-value-delete ref_name="Malicious IPs" value="1.1.1.1"```
#### Human Readable Output

>### value: 1.1.1.1 of reference: Malicious IPs was deleted successfully

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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--config-domain_management-domains-GET.html. | Optional | 

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

#### Command example
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
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--reference_data-maps-bulk_load-namespace-name-domain_id-POST.html. | Optional | 
| quiet_mode | If true, does not output the updated reference set data. This argument helps avoid large outputs when the reference set is large. Possible values are: true, false. | Optional | 

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

### qradar-geolocations-for-ip

***
Retrieves the MaxMind GeoIP data for the specified IP address.

#### Base Command

`qradar-geolocations-for-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma-separated list of IPs fro which to retrieve their geolocation. | Required | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "continent,ip_address". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--services-geolocations-GET.html. | Optional | 

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

#### Command example
```!qradar-geolocations-for-ip ip="1.1.1.1,1.1.1.1" range=0-1```
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
                "IPAddress": "1.1.1.1",
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
                "IPAddress": "1.1.1.1",
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
>| Mukilteo | NorthAmerica | 47.913,<br/>-122.3042 | 1.1.1.1 | 1000 | 47.913 | -122.3042 | 819 | America/Los_Angeles | US | United States | 98275 | US | United States |
>| Mukilteo | NorthAmerica | 47.913,<br/>-122.3042 | 1.1.1.1 | 1000 | 47.913 | -122.3042 | 819 | America/Los_Angeles | US | United States | 98275 | US | United States |


### qradar-log-sources-list

***
Retrieves a list of log sources.

#### Base Command

`qradar-log-sources-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qrd_encryption_algorithm | The algorithm to use for encrypting the sensitive data of this endpoint. Possible values are: AES128, AES256. Default is AES128. | Required | 
| qrd_encryption_password | The password to use for encrypting the sensitive data of this endpoint. If password was not given, random password will be generated. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter log sources, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--config-event_sources-log_source_management-log_sources-GET.html. | Optional | 
| id | ID of a specific log source. | Optional | 

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


#### Command example
```!qradar-log-sources-list qrd_encryption_algorithm=AES128 range=0-2```
#### Context Example
```json
{
    "QRadar": {
        "LogSource": [
            {
                "AutoDiscovered": false,
                "CreationDate": "2022-11-21T18:45:24.624000+00:00",
                "Credibility": 10,
                "Description": "Search Results",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 68,
                "Internal": true,
                "LastEventTime": "1970-01-01T00:00:00+00:00",
                "ModifiedDate": "2022-11-21T18:45:24.624000+00:00",
                "Name": "Search Results-2 :: ip-172-31-17-10",
                "ProtocolParameters": [
                    {
                        "id": 0,
                        "name": "identifier",
                        "value": "1.1.1.1"
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
                "TypeID": 355
            },
            {
                "AutoDiscovered": false,
                "CreationDate": "2022-11-21T18:45:24.621000+00:00",
                "Credibility": 10,
                "Description": "System Notification",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 65,
                "Internal": true,
                "LastEventTime": "2023-08-02T08:39:00.106000+00:00",
                "ModifiedDate": "2022-11-21T18:45:24.621000+00:00",
                "Name": "System Notification-2 :: ip-172-31-17-10",
                "ProtocolParameters": [
                    {
                        "id": 0,
                        "name": "identifier",
                        "value": "1.1.1.1"
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
                    "status": "SUCCESS"
                },
                "TypeID": 147
            },
            {
                "AutoDiscovered": true,
                "CreationDate": "2018-10-24T15:25:21.928000+00:00",
                "Credibility": 5,
                "Description": "WindowsAuthServer device",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 1262,
                "Internal": false,
                "LastEventTime": "2023-06-12T08:17:22.292000+00:00",
                "ModifiedDate": "2023-02-23T14:12:45.774000+00:00",
                "Name": "Experience Center: WindowsAuthServer @ 1.1.1.1",
                "ProtocolParameters": [
                    {
                        "id": 0,
                        "name": "identifier",
                        "value": "1.1.1.1"
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
                "TypeID": 12
            }
        ]
    }
}
```

#### Human Readable Output

>### Log Sources List
>|ID|Name|Description|Internal|ProtocolParameters|Credibility|GroupIDs|CreationDate|Status|Enabled|ProtocolTypeID|AutoDiscovered|Gateway|TypeID|ModifiedDate|LastEventTime|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 68 | Search Results-2 :: ip-172-31-17-10 | Search Results | true | {'name': 'identifier', 'id': 0, 'value': '1.1.1.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | 10 | 0 | 2022-11-21T18:45:24.624000+00:00 | last_updated: 0<br/>status: NA | true | 0 | false | false | 355 | 2022-11-21T18:45:24.624000+00:00 | 1970-01-01T00:00:00+00:00 |
>| 65 | System Notification-2 :: ip-172-31-17-10 | System Notification | true | {'name': 'identifier', 'id': 0, 'value': '1.1.1.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | 10 | 0 | 2022-11-21T18:45:24.621000+00:00 | last_updated: 0<br/>status: SUCCESS | true | 0 | false | false | 147 | 2022-11-21T18:45:24.621000+00:00 | 2023-08-02T08:39:00.106000+00:00 |
>| 1262 | Experience Center: WindowsAuthServer @ 1.1.1.1 | WindowsAuthServer device | false | {'name': 'identifier', 'id': 0, 'value': '1.1.1.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | 5 | 0 | 2018-10-24T15:25:21.928000+00:00 | last_updated: 0<br/>messages: {'severity': 'ERROR', 'text': 'Events have not been received from this Log Source in over 720 minutes.'}<br/>status: ERROR | true | 0 | true | false | 12 | 2023-02-23T14:12:45.774000+00:00 | 2023-06-12T08:17:22.292000+00:00 |


### qradar-get-custom-properties

***
Retrieves a list of event regex properties.

#### Base Command

`qradar-get-custom-properties`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field_name | A comma-separated list of names of the exact properties to search for. | Optional | 
| limit | The maximum number of regex event properties to fetch. Default is 25. | Optional | 
| like_name | A comma-separated list names of a properties to search for. Values are case insensitive. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter regex properties, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,gateway". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--config-event_sources-custom_properties-regex_properties-GET.html. | Optional | 

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

#### Command example
```!qradar-get-custom-properties filter="id between 90 and 100" range=1-1231```
#### Context Example
```json
{
    "QRadar": {
        "Properties": [
            {
                "auto_discovered": false,
                "creation_date": "2012-07-04T17:05:02+00:00",
                "datetime_format": "",
                "description": "Default custom extraction of Event Summary from DSM payload.",
                "id": 97,
                "identifier": "DEFAULT_EVENT_SUMMARY",
                "locale": "en-US",
                "modification_date": "2022-11-21T18:44:07.572000+00:00",
                "name": "Event Summary",
                "property_type": "string",
                "use_for_rule_engine": true,
                "username": "admin"
            },
            {
                "auto_discovered": false,
                "creation_date": "2009-09-04T16:58:12.961000+00:00",
                "datetime_format": "",
                "description": "Default custom extraction of Avt-App-VolumePackets from DSM payload.",
                "id": 99,
                "identifier": "4d616180-00d0-4ba0-b423-bfb54e1b8677",
                "locale": "en-US",
                "modification_date": "2022-11-21T18:44:08.049000+00:00",
                "name": "Packets",
                "property_type": "numeric",
                "use_for_rule_engine": false,
                "username": "admin"
            },
            {
                "auto_discovered": false,
                "creation_date": "2010-07-27T13:32:44.494000+00:00",
                "datetime_format": "NULL::character varying",
                "description": "",
                "id": 96,
                "identifier": "8eb82a2c-bba7-478f-9248-69fba8baf8c7",
                "locale": "NULL::character varying",
                "modification_date": "2022-11-21T18:59:14.020000+00:00",
                "name": "Parent",
                "property_type": "string",
                "use_for_rule_engine": true,
                "username": "admin"
            }
        ]
    }
}
```

#### Human Readable Output

>### Custom Properties
>|auto_discovered|creation_date|datetime_format|description|id|identifier|locale|modification_date|name|property_type|use_for_rule_engine|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2012-07-04T17:05:02+00:00 |  | Default custom extraction of Event Summary from DSM payload. | 97 | DEFAULT_EVENT_SUMMARY | en-US | 2022-11-21T18:44:07.572000+00:00 | Event Summary | string | true | admin |
>| false | 2009-09-04T16:58:12.961000+00:00 |  | Default custom extraction of Avt-App-VolumePackets from DSM payload. | 99 | 4d616180-00d0-4ba0-b423-bfb54e1b8677 | en-US | 2022-11-21T18:44:08.049000+00:00 | Packets | numeric | false | admin |
>| false | 2010-07-27T13:32:44.494000+00:00 | NULL::character varying |  | 96 | 8eb82a2c-bba7-478f-9248-69fba8baf8c7 | NULL::character varying | 2022-11-21T18:59:14.020000+00:00 | Parent | string | true | admin |


### qradar-reset-last-run

***
Resets the fetch incidents last run value, which resets the fetch to its initial fetch state. (Will try to fetch the first available offense).

#### Base Command

`qradar-reset-last-run`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Returns the list of fields for an incident type. This command should be used for debugging purposes.

#### Base Command

`get-mapping-fields`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-remote-data

***
Gets remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The offense ID. | Required | 
| lastUpdate | Date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Required | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Returns the list of incidents IDs that were modified since the last update time. Note that this method is for debugging purposes. The get-modified-remote-data command is used as part of the mirroring feature, which is available from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-offenses

***
Gets offenses from QRadar.

#### Base Command

`qradar-offenses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Query by which to filter offenses. For reference, consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named, are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-GET.html. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.Credibility | number | The credibility of the offense. | 
| QRadar.Offense.Relevance | number | The relevance of the offense. | 
| QRadar.Offense.Severity | number | The severity of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The destination addresses that are associated with the offense. | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname. | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense. | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type. | 
| QRadar.Offense.Protected | boolean | Is the offense protected. | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destinations that are associated with the offesne. If this value is greater than 0 that means your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 

### qradar-offense-by-id

***
Gets offense with matching offense ID from qradar.

#### Base Command

`qradar-offense-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | Offense ID. | Required | 
| filter | Query to filter offense. For reference please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-GET.html. | Optional | 
| headers | Table headers to use in the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.Credibility | number | The credibility of the offense. | 
| QRadar.Offense.Relevance | number | The relevance of the offense. | 
| QRadar.Offense.Severity | number | The severity of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The local destination addresses that are associated with the offense. If your offense has a remote destination, you will need to use the QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip. | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destination that are associated with the offesne. If this value is greater than 0, it means that your offense has a remote destination, you will need to use the QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip. | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname. | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense. | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type. | 
| QRadar.Offense.Protected | boolean | Is the offense protected. | 

| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destinations that are associated with the offesne. If this value is greater than 0 that means your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 

### qradar-searches

***
Searches in QRadar using AQL. It is highly recommended to use the playbook 'QRadarFullSearch' instead of this command - it will execute the search, and will return the result.

#### Base Command

`qradar-searches`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_expression | The query expressions in AQL (for more information about Ariel Query Language, review "https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.0/com.ibm.qradar.doc/c_aql_intro.html"). | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.ID | number | Search ID. | 
| QRadar.Search.Status | string | The status of the search. | 

### qradar-get-search

***
Gets a specific search id and status.

#### Base Command

`qradar-get-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The search id. | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.ID | number | Search ID. | 
| QRadar.Search.Status | string | The status of the search. | 

### qradar-get-search-results

***
Gets search results.

#### Base Command

`qradar-get-search-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The search id. | Required | 
| range | Range of results to return. e.g.: 0-20. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 
| output_path | Replaces the default context output path for the query result (QRadar.Search.Result). e.g. for output_path=QRadar.Correlations the result will be under the key "QRadar.Correlations" in the context data. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Result | Unknown | The result of the search. | 

### qradar-get-assets

***
List all assets found in the model.

#### Base Command

`qradar-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Query to filter assets. For reference please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--asset_model-assets-GET.html. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Asset.ID | number | The ID of the asset. | 
| Endpoint.IPAddress | Unknown | IP address of the asset. | 
| QRadar.Asset.Name.Value | string | Name of the asset. | 
| Endpoint.OS | number | Asset OS. | 
| QRadar.Asset.AggregatedCVSSScore.Value | number | CVSSScore. | 
| QRadar.Asset.AggregatedCVSSScore.LastUser | string | Last user who updated the Aggregated CVSS Score. | 
| QRadar.Asset.Weight.Value | number | Asset weight. | 
| QRadar.Asset.Weight.LastUser | string | Last user who updated the weight. | 
| QRadar.Asset.Name.LastUser | string | Last user who updated the name. | 

### qradar-get-asset-by-id

***
Retrieves the asset by id.

#### Base Command

`qradar-get-asset-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the requested asset. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Asset.ID | number | The ID of the asset. | 
| Endpoint.MACAddress | Unknown | Asset MAC address. | 
| Endpoint.IPAddress | Unknown | IP address of the endpoint. | 
| QRadar.Asset.ComplianceNotes.Value | string | Compliance notes. | 
| QRadar.Asset.CompliancePlan.Value | string | Compliance plan. | 
| QRadar.Asset.CollateralDamagePotential.Value | Unknown | Collateral damage potential. | 
| QRadar.Asset.AggregatedCVSSScore.Value | number | CVSSScore. | 
| QRadar.Asset.Name.Value | string | Name of the asset. | 
| QRadar.Asset.GroupName | string | Name of the asset's group. | 
| Endpoint.Domain | Unknown | DNS name. | 
| Endpoint.OS | Unknown | Asset OS. | 
| QRadar.Asset.Weight.Value | number | Asset weight. | 
| QRadar.Asset.Vulnerabilities.Value | Unknown | Vulnerabilities. | 
| QRadar.Asset.Location | string | Location. | 
| QRadar.Asset.Description | string | The asset description. | 
| QRadar.Asset.SwitchID | number | Switch ID. | 
| QRadar.Asset.SwitchPort | number | Switch port. | 
| QRadar.Asset.Name.LastUser | string | Last user who updated the name. | 
| QRadar.Asset.AggregatedCVSSScore.LastUser | string | Last user who updated the Aggregated CVSS Score. | 
| QRadar.Asset.Weight.LastUser | string | Last user who updated the weight. | 
| QRadar.Asset.ComplianceNotes.LastUser | string | Last user who updated the compliance notes. | 
| QRadar.Asset.CompliancePlan.LastUser | string | Last user who updated the compliance plan. | 
| QRadar.Asset.CollateralDamagePotential.LastUser | string | Last user who updated the collateral damage potential. | 
| QRadar.Asset.Vulnerabilities.LastUser | string | Last user who updated the vulnerabilities. | 

### qradar-get-closing-reasons

***
Get closing reasons.

#### Base Command

`qradar-get-closing-reasons`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_reserved | If true, reserved closing reasons are included in the response. Possible values are: true, false. Default is true. | Optional | 
| include_deleted | If true, deleted closing reasons are included in the response. Possible values are: true, false. Default is true. | Optional | 
| filter | Query to filter results. For reference, consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offense_closing_reasons-GET.html. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.ClosingReasons.ID | number | Closing reason ID. | 
| QRadar.Offense.ClosingReasons.Name | string | Closing reason name. | 

### qradar-get-note

***
Retrieve a note for an offense.

#### Base Command

`qradar-get-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve the note from. | Required | 
| note_id | The note ID. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.ID | number | Note ID. | 
| QRadar.Note.Text | string | Note text. | 
| QRadar.Note.CreateTime | date | The creation time of the note. | 
| QRadar.Note.CreatedBy | string | The user who created the note. | 

### qradar-create-note

***
Create a note on an offense.

#### Base Command

`qradar-create-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to add the note to. | Required | 
| note_text | The note text. | Required | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-POST.html. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.ID | number | Note ID. | 
| QRadar.Note.Text | string | Note text. | 
| QRadar.Note.CreateTime | date | The creation time of the note. | 
| QRadar.Note.CreatedBy | string | The user who created the note. | 

### qradar-get-reference-by-name

***
Information about the reference set that had data added or updated. This returns the information set, but not the contained data. This feature is supported from version 8.1 and upward.

#### Base Command

`qradar-get-reference-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the requestered reference. | Required | 
| headers | Table headers to use in the human readable output (if none provided, will show all table headers). | Optional | 
| date_value | If set to true will try to convert the data values to ISO-8601 string. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeToLive | string | Reference time to live. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. Valid values are: UNKNOWN, FIRST_SEEN, LAST_SEEN. | 
| QRadar.Reference.Data | Unknown | Reference set items. | 


### qradar-create-reference-set

***
Creates a new reference set. If the provided name is already in use, this command will fail.

#### Base Command

`qradar-create-reference-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | Reference name to be created. | Required | 
| element_type | The element type for the values allowed in the reference set. The allowed values are: ALN (alphanumeric), ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric), PORT (port number) or DATE. Note that date values need to be represented in milliseconds since the Unix Epoch January 1st 1970. Possible values are: ALN, ALNIC, IP, NUM, PORT, DATE. | Required | 
| timeout_type | The allowed values are "FIRST_SEEN", LAST_SEEN and UNKNOWN. The default value is UNKNOWN. Possible values are: FIRST_SEEN, LAST_SEEN, UNKNOWN. | Optional | 
| time_to_live | The time to live interval, for example: "1 month" or "5 minutes". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.CreationTime | date | Creation time of the reference set. | 
| QRadar.Reference.ElementType | string | The element type for the values allowed in the reference set. The allowed values are: ALN \(alphanumeric\), ALNIC \(alphanumeric ignore case\), IP \(IP address\), NUM \(numeric\), PORT \(port number\) or DATE. | 
| QRadar.Reference.Name | string | Name of the reference set. | 
| QRadar.Reference.NumberOfElements | number | Number of elements in the created reference set. | 
| QRadar.Reference.TimeoutType | string | Timeout type of the reference. The allowed values are FIRST_SEEN, LAST_SEEN and UNKNOWN. | 

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
| date_value | If set to True, will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN. | 

### qradar-update-reference-set-value

***
Adds or updates a value in a reference set.

#### Base Command

`qradar-update-reference-set-value`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. | Required | 
| value | A comma-separated list of values to add or update in the reference set. Date values must be represented in milliseconds since the Unix Epoch January 1st 1970. | Required | 
| source | An indication of where the data originated. The default value is 'reference data api'. | Optional | 
| date_value | If set to True, will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 

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
| date_value | If set to True will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g.,  '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN. | 

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
| date_value | If set to True will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 

### qradar-get-domains

***
Retrieve all Domains.

#### Base Command

`qradar-get-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html. | Optional | 
| range | Number of results in return. | Optional | 
| filter | Query to filter offenses. | Optional | 

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

### qradar-get-domain-by-id

***
Retrieves Domain information By ID.

#### Base Command

`qradar-get-domain-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the domain. | Required | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html. | Optional | 

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

### qradar-upload-indicators

***
Uploads indicators from Demisto to QRadar.

#### Base Command

`qradar-upload-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. To create a new reference set, you need to set the element type. | Required | 
| element_type | The element type for the values permitted in the reference set. Only required when creating a new reference set. The valid values are: ALN (alphanumeric), ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric), PORT (port number) or DATE. Note that date values need to be represented in milliseconds since the Unix Epoch January 1st 1970. Possible values are: ALN, ALNIC, IP, NUM, PORT, DATE. | Optional | 
| timeout_type | The timeout_type can be "FIRST_SEEN", "LAST_SEEN", or "UNKNOWN". The default value is UNKNOWN. Only required for creating a new reference set. Possible values are: FIRST_SEEN, LAST_SEEN, UNKNOWN. | Optional | 
| time_to_live | The time to live interval, for example: "1 month" or "5 minutes". Only required when creating a new reference set. | Optional | 
| query | The query for getting indicators. | Required | 
| limit | The maximum number of indicators to return. The default value is 1000. Default is 1000. | Optional | 
| page | The page from which to get the indicators. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-ips-source-get

***
Get Source IPs

#### Base Command

`qradar-ips-source-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_ip | Comma separated list. Source IPs to retrieve their data, E.g "1.1.1.1,1.1.1.1". | Optional | 
| filter | Query to filter IPs. E.g, filter=`source_ip="1.1.1.1"`. For reference please consult: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the ones specified. Use this argument to specify which fields should be returned in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-source_addresses-GET.html. | Optional | 
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

#### Command example
```!qradar-ips-source-get filter=`source_ip="1.1.1.1"` range=0-2```
#### Context Example
```json
{
    "QRadar": {
        "SourceIP": {
            "DomainID": 0,
            "EventFlowCount": 654,
            "FirstEventFlowSeen": "2023-07-26T14:31:44.753000+00:00",
            "ID": 31,
            "LastEventFlowSeen": "2023-07-26T15:31:06.386000+00:00",
            "LocalDestinationAddressIDs": [
                64
            ],
            "Magnitude": 0,
            "Network": "Net-10-172-192.Net_192_168_0_0",
            "OffenseIDs": [
                14
            ],
            "SourceIP": "1.1.1.1"
        }
    }
}
```

#### Human Readable Output

>### Source IPs
>|DomainID|EventFlowCount|FirstEventFlowSeen|ID|LastEventFlowSeen|LocalDestinationAddressIDs|Magnitude|Network|OffenseIDs|SourceIP|
>|---|---|---|---|---|---|---|---|---|---|
>| 0 | 654 | 2023-07-26T14:31:44.753000+00:00 | 31 | 2023-07-26T15:31:06.386000+00:00 | 64 | 0 | Net-10-172-192.Net_192_168_0_0 | 14 | 1.1.1.1 |


### qradar-ips-local-destination-get

***
Get Source IPs

#### Base Command

`qradar-ips-local-destination-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_destination_ip | Comma separated list. Local destination IPs to retrieve their data, E.g "1.1.1.1,1.1.1.1". | Optional | 
| filter | Query to filter IPs. E.g, filter=`local_destination_ip="1.1.1.1"` For reference please consult: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the ones specified. Use this argument to specify which fields should be returned in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://ibmsecuritydocs.github.io/qradar_api_14.0/14.0--siem-local_destination_addresses-GET.html. | Optional | 
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

#### Command example
```!qradar-ips-local-destination-get filter=`local_destination_ip="1.1.1.1"````
#### Human Readable Output

>### Local Destination IPs
>**No entries.**


### qradar-search-retrieve-events

***
Polling command to search for events of a specific offense.

#### Base Command

`qradar-search-retrieve-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to retrieve. Mutually exclusive with query_expression. | Optional | 
| events_limit | The number of events to return. Mutually exclusive with query_expression. | Optional | 
| events_columns | Comma separated list of columns to return. Mutually exclusive with query_expression. | Optional | 
| fetch_mode | The mode to use when fetching events. Mutually exclusive with query_expression. Possible values are: Fetch With All Events, Fetch Correlation Events Only. | Optional | 
| start_time | The start time of the search. Mutually exclusive with query_expression. | Optional | 
| query_expression | The AQL query to execute. Mutually exclusive with the other arguments. | Optional | 
| interval_in_seconds | The interval in seconds to use when polling events. | Optional | 
| search_id | The search id to query the results. | Optional | 
| retry_if_not_all_fetched | Whenever set to true, the command retries to fetch all events if the number of events fetched is less than `event_count`. Possible values are: true, false. | Optional | 
| polling | Wait for search results. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SearchEvents.ID | Unknown | The search id of the query. | 
| QRadar.SearchEvents.Events | Unknown | The events from QRadar search. | 
| QRadar.SearchEvents.Status | Unknown | The status of the search \('wait', 'partial', 'success'\). | 

#### Command example
```!qradar-search-retrieve-events offense_id=14```
#### Context Example
```json
{
    "QRadar": {
        "SearchEvents": {
            "ID": "9c2c18a8-5e06-4edb-bc26-53ad44421148",
            "Status": "wait"
        }
    }
}
```

#### Human Readable Output

>Search ID: 9c2c18a8-5e06-4edb-bc26-53ad44421148

### qradar-remote-network-cidr-create

***
Create remote network CIDRs.

#### Base Command

`qradar-remote-network-cidr-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cidrs | An input list of CIDRs to add to QRadar (can be obtained automatically from EDL integrations and playbook). Multiple values in the same object are separated by commas. A CIDR or query is required. | Optional | 
| query | The query for getting indicators from Cortex XSOAR. A CIDR or query is required. | Optional | 
| name | A CIDR (remote network) name that will be displayed for all uploaded values in QRadar. | Required | 
| description | Description that will be displayed and associated with all the newly uploaded CIDRs in QRadar. | Required | 
| group | The exact name of the remote network group that CIDRs should be associated with as it appears in QRadar. A single group can be assigned to each create command. A new remote network group can be created in QRadar by giving a new unique remote network group name (that does not already exist in QRadar remote networks). | Required | 
| fields | Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded from the output. Specify subfields in brackets, and multiple fields in the same object are separated by commas. The possible fields are id, group, name, CIDR, and description. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-remote-network-cidr-list

***
Retrieves the list of staged remote networks.

#### Base Command

`qradar-remote-network-cidr-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default is 50. | Optional | 
| page | The page offset. | Optional | 
| page_size | Maximum number of results to retrieve in each page. | Optional | 
| group | The name of the remote network group that the CIDRs are associated with, as it appears in QRadar. | Optional | 
| id | ID of the CIDR (remote network). | Optional | 
| name | The name of the CIDRs (remote network) as it appears in QRadar. | Optional | 
| filter | Additional options to filter results using a query expression. | Optional | 
| fields | Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. By default, this argument returns all fields (id, name, cidrs, group, description). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.RemoteNetworkCIDR | Number | A list of all the retrieved CIDRs. | 
| QRadar.RemoteNetworkCIDR.id | Number | ID of each CIDR remote network that is part of the group. | 
| QRadar.RemoteNetworkCIDR.name | String | The associated CIDR name as it appears in QRadar. | 
| QRadar.RemoteNetworkCIDR.description | String | The associated CIDR description as it appears in QRadar. | 

### qradar-remote-network-cidr-delete

***
Deletes an existing staged remote network.

#### Base Command

`qradar-remote-network-cidr-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID that is used to locate the staged remote network that users want to remove from QRadar. | Required | 

#### Context Output

There is no context output for this command.
### qradar-remote-network-cidr-update

***
Updates an existing staged remote network.

#### Base Command

`qradar-remote-network-cidr-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID that is associated with the CIDR object that needs to be modified. | Required | 
| name | The CIDR name in QRadar. If the CIDR name should be changed, it can be inserted here. | Required | 
| cidrs | An input list of CIDRs to add to QRadar (can be obtained automatically from EDL integrations and playbook). Multiple values in the same object are separated by commas. A CIDR or query is required. | Optional | 
| query | The query for getting indicators from Cortex XSOAR. A CIDR or query is required. | Optional | 
| description | CIDR associated description presented in QRadar. If the CIDR description should be changed, it can be inserted here. | Required | 
| group | The remote network group that CIDRs should belong to. If the CIDR-associated group should be changed, it can be inserted here. | Required | 
| fields | Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets, and multiple fields in the same object are separated by commas. The possible fields are id,group,name,cidr,description. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.RemoteNetworkCIDR | Number | A list of all the CIDR ranges that were changed. | 
| QRadar.RemoteNetworkCIDR.id | Number | The associated CIDR ID. | 
| QRadar.RemoteNetworkCIDR.name | String | The associated CIDR name. | 
| QRadar.RemoteNetworkCIDR.group | String | The group to which the remote network belongs. | 
| QRadar.RemoteNetworkCIDR.description | String | The description of the remote network. | 

### qradar-remote-network-deploy-execution

***
Executes a deployment.
Potentially harmful: This API command executes any waiting system deployments in QRadar within the same deployment type and hosts defined.


#### Base Command

`qradar-remote-network-deploy-execution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ip | The IP of QRadar console host. | Required | 
| status | The deployment status. Must be in capital letters (“INITIATING”). Possible values are: INITIATING. | Optional | 
| deployment_type | The deployment type. Must be in capital letters (“INCREMENTAL” or “FULL”). Possible values are: INCREMENTAL, FULL. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.deploy.status | String | The deployment status \(INITIALIZING, IN_PROGRESS, COMPLETE\). | 
### qradar-log-source-extensions-list

***
Retrieves a list of log source extensions.

#### Base Command

`qradar-log-source-extensions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter disconnected log collectors, e.g., "protocol=udp". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,protocol". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_extensions-GET.html. | Optional | 
| id | ID of a specific disconnected log collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSourceExtension.Name | String | The name of the log source extension. | 
| QRadar.LogSourceExtension.Description | String | The description of the log source extension. | 
| QRadar.LogSourceExtension.ID | Number | The ID of the extension. | 
| QRadar.LogSourceExtension.UUID | String | The UUID string of the log source extension. | 

### qradar-log-source-delete

***
Deletes a log source by ID or name. One of the arguments must be provided.

#### Base Command

`qradar-log-source-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the log source to be deleted. If this argument is not provided, name must be provided. | Optional | 
| name | The unique name of the log source to be deleted. If this argument is not provided, the ID must be provided. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-wincollect-destinations-list

***
Retrieves a list of WinCollect destinations. 
In order to get wincollect_internal_destination_ids - filter internal=true needs to be used
In order to get wincollect_external_destination_ids - filter internal=false needs to be used.

#### Base Command

`qradar-wincollect-destinations-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter wincollect destinations, e.g., "internal=true". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,host". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-wincollect-wincollect_destinations-GET.html. | Optional | 
| id | ID of a specific WinCollect destination. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.WinCollectDestination.ID | Number | The ID of the WinCollect destination. | 
| QRadar.WinCollectDestination.Name | String | The name of the WinCollect destination. | 
| QRadar.WinCollectDestination.Host | String | The IP or hostname of the WinCollect destination. WinCollect agents that use this destination send syslog event data to this host. | 
| QRadar.WinCollectDestination.TlsCertificate | String | The TLS Certificate of the WinCollect destination. | 
| QRadar.WinCollectDestination.Port | Number | The listen port of the WinCollect destination. WinCollect agents that use this destination send syslog event data to this port. | 
| QRadar.WinCollectDestination.TransportProtocol | String | The protocol that is used to send event data to this WinCollect destination. Possible values are TCP or UDP. | 
| QRadar.WinCollectDestination.IsInternal | Boolean | Set to "true" if the destination corresponds to a QRadar event collector process from this deployment; otherwise, it is set to false if it is any other host. | 
| QRadar.WinCollectDestination.EventRateThrottle | Number | The events-per-second rate that is used to throttle the event flow to this destination. | 

### qradar-log-source-create

***
Creates a new log source.

#### Base Command

`qradar-log-source-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The unique name of the log source. | Required | 
| protocol_type_id | The type of protocol that is used by the log source. Must correspond to an existing protocol type. | Required | 
| type_id | The type of the log source. Must correspond to an existing log source type. | Required | 
| protocol_parameters | The list of protocol parameters corresponding with the selected protocol type ID. The syntax for this argument should follow: protocol_parameters="name_1=value_1,name_2=value_2,...,name_n=value_n" where each name should correspond to a name of a protocol parameter from the protocol type and each value should fit the type of the protocol parameter. The command qradar-log-source-protocol-types-list can be used to list all available protocol types. | Required | 
| target_event_collector_id | The ID of the event collector where the log source sends its data. The ID must correspond to an existing event collector. | Required | 
| sending_ip | The IP of the system which the log source is associated to, or fed by. | Optional | 
| description | The description of the log source. | Optional | 
| coalesce_events | Determines if events collected by this log source are coalesced based on common properties. If each individual event is stored, then the condition is set to false. Defaults to true. | Optional | 
| enabled | Determines if the log source is enabled. Defaults to true. | Optional | 
| parsing_order | The order in which log sources will parse if multiples exist with a common identifier. | Optional | 
| group_ids | The set of log source group IDs this log source is a member of. Each ID must correspond to an existing log source group. The command qradar-log-sources-groups-list can be used to list all available groups. See the Log Source Group API (https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_groups-id-GET.html). | Optional | 
| credibility | On a scale of 0-10, the amount of credibility that the QRadar administrator places on this log source. | Optional | 
| store_event_payload | If the payloads of events that are collected by this log source are stored, the condition is set to 'true'. If only the normalized event records are stored, then the condition is set to 'false'. | Optional | 
| disconnected_log_collector_id | The ID of the disconnected log collector where this log source will run. The ID must correspond to an existing disconnected log collector. | Optional | 
| language_id | The language of the events that are being processed by this log source. Must correspond to an existing log source language. | Optional | 
| requires_deploy | Set to 'true' if you need to deploy changes to enable the log source for use; otherwise, set to 'false' if the log source is already active. | Optional | 
| wincollect_internal_destination_id | The internal WinCollect destination for this log source, if applicable. Log sources without an associated WinCollect agent have a null value. Must correspond to an existing WinCollect destination. | Optional | 
| wincollect_external_destination_ids | The set of external WinCollect destinations for this log source, if applicable. Log sources without an associated WinCollect agent have a null value. Each ID must correspond to an existing WinCollect destination. | Optional | 
| gateway | If the log source is configured as a gateway, the condition is set to 'true'; otherwise, the condition is set to 'false'. A gateway log source is a standalone protocol configuration. The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to feed other log sources. It acts as a "gateway" for events from multiple systems to enter the event pipeline. | Optional | 

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
| QRadar.LogSource.Status | unknown | Status of the log source. | 
| QRadar.LogSource.TargetEventCollectorID | Number | The ID of the event collector where the log source sends its data. | 

### qradar-log-source-languages-list

***
Retrieves a list of log source languages.

#### Base Command

`qradar-log-source-languages-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter disconnected log collectors, e.g., "protocol=udp". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,protocol". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_languages-GET.html. | Optional | 
| id | ID of a specific disconnected log collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSourceLanguage.ID | Number | The ID of the language. This ID does not change across deployments. | 
| QRadar.LogSourceLanguage.Name | String | The display name of the language. | 

### qradar-log-source-protocol-types-list

***
Retrieves the list of protocol types.

#### Base Command

`qradar-log-source-protocol-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter disconnected log collectors, e.g., "protocol=udp". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,protocol_parameters". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-protocol_types-GET.html. | Optional | 
| id | ID of a specific disconnected log collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSourceProtocolType.GatewaySupported | Boolean | If this protocol type can be configured for a gateway log source, the condition is set to 'true'; otherwise, the condition is set to 'false'. A gateway log source is a standalone protocol configuration. The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to feed other log sources. It acts as a 'gateway' for events from multiple systems to enter the event pipeline. Not all protocol types can be used as a gateway if they don't support collecting event data from multiple sources. | 
| QRadar.LogSourceProtocolType.ID | Number | The ID of the protocol type. | 
| QRadar.LogSourceProtocolType.Inbound | Boolean | Indicates whether this is an inbound protocol. | 
| QRadar.LogSourceProtocolType.LatestVersion | String | The latest version available of the protocol type component. | 
| QRadar.LogSourceProtocolType.Name | String | The unique name of the protocol type. | 
| QRadar.LogSourceProtocolType.ParameterGroups.id | Number | The ID of the protocol parameter group. | 
| QRadar.LogSourceProtocolType.ParameterGroups.name | String | The name of the protocol parameter group. | 
| QRadar.LogSourceProtocolType.ParameterGroups.required | Boolean | If at least one parameter in this group must be set, the condition is set to true; otherwise, the condition is set to false. | 
| QRadar.LogSourceProtocolType.Parameters.allowed_values.name | String | An allowed value for the name of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.allowed_values.value | String | An allowed value for the value of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.default_value | String | The optional default parameter value. | 
| QRadar.LogSourceProtocolType.Parameters.description | String | The description of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.group_id | Number | The ID of the protocol parameter group that this parameter belongs to. The group_id is optional. | 
| QRadar.LogSourceProtocolType.Parameters.id | Number | The ID of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.label | String | The label of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.max_length | Number | The maximum length of the parameter value for the following parameter types: STRING, TEXT, HOST, PASSWORD, REGEX. The max_length is optional. | 
| QRadar.LogSourceProtocolType.Parameters.max_value | String | The maximum of the parameter value for the following parameter types: INTEGER, REAL, DATE, TIME, DATETIME, INTERVAL. The max_value is optional. | 
| QRadar.LogSourceProtocolType.Parameters.min_length | Number | The minimum length of the parameter value for the following parameter types: STRING, TEXT, HOST, PASSWORD, REGEX. The max_length is optional. | 
| QRadar.LogSourceProtocolType.Parameters.min_value | String | The minimum of the parameter value for the following parameter types: INTEGER, REAL, DATE, TIME, DATETIME, INTERVAL. The max_value is optional. | 
| QRadar.LogSourceProtocolType.Parameters.name | String | The name of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.pattern | String | An optional Java regex pattern restriction on the parameter value for the following parameter types: STRING, TEXT, HOST, PASSWORD. | 
| QRadar.LogSourceProtocolType.Parameters.pattern_description | String | The description of the pattern of the parameter. | 
| QRadar.LogSourceProtocolType.Parameters.required | Boolean | If the parameter is mandatory, the condition is set to true; otherwise, the condition is set to false. | 
| QRadar.LogSourceProtocolType.Parameters.rules.affected_property | String | The affected property. For possible values visit: https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-protocol_types-GET.html | 
| QRadar.LogSourceProtocolType.Parameters.rules.affected_property_value | String | The value to be applied to the affected parameter when the rule is triggered. For further info visit: https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-protocol_types-GET.html | 
| QRadar.LogSourceProtocolType.Parameters.rules.parameter_id | Number | The ID of the parameter affected by the rule. | 
| QRadar.LogSourceProtocolType.Parameters.rules.trigger_parameter_id | Number | The ID of the trigger parameter. | 
| QRadar.LogSourceProtocolType.Parameters.rules.trigger_pattern | String | The pattern that triggers the rule. For example, if the value of trigger_parameter_id matches the regular expression of this field, the rule triggers. | 
| QRadar.LogSourceProtocolType.Parameters.type | String | The type of the parameter. Possible values are: STRING, TEXT, INTEGER, REAL, BOOLEAN, DATE, TIME, DATETIME, INTERVAL, HOST, PASSWORD, REGEX. | 
| QRadar.LogSourceProtocolType.TestingCapabilities.can_accept_sample_events | Boolean | Indicates whether the protocol type can accept sample events \(only applicable to inbound protocol types\). | 
| QRadar.LogSourceProtocolType.TestingCapabilities.can_collect_events | Boolean | Indicates whether the protocol type can collect test events. | 
| QRadar.LogSourceProtocolType.TestingCapabilities.testable | Boolean | Indicates whether the protocol type is testable. | 
| QRadar.LogSourceProtocolType.Version | String | The version of the protocol type component. | 

### qradar-disconnected-log-collectors-list

***
Retrieves a list of disconnected log collectors.

#### Base Command

`qradar-disconnected-log-collectors-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter disconnected log collectors, e.g., "protocol=udp". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,protocol". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-disconnected_log_collectors-GET.html. | Optional | 
| id | ID of a specific disconnected log collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.DisconnectedLogCollector.ID | Number | The ID of the disconnected log collector. | 
| QRadar.DisconnectedLogCollector.Name | String | The name of the disconnected log Collector. | 
| QRadar.DisconnectedLogCollector.Description | String | The description of the disconnected log collector. | 
| QRadar.DisconnectedLogCollector.Protocol | String | The transport protocol used by the disconnected log collector to send events to QRadar. Possible values are TLS and UDP. | 
| QRadar.DisconnectedLogCollector.UUID | String | The UUID of the disconnected log collector. | 
| QRadar.DisconnectedLogCollector.Version | String | The version of the disconnected log collector. | 

### qradar-log-source-update

***
Updates an exising log source.

#### Base Command

`qradar-log-source-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the log source. | Required | 
| name | The unique name of the log source. | Optional | 
| protocol_type_id | The type of protocol that is used by the log source. Must correspond to an existing protocol type. | Optional | 
| type_id | The type of the log source. Must correspond to an existing log source type. | Optional | 
| protocol_parameters | The list of protocol parameters corresponding with the selected protocol type ID. The syntax for this argument should follow: protocol_parameters="name_1=value_1,name_2=value_2,...,name_n=value_n" where each name should correspond to a name of a protocol parameter from the protocol type and each value should fit the type of the protocol parameter. The command qradar-log-source-protocol-types-list can be used to list all available protocol types. | Optional | 
| target_event_collector_id | The ID of the event collector where the log source sends its data. The ID must correspond to an existing event collector. | Optional | 
| sending_ip | The IP of the system which the log source is associated to, or fed by. | Optional | 
| description | The description of the log source. | Optional | 
| coalesce_events | Determines if events collected by this log source are coalesced based on common properties. If each individual event is stored, then the condition is set to false. Defaults to true. | Optional | 
| enabled | Determines if the log source is enabled. Defaults to true. | Optional | 
| parsing_order | The order in which log sources will parse if multiples exist with a common identifier. | Optional | 
| group_ids | The set of log source group IDs this log source is a member of. Each ID must correspond to an existing log source group. The command qradar-log-sources-groups-list can be used to list all available groups. See the Log Source Group API (https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_groups-id-GET.html). | Optional | 
| credibility | On a scale of 0-10, the amount of credibility that the QRadar administrator places on this log source. | Optional | 
| store_event_payload | If the payloads of events that are collected by this log source are stored, the condition is set to 'true'. If only the normalized event records are stored, then the condition is set to 'false'. | Optional | 
| disconnected_log_collector_id | The ID of the disconnected log collector where this log source will run. The ID must correspond to an existing disconnected log collector. | Optional | 
| language_id | The language of the events that are being processed by this log source. Must correspond to an existing log source language. | Optional | 
| requires_deploy | Set to 'true' if you need to deploy changes to enable the log source for use; otherwise, set to 'false' if the log source is already active. | Optional | 
| wincollect_internal_destination_id | The internal WinCollect destination for this log source, if applicable. Log sources without an associated WinCollect agent have a null value. Must correspond to an existing WinCollect destination. | Optional | 
| wincollect_external_destination_ids | The set of external WinCollect destinations for this log source, if applicable. Log Sources without an associated WinCollect agent have a null value. Each ID must correspond to an existing WinCollect destination. | Optional | 
| gateway | If the log source is configured as a gateway, the condition is set to 'true'; otherwise, the condition is set to 'false'. A gateway log source is a standalone protocol configuration. The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to feed other log sources. It acts as a "gateway" for events from multiple systems to enter the event pipeline. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-log-source-types-list

***
Retrieves a list of log sources types.

#### Base Command

`qradar-log-source-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter disconnected log collectors, e.g., "protocol=udp". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,protocol". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_types-GET.html. | Optional | 
| id | ID of a specific disconnected log collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSourceTypesList.Custom | Boolean | The condition is set to true if this is a custom log source type; otherwise, the condition is set to false. | 
| QRadar.LogSourceTypesList.DefaultProtocolID | Number | The ID of the default protocol type for this log source type. The ID must correspond to an existing protocol type. See the Protocol Type API \(/api/config/event_sources/log_source_management/protocol_types/\). | 
| QRadar.LogSourceTypesList.ID | Number | The ID of the log source type. | 
| QRadar.LogSourceTypesList.Internal | Boolean | The condition is set to true if the log source type is an internal log source type \(for example, System Notification, SIM Audit, Asset Profiler, and so on\) for which log sources cannot be created, edited, or deleted. If this is a user configurable log source type, the condition is set to false. | 
| QRadar.LogSourceTypesList.LatestVersion | String | The latest available version of the log source type component. | 
| QRadar.LogSourceTypesList.LogSourceExtensionID | Number | The log source extension that is associated with the log source type. The ID must correspond to an existing log source extension or be set to null. See the Log Source Extension API \(/api/config/event_sources/log_source_management/log_source_extensions/\). | 
| QRadar.LogSourceTypesList.Name | String | The unique name of the log source type. The name is not localized. | 
| QRadar.LogSourceTypesList.protocol_types.documented | Boolean | Indicates whether the protocol is documented/fully supported for this log source type. | 
| QRadar.LogSourceTypesList.protocol_types.protocol_id | Number | ID of the protocol type. | 
| QRadar.LogSourceTypesList.supported_language_ids | List | The IDs of the languages supported by this log source type. Each ID must correspond to an existing log source language. See the Log Source Language API: https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_languages-id-GET.html | 
| QRadar.LogSourceTypesList.uuid | String | A UUID string of the log source type. | 
| QRadar.LogSourceTypesList.version | String | The log source type plugin version. | 

### qradar-log-source-groups-list

***
Retrieves a list of log source languages.

#### Base Command

`qradar-log-source-groups-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter disconnected log collectors, e.g., "protocol=udp". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,protocol". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-log_source_management-log_source_groups-GET.html. | Optional | 
| id | ID of a specific disconnected log collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSourceGroup.Assignable | Boolean | If log sources can be assigned to this group, the condition is set to true; otherwise, the condition is set to false. Log sources cannot be assigned directly to the "Other" group or to the root log source group node. | 
| QRadar.LogSourceGroup.ChildGroupIDs | List | The list of IDs of any child log source groups that belong to this group. | 
| QRadar.LogSourceGroup.Description | String | The description of the group. | 
| QRadar.LogSourceGroup.ID | Number | The ID of the group. | 
| QRadar.LogSourceGroup.ModificationDate | Number | The date and time \(expressed as milliseconds since epoch\) that the group was last modified. | 
| QRadar.LogSourceGroup.Name | String | The name of the group. | 
| QRadar.LogSourceGroup.Owner | String | The name of the user who owns the group. | 
| QRadar.LogSourceGroup.ParentID | Number | The ID of the group's parent group. The root node group has a null parent_ID. | 

### qradar-event-collectors-list

***
Retrieves a list of event collectors.

#### Base Command

`qradar-event-collectors-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter event collectors, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--config-event_sources-event_collectors-GET.html. | Optional | 
| id | ID of a specific event collector. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.EventCollector.Name | String | The display name of the event collector. Not localized because it is derived from a process/component name and the hostname of the managed host it runs on, neither of which are translatable. | 
| QRadar.EventCollector.HostID | Number | The ID of the host on which this event collector process runs. | 
| QRadar.EventCollector.ComponentName | String | The name of the component backing this event collector process. Also contained in the "name" field. | 
| QRadar.EventCollector.ID | Number | The unique ID of the event collector. | 

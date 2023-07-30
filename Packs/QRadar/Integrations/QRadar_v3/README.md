IBM QRadar SIEM helps security teams accurately detect and prioritize threats across the enterprise, supports API versions 10.1 and above. Provides intelligent insights that enable teams to respond quickly to reduce the impact of incidents.
This integration was integrated and tested with version 17.0 of QRadar v3

## Configure IBM QRadar v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IBM QRadar v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
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
    | Query to fetch offenses. | Define a query to determine which offenses to fetch. E.g., "severity &gt;= 4 AND id &gt; 5". filtering by status in the query may result in unexpected behavior when changing an incident's status. | False |
    | Incidents Enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. | True |
    | Event fields to return from the events query (WARNING: This parameter is correlated to the incoming mapper and changing the values may adversely affect mapping). | The parameter uses the AQL SELECT syntax. For more information, see: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.4/com.ibm.qradar.doc/c_aql_intro.html | False |
    | Mirroring Options | How mirroring from QRadar to Cortex XSOAR should be done, available from QRadar 7.3.3 Fix Pack 3. For further explanation on how to check your QRadar version, see the integration documentation at https://xsoar.pan.dev. | False |
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
| qradar-domains-list | qradar-get-domain-by-id | Specify the *domain_id* argument in the command. |  |


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
                "LinkToOffense": "https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14",
                "Magnitude": 5,
                "OffenseSource": "userD",
                "OffenseType": "Username",
                "Protected": true,
                "Relevance": 1,
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
                "LinkToOffense": "https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=13",
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
                "LinkToOffense": "https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=12",
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
>|ID|Description|OffenseType|Status|Severity|Magnitude|Categories|RemoteDestinationCount|EventCount|Protected|Credibility|Relevance|SourceAddress|OffenseSource|DestinationHostname|Followup|DestinationAddress|LinkToOffense|StartTime|FlowCount|LastUpdatedTime|Rules|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 14 | Detected A Successful Login From Different Geographies For the Same Username - AWSCloud (Exp Center)<br/> preceded by An AWS API Has Been Invoked From Kali - AWSCloud (Exp Center)<br/> preceded by Microsoft Word Launc<br/> preceded by Detected a Massive Creation of EC2 Instances - AWSCloud (Exp Center)<br/> containing Mail Server Info Message<br/> | Username | OPEN | 10 | 5 | Information,<br/>Suspicious Activity,<br/>Process Creation Success,<br/>Suspicious Windows Events,<br/>User Login Attempt,<br/>Misc Login Succeeded,<br/>Virtual Machine Creation Attempt,<br/>Read Activity Attempted,<br/>Object Download Attempt | 1 | 35651 | true | 4 | 1 | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | userD | other,<br/>Net-10-172-192.Net_192_168_0_0 | true | 1.1.1.1,<br/>1.1.1.1 | https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14 | 2023-07-26T14:31:13.387000+00:00 | 0 | 2023-07-26T15:31:11.839000+00:00 | {'id': 102539, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender'},<br/>{'id': 102589, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Microsoft Word Launched a Command Shell'},<br/>{'id': 102639, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected A Successful Login From Different Geographies For the Same Username'},<br/>{'id': 102389, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - An AWS API Has Been Invoked From Kali'},<br/>{'id': 102439, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket'},<br/>{'id': 102489, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected a Massive Creation of EC2 Instances'} |
>| 13 | Flow Source/Interface Stopped Sending Flows<br/> | Rule | OPEN | 1 | 1 | Mail,<br/>System Failure | 0 | 2 | true | 2 | 0 | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | Flow Source Stopped Sending Flows | Net-10-172-192.Net_10_0_0_0 | true | 1.1.1.1 | https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=13 | 2023-06-12T08:19:02.020000+00:00 | 6026 | 2023-06-12T08:49:50.145000+00:00 | {'id': 100270, 'type': 'CRE_RULE', 'name': 'Flow Source Stopped Sending Flows'} |
>| 12 | User Account Created and Used and Deleted within a short time frame (Exp Center)<br/> | Username | OPEN | 5 | 2 | User Activity | 0 | 8 | true | 3 | 0 | 1.1.1.1 | badadmin | Net-10-172-192.Net_172_16_0_0 | true | 1.1.1.1 | https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=12 | 2023-06-12T08:15:54.740000+00:00 | 0 | 2023-06-12T08:17:33.008000+00:00 | {'id': 102989, 'type': 'CRE_RULE', 'name': 'EC: User Account Created and Used and Removed'} |


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
            "LinkToOffense": "https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14",
            "Magnitude": 5,
            "OffenseSource": "userD",
            "OffenseType": "Username",
            "Protected": false,
            "Relevance": 1,
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
>|ID|Description|OffenseType|Status|Severity|Magnitude|Categories|AssignedTo|RemoteDestinationCount|EventCount|Protected|Credibility|Relevance|SourceAddress|OffenseSource|DestinationHostname|Followup|DestinationAddress|LinkToOffense|StartTime|FlowCount|LastUpdatedTime|Rules|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 14 | Detected A Successful Login From Different Geographies For the Same Username - AWSCloud (Exp Center)<br/> preceded by An AWS API Has Been Invoked From Kali - AWSCloud (Exp Center)<br/> preceded by Microsoft Word Launc<br/> preceded by Detected a Massive Creation of EC2 Instances - AWSCloud (Exp Center)<br/> containing Mail Server Info Message<br/> | Username | OPEN | 10 | 5 | Information,<br/>Suspicious Activity,<br/>Process Creation Success,<br/>Suspicious Windows Events,<br/>User Login Attempt,<br/>Misc Login Succeeded,<br/>Virtual Machine Creation Attempt,<br/>Read Activity Attempted,<br/>Object Download Attempt | admin | 1 | 35651 | false | 4 | 1 | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | userD | other,<br/>Net-10-172-192.Net_192_168_0_0 | true | 1.1.1.1,<br/>1.1.1.1 | https://ec2-54-155-52-85.eu-west-1.compute.amazonaws.com/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=14 | 2023-07-26T14:31:13.387000+00:00 | 0 | 2023-07-26T15:31:11.839000+00:00 | {'id': 102539, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender'},<br/>{'id': 102589, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Microsoft Word Launched a Command Shell'},<br/>{'id': 102639, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected A Successful Login From Different Geographies For the Same Username'},<br/>{'id': 102389, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - An AWS API Has Been Invoked From Kali'},<br/>{'id': 102439, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket'},<br/>{'id': 102489, 'type': 'CRE_RULE', 'name': 'EC: AWS Cloud - Detected a Massive Creation of EC2 Instances'} |


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
                "CreateTime": "2023-07-27T10:43:15.800000+00:00",
                "CreatedBy": "API_user: admin",
                "ID": 47,
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
>| 47 | Note Regarding The Offense | API_user: admin | 2023-07-27T10:43:15.800000+00:00 |


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
            "CreateTime": "2023-07-30T09:51:59.141000+00:00",
            "CreatedBy": "API_user: admin",
            "ID": 55,
            "Text": "Note Regarding The Offense"
        }
    }
}
```

#### Human Readable Output

>### Create Note
>|ID|Text|CreatedBy|CreateTime|
>|---|---|---|---|
>| 55 | Note Regarding The Offense | API_user: admin | 2023-07-30T09:51:59.141000+00:00 |


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
>|ID|Name|Type|AverageCapacity|ModificationDate|Owner|Enabled|BaseHostID|BaseCapacity|CapacityTimestamp|Origin|CreationDate|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100068 | Login Successful After Scan Attempt | COMMON | 0 | 2022-11-21T18:44:32.696000+00:00 | admin | true | 0 | 0 | 0 | SYSTEM | 2007-10-14T20:12:00.374000+00:00 |
>| 100102 | Potential Botnet Connection (DNS) | COMMON | 0 | 2023-02-23T14:12:52.067000+00:00 | admin | false | 0 | 0 | 0 | SYSTEM | 2006-03-27T10:54:12.077000+00:00 |
>| 100109 | Host Port Scan Detected by Remote Host | COMMON | 0 | 2023-02-23T14:12:49.992000+00:00 | admin | true | 0 | 0 | 0 | SYSTEM | 2005-12-22T00:54:48.708000+00:00 |


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
>|ID|Name|Description|Owner|ChildItems|Level|ParentID|Type|ModifiedTime|
>|---|---|---|---|---|---|---|---|---|
>| 125 | Asset Reconciliation Exclusion | Rules focused on detection of suspicious asset reconciliation behavior. | admin | 100045,<br/>100046,<br/>100047,<br/>100048,<br/>100049,<br/>100050,<br/>100051,<br/>100052,<br/>100053,<br/>100054,<br/>100055,<br/>100056,<br/>1607,<br/>1608,<br/>1609,<br/>1610,<br/>1611,<br/>1612,<br/>1613,<br/>1614,<br/>1615,<br/>1616,<br/>1617,<br/>1618 | 2 | 3 | RULE_GROUP | 2014-01-06T15:23:26.060000+00:00 |
>| 100020 | Horizontal Movement | Rules that indicate post-intrusion access activity | admin | 100057,<br/>100059 | 2 | 3 | RULE_GROUP | 2015-07-08T20:14:12.250000+00:00 |
>| 101 | Anomaly | Rules based on log source and event anomalies such as high event rates or excessive connections. | admin | 100001,<br/>100003,<br/>100044,<br/>100323,<br/>1219,<br/>1265,<br/>1335,<br/>1410,<br/>1411,<br/>1412,<br/>1431,<br/>1443,<br/>1460,<br/>1461,<br/>1471,<br/>1481,<br/>1509,<br/>1552,<br/>1566 | 1 | 3 | RULE_GROUP | 2010-08-21T11:48:27.850000+00:00 |


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
                "AQL": "select QIDNAME(qid) as 'Event Name',logsourcename(logSourceId) as 'Log Source',\"eventCount\" as 'Event Count',\"startTime\" as 'Time',categoryname(category) as 'Low Level Category',\"sourceIP\" as 'Source IP',\"sourcePort\" as 'Source Port',\"destinationIP\" as 'Destination IP',\"destinationPort\" as 'Destination Port',\"userName\" as 'Username',\"magnitude\" as 'Magnitude' from events where \"Experience Center\" ilike '%AWSCloud%' order by \"startTime\" desc LIMIT 1000 start '2023-07-30 09:47' stop '2023-07-30 09:52'",
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
>|ID|Name|UID|ModifiedDate|AQL|Owner|Database|IsShared|CreationDate|QuickSearch|
>|---|---|---|---|---|---|---|---|---|---|
>| 2817 | EC: AWS Cloud Attack Events | 0144c7d8-a3fe-47c1-b16b-12721a34077e | 2023-02-23T14:12:52.611000+00:00 | select QIDNAME(qid) as 'Event Name',logsourcename(logSourceId) as 'Log Source',"eventCount" as 'Event Count',"startTime" as 'Time',categoryname(category) as 'Low Level Category',"sourceIP" as 'Source IP',"sourcePort" as 'Source Port',"destinationIP" as 'Destination IP',"destinationPort" as 'Destination Port',"userName" as 'Username',"magnitude" as 'Magnitude' from events where "Experience Center" ilike '%AWSCloud%' order by "startTime" desc LIMIT 1000 start '2023-07-30 09:47' stop '2023-07-30 09:52' | admin | EVENTS | false | 2019-04-02T17:39:08.493000+00:00 | false |
>| 2835 | Potential Ransomware (Suspicious activity, Possible Petya, NotPetya) | 0791701a-80e3-4a1c-b11f-7bc943b96bf6 | 2023-03-05T13:34:00.352000+00:00 | select * from flows where destinationport = '445' and (FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%70 00 73 00 65 00 78 00 65 00 63 00 73 00 76 00 63 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%50 00 53 00 45 00 58 00 45 00 53 00 56 00 43 00 2e 00 45 00 58 00 45%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%73 00 76 00 63 00 63 00 74 00 6c 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%5c 00 61 00 64 00 6d 00 69 00 6e 00 24 00%' OR FORMAT::PAYLOAD_TO_HEX(sourcepayload) like '%ff 53 4d 42 72 00 00 00 00 18 07 c0%') last 24 HOURS | admin | FLOWS | true | 2017-07-02T18:11:44.984000+00:00 | false |


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
                "SearchID": "31f27978-f59b-4dea-9ee2-f66610417ffe"
            },
            {
                "SearchID": "6647fddb-9e8b-435d-94c5-e85a07ff58c5"
            },
            {
                "SearchID": "5bf0e510-a969-41d8-a5f6-d1035902e1df"
            },
            {
                "SearchID": "d31a0bf3-cc2a-4c3f-9097-4bfd72984a9d"
            },
            {
                "SearchID": "a9e7887d-8a94-48fe-a0e0-3f97ba2a47f3"
            },
            {
                "SearchID": "345a4d1b-428d-4470-b6c0-6632ea1cc915"
            },
            {
                "SearchID": "8cd443e7-f784-4ab8-99a8-6780dfe5a9fa"
            },
            {
                "SearchID": "36227863-bc6a-488f-9aa4-0f9c6f767655"
            },
            {
                "SearchID": "fe1d5919-d560-472a-890d-2910994b9185"
            },
            {
                "SearchID": "191cb2f2-760d-40a2-9593-3ef43ddabd14"
            },
            {
                "SearchID": "a6c693c0-550e-447b-a6e7-6db1a3fda712"
            },
            {
                "SearchID": "d618105e-a3e5-4e0a-82a9-fe53ae8bef8a"
            },
            {
                "SearchID": "ad70acef-1860-4198-bc78-17c46fd03a92"
            },
            {
                "SearchID": "a62bc421-c59d-4b3f-a482-ffbe28d4e409"
            },
            {
                "SearchID": "1ea246fc-1aa3-4b9b-8a2c-fbe7043b3207"
            },
            {
                "SearchID": "8c1fd5f6-f289-47b4-8c84-e4c47ca4688a"
            },
            {
                "SearchID": "e3fa2bdb-994e-4a35-9152-9fe528426a1e"
            },
            {
                "SearchID": "f559f8f2-784e-41ce-a129-8467f0a9c2a3"
            },
            {
                "SearchID": "d635b4f6-f93c-4951-9807-ba707518a8d4"
            },
            {
                "SearchID": "acbd24c5-a33a-4c39-8c82-b81ba6c928b6"
            },
            {
                "SearchID": "19e76e00-82b4-4cec-8bc7-6d5fcd5c8455"
            },
            {
                "SearchID": "aae19fc5-b3c8-4908-8679-f1eca85ea332"
            },
            {
                "SearchID": "14a2267f-e837-4d43-bad0-777c3edf6560"
            },
            {
                "SearchID": "22081745-93e0-4dc6-9254-98b3cefdd021"
            },
            {
                "SearchID": "1aef8743-2344-4e53-a2f6-5f4e9168ec0e"
            },
            {
                "SearchID": "71673d0a-a766-4681-ac09-3931409ad4a2"
            },
            {
                "SearchID": "d0ffb6d0-c01f-46fc-bc7b-5c55ebf82693"
            },
            {
                "SearchID": "4e6c53c4-1afb-4997-91e7-1613d28192cc"
            },
            {
                "SearchID": "8c1308a8-f68a-465d-a1c4-ed5a4f019351"
            },
            {
                "SearchID": "b386d4bc-908b-4657-ae96-9c23e0bb9fd4"
            },
            {
                "SearchID": "c2e77472-888d-423f-b172-63f3c45c4ff7"
            },
            {
                "SearchID": "20a161a4-9ef9-4b98-825b-8acb7873c6dd"
            },
            {
                "SearchID": "667004ef-a741-4b3a-9674-73389e13c551"
            },
            {
                "SearchID": "dac7c890-c4d4-4b0b-8b73-6916fd0e7982"
            },
            {
                "SearchID": "f5a5dcce-4390-4d24-bcd0-6f54877f9057"
            },
            {
                "SearchID": "eebc9ac3-6719-4f3a-8976-ad5ab807ee76"
            },
            {
                "SearchID": "18168afc-39ff-4887-abd1-7be72c9f0d96"
            },
            {
                "SearchID": "7f134056-8047-43df-8eb6-9e746ab2de66"
            },
            {
                "SearchID": "e8410a1c-0f49-4093-a02b-12650d9fed4c"
            },
            {
                "SearchID": "ca14e016-77c2-4bea-8d9e-830449acd132"
            },
            {
                "SearchID": "62a2a323-4b86-4c4f-a90c-8d1c371d4330"
            },
            {
                "SearchID": "2e12aa6a-ac08-4a3c-87e3-dc50c726b091"
            },
            {
                "SearchID": "344feb8a-9acc-4c1f-9db7-67de2ef78edc"
            },
            {
                "SearchID": "eeccdb8d-d4b5-46b8-a2f1-44fcd83ffc6d"
            },
            {
                "SearchID": "21eb8da7-3c86-4b6b-a97c-b8542951d9ba"
            },
            {
                "SearchID": "450e7012-61db-4aa1-97af-30a0f566f0e7"
            },
            {
                "SearchID": "d656a2a8-2613-486e-b46e-9f9530660d74"
            },
            {
                "SearchID": "407d425e-9b29-49e4-9499-aff692d4e251"
            },
            {
                "SearchID": "06a06a43-421a-4de9-b2d8-6575b2910b93"
            },
            {
                "SearchID": "e9e1233b-9d11-43c5-8760-84fcfa64de2f"
            }
        ]
    }
}
```

#### Human Readable Output

>### Search ID List
>|SearchID|
>|---|
>| 31f27978-f59b-4dea-9ee2-f66610417ffe |
>| 6647fddb-9e8b-435d-94c5-e85a07ff58c5 |
>| 5bf0e510-a969-41d8-a5f6-d1035902e1df |
>| d31a0bf3-cc2a-4c3f-9097-4bfd72984a9d |
>| a9e7887d-8a94-48fe-a0e0-3f97ba2a47f3 |
>| 345a4d1b-428d-4470-b6c0-6632ea1cc915 |
>| 8cd443e7-f784-4ab8-99a8-6780dfe5a9fa |
>| 36227863-bc6a-488f-9aa4-0f9c6f767655 |
>| fe1d5919-d560-472a-890d-2910994b9185 |
>| 191cb2f2-760d-40a2-9593-3ef43ddabd14 |
>| a6c693c0-550e-447b-a6e7-6db1a3fda712 |
>| d618105e-a3e5-4e0a-82a9-fe53ae8bef8a |
>| ad70acef-1860-4198-bc78-17c46fd03a92 |
>| a62bc421-c59d-4b3f-a482-ffbe28d4e409 |
>| 1ea246fc-1aa3-4b9b-8a2c-fbe7043b3207 |
>| 8c1fd5f6-f289-47b4-8c84-e4c47ca4688a |
>| e3fa2bdb-994e-4a35-9152-9fe528426a1e |
>| f559f8f2-784e-41ce-a129-8467f0a9c2a3 |
>| d635b4f6-f93c-4951-9807-ba707518a8d4 |
>| acbd24c5-a33a-4c39-8c82-b81ba6c928b6 |
>| 19e76e00-82b4-4cec-8bc7-6d5fcd5c8455 |
>| aae19fc5-b3c8-4908-8679-f1eca85ea332 |
>| 14a2267f-e837-4d43-bad0-777c3edf6560 |
>| 22081745-93e0-4dc6-9254-98b3cefdd021 |
>| 1aef8743-2344-4e53-a2f6-5f4e9168ec0e |
>| 71673d0a-a766-4681-ac09-3931409ad4a2 |
>| d0ffb6d0-c01f-46fc-bc7b-5c55ebf82693 |
>| 4e6c53c4-1afb-4997-91e7-1613d28192cc |
>| 8c1308a8-f68a-465d-a1c4-ed5a4f019351 |
>| b386d4bc-908b-4657-ae96-9c23e0bb9fd4 |
>| c2e77472-888d-423f-b172-63f3c45c4ff7 |
>| 20a161a4-9ef9-4b98-825b-8acb7873c6dd |
>| 667004ef-a741-4b3a-9674-73389e13c551 |
>| dac7c890-c4d4-4b0b-8b73-6916fd0e7982 |
>| f5a5dcce-4390-4d24-bcd0-6f54877f9057 |
>| eebc9ac3-6719-4f3a-8976-ad5ab807ee76 |
>| 18168afc-39ff-4887-abd1-7be72c9f0d96 |
>| 7f134056-8047-43df-8eb6-9e746ab2de66 |
>| e8410a1c-0f49-4093-a02b-12650d9fed4c |
>| ca14e016-77c2-4bea-8d9e-830449acd132 |
>| 62a2a323-4b86-4c4f-a90c-8d1c371d4330 |
>| 2e12aa6a-ac08-4a3c-87e3-dc50c726b091 |
>| 344feb8a-9acc-4c1f-9db7-67de2ef78edc |
>| eeccdb8d-d4b5-46b8-a2f1-44fcd83ffc6d |
>| 21eb8da7-3c86-4b6b-a97c-b8542951d9ba |
>| 450e7012-61db-4aa1-97af-30a0f566f0e7 |
>| d656a2a8-2613-486e-b46e-9f9530660d74 |
>| 407d425e-9b29-49e4-9499-aff692d4e251 |
>| 06a06a43-421a-4de9-b2d8-6575b2910b93 |
>| e9e1233b-9d11-43c5-8760-84fcfa64de2f |


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
            "ID": "f9772703-8c15-4e0d-8756-d2d9ce96a4d9",
            "Status": "WAIT"
        }
    }
}
```

#### Human Readable Output

>### Create Search
>|ID|Status|
>|---|---|
>| f9772703-8c15-4e0d-8756-d2d9ce96a4d9 | WAIT |


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

#### Command example
```!qradar-search-status-get search_id=36227863-bc6a-488f-9aa4-0f9c6f767655```
#### Context Example
```json
{
    "QRadar": {
        "Search": {
            "ID": "36227863-bc6a-488f-9aa4-0f9c6f767655",
            "Status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### Search Status For Search ID 36227863-bc6a-488f-9aa4-0f9c6f767655
>|ID|Status|
>|---|---|
>| 36227863-bc6a-488f-9aa4-0f9c6f767655 | COMPLETED |


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

#### Command example
```!qradar-search-results-get search_id=36227863-bc6a-488f-9aa4-0f9c6f767655 range=0-3```
#### Context Example
```json
{
    "QRadar": {
        "Search": {
            "Result": {
                "events": [
                    {
                        "categoryname_category": "Object Download Attempt",
                        "categoryname_highlevelcategory": "Audit",
                        "credibility": 10,
                        "destinationgeographiclocation": "other",
                        "destinationip": "1.1.1.1",
                        "destinationport": 0,
                        "destinationv6": "0:0:0:0:0:0:0:0",
                        "devicetime": "2023-03-15T15:46:04+00:00",
                        "eventDirection": "R2L",
                        "eventcount": 1,
                        "logsourcename_logsourceid": "Experience Center: AWS Syslog @ 1.1.1.1",
                        "logsourcetypename_devicetype": "Universal DSM",
                        "magnitude": 10,
                        "postNatDestinationIP": "1.1.1.1",
                        "postNatDestinationPort": 0,
                        "postNatSourceIP": "1.1.1.1",
                        "postNatSourcePort": 0,
                        "preNatDestinationPort": 0,
                        "preNatSourceIP": "1.1.1.1",
                        "preNatSourcePort": 0,
                        "protocolname_protocolid": "Reserved",
                        "qiddescription_qid": "Get Object",
                        "qidname_qid": "Get Object",
                        "rulename_creEventList": [
                            "Source Asset Weight is Low",
                            "EC: AWS Cloud - An AWS API Has Been Invoked From Kali",
                            "EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket",
                            "Destination Asset Weight is Low",
                            "Context is Remote to Local",
                            "ECBB:CategoryDefinition: Destination IP is a Third Country/Region"
                        ],
                        "severity": 10,
                        "sourceMAC": "00:00:00:00:00:00",
                        "sourcegeographiclocation": "Europe.RussianFederation",
                        "sourceip": "1.1.1.1",
                        "sourceport": 0,
                        "sourcev6": "0:0:0:0:0:0:0:0",
                        "starttime": "2023-07-26T15:31:00.631000+00:00",
                        "username": "userD",
                        "utf8_payload": "<182>Mar 15 15:46:04 1.1.1.1 {\"eventVersion\":\"1.05\",\"userIdentity\":{\"type\":\"IAMUser\",\"arn\":\"arn:aws:iam::911534260404:user/user22\",\"accountId\":\"911534260404\",\"accessKeyId\":\"ASIA5IO5NAC2OIBXQ4NY\",\"userName\":\"userD\",\"invokedBy\":\"userD\"},\"eventSource\":\"s3.amazonaws.com\",\"eventName\":\"GetObject\",\"awsRegion\":\"us-west-2\",\"sourceIPAddress\":\"1.1.1.1\",\"userAgent\":\"[aws-cli/1.15.57 Python/2.7.14+ Linux/4.15.0-kali2-amd64 botocore/1.10.56]\",\"requestParameters\":{\"X-Amz-Date\":\"20180609T210803Z\",\"bucketName\":\"db_backups2032\",\"response-content-disposition\":\"inline\",\"X-Amz-Algorithm\":\"AWS4-HMAC-SHA256\",\"X-Amz-SignedHeaders\":\"host\",\"X-Amz-Expires\":\"300\",\"key\":\"fullDB_dump30102018.dump\"},\"resources\":[{\"type\":\"AWS::s3::Object\",\"ARN\":\"arn:aws:s3:::mystorage2007/fullDB_dump30102018.dump\"},{\"accountId\":\"911534260404\",\"type\":\"AWS::s3::Bucket\",\"ARN\":\"arn:aws:s3:::db_backups2032\"}]},\"ExperienceCenter\":\"AWSCloud\" "
                    },
                    {
                        "categoryname_category": "Suspicious Activity",
                        "categoryname_highlevelcategory": "Suspicious Activity",
                        "credibility": 10,
                        "destinationgeographiclocation": "other",
                        "destinationip": "1.1.1.1",
                        "destinationport": 0,
                        "destinationv6": "0:0:0:0:0:0:0:0",
                        "devicetime": "2023-07-26T15:31:00.732000+00:00",
                        "eventDirection": "R2L",
                        "eventcount": 1,
                        "logsourcename_logsourceid": "Custom Rule Engine-8 :: ip-172-31-17-10",
                        "logsourcetypename_devicetype": "Custom Rule Engine",
                        "magnitude": 7,
                        "postNatDestinationIP": "1.1.1.1",
                        "postNatDestinationPort": 0,
                        "postNatSourceIP": "1.1.1.1",
                        "postNatSourcePort": 0,
                        "preNatDestinationPort": 0,
                        "preNatSourceIP": "1.1.1.1",
                        "preNatSourcePort": 0,
                        "protocolname_protocolid": "Reserved",
                        "qiddescription_qid": "A Database backup Has Been Downloaded From S3 Bucket",
                        "qidname_qid": "A Database backup Has Been Downloaded From S3 Bucket - AWSCloud (Exp Center)",
                        "rulename_creEventList": [
                            "EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket",
                            "BB:CategoryDefinition: Suspicious Event Categories",
                            "BB:CategoryDefinition: Suspicious Events",
                            "Source Asset Weight is Low",
                            "Destination Asset Weight is Low",
                            "Load Basic Building Blocks",
                            "Context is Remote to Local",
                            "ECBB:CategoryDefinition: Destination IP is a Third Country/Region"
                        ],
                        "severity": 5,
                        "sourceMAC": "00:00:00:00:00:00",
                        "sourcegeographiclocation": "Europe.RussianFederation",
                        "sourceip": "1.1.1.1",
                        "sourceport": 0,
                        "sourcev6": "0:0:0:0:0:0:0:0",
                        "starttime": "2023-07-26T15:31:00.732000+00:00",
                        "username": "userD",
                        "utf8_payload": "A Database backup Has Been Downloaded From S3 Bucket - AWSCloud (Exp Center)\tA Database backup Has Been Downloaded From S3 Bucket"
                    },
                    {
                        "categoryname_category": "Information",
                        "categoryname_highlevelcategory": "System",
                        "credibility": 10,
                        "destinationgeographiclocation": "other",
                        "destinationip": "1.1.1.1",
                        "destinationport": 0,
                        "destinationv6": "0:0:0:0:0:0:0:0",
                        "devicetime": "2015-03-15T15:38:28+00:00",
                        "eventDirection": "L2L",
                        "eventcount": 1,
                        "logsourcename_logsourceid": "Experience Center: Cisco IronPort @ 1.1.1.1",
                        "logsourcetypename_devicetype": "Cisco IronPort",
                        "magnitude": 10,
                        "postNatDestinationIP": "1.1.1.1",
                        "postNatDestinationPort": 0,
                        "postNatSourceIP": "1.1.1.1",
                        "postNatSourcePort": 0,
                        "preNatDestinationPort": 0,
                        "preNatSourceIP": "1.1.1.1",
                        "preNatSourcePort": 0,
                        "protocolname_protocolid": "Reserved",
                        "qiddescription_qid": "Mail server info message",
                        "qidname_qid": "Mail Server Info Message",
                        "rulename_creEventList": [
                            "Source Asset Weight is Low",
                            "Destination Asset Weight is Low",
                            "EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender",
                            "BB:DeviceDefinition: Mail",
                            "BB:DeviceDefinition: Proxy",
                            "Load Basic Building Blocks",
                            "Context is Local to Local",
                            "ECBB:CategoryDefinition: Destination IP is a Third Country/Region"
                        ],
                        "severity": 10,
                        "sourceMAC": "00:00:00:00:00:00",
                        "sourcegeographiclocation": "other",
                        "sourceip": "1.1.1.1",
                        "sourceport": 0,
                        "sourcev6": "0:0:0:0:0:0:0:0",
                        "starttime": "2023-07-26T15:31:06.276000+00:00",
                        "username": "userD",
                        "utf8_payload": "<182>Mar 15 15:38:28 1.1.1.1 13:46:14 2015 Info: MID 987654321 ICID 351684134 From: <admin.AWS.console.management.aws.amazon.com@yoyobadh.date> To: <userD@example.com> Subject 'Urgent: AWS bill' attachment 'critical AWS bill.docx' ExperienceCenter=AWSCloud "
                    },
                    {
                        "categoryname_category": "Process Creation Success",
                        "categoryname_highlevelcategory": "System",
                        "credibility": 10,
                        "destinationgeographiclocation": "other",
                        "destinationip": "1.1.1.1",
                        "destinationport": 0,
                        "destinationv6": "0:0:0:0:0:0:0:0",
                        "devicetime": "2023-03-15T15:42:54+00:00",
                        "eventDirection": "R2R",
                        "eventcount": 1,
                        "logsourcename_logsourceid": "Experience Center: WindowsAuthServer @ IE8WIN7",
                        "logsourcetypename_devicetype": "Microsoft Windows Security Event Log",
                        "magnitude": 10,
                        "postNatDestinationIP": "1.1.1.1",
                        "postNatDestinationPort": 0,
                        "postNatSourceIP": "1.1.1.1",
                        "postNatSourcePort": 0,
                        "preNatDestinationPort": 0,
                        "preNatSourceIP": "1.1.1.1",
                        "preNatSourcePort": 0,
                        "protocolname_protocolid": "Reserved",
                        "qiddescription_qid": "The process creation event provides extended information about a newly created process.",
                        "qidname_qid": "Process Create",
                        "rulename_creEventList": [
                            "BB:NetworkDefinition: Honeypot like Addresses",
                            "BB:DeviceDefinition: Operating System",
                            "Source Asset Weight is Low",
                            "Source Address is a Bogon IP",
                            "Destination Asset Weight is Low",
                            "BB:NetworkDefinition: Darknet Addresses",
                            "Load Basic Building Blocks",
                            "EC: AWS Cloud - Microsoft Word Launched a Command Shell",
                            "ECBB:CategoryDefinition: Destination IP is a Third Country/Region"
                        ],
                        "severity": 10,
                        "sourceMAC": "00:00:00:00:00:00",
                        "sourcegeographiclocation": "other",
                        "sourceip": "1.1.1.1",
                        "sourceport": 0,
                        "sourcev6": "0:0:0:0:0:0:0:0",
                        "starttime": "2023-07-26T15:31:06.635000+00:00",
                        "username": "userD",
                        "utf8_payload": "<182>Mar 15 15:42:54 IE8WIN7 AgentDevice=WindowsLog\tAgentLogFile=Microsoft-Windows-Sysmon/Operational\tPluginVersion=1.1.1.1\tSource=Microsoft-Windows-Sysmon\tComputer=IE8WIN7\tOriginatingComputer=IE8WIN7\tUser=userD\tDomain=NT AUTHORITY\tEventID=1\tEventIDCode=1\tEventType=4\tEventCategory=4\tRecordNumber=32642\tLevel=Informational\tKeywords=0x8000000000000000\tTask=SysmonTask-SYSMON_CREATE_PROCESS\tOpcode=Info\tExperienceCenter=AWSCloud\tMessage=Process Create: UtcTime: 2018-10-28 16:01:32.836 Image: C:\\Windows\\System32\\cmd.exe CommandLine: C:\\Windows\\System32\\cmd.exe CurrentDirectory: C:\\Users\\userD\\ User: domain\\userD IntegrityLevel: Medium Hashes: MD5=6242E3D67787CCBF4E06AD2982853144 ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE ParentCommandLine: \"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" "
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Search Results For Search ID 36227863-bc6a-488f-9aa4-0f9c6f767655
>|categoryname_category|categoryname_highlevelcategory|credibility|destinationgeographiclocation|destinationip|destinationport|destinationv6|devicetime|eventDirection|eventcount|logsourcename_logsourceid|logsourcetypename_devicetype|magnitude|postNatDestinationIP|postNatDestinationPort|postNatSourceIP|postNatSourcePort|preNatDestinationPort|preNatSourceIP|preNatSourcePort|protocolname_protocolid|qiddescription_qid|qidname_qid|rulename_creEventList|severity|sourceMAC|sourcegeographiclocation|sourceip|sourceport|sourcev6|starttime|username|utf8_payload|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Object Download Attempt | Audit | 10 | other | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-03-15T15:46:04+00:00 | R2L | 1 | Experience Center: AWS Syslog @ 1.1.1.1 | Universal DSM | 10 | 1.1.1.1 | 0 | 1.1.1.1 | 0 | 0 | 1.1.1.1 | 0 | Reserved | Get Object | Get Object | Source Asset Weight is Low,<br/>EC: AWS Cloud - An AWS API Has Been Invoked From Kali,<br/>EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket,<br/>Destination Asset Weight is Low,<br/>Context is Remote to Local,<br/>ECBB:CategoryDefinition: Destination IP is a Third Country/Region | 10 | 00:00:00:00:00:00 | Europe.RussianFederation | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-07-26T15:31:00.631000+00:00 | userD | <182>Mar 15 15:46:04 1.1.1.1 {"eventVersion":"1.05","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::911534260404:user/user22","accountId":"911534260404","accessKeyId":"ASIA5IO5NAC2OIBXQ4NY","userName":"userD","invokedBy":"userD"},"eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-west-2","sourceIPAddress":"1.1.1.1","userAgent":"[aws-cli/1.15.57 Python/2.7.14+ Linux/4.15.0-kali2-amd64 botocore/1.10.56]","requestParameters":{"X-Amz-Date":"20180609T210803Z","bucketName":"db_backups2032","response-content-disposition":"inline","X-Amz-Algorithm":"AWS4-HMAC-SHA256","X-Amz-SignedHeaders":"host","X-Amz-Expires":"300","key":"fullDB_dump30102018.dump"},"resources":[{"type":"AWS::s3::Object","ARN":"arn:aws:s3:::mystorage2007/fullDB_dump30102018.dump"},{"accountId":"911534260404","type":"AWS::s3::Bucket","ARN":"arn:aws:s3:::db_backups2032"}]},"ExperienceCenter":"AWSCloud"  |
>| Suspicious Activity | Suspicious Activity | 10 | other | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-07-26T15:31:00.732000+00:00 | R2L | 1 | Custom Rule Engine-8 :: ip-172-31-17-10 | Custom Rule Engine | 7 | 1.1.1.1 | 0 | 1.1.1.1 | 0 | 0 | 1.1.1.1 | 0 | Reserved | A Database backup Has Been Downloaded From S3 Bucket | A Database backup Has Been Downloaded From S3 Bucket - AWSCloud (Exp Center) | EC: AWS Cloud - A Database backup Has Been Downloaded From S3 Bucket,<br/>BB:CategoryDefinition: Suspicious Event Categories,<br/>BB:CategoryDefinition: Suspicious Events,<br/>Source Asset Weight is Low,<br/>Destination Asset Weight is Low,<br/>Load Basic Building Blocks,<br/>Context is Remote to Local,<br/>ECBB:CategoryDefinition: Destination IP is a Third Country/Region | 5 | 00:00:00:00:00:00 | Europe.RussianFederation | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-07-26T15:31:00.732000+00:00 | userD | A Database backup Has Been Downloaded From S3 Bucket - AWSCloud (Exp Center)	A Database backup Has Been Downloaded From S3 Bucket |
>| Information | System | 10 | other | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2015-03-15T15:38:28+00:00 | L2L | 1 | Experience Center: Cisco IronPort @ 1.1.1.1 | Cisco IronPort | 10 | 1.1.1.1 | 0 | 1.1.1.1 | 0 | 0 | 1.1.1.1 | 0 | Reserved | Mail server info message | Mail Server Info Message | Source Asset Weight is Low,<br/>Destination Asset Weight is Low,<br/>EC: AWS Cloud - Detected An Email with An Attachment From a Spam Sender,<br/>BB:DeviceDefinition: Mail,<br/>BB:DeviceDefinition: Proxy,<br/>Load Basic Building Blocks,<br/>Context is Local to Local,<br/>ECBB:CategoryDefinition: Destination IP is a Third Country/Region | 10 | 00:00:00:00:00:00 | other | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-07-26T15:31:06.276000+00:00 | userD | <182>Mar 15 15:38:28 1.1.1.1 13:46:14 2015 Info: MID 987654321 ICID 351684134 From: <admin.AWS.console.management.aws.amazon.com@yoyobadh.date> To: <userD@example.com> Subject 'Urgent: AWS bill' attachment 'critical AWS bill.docx' ExperienceCenter=AWSCloud  |
>| Process Creation Success | System | 10 | other | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-03-15T15:42:54+00:00 | R2R | 1 | Experience Center: WindowsAuthServer @ IE8WIN7 | Microsoft Windows Security Event Log | 10 | 1.1.1.1 | 0 | 1.1.1.1 | 0 | 0 | 1.1.1.1 | 0 | Reserved | The process creation event provides extended information about a newly created process. | Process Create | BB:NetworkDefinition: Honeypot like Addresses,<br/>BB:DeviceDefinition: Operating System,<br/>Source Asset Weight is Low,<br/>Source Address is a Bogon IP,<br/>Destination Asset Weight is Low,<br/>BB:NetworkDefinition: Darknet Addresses,<br/>Load Basic Building Blocks,<br/>EC: AWS Cloud - Microsoft Word Launched a Command Shell,<br/>ECBB:CategoryDefinition: Destination IP is a Third Country/Region | 10 | 00:00:00:00:00:00 | other | 1.1.1.1 | 0 | 0:0:0:0:0:0:0:0 | 2023-07-26T15:31:06.635000+00:00 | userD | <182>Mar 15 15:42:54 IE8WIN7 AgentDevice=WindowsLog	AgentLogFile=Microsoft-Windows-Sysmon/Operational	PluginVersion=1.1.1.1	Source=Microsoft-Windows-Sysmon	Computer=IE8WIN7	OriginatingComputer=IE8WIN7	User=userD	Domain=NT AUTHORITY	EventID=1	EventIDCode=1	EventType=4	EventCategory=4	RecordNumber=32642	Level=Informational	Keywords=0x8000000000000000	Task=SysmonTask-SYSMON_CREATE_PROCESS	Opcode=Info	ExperienceCenter=AWSCloud	Message=Process Create: UtcTime: 2018-10-28 16:01:32.836 Image: C:\Windows\System32\cmd.exe CommandLine: C:\Windows\System32\cmd.exe CurrentDirectory: C:\Users\userD\ User: domain\userD IntegrityLevel: Medium Hashes: MD5=6242E3D67787CCBF4E06AD2982853144 ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE ParentCommandLine: "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"  |


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
| ref_name | The name of the reference set to be created. | Required | 
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
            "CreationTime": "2023-07-30T09:52:12.945000+00:00",
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
>| Malicious IPs | IP | 1 years 0 mons 0 days 0 hours 0 mins 0.0 secs | FIRST_SEEN | 2023-07-30T09:52:12.945000+00:00 | 0 |


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

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.completed | Number | The timestamp time of the task. | 
| QRadar.Reference.created | Number | The timestamp the task was created. | 
| QRadar.Reference.created_by | String | The use the task was created by. | 
| QRadar.Reference.error_code | Number | The error code of the task creation. | 
| QRadar.Reference.error_message | String | The error message of the task creation, if failed. | 
| QRadar.Reference.modified | Number | The timestamp this task was modified. | 
| QRadar.Reference.name | String | The name of the reference set. | 
| QRadar.Reference.started | Number | The timestamp the task was started. | 
| QRadar.Reference.status | String | The status of the task. One of CANCELLED, CANCELING, CANCEL_REQUESTED, COMPLETED, CONFLICT, EXCEPTION, INITIALIZING, INTERRUPTED, PAUSED, PROCESSING, QUEUED, RESUMING. | 

#### Command example
```!qradar-reference-set-value-upsert ref_name="Malicious IPs" value="1.1.1.1,1.1.1.1,1.1.1.1"```
#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "Name": "Reference Data Collection Bulk Update Task"
        }
    }
}
```

#### Human Readable Output

>### Reference Update Create
>|Name|
>|---|
>| Reference Data Collection Bulk Update Task |


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

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.completed | Number | The timestamp time of the task. | 
| QRadar.Reference.created | Number | The timestamp the task was created. | 
| QRadar.Reference.created_by | String | The use the task was created by. | 
| QRadar.Reference.error_code | Number | The error code of the task creation. | 
| QRadar.Reference.error_message | String | The error message of the task creation, if failed. | 
| QRadar.Reference.modified | Number | The timestamp this task was modified. | 
| QRadar.Reference.name | String | The name of the reference set. | 
| QRadar.Reference.started | Number | The timestamp the task was started. | 
| QRadar.Reference.status | String | The status of the task. One of CANCELLED, CANCELING, CANCEL_REQUESTED, COMPLETED, CONFLICT, EXCEPTION, INITIALIZING, INTERRUPTED, PAUSED, PROCESSING, QUEUED, RESUMING. | 

#### Command example
```!qradar-indicators-upload ref_name="Mail Servers" limit=2 query="type:IP"```
#### Context Example
```json
{
    "QRadar": {
        "Reference": {
            "created": "2023-07-30T09:52:20.104000+00:00",
            "created_by": "admin",
            "id": 487,
            "modified": 1690710740118,
            "name": "Reference Data Collection Bulk Update Task",
            "status": "QUEUED"
        }
    }
}
```

#### Human Readable Output

>### Indicators Upload For Reference Set Mail Servers
>|created|created_by|id|modified|name|status|
>|---|---|---|---|---|---|
>| 2023-07-30T09:52:20.104000+00:00 | admin | 487 | 1690710740118 | Reference Data Collection Bulk Update Task | QUEUED |
>
>### Indicators Uploaded
>|Indicator Type|Indicator Value|
>|---|---|
>| IP | 1.1.1.1 |
>| IP | 1.1.1.1 |


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
                "CreationDate": "2022-11-21T18:45:24.619000+00:00",
                "Credibility": 8,
                "Description": "Custom Rule Engine",
                "Enabled": true,
                "Gateway": false,
                "GroupIDs": [
                    0
                ],
                "ID": 63,
                "Internal": true,
                "LastEventTime": "2023-07-16T10:49:05.889000+00:00",
                "ModifiedDate": "2022-11-21T18:45:24.619000+00:00",
                "Name": "Custom Rule Engine-8 :: ip-172-31-17-10",
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
                "TypeID": 18
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
>|ID|Name|Description|Enabled|Credibility|TypeID|ModifiedDate|ProtocolParameters|AutoDiscovered|Internal|GroupIDs|ProtocolTypeID|Gateway|LastEventTime|CreationDate|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 68 | Search Results-2 :: ip-172-31-17-10 | Search Results | true | 10 | 355 | 2022-11-21T18:45:24.624000+00:00 | {'name': 'identifier', 'id': 0, 'value': '1.1.1.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | false | true | 0 | 0 | false | 1970-01-01T00:00:00+00:00 | 2022-11-21T18:45:24.624000+00:00 | last_updated: 0<br/>status: NA |
>| 63 | Custom Rule Engine-8 :: ip-172-31-17-10 | Custom Rule Engine | true | 8 | 18 | 2022-11-21T18:45:24.619000+00:00 | {'name': 'identifier', 'id': 0, 'value': '1.1.1.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | false | true | 0 | 0 | false | 2023-07-16T10:49:05.889000+00:00 | 2022-11-21T18:45:24.619000+00:00 | last_updated: 0<br/>messages: {'severity': 'ERROR', 'text': 'Events have not been received from this Log Source in over 720 minutes.'}<br/>status: ERROR |
>| 1262 | Experience Center: WindowsAuthServer @ 1.1.1.1 | WindowsAuthServer device | true | 5 | 12 | 2023-02-23T14:12:45.774000+00:00 | {'name': 'identifier', 'id': 0, 'value': '1.1.1.1'},<br/>{'name': 'incomingPayloadEncoding', 'id': 1, 'value': 'UTF-8'} | true | false | 0 | 0 | false | 2023-06-12T08:17:22.292000+00:00 | 2018-10-24T15:25:21.928000+00:00 | last_updated: 0<br/>messages: {'severity': 'ERROR', 'text': 'Events have not been received from this Log Source in over 720 minutes.'}<br/>status: ERROR |


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
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.Credibility | number | The credibility of the offense. | 
| QRadar.Offense.Relevance | number | The relevance of the offense. | 
| QRadar.Offense.Severity | number | The severity of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The local destination addresses that are associated with the offense. If your offense has a remote destination, you will need to use the QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destination that are associated with the offesne. If this value is greater than 0, it means that your offense has a remote destination, you will need to use the QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
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

### qradar-update-offense

***
Update an offense.

#### Base Command

`qradar-update-offense`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to update. | Required | 
| protected | Set to true to protect the offense. Possible values are: true, false. | Optional | 
| follow_up | Set to true to set the follow up flag on the offense. Possible values are: true, false. | Optional | 
| status | The new status for the offense. Possible values are: OPEN, HIDDEN, CLOSED. | Optional | 
| closing_reason_id | The id of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation. | Optional | 
| closing_reason_name | The name of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation. | Optional | 
| assigned_to | A user to assign the offense to. | Optional | 
| fields | Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object  separated by commas. Please consult - https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-POST.html. | Optional | 

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
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 
| date_value | If set to true will try to convert the data values to ISO-8601 string. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeToLive | string | Reference time to live. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. Valid values are: UNKNOWN, FIRST_SEEN, LAST_SEEN | 
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

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and IBM QRadar v3 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in IBM QRadar v3.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and IBM QRadar v3.

## Breaking changes from the previous version of this integration - IBM QRadar v3
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.

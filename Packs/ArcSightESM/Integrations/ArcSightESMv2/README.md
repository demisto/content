ArcSight ESM SIEM by Micro Focus (Formerly HPE Software).
This integration was integrated and tested with version 7.0.0.2436.1 of ArcSight ESM
## Configure ArcSight ESM v2 on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ArcSight ESM v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server full URL \(e.g., https://192.168.0.1:8443\) | True |
| credentials | Credentials | True |
| viewerId | Fetch events as incidents via Query Viewer ID. Mandatory fields for query are "Start Time" and "Event ID". | False |
| casesQueryViewerId | Fetch cases as incidents via Query Viewer ID. Mandatory fields for query are "Create Time" and "ID". | False |
| max_unique | The maximum number of unique IDs expected to be fetched. | False |
| fetch_chunk_size | The maximum number of incidents to fetch each time. Maximum is 50. | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### as-get-all-cases
***
(Deprecated) Retrieves all case resource IDs.


#### Base Command

`as-get-all-cases`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.AllCaseIDs | Unknown | All case resource IDs | 


#### Command Example
```!as-get-all-cases ```

#### Context Example
```
{
    "ArcSightESM": {
        "AllCaseIDs": [
            "1234DfGkBABCenF0601F2Ww==",
            "456mUEWcBABD6cSFwTn5Fog==",
            "789pEo2gBABCBcJbK9kU04Q==",
        ]
    }
}
```

#### Human Readable Output

>### All cases
>|caseID|
>|---|
>| 1234DfGkBABCenF0601F2Ww== |
>| 456mUEWcBABD6cSFwTn5Fog== |
>| 789pEo2gBABCBcJbK9kU04Q== |



### as-get-case
***
Gets information about a single case.


#### Base Command

`as-get-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the case to get information for | Required | 
| withBaseEvents | If "true", then will return case and base events of that case | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases.resourceid | string | Case ID | 
| ArcSightESM.Cases.name | string | Case name | 
| ArcSightESM.Cases.eventIDs | Unknown | Related base event IDs | 
| ArcSightESM.Cases.createdTimestamp | number | Time the case was created \(in milliseconds\) | 
| ArcSightESM.Cases.createdTime | string | Created time \(dd\-mm\-yyyyTHH:MM:SS.SSS timezone\) | 
| ArcSightESM.Cases.modifiedTimestamp | number | Modified timestamp \(in milliseconds\) | 
| ArcSightESM.Cases.modifiedTime | date | Modified time \(dd\-mm\-yyyyTHH:MM:SS.SSS timezone\) | 
| ArcSightESM.Cases.action | string | Action \(e.g., BLOCK\_OR\_SHUTDOWN\) | 
| ArcSightESM.Cases.associatedImpact | string | Associated impact \(e.g., AVAILABILITY\) | 
| ArcSightESM.Cases.attackAgent | string | Attack agent \(e.g., INSIDER\) | 
| ArcSightESM.Cases.attackMechanism | string | Attack mechanism \(e.g., PHYSICAL\) | 
| ArcSightESM.Cases.consequenceSeverity | string | Consequence severity \(e.g., NONE\) | 
| ArcSightESM.Cases.detectionTime | date | Detection time \(dd\-mm\-yyyyTHH:MM:SS.SSS timezone\) | 
| ArcSightESM.Cases.displayID | number | Display ID | 
| ArcSightESM.Cases.estimatedStartTime | date | Estimated start time \(dd\-mm\-yyyyTHH:MM:SS.SSS timezone\) | 
| ArcSightESM.Cases.eventIDs | unknown | Base event IDs | 
| ArcSightESM.Cases.frequency | string | Frequency \(e.g., NEVER\_OR\_ONCE\) | 
| ArcSightESM.Cases.history | Unknown | History \(e.g., KNOWN\_OCCURENCE\) | 
| ArcSightESM.Cases.numberOfOccurences | number | Number Of Occurences | 
| ArcSightESM.Cases.resistance | string | Resistance \(e.g., HIGH\) | 
| ArcSightESM.Cases.securityClassification | string | Security Classification \(e.g., UNCLASSIFIED\) | 
| ArcSightESM.Cases.sensitivity | string | Sensitivity \(e.g., UNCLASSIFIED\) | 
| ArcSightESM.Cases.stage | string | Stage \(e.g., QUEUED,INITIAL,FOLLOW\_UP,FINAL,CLOSED\) | 
| ArcSightESM.Cases.ticketType | string | Ticket type \(e.g., INTERNAL,CLIENT,INCIDENT\) | 
| ArcSightESM.Cases.vulnerability | string | Vulnerability \(e.g., DESIGN\) | 


#### Command Example
```!as-get-case resourceId="12ax-uGgBABCWb2puJdY8ZA=="```

#### Context Example
```
{
    "ArcSightESM": {
        "Cases": {
            "URI": "/All Cases/All Cases/Downloads/test",
            "action": "BLOCK_OR_SHUTDOWN",
            "associatedImpact": "AVAILABILITY",
            "attackAgent": "INSIDER",
            "attackMechanism": "PHYSICAL",
            "attributeInitializationInProgress": false,
            "consequenceSeverity": "INSIGNIFICANT",
            "createdDate": "2019-02-04T12:33:21.000Z",
            "createdTime": {
                "day": 4,
                "hour": 7,
                "milliSecond": 646,
                "minute": 33,
                "month": 1,
                "second": 21,
                "timezoneID": "America/New_York",
                "year": 2019
            },
            "createdTimestamp": 1549283601646,
            "creatorName": "admin",
            "deprecated": false,
            "detectionTime": {
                "day": 5,
                "hour": 4,
                "milliSecond": 986,
                "minute": 20,
                "month": 1,
                "second": 41,
                "timezoneID": "America/New_York",
                "year": 2019
            },
            "disabled": false,
            "displayID": 10017,
            "estimatedStartTime": {
                "day": 5,
                "hour": 4,
                "milliSecond": 525,
                "minute": 19,
                "month": 1,
                "second": 55,
                "timezoneID": "America/New_York",
                "year": 2019
            },
            "eventIDs": [
                12395741,
                45696713,
                78996719
            ],
            "frequency": "NEVER_OR_ONCE",
            "history": "KNOWN_OCCURENCE",
            "inCache": false,
            "inactive": false,
            "initialized": true,
            "isAdditionalLoaded": false,
            "localID": 30064771012,
            "modificationCount": 1462,
            "modifiedDate": "2020-05-10T10:42:34.000Z",
            "modifiedTime": {
                "day": 10,
                "hour": 6,
                "milliSecond": 194,
                "minute": 42,
                "month": 4,
                "second": 34,
                "timezoneID": "America/New_York",
                "year": 2020
            },
            "modifiedTimestamp": 1589107354194,
            "modifierName": "admin",
            "name": "test",
            "numberOfOccurences": 0,
            "operationalImpact": "NO_IMPACT",
            "reference": {
                "id": "12ax-uGgBABCWb2puJdY8ZA==",
                "isModifiable": true,
                "managerID": "A1xxqmYBABCAXZPTkLg+BA==",
                "referenceName": "Case",
                "referenceString": "<Resource URI=\"/All Cases/All Cases/Downloads/test\" ID=\"12ax-uGgBABCWb2puJdY8ZA==\"/>",
                "referenceType": 7,
                "uri": "/All Cases/All Cases/Downloads/test"
            },
            "reportingLevel": 1,
            "resistance": "HIGH",
            "resourceid": "12ax-uGgBABCWb2puJdY8ZA==",
            "securityClassification": "UNCLASSIFIED",
            "securityClassificationCode": "P I   D U A B ",
            "sensitivity": "UNCLASSIFIED",
            "stage": "QUEUED",
            "state": 2,
            "ticketType": "INTERNAL",
            "type": 7,
            "typeName": "Case",
            "vulnerability": "DESIGN",
            "vulnerabilityType1": "ACCIDENTAL",
            "vulnerabilityType2": "EMI_RFI"
        }
    }
}
```

#### Human Readable Output

>### Case 12ax-uGgBABCWb2puJdY8ZA==
>|Action|CaseID|CreatedTime|EventIDs|Name|Severity|Stage|
>|---|---|---|---|---|---|---|
>| BLOCK_OR_SHUTDOWN | 12ax-uGgBABCWb2puJdY8ZA== | 2019-02-04 12:33:21 | 12395741, 45696713, 7896719 | test | INSIGNIFICANT | QUEUED |


### as-get-matrix-data
***
Retrieves query viewer results (query viewer must be configured to be refreshed every minute, see documentation)


#### Base Command

`as-get-matrix-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID of a query viewer | Required | 
| onlyColumns | If "true", will return only the columns of the query. If "false", will return the column headers and all query results. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!as-get-matrix-data id=aBBnu5XEBABCJHuGRQA-nwg== ```

#### Context Example
```
{}
```

#### Human Readable Output

>|Column Headers|
>|---|
>| Alias |
>| Create Time |
>| Creator |
>| Description |
>| Display ID |
>| External ID |
>| Group ID |
>| ID |
>| Modification Time |
>| Name |
>| Owner Groups |
>| Owner |
>| ServiceNow® ITSM ID |
>| Category of Situation |
>| Consequence Severity |
>| Operational Impact |
>| Frequency |
>| Reason for Closure |
>| Reporting Level |
>| Security Classification |
>| Stage |
>| Ticket Type |
>| Detection Time |
>| Estimated Restore Time |
>| Estimated Start Time |
>| Incident Source 1 |
>| Incident Source 2 |
>| Incident Source Address |
>| Originator |
>| Affected Elements |
>| Affected Services |
>| Affected Sites |
>| Estimated Impact |
>| Action |
>| Associated Impact |
>| Attack Agent |
>| Attack Mechanism |
>| Security Classification Code |
>| Sensitivity |
>| Vulnerability |
>| Actions Taken |
>| Followup Contact |
>| Planned Actions |
>| Recommended Actions |
>| Attack Impact |
>| Attack OS |
>| Attack Program |
>| Attack Protocol |
>| Attack Service |
>| Attack Target |
>| Attack Time |
>| Final Report Action |
>| Resistance |
>| Attack Address |
>| Attack Location ID |
>| Attack Node |
>| Vulnerability Data |
>| Vulnerability Evidence |
>| Vulnerability Source |
>| Vulnerability Type 1 |
>| Vulnerability Type 2 |
>| History |
>| Last Occurrence Time |
>| No. of Occurrences |
>| Conclusions |
>| Inspection Results |
>| Recorded Data |
>| Event-Aggregated Event Count |
>| Event-Application Protocol |
>| Event-Bytes In |
>| Event-Bytes Out |
>| Event-Concentrator Agents |
>| Event-Concentrator Devices |
>| Event-Correlated Event Count |
>| Event-Crypto Signature |
>| Event-Customer |
>| Event-Customer External ID |
>| Event-Customer ID |
>| Event-Customer Reference ID |
>| Event-Customer Name |
>| Event-Customer URI |
>| Event-Domain |
>| Event-Domain External ID |
>| Event-Domain ID |
>| Event-Domain Name |
>| Event-Domain Reference ID |
>| Event-Domain URI |
>| Event-End Time |
>| Event-Event ID |
>| Event-Event Outcome |
>| Event-External ID |
>| Event-Category Behavior |
>| Event-Category Custom Format Field |
>| Event-Category Descriptor ID |
>| Event-Category Device Group |
>| Event-Category Device Type |
>| Event-Category Outcome |
>| Event-Category Significance |
>| Event-Category Object |
>| Event-Category Technique |
>| Event-Category Tuple Description |
>| Event-Asset Criticality |
>| Event-Model Confidence |
>| Event-Priority |
>| Event-Severity |
>| Event-Relevance |
>| Event-Agent Address |
>| Event-Agent Asset ID |
>| Event-Agent Asset Local ID |
>| Event-Agent Asset Name |
>| Event-Agent Descriptor ID |
>| Event-Agent Dns Domain |
>| Event-Agent Host Name |
>| Event-Agent ID |
>| Event-Agent Mac Address |
>| Event-Generator |
>| Event-Generator External ID |
>| Event-Generator Reference ID |
>| Event-Generator Name |
>| Event-Generator ID |
>| Event-Generator URI |
>| Event-Locality |
>| Event-Manager Receipt Time |
>| Event-Message |
>| Event-Raw Event |
>| Event-Persistence |
>| Event-Rule Thread ID |
>| Event-Originator |
>| Event-Name |
>| Event-Reason |
>| Event-Session ID |
>| Event-Start Time |
>| Event-Transport Protocol |
>| Event-Type |
>| Event-Vulnerability |
>| Event-Vulnerability External ID |
>| Event-Vulnerability ID |
>| Event-Vulnerability Name |
>| Event-Vulnerability Reference ID |
>| Event-Vulnerability URI |
>| Event-Agent Name |
>| Event-Agent Nt Domain |
>| Event-Agent Receipt Time |
>| Event-Agent Time Zone |
>| Event-Agent Severity |
>| Event-Agent Time Zone Offset |
>| Event-Agent Translated Address |
>| Event-Agent Translated Zone |
>| Event-Agent Translated Zone External ID |
>| Event-Agent Translated Zone ID |
>| Event-Agent Translated Zone Name |
>| Event-Agent Translated Zone URI |
>| Event-Agent Type |
>| Event-Agent Version |
>| Event-Agent Zone |
>| Event-Agent Zone External ID |
>| Event-Agent Zone ID |
>| Event-Agent Zone Name |
>| Event-Agent Zone Reference ID |
>| Event-Agent Zone URI |
>| Event-Device Action |
>| Event-Device Address |
>| Event-Device Asset ID |
>| Event-Device Descriptor ID |
>| Event-Device Asset Local ID |
>| Event-Device Asset Name |
>| Event-Device Direction |
>| Event-Device Dns Domain |
>| Event-Device Domain |
>| Event-Device Event Category |
>| Event-Device Event Class ID |
>| Event-Device Facility |
>| Event-Device External ID |
>| Event-Device Host Name |
>| Event-Device Inbound Interface |
>| Event-Device Mac Address |
>| Event-Device Nt Domain |
>| Event-Device Outbound Interface |
>| Event-Device Payload ID |
>| Event-Device Process ID |
>| Event-Device Process Name |
>| Event-Device Product |
>| Event-Device Receipt Time |
>| Event-Device Severity |
>| Event-Device Time Zone |
>| Event-Device Time Zone Offset |
>| Event-Device Translated Address |
>| Event-Device Translated Zone |
>| Event-Device Translated Zone External ID |
>| Event-Device Translated Zone ID |
>| Event-Device Translated Zone Name |
>| Event-Device Translated Zone Reference ID |
>| Event-Device Translated Zone URI |
>| Event-Device Vendor |
>| Event-Device Version |
>| Event-Device Zone |
>| Event-Device Zone External ID |
>| Event-Device Zone ID |
>| Event-Device Zone Name |
>| Event-Device Zone Reference ID |
>| Event-Device Zone URI |
>| Event-Source Address |
>| Event-Source Asset ID |
>| Event-Source Asset Local ID |
>| Event-Source Asset Name |
>| Event-Source Dns Domain |
>| Event-Source Fqdn |
>| Event-Source Geo Country Code |
>| Event-Source Geo Country Flag Url |
>| Event-Source Geo Country Name |
>| Event-Source Geo Descriptor ID |
>| Event-Source Geo Latitude |
>| Event-Source Geo Location Info |
>| Event-Source Geo Postal Code |
>| Event-Source Geo Longitude |
>| Event-Source Geo Region Code |
>| Event-Source Host Name |
>| Event-Source Mac Address |
>| Event-Source Nt Domain |
>| Event-Source Port |
>| Event-Source Process ID |
>| Event-Source Process Name |
>| Event-Source Service Name |
>| Event-Source Translated Address |
>| Event-Source Translated Port |
>| Event-Source Translated Zone |
>| Event-Source Translated Zone ID |
>| Event-Source Translated Zone External ID |
>| Event-Source Translated Zone Name |
>| Event-Source Translated Zone Reference ID |
>| Event-Source Translated Zone URI |
>| Event-Source User ID |
>| Event-Source User Name |
>| Event-Source User Privileges |
>| Event-Source Zone |
>| Event-Source Zone External ID |
>| Event-Source Zone ID |
>| Event-Source Zone Name |
>| Event-Source Zone Reference ID |
>| Event-Source Zone URI |
>| Event-Destination Address |
>| Event-Destination Asset ID |
>| Event-Destination Asset Local ID |
>| Event-Destination Asset Name |
>| Event-Destination Dns Domain |
>| Event-Destination Fqdn |
>| Event-Destination Geo Country Code |
>| Event-Destination Geo Descriptor ID |
>| Event-Destination Geo Country Flag Url |
>| Event-Destination Geo Country Name |
>| Event-Destination Geo Latitude |
>| Event-Destination Geo Location Info |
>| Event-Destination Geo Longitude |
>| Event-Destination Geo Postal Code |
>| Event-Destination Geo Region Code |
>| Event-Destination Host Name |
>| Event-Destination Mac Address |
>| Event-Destination Nt Domain |
>| Event-Destination Port |
>| Event-Destination Process ID |
>| Event-Destination Process Name |
>| Event-Destination Service Name |
>| Event-Destination Translated Address |
>| Event-Destination Translated Port |
>| Event-Destination Translated Zone |
>| Event-Destination Translated Zone External ID |
>| Event-Destination Translated Zone ID |
>| Event-Destination Translated Zone Name |
>| Event-Destination Translated Zone Reference ID |
>| Event-Destination Translated Zone URI |
>| Event-Destination User ID |
>| Event-Destination User Name |
>| Event-Destination User Privileges |
>| Event-Destination Zone |
>| Event-Destination Zone External ID |
>| Event-Destination Zone ID |
>| Event-Destination Zone Name |
>| Event-Destination Zone Reference ID |
>| Event-Destination Zone URI |
>| Event-Attacker Address |
>| Event-Attacker Asset ID |
>| Event-Attacker Asset Local ID |
>| Event-Attacker Asset Name |
>| Event-Attacker Dns Domain |
>| Event-Attacker Fqdn |
>| Event-Attacker Geo Country Code |
>| Event-Attacker Geo Country Flag Url |
>| Event-Attacker Geo Country Name |
>| Event-Attacker Geo Descriptor ID |
>| Event-Attacker Geo Latitude |
>| Event-Attacker Geo Location Info |
>| Event-Attacker Geo Longitude |
>| Event-Attacker Geo Postal Code |
>| Event-Attacker Geo Region Code |
>| Event-Attacker Host Name |
>| Event-Attacker Nt Domain |
>| Event-Attacker Mac Address |
>| Event-Attacker Port |
>| Event-Attacker Process ID |
>| Event-Attacker Service Name |
>| Event-Attacker Translated Address |
>| Event-Attacker Process Name |
>| Event-Attacker Translated Port |
>| Event-Attacker Translated Zone ID |
>| Event-Attacker Translated Zone |
>| Event-Attacker Translated Zone External ID |
>| Event-Attacker Translated Zone Name |
>| Event-Attacker Translated Zone Reference ID |
>| Event-Attacker Translated Zone URI |
>| Event-Attacker User ID |
>| Event-Attacker User Name |
>| Event-Attacker User Privileges |
>| Event-Attacker Zone |
>| Event-Attacker Zone External ID |
>| Event-Attacker Zone ID |
>| Event-Attacker Zone Name |
>| Event-Attacker Zone Reference ID |
>| Event-Attacker Zone URI |
>| Event-Target Address |
>| Event-Target Asset ID |
>| Event-Target Asset Local ID |
>| Event-Target Asset Name |
>| Event-Target Dns Domain |
>| Event-Target Fqdn |
>| Event-Target Geo Country Code |
>| Event-Target Geo Country Flag Url |
>| Event-Target Geo Descriptor ID |
>| Event-Target Geo Country Name |
>| Event-Target Geo Latitude |
>| Event-Target Geo Postal Code |
>| Event-Target Geo Location Info |
>| Event-Target Geo Longitude |
>| Event-Target Geo Region Code |
>| Event-Target Host Name |
>| Event-Target Mac Address |
>| Event-Target Nt Domain |
>| Event-Target Port |
>| Event-Target Process ID |
>| Event-Target Process Name |
>| Event-Target Service Name |
>| Event-Target Translated Address |
>| Event-Target Translated Port |
>| Event-Target Translated Zone |
>| Event-Target Translated Zone External ID |
>| Event-Target Translated Zone ID |
>| Event-Target Translated Zone Name |
>| Event-Target Translated Zone Reference ID |
>| Event-Target Translated Zone URI |
>| Event-Target User ID |
>| Event-Target User Name |
>| Event-Target User Privileges |
>| Event-Target Zone |
>| Event-Target Zone External ID |
>| Event-Target Zone ID |
>| Event-Target Zone Name |
>| Event-Target Zone Reference ID |
>| Event-Target Zone URI |
>| Event-File Create Time |
>| Event-File Hash |
>| Event-File ID |
>| Event-File Modification Time |
>| Event-File Name |
>| Event-File Path |
>| Event-File Permission |
>| Event-File Size |
>| Event-File Type |
>| Event-Old File Create Time |
>| Event-Old File Hash |
>| Event-Old File ID |
>| Event-Old File Modification Time |
>| Event-Old File Name |
>| Event-Old File Path |
>| Event-Old File Permission |
>| Event-Old File Size |
>| Event-Old File Type |
>| Event-Request Client Application |
>| Event-Request Cookies |
>| Event-Request Context |
>| Event-Request Method |
>| Event-Request Protocol |
>| Event-Request Url |
>| Event-Request Url Authority |
>| Event-Request Url File Name |
>| Event-Request Url Host |
>| Event-Request Url Port |
>| Event-Request Url Query |


### as-add-entries
***
Adds new entries to the Active List.


#### Base Command

`as-add-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the Active List | Required | 
| entries | Entries are in JSON format. JSON must be an array of entries. Each entry must contain the same columns as they appear in the Active List, e.g., [{ "UserName": "john", "IP":"19.12.13.11"},{ "UserName": "bob", "IP":"22.22.22.22"}] | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!as-add-entries resourceId="A1LvlmWgBABCA5+HbRyHZoQ==" entries="[{\"name\": \"t3\", \"EventID\": \"9\"},{\"name\": \"t4\", \"EventID\": \"9\"}]"```

#### Context Example
```
{}
```

#### Human Readable Output

>Success

### as-clear-entries
***
Deletes all entries in the Active List.


#### Base Command

`as-clear-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of a specific Active List | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!as-clear-entries resourceId="A1LvlmWgBABCA5+HbRyHZoQ=="```

#### Context Example
```
{}
```

#### Human Readable Output

>Success

### as-get-entries
***
Returns all entries in the Active List


#### Base Command

`as-get-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of a specific Active List | Required | 
| entryFilter | Filters the entries, e.g., entryFilter="moo:moo1" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.ActiveList | Unknown | Active List is a map of active list resource id =&gt; active list entries | 
| ArcSightESM.ActiveList.ListID | list | The ActiveList ID | 
| ArcSightESM.ActiveList.Entry | Unknown | Active List is a map of active list resource id =&gt; active list | 


#### Command Example
```!as-get-entries resourceId=A1LvlmWgBABCA5+HbRyHZoQ== entryFilter="name:test"```

#### Context Example
```
{}
```

#### Human Readable Output

>|Columns|
>|---|
>| eventId |
>| name |
>| startTime |
>Active List has no entries

### as-get-security-events
***
Returns the security event details


#### Base Command

`as-get-security-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID or multiple ids separated by comma of security events. Event ID is ArcSight is always a number. Example: 13906590 | Required | 
| lastDateRange | Query last events. Format follows 'number date_range_unit', e.g., 2 hours, 4 minutes, 6 month, 1 day | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.SecurityEvents | Unknown | List of security events | 
| ArcSightESM.SecurityEvents.name | string | Event name | 
| ArcSightESM.SecurityEvents.eventId | number | Event ID | 
| ArcSightESM.SecurityEvents.type | string | Event type \(e.g., CORRELATION\) | 
| ArcSightESM.SecurityEvents.baseEventIds | Unknown | Base event IDs | 
| ArcSightESM.SecurityEvents.source.address | Unknown | Event source address | 
| ArcSightESM.SecurityEvents.destination.address | Unknown | Event destination address | 
| ArcSightESM.SecurityEvents.startTime | date | Start time in milliseconds | 


#### Command Example
```!as-get-security-events ids=12352349,45652798```

#### Context Example
```
{
    "ArcSightESM": {
        "SecurityEvents": [
            {
                "agent": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "id": "123xxqmYBABCAY8SQ92zN9g==",
                    "mutable": true,
                    "name": "Manager Internal Agent",
                    "type": "arcsight_security_manager",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "12332AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "agentSeverity": 1,
                "aggregatedEventCount": 1,
                "assetCriticality": 0,
                "baseEventCount": 0,
                "category": {
                    "behavior": "/Execute/Response",
                    "deviceGroup": "/Application",
                    "mutable": true,
                    "object": "/Host/Application",
                    "outcome": "/Success",
                    "significance": "/Informational"
                },
                "concentratorAgents": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "id": "123xxqmYBABCAY8SQ92zN9g==",
                    "mutable": true,
                    "name": "Manager Internal Agent",
                    "type": "arcsight_security_manager",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "12332AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"12U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "concentratorDevices": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "126xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "product": "ArcSight",
                    "vendor": "ArcSight",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "12U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "12xxqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"12fU32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "correlatedEventCount": 0,
                "destination": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "126xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "geo": {
                        "latitude": 0,
                        "latitudeLong": 0,
                        "longitude": 0,
                        "longitudeLong": 0,
                        "mutable": true
                    },
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "zone": {
                        "id": "12U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "12xxqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"12U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "device": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "126xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "product": "ArcSight",
                    "vendor": "ArcSight",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "12fU32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "12xxqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"12fU32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "deviceCustom": {
                    "mutable": true,
                    "number1Label": "Temporary Active list usage (Percent)",
                    "string1Label": "Unit",
                    "string2Label": "Time Frame"
                },
                "deviceCustomNumber1": 0,
                "deviceCustomString1": "Percent",
                "deviceCustomString2": "current value",
                "deviceEventCategory": "/Monitor/ActiveLists/TemporaryPercentageUsed",
                "deviceEventClassId": "monitor:121",
                "deviceReceiptDate": "2020-05-07T14:43:00.000Z",
                "deviceReceiptTime": 1588862580001,
                "deviceSeverity": "Warning",
                "endDate": "2020-05-07T14:43:00.000Z",
                "endTime": 1588862580001,
                "eventAnnotation": {
                    "auditTrail": "1,1589114529805,root,Queued,,,,",
                    "endDate": "2020-05-07T14:43:00.000Z",
                    "endTime": 1588862580001,
                    "eventId": 12352349,
                    "flags": 0,
                    "managerReceiptDate": "2020-05-07T14:43:00.000Z",
                    "managerReceiptTime": 1588862580001,
                    "modificationDate": "2020-05-07T14:43:00.000Z",
                    "modificationTime": 1588862580001,
                    "stage": {
                        "id": "123HiNfoAABCASsxbPIxG0g==",
                        "isModifiable": false,
                        "managerID": "123qmYBABCAXZPTkLg+BA==",
                        "referenceID": 2209,
                        "referenceName": "Stage",
                        "referenceString": "<Resource URI=\"/All Stages/Queued\" ID=\"12MHiNfoAABCASsxbPIxG0g==\"/>",
                        "referenceType": 34,
                        "uri": "/All Stages/Queued"
                    },
                    "stageUpdateDate": "2020-05-07T14:43:00.000Z",
                    "stageUpdateTime": 1588862580001,
                    "version": 1
                },
                "eventId": 12352349,
                "finalDevice": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "product": "ArcSight",
                    "vendor": "ArcSight",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "locality": 0,
                "managerId": -128,
                "managerReceiptDate": "2020-05-07T14:43:00.000Z",
                "managerReceiptTime": 1588862580001,
                "modelConfidence": 4,
                "name": "Monitor Event",
                "originalAgent": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "id": "123xxqmYBABCAY8SQ92zN9g==",
                    "mutable": true,
                    "name": "Manager Internal Agent",
                    "type": "arcsight_security_manager",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "originator": "SOURCE",
                "priority": 3,
                "relevance": 10,
                "severity": 0,
                "startDate": "2020-05-07T14:43:00.000Z",
                "startTime": 1588862580001,
                "ttl": 10,
                "type": "BASE"
            },
            {
                "agent": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "id": "123xxqmYBABCAY8SQ92zN9g==",
                    "mutable": true,
                    "name": "Manager Internal Agent",
                    "type": "arcsight_security_manager",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "12332AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "agentSeverity": 1,
                "aggregatedEventCount": 1,
                "assetCriticality": 0,
                "baseEventCount": 0,
                "category": {
                    "behavior": "/Authentication/Verify",
                    "deviceGroup": "/Application",
                    "mutable": true,
                    "object": "/Host/Application",
                    "outcome": "/Success",
                    "significance": "/Normal"
                },
                "concentratorAgents": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "id": "123xxqmYBABCAY8SQ92zN9g==",
                    "mutable": true,
                    "name": "Manager Internal Agent",
                    "type": "arcsight_security_manager",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "concentratorDevices": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "product": "ArcSight",
                    "vendor": "ArcSight",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "correlatedEventCount": 0,
                "destination": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "geo": {
                        "latitude": 0,
                        "latitudeLong": 0,
                        "longitude": 0,
                        "longitudeLong": 0,
                        "mutable": true
                    },
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "port": 8443,
                    "userId": "123FwqmYBABCA23X2wprUSg==",
                    "userName": "admin",
                    "zone": {
                        "id": "12332AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"12332AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "device": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "product": "ArcSight",
                    "vendor": "ArcSight",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "deviceCustom": {
                    "mutable": true,
                    "string2Label": "Configuration Resource",
                    "string3Label": "Login Type",
                    "string4Label": "Session ID",
                    "string5Label": "Client Version",
                    "string6Label": "Client ID"
                },
                "deviceCustomString2": "<Resource URI=\"/All Users/Administrators/admin\" ID=\"12GFwqmYBABCA23X2wprUSg==\"/>",
                "deviceCustomString3": "password based login",
                "deviceCustomString4": "acsfxxxx",
                "deviceCustomString5": "7.0.0.2436.1",
                "deviceCustomString6": "Service",
                "deviceEventCategory": "/Authentication/Login/User?Success",
                "deviceEventClassId": "authentication:100",
                "deviceReceiptDate": "2020-05-07T14:48:54.000Z",
                "deviceReceiptTime": 1588862934523,
                "deviceSeverity": "Warning",
                "endDate": "2020-05-07T14:48:54.000Z",
                "endTime": 1588862934523,
                "eventAnnotation": {
                    "auditTrail": "1,1589114529805,root,Queued,,,,",
                    "endDate": "2020-05-07T14:48:54.000Z",
                    "endTime": 1588862934523,
                    "eventId": 45652798,
                    "flags": 0,
                    "managerReceiptDate": "2020-05-07T14:48:54.000Z",
                    "managerReceiptTime": 1588862934523,
                    "modificationDate": "2020-05-07T14:48:54.000Z",
                    "modificationTime": 1588862934523,
                    "stage": {
                        "id": "123HiNfoAABCASsxbPIxG0g==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 2209,
                        "referenceName": "Stage",
                        "referenceString": "<Resource URI=\"/All Stages/Queued\" ID=\"123HiNfoAABCASsxbPIxG0g==\"/>",
                        "referenceType": 34,
                        "uri": "/All Stages/Queued"
                    },
                    "stageUpdateDate": "2020-05-07T14:48:54.000Z",
                    "stageUpdateTime": 1588862934523,
                    "version": 1
                },
                "eventId": 45652798,
                "file": {
                    "name": "admin",
                    "path": "/All Users/Administrators/admin",
                    "type": "User"
                },
                "finalDevice": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "mutable": true,
                    "product": "ArcSight",
                    "vendor": "ArcSight",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "locality": 0,
                "managerId": -128,
                "managerReceiptDate": "2020-05-07T14:48:54.000Z",
                "managerReceiptTime": 1588862934523,
                "modelConfidence": 4,
                "name": "Login succeeded for user name 'admin'",
                "originalAgent": {
                    "address": "1.1.1.1",
                    "addressAsBytes": "abgBRQ==",
                    "assetId": "123xxqmYBABCAWiGUuYaX-w==",
                    "assetLocalId": 17179869185,
                    "assetName": "content.demisto.works",
                    "decodedAddress": "1.1.1.1",
                    "hostName": "content.demisto.works",
                    "id": "123xxqmYBABCAY8SQ92zN9g==",
                    "mutable": true,
                    "name": "Manager Internal Agent",
                    "type": "arcsight_security_manager",
                    "version": "7.0.0.2436.1",
                    "zone": {
                        "id": "123U32AABABCDVFpYAT3UdQ==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 1102,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255\" ID=\"123U32AABABCDVFpYAT3UdQ==\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255"
                    }
                },
                "originator": "SOURCE",
                "priority": 3,
                "relevance": 10,
                "severity": 0,
                "source": {
                    "address": "2.2.2.2",
                    "addressAsBytes": "ABCIDg==",
                    "decodedAddress": "2.2.2.2",
                    "geo": {
                        "countryCode": "IE",
                        "latitude": 53.3331,
                        "latitudeLong": 533331000000,
                        "locationInfo": "Dublin",
                        "longitude": -6.2489,
                        "longitudeLong": -62489000000,
                        "mutable": true,
                        "postalCode": "D02",
                        "regionCode": "L"
                    },
                    "hostName": "ec2-52-213-8-14.eu-west-1.compute.amazonaws.com",
                    "mutable": true,
                    "zone": {
                        "externalID": "E.I. duPont de Nemours and Co. Inc.",
                        "id": "123TU5fsAABCCerv-GNArfg==",
                        "isModifiable": false,
                        "managerID": "123xqmYBABCAXZPTkLg+BA==",
                        "referenceID": 2178,
                        "referenceName": "Zone",
                        "referenceString": "<Resource URI=\"/All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc.\" ID=\"123TU5fsAABCCerv-GNArfg==\" ExternalID=\"E.I. duPont de Nemours and Co. Inc.\"/>",
                        "referenceType": 29,
                        "uri": "/All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc."
                    }
                },
                "startDate": "2020-05-07T14:48:54.000Z",
                "startTime": 1588862934523,
                "ttl": 10,
                "type": "BASE"
            }
        ]
    }
}
```

#### Human Readable Output

>|Destination Address|Event ID|Name|Source Address|Time|
>|---|---|---|---|---|
>| 1.1.1.1 | 12352349 | Monitor Event |  | 2020-05-07, 14:43:00 |
>| 1.1.1.1 | 45652798 | Login succeeded for user name 'admin' | 2.2.2.2 | 2020-05-07, 14:48:54 |


### as-get-case-event-ids
***
Returns all case event IDs.


#### Base Command

`as-get-case-event-ids`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Case ID, e.g., 7e6LEbF8BABCfA-dlp1rl1A== | Required | 
| withCorrelatedEvents | If "true", then will return case and correlated events | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.CaseEvents | Unknown | Map of caseId =&gt; related event ids | 
| ArcSightESM.CaseEvents.LatestResult | Unknown | Event IDs of the last execution of this command | 


#### Command Example
```!as-get-case-event-ids caseId="12ax-uGgBABCWb2puJdY8ZA==" withCorrelatedEvents="true"```

#### Context Example
```
{
    "ArcSightESM": {
        "CaseEvents": [
            12396713,
            45695741,
            78996719
        ]
    }
}
```

#### Human Readable Output

>|Case 12ax-uGgBABCWb2puJdY8ZA== Event IDs|
>|---|
>| 12396713 |
>| 45695741 |
>| 78996719 |


### as-update-case
***
Updates a specific case.


#### Base Command

`as-update-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Case resource ID to update. The case must be unlocked, and the user should have edit permissions. | Required | 
| stage | Stage the case is in | Optional | 
| severity | Ticket consequence Severity | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases | unknown | List of cases | 
| ArcSightESM.Cases.resourceid | string | Case resource ID | 
| ArcSightESM.Cases.stage | string | Case stage  | 
| ArcSightESM.Cases.consequenceSeverity | string | Case severity | 


#### Command Example
```!as-update-case caseId="12ax-uGgBABCWb2puJdY8ZA==" stage="QUEUED" severity="INSIGNIFICANT"```

#### Context Example
```
{
    "ArcSightESM": {
        "Cases": {
            "URI": "/All Cases/All Cases/Downloads/test",
            "action": "BLOCK_OR_SHUTDOWN",
            "associatedImpact": "AVAILABILITY",
            "attackAgent": "INSIDER",
            "attackMechanism": "PHYSICAL",
            "attributeInitializationInProgress": false,
            "consequenceSeverity": "INSIGNIFICANT",
            "createdDate": "2019-02-04T12:33:21.000Z",
            "createdTime": {
                "day": 4,
                "hour": 7,
                "milliSecond": 646,
                "minute": 33,
                "month": 1,
                "second": 21,
                "timezoneID": "America/New_York",
                "year": 2019
            },
            "createdTimestamp": 1549283601646,
            "creatorName": "admin",
            "deprecated": false,
            "detectionTime": {
                "day": 5,
                "hour": 4,
                "milliSecond": 986,
                "minute": 20,
                "month": 1,
                "second": 41,
                "timezoneID": "America/New_York",
                "year": 2019
            },
            "disabled": false,
            "displayID": 12017,
            "estimatedStartTime": {
                "day": 5,
                "hour": 4,
                "milliSecond": 525,
                "minute": 19,
                "month": 1,
                "second": 55,
                "timezoneID": "America/New_York",
                "year": 2019
            },
            "eventIDs": [
                12395741,
                45696713,
                78996719
            ],
            "frequency": "NEVER_OR_ONCE",
            "history": "KNOWN_OCCURENCE",
            "inCache": false,
            "inactive": false,
            "initialized": true,
            "isAdditionalLoaded": false,
            "localID": 12064771092,
            "modificationCount": 1462,
            "modifiedDate": "2020-05-10T10:42:34.000Z",
            "modifiedTime": {
                "day": 10,
                "hour": 6,
                "milliSecond": 194,
                "minute": 42,
                "month": 4,
                "second": 34,
                "timezoneID": "America/New_York",
                "year": 2020
            },
            "modifiedTimestamp": 1589107354194,
            "modifierName": "admin",
            "name": "test",
            "numberOfOccurences": 0,
            "operationalImpact": "NO_IMPACT",
            "reference": {
                "id": "12ax-uGgBABCWb2puJdY8ZA==",
                "isModifiable": true,
                "managerID": "12xxqmYBABCAXZPTkLg+BA==",
                "referenceName": "Case",
                "referenceString": "<Resource URI=\"/All Cases/All Cases/Downloads/test\" ID=\"12ax-uGgBABCWb2puJdY8ZA==\"/>",
                "referenceType": 7,
                "uri": "/All Cases/All Cases/Downloads/test"
            },
            "reportingLevel": 1,
            "resistance": "HIGH",
            "resourceid": "12ax-uGgBABCWb2puJdY8ZA==",
            "securityClassification": "UNCLASSIFIED",
            "securityClassificationCode": "P I   D U A B ",
            "sensitivity": "UNCLASSIFIED",
            "stage": "QUEUED",
            "state": 2,
            "ticketType": "INTERNAL",
            "type": 7,
            "typeName": "Case",
            "vulnerability": "DESIGN",
            "vulnerabilityType1": "ACCIDENTAL",
            "vulnerabilityType2": "EMI_RFI"
        }
    }
}
```

#### Human Readable Output

>### Case 12ax-uGgBABCWb2puJdY8ZA==
>|Action|CaseID|CreatedTime|EventIDs|Name|Severity|Stage|
>|---|---|---|---|---|---|---|
>| BLOCK_OR_SHUTDOWN | 12ax-uGgBABCWb2puJdY8ZA== | 2019-02-04 12:33:21 | 12395741, 45696713, 78996719 | test | INSIGNIFICANT | QUEUED |


### as-get-all-query-viewers
***
Returns all the query viewer IDs.


#### Base Command

`as-get-all-query-viewers`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.AllQueryViewers | Unknown | List of all query viewer IDs | 


#### Command Example
```!as-get-all-query-viewers```

#### Context Example
```
{
    "ArcSightESM": {
        "AllQueryViewers": [
            "123457WYBABCw9lZRkCjVIQ==",
            "54321rlkBABCJREkQ7PrIRg==",
            "56789py4BABCN9NYml6MSoA==",
        ]
    }
}
```

#### Human Readable Output

>|Query Viewers|
>|---|
>| 123457WYBABCw9lZRkCjVIQ== |
>| 54321rlkBABCJREkQ7PrIRg== |
>| 56789py4BABCN9NYml6MSoA== |



### as-case-delete
***
Deletes a case


#### Base Command

`as-case-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Resource ID of the case | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases.resourceid | string | Resource ID of case | 
| ArcSightESM.Cases.Deleted | boolean | Boolean flag. "True" if deleted. | 


#### Command Example
```!as-case-delete caseId=123WHEWcBABD6VdKLNcKE2Q==```

#### Context Example
```
{
    "ArcSightESM": {
        "Cases": {
            "deleted": "True",
            "resourceid": "123WHEWcBABD6VdKLNcKE2Q=="
        }
    }
}
```

#### Human Readable Output

>Case 123WHEWcBABD6VdKLNcKE2Q== successfully deleted

### as-get-query-viewer-results
***
Retrieves query viewer results (query viewer must be configured to be refreshed every minute, see documentation)


#### Base Command

`as-get-query-viewer-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID of the query viewer | Required | 
| onlyColumns | If "true", will return only the columns of the query. If "false", will return the column headers and all query results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSight.QueryViewerResults | Unknown | Query viewer results | 


#### Command Example
```!as-get-query-viewer-results id="123457WYBABCw9lZRkCjVIQ=="```

#### Context Example
```
{
    "ArcSightESM": {
        "QueryViewerResults": [
            {
                "Attacker Address": "1.1.1.1",
                "Attacker Zone URI": "/All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc.",
                "End Time": "1589028174502",
                "Event ID": "12345678",
                "Name": "Login succeeded for user name 'admin'",
                "Start Time": "1589028174502"
            },
            {
                "Attacker Address": "2.2.2.2",
                "Attacker Zone URI": "/All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc.",
                "End Time": "1589028234536",
                "Event ID": "87654321",
                "Name": "Login succeeded for user name 'admin'",
                "Start Time": "1589028234536"
            },
            {
                "Attacker Address": "3.3.3.3",
                "Attacker Zone URI": "/All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc.",
                "End Time": "1589028294471",
                "Event ID": "14725836",
                "Name": "Login succeeded for user name 'admin'",
                "Start Time": "1589028294471"
            }
        ]
    }
}
```

#### Human Readable Output

>|Column Headers|
>|---|
>| Name |
>| End Time |
>| Attacker Zone URI |
>| Attacker Address |
>| Event ID |
>| Start Time |
>### Query Viewer Results: 123457WYBABCw9lZRkCjVIQ==
>|Attacker Address|Attacker Zone URI|End Time|Event ID|Name|Start Time|
>|---|---|---|---|---|---|
>| 1.1.1.1 | /All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc. | 1589028174502 | 12345678 | Login succeeded for user name 'admin' | 1589028174502 |
>| 2.2.2.2 | /All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc. | 1589028234536 | 87654321 | Login succeeded for user name 'admin' | 1589028234536 |
>| 3.3.3.3 | /All Zones/ArcSight System/Public Address Space Zones/E.I. duPont de Nemours and Co. Inc. | 1589028294471 | 14725836 | Login succeeded for user name 'admin' | 1589028294471 |


### as-fetch-incidents
***
Fetches incidents


#### Base Command

`as-fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_run | Last run to start fetching incidents from | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!as-fetch-incidents```

#### Context Example
```
{}
```


### as-delete-entries
***
Delete entries from the Active List.


#### Base Command

`as-delete-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the Active List | Required | 
| entries | Entries are in JSON format. JSON must be an array of entries. Each entry must contain the same columns as they appear in the Active List, e.g., [{ "UserName": "john", "IP":"19.12.13.11"},{ "UserName": "bob", "IP":"22.22.22.22"}] | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!as-delete-entries resourceId="A1LvlmWgBABCA5+HbRyHZoQ==" entries="[{\"name\": \"t3\", \"EventID\": \"9\"},{\"name\": \"t4\", \"EventID\": \"9\"}]" ```

#### Context Example
```
{}
```

#### Human Readable Output

>Success

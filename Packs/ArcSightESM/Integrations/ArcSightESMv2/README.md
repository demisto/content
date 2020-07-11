# ArcSight ESM
ArcSight ESM is a security information and event management (SIEM) product.
It collects security log data from an enterprise’s security technologies, operating systems, applications and other log sources, and analyzes that data for signs of compromise, attacks or other malicious activity.
The product generates cases to security administrators and analysts.

##### NOTE: 
ArcSight XML is no longer supported. Use the ArcSight ESM integration instead.

## Use Cases
1. Fetching events and cases based on a query viewer.
2. Getting additional information by event or case ID.
3. Searching for events.
4. Updating a case or deleting it.
5. Getting all entries from an active list, updating an entry and clearing the list.

## Set up ArcSight ESM to work with Demisto
The set up for using ArcSight ESM to work with Demisto depends on whether you will be using the integration to fetch events or cases.

#### For fetching Events/Cases:

1. Create an Event/Case query.

2. Add a row limit (1000).

3. Add a start time limit (e.g. $Now-10m).

4. Go to the following fields and add conditions if needed:

    - Select the Event ID and Start Time fields for Events (mandatory).
    - Select the ID and Create Time fields for Cases (mandatory).
    - Select additional fields of your choice.
    - Add conditions if needed (malicious/suspicious behavior such as malware found, failed login,
      access to a known malicious site and/or conditions like severity, criticality, assets etc).
#### Note: 
Demisto is designed for an automatic response, so make sure to define conditions for actionable/sever/critical events only.

5.Create a query viewer based on the query.

    - In your ArcSight ESM environment, navigate to the Query Viewer > Attributes tab.
    - Set the Refresh Data After parameter to 1.
    - Configure the rest of the query viewer as necessary.
    
6.Save the Query Viewer resource ID integration configuration in Demisto.


# Configure ArcSight ESM on Demisto
1. Navigate to Settings>Integrations>Servers & Services.
2. Search for ArcSight ESM.
3. Click Add instance to create and configure a new integration instance.
    - **Name**: a textual name for the integration instance.
    - **Server URL (e.g. https://192.168.0.1:8443)**: The hostname or IP address of the appliance being used, for example, `https://your_arcsight_esm:port`.
    - **Credentials and Password**: Use the username and password used to access the ArcSight ESM account.
    - **Fetch Events as incidents via Query Viewer ID**: Must have Start Time and Event ID fields.
    - **Fetch Cases as incidents via Query Viewer ID**: Must have Create Time and ID fields.
    - **The maximum number of unique IDs expected to be fetched**: If unique IDs exceeds the maximum, duplicates will be fetched.
    - **Do not validate server certificate (unsecured)**: Select to avoid server certification validation. You may want to do this in case Demisto cannot validate the integration server certificate (due to missing CA certificate).
    - **Use system proxy settings**: Select whether to communicate via the system proxy server or not.
    - **Fetch incidents**: Mark the Fetch incidents checkbox to automatically create Demisto incidents from this integration instance.
    - **Incident type**: Select the incident type to trigger.
    - **Use REST Endpoints**: Mark this checkbox to use REST endpoints for the commands related to 'entries' instead of the default legacy SOAP endpoints.
4. Click **Test** to validate the URLs, token, and connection.
    If you are experiencing issues with the service configuration, please contact Demisto support at support@demisto.com.
5. After completing the test successfully, press the ‘Done’ button.

## Use-Cases
- **Fetch events** - New events that match the predefined condition will be fetched to Demisto as an incident and will trigger playbooks for automation and response. Such events could be any kind of security events.
- **Fetch cases** - New cases that match the predefined condition will be fetched to Demisto as an incident and will trigger playbooks for automation and response. Such cases could include any kind of security events. The final step of the playbook could be updating, closing or deleting the case.
- **Search events** - Query specific events based on an existing query viewer.
- **Getting active** list entries - Returning active list entries (such as “Blacklist IPS”, “Malicious MD5s”, etc) by using as-get-entries and providing the resource ID of the active list. The entries can be added as a list in Demisto for cross-platform usage, additional automation, and data enrichment.

## Fetched Incidents Data
The integration can fetch events and cases.

- When first turned on, the integration fetches all events/cases from the query viewer.
- The fetched incidents are later filtered by timestamp (start time/create time).

## Commands
You can execute these commands from the Demisto CLI, as part of automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. (Deprecated) Get all case resource IDs: as-get-all-cases
2. Get information for a single case: as-get-case
3. Get query viewer results: as-get-matrix-data
4. Add entries to the Active List: as-add-entries
5. Delete all entries from the Active List: as-clear-entries
6. Get all entries on the Active List: as-get-entries
7. Get details for security event: as-get-security-events
8. Get all case event IDs: as-get-case-event-ids
9. Update a single case: as-update-case
10. Get all query viewer IDs: as-get-all-query-viewers
11. Delete a single case: as-case-delete
12. Get all query viewer results: as-get-query-viewer-results
13. Fetches incidents: as-fetch-incidents
14. Delete entries from the Active List: as-delete-entries


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
{
  "ArcSightESM.QueryViewerResults": [
    {
      "Alias": null,
      "Create Time": "1582763229550",
      "Display ID": "30001",
      "Event-Name": null,
      "ID": "123nu5XEBABCJHuGRQA-nwg==",
      "Name": "test1",
      "Originator": null
    },
    {
      "Alias": null,
      "Create Time": "1589103446811",
      "Display ID": "30003",
      "Event-Name": null,
      "ID": "123gfy-XEBABCAD7Y9AVwrTA==",
      "Name": "test2",
      "Originator": null
    },
    {
      "Alias": null,
      "Create Time": "1588004035004",
      "Display ID": "30002",
      "Event-Name": "Login succeeded for user name 'admin'",
      "ID": "123lqvHEBABDmMHb-MM+jnA==",
      "Name": "test3",
      "Originator": null
    },
    {
      "Alias": null,
      "Create Time": "1588004035004",
      "Display ID": "30002",
      "Event-Name": "ArcSight User Login",
      "ID": "123lqvHEBABDmMHb-MM+jnA==",
      "Name": "test4",
      "Originator": null
    }
  ]
}
```

#### Human Readable Output


|Column Headers|
|---|
| Name |
| ID |
| Create Time |
| Event-Name |
| Originator |
| Alias |
| Display ID |

### Query Viewer Results: aBBnu5XEBABCJHuGRQA-nwg==

|**Create Time** | **Display ID** | **Event-Name** | **ID** | **Name** |
|---|---|---|---|---|
| 1582763229550 | 30001 |  | 123nu5XEBABCJHuGRQA-nwg== | test1 |
| 1589103446811 | 30003 |  | 123gfy-XEBABCAD7Y9AVwrTA== | test2 |
| 1588004035004 | 30002 | Login succeeded for user name 'admin' | 123lqvHEBABDmMHb-MM+jnA== | test3 |
| 1588004035004 | 30002 | ArcSight User Login | 123lqvHEBABDmMHb-MM+jnA== | test4 |

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
```!as-get-entries resourceId=A1LvlmWgBABCA5+HbRyHZoQ==```

#### Context Example
```
{
    "ArcSightESM": {
        "ActiveList": {
            "A1LvlmWgBABCA5+HbRyHZoQ==": [
                {
                    "eventId": "9", 
                    "startDate": "None", 
                    "name": "T4", 
                    "startTime": "31 Dec 1969 19:00:00 EST"
                }, 
                {
                    "eventId": "9", 
                    "startDate": "None", 
                    "name": "T3", 
                    "startTime": "31 Dec 1969 19:00:00 EST"
                }
            ]
        }
    }
}
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

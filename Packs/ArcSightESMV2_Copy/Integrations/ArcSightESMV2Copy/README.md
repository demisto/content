ArcSight ESM SIEM by Micro Focus (Formerly HPE Software).
## Configure ArcSight ESM v2_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ArcSight ESM v2_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server full URL (e.g., https://192.168.0.1:8443) |  | True |
    | Credentials |  | True |
    | Password |  | True |
    | Fetch events as incidents via Query Viewer ID. Mandatory fields for query are "Start Time" and "Event ID". |  | False |
    | Fetch cases as incidents via Query Viewer ID. Mandatory fields for query are "Create Time" and "ID". |  | False |
    | The maximum number of unique IDs expected to be fetched. |  | False |
    | The maximum number of incidents to fetch each time. Default is 50, maximum is 300. |  | False |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Use REST Endpoints | Use REST endpoints for the commands related to 'entries' instead of the default legacy SOAP endpoints. | False |
    | Product Version | Different versions requires to use a different API. | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### as-get-all-cases

***
(Deprecated) Retrieves all case resource IDs.

#### Base Command

`as-get-all-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.AllCaseIDs | Unknown | All case resource IDs. | 

### as-get-case

***
Gets information about a single case.

#### Base Command

`as-get-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the case to get information for. | Required | 
| withBaseEvents | If "true", then will return case and base events of that case. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases.resourceid | string | Case ID. | 
| ArcSightESM.Cases.name | string | Case name. | 
| ArcSightESM.Cases.eventIDs | Unknown | Related base event IDs. | 
| ArcSightESM.Cases.createdTimestamp | number | Time the case was created \(in milliseconds\). | 
| ArcSightESM.Cases.createdTime | string | Created time \(dd-mm-yyyyTHH:MM:SS.SSS timezone\). | 
| ArcSightESM.Cases.modifiedTimestamp | number | Modified timestamp \(in milliseconds\). | 
| ArcSightESM.Cases.modifiedTime | date | Modified time \(dd-mm-yyyyTHH:MM:SS.SSS timezone\). | 
| ArcSightESM.Cases.action | string | Action \(e.g., BLOCK_OR_SHUTDOWN\). | 
| ArcSightESM.Cases.associatedImpact | string | Associated impact \(e.g., AVAILABILITY\). | 
| ArcSightESM.Cases.attackAgent | string | Attack agent \(e.g., INSIDER\). | 
| ArcSightESM.Cases.attackMechanism | string | Attack mechanism \(e.g., PHYSICAL\). | 
| ArcSightESM.Cases.consequenceSeverity | string | Consequence severity \(e.g., NONE\). | 
| ArcSightESM.Cases.detectionTime | date | Detection time \(dd-mm-yyyyTHH:MM:SS.SSS timezone\). | 
| ArcSightESM.Cases.displayID | number | Display ID. | 
| ArcSightESM.Cases.estimatedStartTime | date | Estimated start time \(dd-mm-yyyyTHH:MM:SS.SSS timezone\). | 
| ArcSightESM.Cases.eventIDs | unknown | Base event IDs. | 
| ArcSightESM.Cases.frequency | string | Frequency \(e.g., NEVER_OR_ONCE\). | 
| ArcSightESM.Cases.history | Unknown | History \(e.g., KNOWN_OCCURENCE\). | 
| ArcSightESM.Cases.numberOfOccurences | number | Number Of Occurences. | 
| ArcSightESM.Cases.resistance | string | Resistance \(e.g., HIGH\). | 
| ArcSightESM.Cases.securityClassification | string | Security Classification \(e.g., UNCLASSIFIED\). | 
| ArcSightESM.Cases.sensitivity | string | Sensitivity \(e.g., UNCLASSIFIED\). | 
| ArcSightESM.Cases.stage | string | Stage \(e.g., QUEUED,INITIAL,FOLLOW_UP,FINAL,CLOSED\). | 
| ArcSightESM.Cases.ticketType | string | Ticket type \(e.g., INTERNAL,CLIENT,INCIDENT\). | 
| ArcSightESM.Cases.vulnerability | string | Vulnerability \(e.g., DESIGN\). | 

### as-get-matrix-data

***
Retrieves query viewer results (query viewer must be configured to be refreshed every minute, see documentation).

#### Base Command

`as-get-matrix-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID of a query viewer. | Required | 
| onlyColumns | If "true", will return only the columns of the query. If "false", will return the column headers and all query results. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

There is no context output for this command.
### as-add-entries

***
Adds new entries to the Active List.

#### Base Command

`as-add-entries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the Active List. | Required | 
| entries | Entries are in JSON format. JSON must be an array of entries. Each entry must contain the same columns as they appear in the Active List, e.g., [{ "UserName": "john", "IP":"19.12.13.11"},{ "UserName": "bob", "IP":"22.22.22.22"}]. | Required | 

#### Context Output

There is no context output for this command.
### as-clear-entries

***
Deletes all entries in the Active List.

#### Base Command

`as-clear-entries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of a specific Active List. | Required | 

#### Context Output

There is no context output for this command.
### as-get-entries

***
Returns all entries in the Active List.

#### Base Command

`as-get-entries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of a specific Active List. | Required | 
| entryFilter | Filters the entries, e.g., entryFilter="moo:moo1". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.ActiveList | Unknown | Active List is a map of active list resource id =&gt; active list entries. | 
| ArcSightESM.ActiveList.ListID | list | The ActiveList ID. | 
| ArcSightESM.ActiveList.Entries | Unknown | Active List is a map of active list resource id =&gt; active list. | 

### as-get-security-events

***
Returns the security event details.

#### Base Command

`as-get-security-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID or multiple ids separated by comma of security events. Event ID is ArcSight is always a number. Example: 13906590. | Required | 
| lastDateRange | Query last events. Format follows 'number date_range_unit', e.g., 2 hours, 4 minutes, 6 month, 1 day. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.SecurityEvents | Unknown | List of security events. | 
| ArcSightESM.SecurityEvents.name | string | Event name. | 
| ArcSightESM.SecurityEvents.eventId | string | Event ID. | 
| ArcSightESM.SecurityEvents.type | string | Event type \(e.g., CORRELATION\). | 
| ArcSightESM.SecurityEvents.baseEventIds | string | Base event IDs. | 
| ArcSightESM.SecurityEvents.source.address | Unknown | Event source address. | 
| ArcSightESM.SecurityEvents.destination.address | Unknown | Event destination address. | 
| ArcSightESM.SecurityEvents.startTime | date | Start time in milliseconds. | 

### as-get-case-event-ids

***
Returns all case event IDs.

#### Base Command

`as-get-case-event-ids`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Case ID, e.g., 7e6LEbF8BABCfA-dlp1rl1A==. | Required | 
| withCorrelatedEvents | If "true", then will return case and correlated events. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.CaseEvents | Unknown | Map of caseId =&gt; related event ids. | 
| ArcSightESM.CaseEvents.LatestResult | Unknown | Event IDs of the last execution of this command. | 

### as-update-case

***
Updates a specific case.

#### Base Command

`as-update-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Case resource ID to update. The case must be unlocked, and the user should have edit permissions. | Required | 
| stage | Stage the case is in. Possible values are: CLOSED, QUEUED, FINAL, FOLLOW_UP, INITIAL. | Optional | 
| severity | Ticket consequence Severity. Possible values are: NONE, INSIGNIFICANT, MARGINAL, CRITICAL, CATASTROPHIC. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases | unknown | List of cases. | 
| ArcSightESM.Cases.resourceid | string | Case resource ID. | 
| ArcSightESM.Cases.stage | string | Case stage. | 
| ArcSightESM.Cases.consequenceSeverity | string | Case severity. | 

### as-get-all-query-viewers

***
Returns all the query viewer IDs.

#### Base Command

`as-get-all-query-viewers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.AllQueryViewers | Unknown | List of all query viewer IDs. | 

### as-case-delete

***
Deletes a case.

#### Base Command

`as-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Resource ID of the case. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases.resourceid | string | Resource ID of case. | 
| ArcSightESM.Cases.Deleted | boolean | Boolean flag. "True" if deleted. | 

### as-get-query-viewer-results

***
Retrieves query viewer results (query viewer must be configured to be refreshed every minute, see documentation).

#### Base Command

`as-get-query-viewer-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID of the query viewer. | Required | 
| onlyColumns | If "true", will return only the columns of the query. If "false", will return the column headers and all query results. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSight.QueryViewerResults | Unknown | Query viewer results. | 

### as-fetch-incidents

***
Fetches incidents.

#### Base Command

`as-fetch-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_run | Last run to start fetching incidents from. | Optional | 

#### Context Output

There is no context output for this command.
### as-delete-entries

***
Delete entries from the Active List.

#### Base Command

`as-delete-entries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the Active List. | Required | 
| entries | Entries are in JSON format. JSON must be an array of entries. Each entry must contain the same columns as they appear in the Active List, e.g., [{ "UserName": "john", "IP":"19.12.13.11"},{ "UserName": "bob", "IP":"22.22.22.22"}]. | Required | 

#### Context Output

There is no context output for this command.

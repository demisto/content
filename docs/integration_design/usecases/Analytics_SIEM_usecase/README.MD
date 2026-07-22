# Analytics and SIEM
**Please Note:** Will normally include the Fetch Incidents possibility for the instance. Can also include list-incidents or get-incident as integration commands.
Important information for an Event/Incident:

Top Use-Cases:
- Fetch Incidents with relevant filters
- [Create, close and delete incidents/events/cases](#get-case-example)
- [Update Incidents - Update status, assignees, Severity, SLA, etc](#update-example)
- Get events related to an incident/case.
- Query SIEM (consider aggregating logs) 

**Analytics & SIEM Integration Example** – ArcSight ESM

## Command Examples

### as-get-case <a name="get-case-example"></a> 
---
Gets information about a single case.
##### Base Command
`as-get-case`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | Resource ID of the case to get information for | Required | 
| withBaseEvents | If "true", then will return case and base events of that case | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases.resourceid | string | Case ID | 
| ArcSightESM.Cases.name | string | Case name | 
| ArcSightESM.Cases.eventIDs | Unknown | Related base event IDs | 
| ArcSightESM.Cases.createdTimestamp | number | Time the case was created (in milliseconds) | 
| ArcSightESM.Cases.createdTime | string | Created time (dd-mm-yyyyTHH:MM:SS.SSS timezone) | 
| ArcSightESM.Cases.modifiedTimestamp | number | Modified timestamp (in milliseconds) | 
| ArcSightESM.Cases.modifiedTime | date | Modified time (dd-mm-yyyyTHH:MM:SS.SSS timezone) | 
| ArcSightESM.Cases.action | string | Action (e.g., BLOCK_OR_SHUTDOWN) | 
| ArcSightESM.Cases.associatedImpact | string | Associated impact (e.g., AVAILABILITY) | 
| ArcSightESM.Cases.attackAgent | string | Attack agent (e.g., INSIDER) | 
| ArcSightESM.Cases.attackMechanism | string | Attack mechanism (e.g., PHYSICAL) | 
| ArcSightESM.Cases.consequenceSeverity | string | Consequence severity (e.g., NONE) | 
| ArcSightESM.Cases.detectionTime | date | Detection time (dd-mm-yyyyTHH:MM:SS.SSS timezone) | 
| ArcSightESM.Cases.displayID | number | Display ID | 
| ArcSightESM.Cases.estimatedStartTime | date | Estimated start time (dd-mm-yyyyTHH:MM:SS.SSS timezone) | 
| ArcSightESM.Cases.eventIDs | unknown | Base event IDs | 
| ArcSightESM.Cases.frequency | string | Frequency (e.g., NEVER_OR_ONCE) | 
| ArcSightESM.Cases.history | Unknown | History (e.g., KNOWN_OCCURENCE) | 
| ArcSightESM.Cases.numberOfOccurences | number | Number Of Occurences | 
| ArcSightESM.Cases.resistance | string | Resistance (e.g., HIGH) | 
| ArcSightESM.Cases.securityClassification | string | Security Classification (e.g., UNCLASSIFIED) | 
| ArcSightESM.Cases.sensitivity | string | Sensitivity (e.g., UNCLASSIFIED) | 
| ArcSightESM.Cases.stage | string | Stage (e.g., QUEUED,INITIAL,FOLLOW_UP,FINAL,CLOSED) | 
| ArcSightESM.Cases.ticketType | string | Ticket type (e.g., INTERNAL,CLIENT,INCIDENT) | 
| ArcSightESM.Cases.vulnerability | string | Vulnerability (e.g., DESIGN) | 
##### Command Example
`!as-get-case resourceId="7dBWHEWcBABD6VdKLNcKE2Q==" withBaseEvents="false"`
##### Context Example
```
{
    "ArcSightESM": {
        "Cases": {
            "reference": {
                "uri": "/All Cases/All Cases/Personal/admin's Cases/newtest", 
                "referenceString": "<Resource URI=\"/All Cases/All Cases/Personal/admin's Cases/newtest\" ID=\"7dBWHEWcBABD6VdKLNcKE2Q==\"/>", 
                "isModifiable": true, 
                "referenceName": "Case", 
                "referenceType": 7, 
                "managerID": "V6xxqmYBABCAXZPTkLg+BA==", 
                "id": "7dBWHEWcBABD6VdKLNcKE2Q=="
            }, 
            "attackAgent": "INSIDER", 
            "sensitivity": "UNCLASSIFIED", 
            "modificationCount": 29, 
            "resistance": "HIGH", 
            "disabled": false, 
            "typeName": "Case", 
            "inactive": false, 
            "inCache": false, 
            "initialized": true, 
            "action": "BLOCK_OR_SHUTDOWN", 
            "consequenceSeverity": "CRITICAL", 
            "vulnerabilityType2": "EMI_RFI", 
            "vulnerabilityType1": "ACCIDENTAL", 
            "localID": 30064771083, 
            "resourceid": "7dBWHEWcBABD6VdKLNcKE2Q==", 
            "modifierName": "admin", 
            "reportingLevel": 3, 
            "associatedImpact": "AVAILABILITY", 
            "isAdditionalLoaded": false, 
            "securityClassificationCode": "P I   D U A B ", 
            "type": 7, 
            "numberOfOccurences": 0, 
            "modifiedTime": {
                "milliSecond": 146, 
                "timezoneID": "America/New_York", 
                "hour": 6, 
                "month": 1, 
                "second": 22, 
                "year": 2019, 
                "day": 26, 
                "minute": 5
            }, 
            "state": 2, 
            "creatorName": "admin", 
            "URI": "/All Cases/All Cases/Personal/admin's Cases/newtest", 
            "createdTimestamp": 1542187324789, 
            "displayID": 11, 
            "modifiedDate": "2019-02-26T11:05:22.000Z", 
            "createdDate": "2018-11-14T09:22:04.000Z", 
            "securityClassification": "UNCLASSIFIED", 
            "operationalImpact": "NO_IMPACT", 
            "attributeInitializationInProgress": false, 
            "name": "newtest", 
            "deprecated": false, 
            "vulnerability": "DESIGN", 
            "attackMechanism": "PHYSICAL", 
            "modifiedTimestamp": 1551179122146, 
            "frequency": "NEVER_OR_ONCE", 
            "createdTime": {
                "milliSecond": 789, 
                "timezoneID": "America/New_York", 
                "hour": 4, 
                "month": 10, 
                "second": 4, 
                "year": 2018, 
                "day": 14, 
                "minute": 22
            }, 
            "ticketType": "INCIDENT", 
            "history": "KNOWN_OCCURENCE"
        }
    }
}
```
### as-update-case <a name="update-example"></a>
---
Updates a specific case.
##### Base Command
`as-update-case`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Case resource ID to update. | Required | 
| stage | Stage the case is in | Optional | 
| severity | Ticket consequence Severity | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcSightESM.Cases | unknown | List of cases | 
| ArcSightESM.Cases.resourceid | string | Case resource ID | 
| ArcSightESM.Cases.stage | string | Case stage  | 
| ArcSightESM.Cases.consequenceSeverity | string | Case severity | 
##### Command Example
`!as-update-case caseId="7dBWHEWcBABD6VdKLNcKE2Q==" severity="CRITICAL`
##### Context Example
```
Demisto LogoArtifact Viewer
DBot
Playground
2/26/2019 1:18 PM
!PrintContext
Download as a file
< 193 / 51 >
Search...
Context data:
{
    "ArcSightESM": {
        "Cases": {
            "reference": {
                "uri": "/All Cases/All Cases/Personal/admin's Cases/newtest", 
                "referenceString": "<Resource URI=\"/All Cases/All Cases/Personal/admin's Cases/newtest\" ID=\"7dBWHEWcBABD6VdKLNcKE2Q==\"/>", 
                "isModifiable": true, 
                "referenceName": "Case", 
                "referenceType": 7, 
                "managerID": "V6xxqmYBABCAXZPTkLg+BA==", 
                "id": "7dBWHEWcBABD6VdKLNcKE2Q=="
            }, 
            "attackAgent": "INSIDER", 
            "sensitivity": "UNCLASSIFIED", 
            "modificationCount": 29, 
            "resistance": "HIGH", 
            "disabled": false, 
            "typeName": "Case", 
            "inactive": false, 
            "inCache": false, 
            "initialized": true, 
            "action": "BLOCK_OR_SHUTDOWN", 
            "consequenceSeverity": "CRITICAL", 
            "vulnerabilityType2": "EMI_RFI", 
            "vulnerabilityType1": "ACCIDENTAL", 
            "localID": 30064771083, 
            "resourceid": "7dBWHEWcBABD6VdKLNcKE2Q==", 
            "modifierName": "admin", 
            "reportingLevel": 3, 
            "associatedImpact": "AVAILABILITY", 
            "isAdditionalLoaded": false, 
            "securityClassificationCode": "P I   D U A B ", 
            "stage": null, 
            "type": 7, 
            "numberOfOccurences": 0, 
            "modifiedTime": {
                "milliSecond": 146, 
                "timezoneID": "America/New_York", 
                "hour": 6, 
                "month": 1, 
                "second": 22, 
                "year": 2019, 
                "day": 26, 
                "minute": 5
            }, 
            "state": 2, 
            "creatorName": "admin", 
            "URI": "/All Cases/All Cases/Personal/admin's Cases/newtest", 
            "createdTimestamp": 1542187324789, 
            "displayID": 11, 
            "modifiedDate": "2019-02-26T11:05:22.000Z", 
            "createdDate": "2018-11-14T09:22:04.000Z", 
            "securityClassification": "UNCLASSIFIED", 
            "operationalImpact": "NO_IMPACT", 
            "attributeInitializationInProgress": false, 
            "name": "newtest", 
            "deprecated": false, 
            "vulnerability": "DESIGN", 
            "attackMechanism": "PHYSICAL", 
            "modifiedTimestamp": 1551179122146, 
            "frequency": "NEVER_OR_ONCE", 
            "createdTime": {
                "milliSecond": 789, 
                "timezoneID": "America/New_York", 
                "hour": 4, 
                "month": 10, 
                "second": 4, 
                "year": 2018, 
                "day": 14, 
                "minute": 22
            }, 
            "ticketType": "INCIDENT", 
            "history": "KNOWN_OCCURENCE"
        }
    }
}
```
##### Human Readable Output

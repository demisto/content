
### branddefense-get-assets

***
Gets assets from Brandefense.

#### Base Command

`branddefense-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_assets | unknown | Assets from Branddefense Platform. | 
### branddefense-get-specific-asset

***
Call a specific asset from Brandefense.

#### Base Command

`branddefense-get-specific-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assetid | The id of the asset. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_requested_asset | unknown | The requested asset from Brandefense. | 
### branddefense-get-audit-logs

***
Get audit logs from Brandefense platform.

#### Base Command

`branddefense-get-audit-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_audit_logs | unknown | Audit logs from Brandefense. | 
### branddefense-get-specific-audit-log

***
Get a specific audit log from Brandefense platform.

#### Base Command

`branddefense-get-specific-audit-log`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| audit_log_id | The id of the audit log from Brandefense platform. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_requested_audit_log | unknown | The requested audit log from Brandefense. | 
### branddefense-get-threat-search

***
Get Threat Search endpoint allows you to investigate indicator of compromises by UUID.

#### Base Command

`branddefense-get-threat-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_uuid | the uuid of the search on Brandefense. | Optional | 

#### Context Output

There is no context output for this command.
### branddefense-get-specific-incident

***
Search for a specific incident on Brandefense.

#### Base Command

`branddefense-get-specific-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_code | The required code parameter should be given to perform incident searches on Brandefense. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_requested_incident | unknown | The requested incident via incident code from Brandefense. | 
### branddefense-change-incident-status

***
Change the status of an existing incident on Brandefense.

#### Base Command

`branddefense-change-incident-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_code | The required code parameter should be given to perform incident searches on Brandefense. | Required | 
| incident_status | The required status parameter should be given to perform change incident status Possible Values: 'OPEN' 'IN_PROGRESS' 'CLOSED' 'RISK_ACCEPTED' 'REJECTED'. | Required | 

#### Context Output

There is no context output for this command.
### branddefense-get-incident-indicators

***
Get indicators related to an incident on Brandefense using incident's code.

#### Base Command

`branddefense-get-incident-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_code | The required code parameter should be given to perform incident searches on Brandefense. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_requested_incident_indicators | unknown | Requested indicators from Brandefense based on provided incident code. | 
### branddefense-get-ioc

***
Get IOCs from Brandefense.

#### Base Command

`branddefense-get-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | The required ioc_type parameter allows you to select Indicators of Compromise (IoCs) types from the threat lists. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_ioc | unknown | hash,domain,url veya ip address girilmeli. | 
### branddefense-get-cti-rules

***
Get CTI rules from Brandefense.

#### Base Command

`branddefense-get-cti-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_at__range | Cti Rule Created at range. | Optional | 
| search | Cti rule search. | Optional | 
| tag | Tag for the Brandefense search. | Optional | 
| source__ilike | Source from Brandefense CTI rule search. | Optional | 

#### Context Output

There is no context output for this command.
### branddefense-create-threat-search

***
Create Threat Search endpoint allows you to post indicator of compromises to investigate suspicious/malicious IP, Domain, URL address or Hash values.

#### Base Command

`branddefense-create-threat-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Required value for Created Threat Search such as an IP address, domain, Hash or url. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| search_result | unknown | The result of Theat search from Brandefense. | 
### branddefense-get-incidents

***
Get incidents from the Brandefense platform.

#### Base Command

`branddefense-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_at | Exact created date of the incident. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| branddefense_all_incidents | unknown | All incidents from the Brandefense platform. | 

WithSecure Elements API integration for endpoint protection, security events, and device management
## Configure WithSecure Elements in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Client Secret | True |
| API Scope | True |
| Fetch incidents | False |
| Incident type | False |
| Fetch incidents from type | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Engine Group | False |
| Fetch limit (maximum 200) | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Incidents Fetch Interval | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### withsecure-whoami

***
Get current user information

#### Base Command

`withsecure-whoami`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Whoami.clientId | String | Client ID | 
| WithSecure.Whoami.organizationId | String | Organization ID | 

### withsecure-get-security-events

***
Query security events. Note: A time range (start or end) and an engine scope (engine or engine group) are required.

#### Base Command

`withsecure-get-security-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID (UUID format). | Optional | 
| engine_group | Engine group to filter by. Possible values are: epp, edr, ecp, xm. | Optional | 
| persistence_timestamp_start | Start timestamp (ISO format), e.g., 2025-07-15T14:00:00Z. | Optional | 
| persistence_timestamp_end | End timestamp (ISO format). | Optional | 
| engine | Specific engines to filter by. Mutually exclusive with engine_group. | Optional | 
| severity | Event severity levels. Possible values are: critical, warning, info. | Optional | 
| limit | Maximum number of events to return (1-200). Default is 200. | Optional | 
| anchor | Pagination anchor. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.SecurityEvent.id | String | Event ID | 
| WithSecure.SecurityEvent.severity | String | Event severity | 
| WithSecure.SecurityEvent.engine | String | Engine that triggered the event | 
| WithSecure.SecurityEvent.action | String | Action taken | 
| WithSecure.SecurityEvent.serverTimestamp | Date | Server timestamp | 
| WithSecure.SecurityEvent.NextAnchor | String | Next page anchor | 

### withsecure-get-incidents

***
Get Broad Context Detections (BCDs)

#### Base Command

`withsecure-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID (UUID format). | Optional | 
| anchor | Pagination anchor. | Optional | 
| created_timestamp_start | Start timestamp for creation date. | Optional | 
| created_timestamp_end | End timestamp for creation date. | Optional | 
| status | Incident status. Possible values are: new, acknowledged, inProgress, monitoring, closed, waitingForCustomer. | Optional | 
| resolution | Incident resolution. Possible values are: unconfirmed, confirmed, falsePositive, merged, autoUnconfirmed, autoFalsePositive, securityTest, acceptedRisk, acceptedBehavior. | Optional | 
| risk_level | Risk level. Possible values are: info, low, medium, high, severe. | Optional | 
| archived | Include archived incidents. Possible values are: true, false. | Optional | 
| limit | Maximum number of incidents to return (1-50). Default is 20. | Optional | 
| order | Sort order. Possible values are: asc, desc. Default is desc. | Optional | 
| source | Incident source. Possible values are: endpoint, cloud, customer, endpointExpert, identityAzure, workloadAzure, workloadAws. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Incident.incidentId | String | Incident ID | 
| WithSecure.Incident.incidentPublicId | String | Public incident ID | 
| WithSecure.Incident.name | String | Incident name | 
| WithSecure.Incident.status | String | Incident status | 
| WithSecure.Incident.severity | String | Incident severity | 
| WithSecure.Incident.riskLevel | String | Risk level | 
| WithSecure.Incident.createdTimestamp | Date | Creation timestamp | 
| WithSecure.Incident.NextAnchor | String | Next page anchor | 

### withsecure-update-incident-status

***
Update incident status

#### Base Command

`withsecure-update-incident-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | List of incident IDs to update. | Required | 
| status | New status. Possible values are: new, acknowledged, inProgress, monitoring, closed, waitingForCustomer. | Required | 
| resolution | Resolution (required when status is closed). Possible values are: unconfirmed, confirmed, falsePositive. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.IncidentUpdate.target | String | Target incident ID | 
| WithSecure.IncidentUpdate.status | Number | Operation status code | 
| WithSecure.IncidentUpdate.details | String | Operation details | 

### withsecure-add-comment-to-incident

***
Add comment to incidents

#### Base Command

`withsecure-add-comment-to-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | List of incident IDs. | Required | 
| comment | Comment text. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.IncidentComment.incidentId | String | Incident ID | 
| WithSecure.IncidentComment.comment | String | Added comment | 

### withsecure-get-detections

***
Get detections for an incident

#### Base Command

`withsecure-get-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID. | Optional | 
| incident_id | Incident ID. | Required | 
| anchor | Pagination anchor. | Optional | 
| created_timestamp_start | Start timestamp. | Optional | 
| created_timestamp_end | End timestamp. | Optional | 
| limit | Maximum results (1-100). Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Detection.detectionId | String | Detection ID | 
| WithSecure.Detection.incidentId | String | Incident ID | 
| WithSecure.Detection.deviceId | String | Device ID | 
| WithSecure.Detection.name | String | Detection name | 
| WithSecure.Detection.severity | String | Detection severity | 
| WithSecure.Detection.createdTimestamp | Date | Creation timestamp | 
| WithSecure.Detection.NextAnchor | String | Next page anchor | 

### withsecure-get-devices

***
Query devices

#### Base Command

`withsecure-get-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID. | Optional | 
| device_id | Specific device ID. | Optional | 
| type | Device type. Possible values are: computer, connector, mobile. | Optional | 
| state | Device state. Possible values are: active, blocked, inactive. | Optional | 
| name | Device name (exact match). | Optional | 
| online | Online status. Possible values are: true, false. | Optional | 
| protection_status_overview | Protection status overview filter. | Optional | 
| patch_overall_state | Patch overall state filter. Possible values are: missingCriticalUpdates, upToDate, missingUpdates. | Optional | 
| limit | Maximum results (1-200). Default is 200. | Optional | 
| anchor | Pagination anchor. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Device.id | String | Device ID | 
| WithSecure.Device.name | String | Device name | 
| WithSecure.Device.type | String | Device type | 
| WithSecure.Device.state | String | Device state | 
| WithSecure.Device.online | Boolean | Online status | 
| WithSecure.Device.protectionStatus | String | Protection status | 
| WithSecure.Device.NextAnchor | String | Next page anchor | 

### withsecure-update-device-state

***
Update device state

#### Base Command

`withsecure-update-device-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | List of device IDs. | Required | 
| state | New state. Possible values are: blocked, inactive. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.DeviceUpdate.target | String | Target device ID | 
| WithSecure.DeviceUpdate.status | Number | Operation status code | 
| WithSecure.DeviceUpdate.details | String | Operation details | 

### withsecure-trigger-device-operation

***
Trigger remote operation on devices

#### Base Command

`withsecure-trigger-device-operation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID. | Required | 
| operation | Operation type. Possible values are: isolateFromNetwork, releaseFromNetworkIsolation, assignProfile, scanForMalware, showMessage, turnOnFeature, collectDiagnosticFile. | Required | 
| device_ids | List of device IDs. | Required | 
| parameters | Operation parameters (JSON format). | Optional | 
| comment | Operation comment. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.DeviceOperation.target | String | Target device ID | 
| WithSecure.DeviceOperation.status | Number | Operation status code | 
| WithSecure.DeviceOperation.operationId | String | Operation ID | 
| WithSecure.DeviceOperation.details | String | Operation details | 

### withsecure-get-device-operations

***
Get device operations

#### Base Command

`withsecure-get-device-operations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Device ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.DeviceOperationStatus.id | String | Operation ID | 
| WithSecure.DeviceOperationStatus.status | String | Operation status | 
| WithSecure.DeviceOperationStatus.operationName | String | Operation name | 
| WithSecure.DeviceOperationStatus.startedTimestamp | Date | Start timestamp | 
| WithSecure.DeviceOperationStatus.lastUpdatedTimestamp | Date | Last update timestamp | 

### withsecure-get-organizations

***
Get organizations

#### Base Command

`withsecure-get-organizations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID. | Optional | 
| anchor | Pagination anchor. | Optional | 
| type | Organization type. Possible values are: company, partner. Default is company. | Optional | 
| limit | Maximum results (1-1000). Default is 200. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Organization.id | String | Organization ID | 
| WithSecure.Organization.name | String | Organization name | 
| WithSecure.Organization.type | String | Organization type | 
| WithSecure.Organization.NextAnchor | String | Next page anchor | 

### withsecure-get-invitations

***
Get device invitations

#### Base Command

`withsecure-get-invitations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Organization ID. | Optional | 
| anchor | Pagination anchor. | Optional | 
| limit | Maximum results (1-200). Default is 200. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Invitation.id | String | Invitation ID | 
| WithSecure.Invitation.email | String | Invitation email | 
| WithSecure.Invitation.deviceType | String | Device type | 
| WithSecure.Invitation.status | String | Invitation status | 
| WithSecure.Invitation.createdTimestamp | Date | Creation timestamp | 
| WithSecure.Invitation.NextAnchor | String | Next page anchor | 

### withsecure-create-invitation

***
Sends an invitation to a user to join the WithSecure Elements portal.

#### Base Command

`withsecure-create-invitation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address of the user to invite. | Required | 
| subscription_key | Subscription key under which the invitation is to be created. | Required | 
| language_code | Language code for the invitation email (default is "en"). Default is en. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WithSecure.Invitation.email | String | The email of the invited user. | 
| WithSecure.Invitation.status | String | Status of the invitation request. | 
| WithSecure.Invitation.details | String | Details or metadata of the invitation process. | 

### withsecure-delete-invitation

***
Delete device invitation

#### Base Command

`withsecure-delete-invitation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| invitation_id | Invitation ID to delete. | Required | 

#### Context Output

There is no context output for this command.

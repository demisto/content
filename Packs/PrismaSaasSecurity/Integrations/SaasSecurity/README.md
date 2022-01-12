Use the SaaS Security integration to protect against cloud‑based threats by scanning and analyzing all your assets; applying Security policy to identify exposures, external collaborators, risky user behavior, and sensitive documents; and identifying the potential risks associated with each asset.
This integration was integrated and tested with version xx of SaasSecurity

## Configure SaaS Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SaaS Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The instance configuration URL based on the server location: &amp;lt;br/&amp;gt;US: https://api.aperture.paloaltonetworks.com&amp;lt;br/&amp;gt; EU: https://api.aperture-eu.paloaltonetworks.com&amp;lt;br/&amp;gt; APAC: https://api.aperture-apac.paloaltonetworks.com | True |
    | Client ID | The Saas Security Client ID and Client Secret. | True |
    | Client Secret |  | True |
    | Fetch incidents | If selected, fetches incidents from SaaS Security. | False |
    | Incidents Fetch Interval | Frequency \(in hours and minutes\) by which Cortex XSOAR fetches incidents from SaaS Security when \*\*Fetch Incidents\*\* is selected. | False |
    | Incident type | Incident type is set by this field if a classifier does not exist. If a  classifier is selected, it takes precedence. | False |
    | Incident Mirroring Direction | Selects which direction you want the incidents mirrored. You can mirror Incoming only \(from Saas Security to Cortex XSOAR\), \*\*Outgoing\*\* only \(from Cortex XSOAR to Saas Security\), or both \*\*Incoming And Outgoing\*\*. | False |
    | Number of incidents per fetch | Minimum is 10. Maximum is 1000. | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;. For example, 12 hours, 7 days) |  | False |
    | Fetch only incidents with matching state | Fetches only incidents with matching \*\*All\*\*, \*\*Closed\*\*, or \*\*Open\*\* state. If nothing is selected, \*\*All\*\* states will be used. | False |
    | Fetch only incidents with matching severity | If nothing is selected, \*\*All\*\* severities will be used. | False |
    | Fetch only incidents with matching status | If nothing is selected, \*\*All\*\* statuses will be used. | False |
    | Fetch only incidents with matching Application IDs | A comma-separated list of Application IDs. Run the \*\*\*saas-security-get-apps\*\*\* command to return the \*\*Application ID\*\*, \*\*Name\*\*, and \*\*Type\*\* for all applications. | False |
    | Close Mirrored XSOAR Incident | If selected, when the incident closes on Saas Security, the incident closes in Cortex XSOAR. | False |
    | Trust any certificate (not secure) | By default, SSL verification is enabled. If selected, the connection isn’t secure and all requests return an SSL error because the certificate cannot be verified. | False |
    | Use system proxy settings | Uses the system proxy server to communicate with the  integration. If not selected, the integration will not use the system proxy server. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### saas-security-incidents-get
***
Retrieves incidents from the SaaS Security platform.


#### Base Command

`saas-security-incidents-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of incidents to pull. Maximum is 200, minimum is 10. Default is 50. Default is 50. | Optional | 
| from | The start time of the query, filtered by the date the incident was updated,\ \ For example, `2021-08-23T09:26:25.872Z`. | Optional | 
| to | The end time of the query, filtered by the date the incident was updated. For example, `2021-08-23T09:26:25.872Z`. | Optional | 
| app_ids | Comma-separated list of application IDs. Run the 'saas-security-get-apps' command to return the Application ID, Name, and Type for all applications. | Optional | 
| state | The state of the incidents. If empty, retrieves all states. Possible values: "All", "Open", and "Closed". Possible values are: All, Open, Closed. Default is open. | Optional | 
| severity | The severity of the incidents. In none is selected, all severities will be pulled. Possible values: "1", "2", "3", "4", and "5". Possible values are: 1, 2, 3, 4, 5. | Optional | 
| status | The status of the incidents. Possible values: "New", "Assigned", "In Progress", "Pending", "No Reason", "Business Justified", "Misidentified", "In The Cloud", and "Dismiss". Possible values are: New, Assigned, In Progress, Pending, No Reason, Business Justified, Misidentified, In The Cloud, Dismiss. | Optional | 
| next_page | Get the next batch of incidents. No other argument is needed when providing this. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.Incident.incident_id | Number | The incident ID. | 
| SaasSecurity.Incident.tenant | String | The tenant associated with the incident. | 
| SaasSecurity.Incident.app_id | String | The application ID. | 
| SaasSecurity.Incident.app_name | String | The application name. | 
| SaasSecurity.Incident.app_type | String | The application type. | 
| SaasSecurity.Incident.cloud_id | String | The cloud ID. | 
| SaasSecurity.Incident.asset_name | String | The asset name. | 
| SaasSecurity.Incident.asset_sha256 | String | The SHA256 hash value of the asset. | 
| SaasSecurity.Incident.asset_id | String | The asset ID. | 
| SaasSecurity.Incident.asset_page_uri | String | The asset page URI. | 
| SaasSecurity.Incident.asset_cloud_uri | String | The asset cloud URI. | 
| SaasSecurity.Incident.exposure_type | Number | The exposure type \(Internal/External\). | 
| SaasSecurity.Incident.exposure_level | String | The exposure level. | 
| SaasSecurity.Incident.policy_id | String | The policy ID. | 
| SaasSecurity.Incident.policy_name | String | The policy name. | 
| SaasSecurity.Incident.policy_version | Number | The policy version. | 
| SaasSecurity.Incident.policy_page_uri | String | The policy page URI. | 
| SaasSecurity.Incident.severity | String | The severity of the incident. | 
| SaasSecurity.Incident.status | String | The incident status. | 
| SaasSecurity.Incident.state | String | The incident state. | 
| SaasSecurity.Incident.category | String | The incident category. | 
| SaasSecurity.Incident.resolved_by | String | The name of the user who resolved the incident. | 
| SaasSecurity.Incident.resolution_date | Date | The date the incident was resolved. | 
| SaasSecurity.Incident.created_at | Date | The date the incident was created, e.g., \`2021-08-23T09:26:25.872Z\`. | 
| SaasSecurity.Incident.updated_at | Date | The Date the incident was last updated. e.g., \`2021-08-24T09:26:25.872Z\`. | 
| SaasSecurity.Incident.asset_owner_id | String | The ID of the asset owner. | 
| SaasSecurity.Incident.asset_owner_name | String | The name of the asset owner. | 
| SaasSecurity.Incident.asset_owner_email | String | The email address of the asset owner. | 
| SaasSecurity.NextResultsPage | String | The URI for the next batch of incidents. | 

### saas-security-incident-get-by-id
***
Gets an incident by its ID.


#### Base Command

`saas-security-incident-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.Incident.incident_id | Number | The Incident ID. | 
| SaasSecurity.Incident.tenant | String | The tenant associated with the incident. | 
| SaasSecurity.Incident.app_id | String | The application ID. | 
| SaasSecurity.Incident.app_name | String | The application name. | 
| SaasSecurity.Incident.app_type | String | The application type. | 
| SaasSecurity.Incident.cloud_id | String | The cloud ID. | 
| SaasSecurity.Incident.asset_name | String | The asset name. | 
| SaasSecurity.Incident.asset_sha256 | String | The SHA256 hash value of the asset. | 
| SaasSecurity.Incident.asset_id | String | The asset ID. | 
| SaasSecurity.Incident.asset_page_uri | String | The asset page URI. | 
| SaasSecurity.Incident.asset_cloud_uri | String | The asset cloud URI. | 
| SaasSecurity.Incident.exposure_type | Number | The exposure type \(Internal/External\). | 
| SaasSecurity.Incident.exposure_level | String | The exposure level. | 
| SaasSecurity.Incident.policy_id | String | The policy ID. | 
| SaasSecurity.Incident.policy_name | String | The policy name. | 
| SaasSecurity.Incident.policy_version | Number | The policy version. | 
| SaasSecurity.Incident.policy_page_uri | String | The policy page URI. | 
| SaasSecurity.Incident.severity | String | The severity of the incident. | 
| SaasSecurity.Incident.status | String | The incident status. | 
| SaasSecurity.Incident.state | String | The incident state. | 
| SaasSecurity.Incident.category | String | The incident category. | 
| SaasSecurity.Incident.resolved_by | String | The name of the user who resolved the incident. | 
| SaasSecurity.Incident.resolution_date | Date | The date the incident was resolved. | 
| SaasSecurity.Incident.created_at | Date | The date the incident was created, e.g., \`2021-08-23T09:26:25.872Z\`. | 
| SaasSecurity.Incident.updated_at | Date | The date the incident was last updated, e.g., \`2021-08-24T09:26:25.872Z\`. | 
| SaasSecurity.Incident.asset_owner_id | String | The ID of the asset owner. | 
| SaasSecurity.Incident.asset_owner_name | String | The name of the asset owner. | 
| SaasSecurity.Incident.asset_owner_email | String | The email address of the asset owner. | 

### saas-security-incident-state-update
***
Closes an incident and updates its category.


#### Base Command

`saas-security-incident-state-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. | Required | 
| category | The reason for closing the incident. Possible values: "Misidentified", "No Reason", and "Business Justified". Possible values are: Misidentified, No Reason, Business Justified. Default is Reason for state update.. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.IncidentState.incident_id | String | Incident ID. | 
| SaasSecurity.IncidentState.state | String | The incident state \(open/closed\). | 
| SaasSecurity.IncidentState.category | String | The incident category. | 
| SaasSecurity.IncidentState.resolved_by | String | The name of the user who resolved the incident. | 
| SaasSecurity.IncidentState.resolution_date | Date | The date when the incident was resolved. | 

### saas-security-get-apps
***
Returns the Application ID, Name, and Type for all applications.


#### Base Command

`saas-security-get-apps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.App.app_name | String | The application name. | 
| SaasSecurity.App.app_id | String | The application ID. | 
| SaasSecurity.App.app_type | String | The application type. | 

### saas-security-asset-remediate
***
Remediates an asset.


#### Base Command

`saas-security-asset-remediate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset to remediate. | Required | 
| remediation_type | The remediation action to take. Possible values: "Remove public sharing"(only for Office365, Dropbox, Box, Google Drive apps), "Quarantine", and "Restore". Possible values are: Remove public sharing, Quarantine, Restore. | Required | 
| remove_inherited_sharing | Used when the remediation type is “Remove public sharing”. When set to true, all the parent folders with a shared URL will be removed. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.Remediation.asset_id | String | Asset ID. | 
| SaasSecurity.Remediation.remediation_type | String | The remediation type. | 
| SaasSecurity.Remediation.status | String | The remediation action status. | 

### saas-security-remediation-status-get
***
Gets the remediation status for a given asset ID.


#### Base Command

`saas-security-remediation-status-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID. | Required | 
| remediation_type | The remediation action that was taken. Possible values: "Remove public sharing"(only for Office365, Dropbox, Box, Google Drive apps), "Quarantine", and "Restore". Possible values are: Remove public sharing, Quarantine, Restore. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.Remediation.asset_id | String | The asset ID. | 
| SaasSecurity.Remediation.asset_name | String | The asset name. | 
| SaasSecurity.Remediation.remediation_type | String | The remediation type. | 
| SaasSecurity.Remediation.action_taker | String | The source of the remediation action. For example, 'api'. | 
| SaasSecurity.Remediation.action_date | Date | The date when the remediation action was taken. | 
| SaasSecurity.Remediation.status | String | The remediation action status. | 

### get-remote-data
***
Get remote data from a remote incident. Note that this method will not update the current incident. It's used for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 


#### Context Output

There is no context output for this command.
### get-mapping-fields
***
Returns the list of fields for an incident type.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-modified-remote-data
***
Get the list of incidents that were modified since the last update. Note that this method is used for debugging purposes. get-modified-remote-data is used as part of a Mirroring feature, which is available since version 6.1.


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time. The incident is only returned if it was modified after the last update time. | Optional | 


#### Context Output

There is no context output for this command.
### update-remote-system
***
Updates local incident changes in the remote incident. This method is only used for debugging purposes and will not update the current incident.


#### Base Command

`update-remote-system`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
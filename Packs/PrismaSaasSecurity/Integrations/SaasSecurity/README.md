Use the SaaS Security integration to protect against cloud‑based threats by:
- Scanning and analyzing all your assets.
- Applying Security policy to identify exposures, external collaborators, risky user behavior, and sensitive documents.
- Identifying the potential risks associated with each asset.

## Configure SaaS Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SaaS Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The instance configuration URL based on the server location: https://api.aperture.paloaltonetworks.com (US)<br/>https://api.aperture-eu.paloaltonetworks.com (EU)<br/>https://api.aperture-apac.paloaltonetworks.com (APAC) | True |
    | Client ID | The SaaS Security Client ID. See instructions below. | True |
    | Client Secret | The SaaS Security Client Secret. See instructions below. | True |
    | Fetch incidents | If selected, fetches incidents from SaaS Security. | False |
    | Incidents Fetch Interval | Frequency \(in hours and minutes\) by which Cortex XSOAR fetches incidents from SaaS Security when **Fetch Incidents** is selected. | False |
    | Incident type | Incident type is set by this field if a classifier does not exist. If a  classifier is selected, it takes precedence. | False |
    | Incident Mirroring Direction | Selects which direction you want the incidents mirrored. You can mirror Incoming only \(from SaaS Security to Cortex XSOAR\), **Outgoing** only \(from Cortex XSOAR to SaaS Security\), or both **Incoming And Outgoing**. | False |
    | Number of incidents per fetch | Important: The limit value can range from 10 to 200 and must be in multiples of 10. | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;. For example, 12 hours, 7 days) |  | False |
    | Fetch only incidents with matching state | Fetches only incidents with matching **All**, **Closed**, or **Open** state. If nothing is selected, **All** states will be used. | False |
    | Fetch only incidents with matching severity | If nothing is selected, **All** severities will be used. | False |
    | Fetch only incidents with matching status | If nothing is selected, **All** statuses will be used. | False |
    | Fetch only incidents with matching Application IDs | A comma-separated list of Application IDs. Run the ***saas-security-get-apps*** command to return the **Application ID**, **Name**, and **Type** for all applications. | False |
    | Close Mirrored XSOAR Incident | If selected, when the incident closes on SaaS Security, the incident closes in Cortex XSOAR. | False |
    | Trust any certificate (not secure) | By default, SSL verification is enabled. If selected, the connection isn’t secure and all requests return an SSL error because the certificate cannot be verified. | False |
    | Use system proxy settings | Uses the system proxy server to communicate with the  integration. If not selected, the integration will not use the system proxy server. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Configure SaaS Security Incident Mirroring
You can enable incident mirroring between Cortex XSOAR incidents and SaaS Security notables (available from Cortex XSOAR version 6.0.0).
To set up mirroring.<br/>

To configure mirroring:
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for **SaaS Security** and select your integration instance.
3. Enable **Fetches incidents**.
4. In the *Incident Mirroring Direction* integration parameter, select which direction you want the incidents to be mirrored:
    - Incoming — Any changes in the following SaaS Security incidents fields (*state*, *category*, *status*, *assigned_to*, *resolved_by*, *asset_sha256*) will be reflected in Cortex XSOAR incidents.
    - Outgoing — Any changes in the following Cortex XSOAR incidents fields (*state*, *category*) will be reflected in SaaS Security incidents.
    - Incoming And Outgoing (Recommended) — Changes in Cortex XSOAR incidents and SaaS Security incidents will be reflected in both directions.
    - None — Turns off incident mirroring.
5. (Recommended) Select the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding incident is closed on SaaS Security.
    - There is no closing parameter for the opposite direction (to close incidents in SaaS Security when they are closed in XSOAR). *Close Mirrored XSOAR Incident* is the only use case available for *mirrored out*, when the state and category are updated.
Newly fetched incidents will be mirrored in the direction you select. However, this selection does not affect existing incidents.

**Important Notes**
 - For mirroring to work, the *Incident Mirroring Direction* parameter needs to be set before the incident is fetched.
 - To ensure mirroring works as expected, mappers are required for both **Incoming** and **Outgoing** to map the expected fields in Cortex XSOAR and SaaS Security.
 - The only fields that can be *mirrored in* from SaaS Security to Cortex XSOAR are:
     - *state*
     - *category*
     - *status*
     - *assigned_to*
     - *resolved_by*
     - *asset_sha256*
 - The only fields that can be *mirrored out* from XSOAR to SaaS Security are:
     - *state*
     - *category* The supported categories for closing incidents are: "misidentified", "no_reason", and "business_justified".
    **Note**: Mirroring out works only for closed incidents due to an API limitation.


## Create the Client ID and Client Secret on SaaS Security
In the SaaS Security UI, do the following:
1. Navigate to **Settings** > **External Service**.
2. Click **Add API Client**.
3. Specify a unique name for the API client.
4. Authorize the API client for the required scopes. You use these scopes in the POST request to the /oauth/token endpoint. The Required Scopes are:
    - Log access — Access log files. You can either provide the client log access API or add a syslog receiver.
    - Incident management — Retrieve and change the incident status.
    - Quarantine management — Quarantine assets and restore quarantined assets.
6. Copy the client ID and client secret.<br/>
Tip: Record your API client secret somewhere safe. For security purposes, it’s only shown when you create or reset the API client. If you lose your secret you must reset it, which removes access for any integrations that still use the previous secret.
7. Add the **Client ID** and **Client Secret** to Cortex XSOAR.<br/>
Note: For more information see the [SaaS Security Administrator's Guide](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/add-your-api-client-app.html)


## Commands
You can execute these commands from the Cortex XSOAR CLI as part of an automation or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### saas-security-incidents-get
***
Retrieves incidents from the SaaS Security platform.


#### Base Command

`saas-security-incidents-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Important: The limit value can range from 10 to 200 and must be in multiples of 10. Default is 50. | Optional | 
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


#### Command Example
```!saas-security-incidents-get limit=11 app_ids=acf49b2389c09f26ad0ccd2b1a603328 from=2021-08-23T20:25:17.495Z state=open```
#### Context Example
```json
{
    "SaasSecurity": {
        "Incident": [
            {
                "app_id": "acf49b2389c09f26ad0ccd2b1a603328",
                "app_name": "Box 1",
                "app_type": "box",
                "asset_cloud_uri": "https://www.box.com/files/0/f/114948778953/1/f_675197457403",
                "asset_id": "61099dc26b544e38fa3ce06d",
                "asset_name": "SP0605 copy 6.java",
                "asset_owner_email": "xsoartest@cirrotester.com",
                "asset_owner_id": "22FD054D362DC548A9C22F25782E1DAEED03C12F3898CD0F2E2A1B4CF728D04BD644B3CC010FDAC3D10EC0D408F4F79AC147E3D56415D1052BCFCD899A8E249F",
                "asset_owner_name": "Xsoar test",
                "asset_page_uri": "https://xsoartest.staging.cirrotester.com/cloud_assets/61099dc26b544e38fa3ce06d",
                "asset_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "category": "business_justified",
                "cloud_id": "675197457403",
                "collaborators": [],
                "created_at": "2021-08-03T20:25:15.417Z",
                "data_patterns": [],
                "exposure_level": "internal",
                "exposure_type": 8,
                "group_ids": [],
                "incident_id": 4,
                "policy_id": "6109a5d0e64152534b240f48",
                "policy_page_uri": "https://xsoartest.staging.cirrotester.com/data_policies/6109a5d0e64152534b240f48",
                "policy_version": 1,
                "policy_name": "policy name",
                "resolution_date": "2021-08-24T07:44:21.608Z",
                "resolved_by": "api",
                "severity": "Low",
                "state": "closed",
                "status": "Closed-Business Justified",
                "tenant": "xsoartest",
                "updated_at": "2021-08-24T07:44:21.608Z"
            },
            {
                "app_id": "acf49b2389c09f26ad0ccd2b1a603328",
                "app_name": "Box 1",
                "app_type": "box",
                "asset_cloud_uri": "https://www.box.com/files/0/f/114948778953/1/f_675197556380",
                "asset_id": "61099dbe6b544e38fa3cc9b8",
                "asset_name": "SP0605 copy 2.java",
                "asset_owner_email": "xsoartest@cirrotester.com",
                "asset_owner_id": "22FD054D362DC548A9C22F25782E1DAEED03C12F3898CD0F2E2A1B4CF728D04BD644B3CC010FDAC3D10EC0D408F4F79AC147E3D56415D1052BCFCD899A8E249F",
                "asset_owner_name": "Xsoar test",
                "asset_page_uri": "https://xsoartest.staging.cirrotester.com/cloud_assets/61099dbe6b544e38fa3cc9b8",
                "asset_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "category": "business_justified",
                "cloud_id": "675197556380",
                "collaborators": [],
                "created_at": "2021-08-03T20:25:12.000Z",
                "data_patterns": [],
                "exposure_level": "internal",
                "exposure_type": 8,
                "group_ids": [],
                "incident_id": 1,
                "policy_id": "6109a5d0e64152534b240f48",
                "policy_page_uri": "https://xsoartest.staging.cirrotester.com/data_policies/6109a5d0e64152534b240f48",
                "policy_version": 1,
                "resolution_date": "2021-08-24T08:19:57.429Z",
                "resolved_by": "api",
                "severity": "Low",
                "status": "Closed-Business Justified",
                "tenant": "xsoartest",
                "updated_at": "2021-08-24T08:19:57.429Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Incident Id|App Id|App Name|Asset Name|Exposure Level|Severity|Category|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|
>| 4 | acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | SP0605 copy 6.java | internal | Low | business_justified | 2021-08-03T20:25:15.417Z | 2021-08-24T07:44:21.608Z |
>| 1 | acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | SP0605 copy 2.java | internal | Low | business_justified | 2021-08-03T20:25:12.000Z | 2021-08-24T08:19:57.429Z |
>| 5 | acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | SP0605 copy 7.java | internal | Low | aperture | 2021-08-03T20:25:16.842Z | 2021-08-24T17:08:51.022Z |
>| 8 | acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | ml_file.java | internal | Low | aperture | 2021-08-03T20:25:17.043Z | 2021-08-24T17:10:37.433Z |
>| 3 | acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | SP0605 copy 5.java | internal | Low | misidentified | 2021-08-03T20:25:13.770Z | 2021-08-25T14:29:42.288Z |


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


#### Command Example
```!saas-security-incident-get-by-id id=4```

#### Context Example
```json
{
    "SaasSecurity": {
        "Incident": {
            "app_id": "acf49b2389c09f26ad0ccd2b1a603328",
            "app_name": "Box 1",
            "app_type": "box",
            "asset_cloud_uri": "https://www.box.com/files/0/f/114948778953/1/f_675197457403",
            "asset_id": "61099dc26b544e38fa3ce06d",
            "asset_name": "SP0605 copy 6.java",
            "asset_owner_email": "xsoartest@cirrotester.com",
            "asset_owner_id": "22FD054D362DC548A9C22F25782E1DAEED03C12F3898CD0F2E2A1B4CF728D04BD644B3CC010FDAC3D10EC0D408F4F79AC147E3D56415D1052BCFCD899A8E249F",
            "asset_owner_name": "Xsoar test",
            "asset_page_uri": "https://xsoartest.staging.cirrotester.com/cloud_assets/61099dc26b544e38fa3ce06d",
            "asset_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "category": "business_justified",
            "cloud_id": "675197457403",
            "collaborators": [],
            "created_at": "2021-08-03T20:25:15.417Z",
            "data_patterns": [],
            "exposure_level": "internal",
            "exposure_type": 8,
            "group_ids": [],
            "incident_id": 4,
            "policy_id": "6109a5d0e64152534b240f48",
            "policy_page_uri": "https://xsoartest.staging.cirrotester.com/data_policies/6109a5d0e64152534b240f48",
            "policy_version": 1,
            "resolution_date": "2021-08-26T07:04:14.598Z",
            "resolved_by": "api",
            "severity": "Low",
            "state": "closed",
            "tenant": "xsoartest",
            "updated_at": "2021-08-26T07:04:14.598Z"
        }
    }
}
```

#### Human Readable Output

>### Incident 4 details
>|Incident Id|App Id|App Name|Asset Name|Exposure Level|Severity|State|Category|Created At|Updated At|
>|---|---|---|---|---|---|---|---|---|---|
>| 4 | acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | SP0605 copy 6.java | internal | 1.0 | closed | business_justified | 2021-08-03T20:25:15.417Z | 2021-08-26T07:04:14.598Z |



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
| SaasSecurity.IncidentState.incident_id | String | The incident ID. |
| SaasSecurity.IncidentState.state | String | The incident state \(open/closed\). | 
| SaasSecurity.IncidentState.category | String | The incident category. | 
| SaasSecurity.IncidentState.resolved_by | String | The name of the user who resolved the incident. | 
| SaasSecurity.IncidentState.resolution_date | Date | The date when the incident was resolved. |


#### Command Example
```!saas-security-incident-state-update category="Business Justified" id=4```

#### Context Example
```json
{
    "SaasSecurity": {
        "IncidentState": {
            "category": "business_justified",
            "incident_id": "4",
            "resolution_date": "2021-08-26T07:04:14.598Z",
            "resolved_by": "api",
            "state": "closed"
        }
    }
}
```

#### Human Readable Output

>### Incident 4 status details
>|Category|Incident Id|Resolution Date|Resolved By|State|
>|---|---|---|---|---|
>| business_justified | 4 | 2021-08-26T07:04:14.598Z | api | closed |


### saas-security-get-apps
***
Returns the Application ID, Name, and Type for all applications.


#### Base Command

`saas-security-get-apps`
#### Input

No inputs.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.App.app_name | String | The application name. | 
| SaasSecurity.App.app_id | String | The application ID. | 
| SaasSecurity.App.app_type | String | The application type. |


#### Command Example
```!saas-security-get-apps```

#### Context Example
```json
{
    "SaasSecurity": {
        "App": [
            {
                "app_id": "acf49b2389c09f26ad0ccd2b1a603328",
                "app_name": "Box 1",
                "app_type": "box"
            },
            {
                "app_id": "2642aaa03dc6fc44496bdfffe5e1bc74",
                "app_name": "Office 365 1",
                "app_type": "office365"
            }
        ]
    }
}
```

#### Human Readable Output

>### Apps Info
>|App Id|App Name|App Type|
>|---|---|---|
>| acf49b2389c09f26ad0ccd2b1a603328 | Box 1 | box |
>| 2642aaa03dc6fc44496bdfffe5e1bc74 | Office 365 1 | office365 |


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
| SaasSecurity.Remediation.asset_id | String | The asset ID. |
| SaasSecurity.Remediation.remediation_type | String | The remediation type. | 
| SaasSecurity.Remediation.status | String | The remediation action status. |


#### Command Example
```!saas-security-asset-remediate asset_id=61099dc46b544e38fa3ce89a remediation_type=Quarantine```

#### Context Example
```json
{
    "SaasSecurity": {
        "Remediation": {
            "asset_id": "61099dc46b544e38fa3ce89a",
            "remediation_type": "system_quarantine",
            "status": "pending"
        }
    }
}
```

#### Human Readable Output

>### Remediation details for asset: 61099dc46b544e38fa3ce89a
>|Asset Id|Remediation Type|Status|
>|---|---|---|
>| 61099dc46b544e38fa3ce89a | system_quarantine | pending |


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


#### Command Example
```!saas-security-remediation-status-get asset_id=61099dc46b544e38fa3ce89a remediation_type=Quarantine```
#### Context Example
```json
{
    "SaasSecurity": {
        "Remediation": {
            "action_date": "2021-08-25T21:18:37.148+0000",
            "action_taker": "api",
            "asset_id": "61099dc46b544e38fa3ce89a",
            "asset_name": "SP0605 copy.java",
            "remediation_type": "system_quarantine",
            "status": "success"
        }
    }
}
```

#### Human Readable Output

>### Asset 61099dc46b544e38fa3ce89a remediation details
>|Action Date|Action Taker|Asset Id|Asset Name|Remediation Type|Status|
>|---|---|---|---|---|---|
>| 2021-08-25T21:18:37.148+0000 | api | 61099dc46b544e38fa3ce89a | SP0605 copy.java | system_quarantine | success |
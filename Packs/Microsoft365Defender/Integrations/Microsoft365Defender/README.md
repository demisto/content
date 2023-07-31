Microsoft 365 Defender is a unified pre- and post-breach enterprise defense suite that natively coordinates detection,
prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated
protection against sophisticated attacks.

## Authentication Using the Device Code Flow
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Microsoft 365 Defender with Cortex XSOAR.

To connect to the Microsoft 365 Defender:
1. Fill in the required parameters.
2. Run the ***!microsoft-365-defender-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-365-defender-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

*Note: In case of a password change, the `microsoft-365-defender-auth-reset` command should be executed followed by the authentication process described above.*
### Cortex XSOAR App

In order to use the Cortex XSOAR application, use the default application ID.
```9093c354-630a-47f1-b087-6768eb9427e6```

### Self-Deployed Application - Device Code Flow

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. For more details, follow [Self Deployed Application - Device Code Flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow).

#### Required Permissions
The required API permissions are for the ***Microsoft Threat Protection*** app.
 * offline_access - Delegate
 * Incident.ReadWrite.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)
 * AdvancedHunting.Read.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)

## Self-Deployed Application - Client Credentials Flow

Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the instance configuration, select the ***client-credentials*** checkbox.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.

#### Required Permissions
 * AdvancedHunting.Read.All - Application
 * Incident.ReadWrite.All - Application

## Configure Microsoft 365 Defender on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft 365 Defender.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID or Client ID | The API key to use to connect. | False |
    | Endpoint URI | The United States: api-us.security.microsoft.com<br/>Europe: api-eu.security.microsoft.com<br/>The United Kingdom: api-uk.security.microsoft.co | True |
    | Use Client Credentials Authorization Flow | Use a self-deployed Azure application and authenticate using the Client Credentials flow. | False |
    | Token or Tenant ID (for Client Credentials mode) |  | False |
    | Password |  | False |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates & secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Fetch incidents timeout | The time limit in seconds for fetch incidents to run. Leave this empty to cancel the timeout limit. | False |
    | Number of incidents for each fetch. | Due to API limitations, the maximum is 100. | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Run the !microsoft-365-defender-auth-test command to validate the authentication process.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### microsoft-365-defender-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results. (for device-code mode)


#### Base Command

`microsoft-365-defender-auth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!microsoft-365-defender-auth-start```

#### Human Readable Output


>###Authorization instructions
>1. To sign in, use a web browser to open the page {URL}
>and enter the code {code} to authenticate.
>2. Run the !microsoft-365-defender-auth-complete command in the War Room.


### microsoft-365-defender-auth-complete

***
Run this command to complete the authorization process. Should be used after running the microsoft-365-defender-auth-start command. (for device-code mode)


#### Base Command

`microsoft-365-defender-auth-complete`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!microsoft-365-defender-auth-complete```

#### Human Readable Output

>✅ Authorization completed successfully.


### microsoft-365-defender-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`microsoft-365-defender-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!microsoft-365-defender-auth-reset```

#### Human Readable Output


>Authorization was reset successfully. 
>You can now run !microsoft-365-defender-auth-start and
>!microsoft-365-defender-auth-complete.



### microsoft-365-defender-auth-test
***
Tests the connectivity to the Microsoft 365 Defender.


#### Base Command

`microsoft-365-defender-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-365-defender-auth-test```

#### Human Readable Output
>✅ Success!


### microsoft-365-defender-incidents-list
***
Get the most recent incidents.


#### Base Command

`microsoft-365-defender-incidents-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Categorize incidents (as Active, Resolved, or Redirected). Possible values are: Active, Resolved, Redirected. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| limit | Number of incidents in the list. Maximum is 100. Default is 100. | Optional | 
| offset | Number of entries to skip. | Optional | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Incident.incidentId | Number | Incident's ID. | 
| Microsoft365Defender.Incident.redirectIncidentId | Unknown | Only populated in case an incident is grouped together with another incident, as part of the incident processing logic. | 
| Microsoft365Defender.Incident.incidentName | String | The name of the incident. | 
| Microsoft365Defender.Incident.createdTime | Date | The date and time \(in UTC\) the incident was created. | 
| Microsoft365Defender.Incident.lastUpdateTime | Date | The date and time \(in UTC\) the incident was last updated. | 
| Microsoft365Defender.Incident.assignedTo | String | Owner of the incident. | 
| Microsoft365Defender.Incident.classification | String | Specification of the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | 
| Microsoft365Defender.Incident.determination | String | The determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | 
| Microsoft365Defender.Incident.status | String | The current status of the incident. Possible values are: Active, Resolved, and Redirected. | 
| Microsoft365Defender.Incident.severity | String | Severity of the incident. Possible values are: UnSpecified, Informational, Low, Medium, and High. | 
| Microsoft365Defender.Incident.alerts | Unknown | List of alerts relevant for the incidents. | 


#### Command Example
```!ms-365-defender-incidents-list status=Active limit=10 assigned_to=user```

#### Human Readable Output
>### Incidents:
>|Incident name|Tags|Severity|Incident ID|Categories|Impacted entities|Active alerts|Service sources|Detection sources|First activity|Last activity|Status|Assigned to|Classification|Device groups|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Automated investigation started manually on one endpoint | tag1, tag2 | Informational | 263 | SuspiciousActivity | user | 5 / 12 | MicrosoftDefenderForEndpoint | AutomatedInvestigation | 2021-03-22T12:34:31.8123759Z | 2021-03-22T12:59:07.526847Z | Active | email| Unknown | computer |
>| Impossible travel activity involving one user |  | Medium | 264 | InitialAccess | user | 1 / 1 | MicrosoftCloudAppSecurity | MCAS | 2021-04-05T06:56:06.833Z | 2021-04-05T15:34:25.736Z | Resolved | email | Unknown |  |



### microsoft-365-defender-incident-get
***
Get incident with the given ID.


#### Base Command

`microsoft-365-defender-incident-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident's ID. | Required | 
| timeout | The time limit in seconds for the http request to run. Default value is 30| Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Incident.incidentId | Number | Incident's ID. | 
| Microsoft365Defender.Incident.redirectIncidentId | Unknown | Only populated in case an incident is grouped together with another incident, as part of the incident processing logic. | 
| Microsoft365Defender.Incident.incidentName | String | The name of the incident. | 
| Microsoft365Defender.Incident.createdTime | Date | The date and time \(in UTC\) the incident was created. | 
| Microsoft365Defender.Incident.lastUpdateTime | Date | The date and time \(in UTC\) the incident was last updated. | 
| Microsoft365Defender.Incident.assignedTo | String | Owner of the incident. | 
| Microsoft365Defender.Incident.classification | String | Specification of the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | 
| Microsoft365Defender.Incident.determination | String | The determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | 
| Microsoft365Defender.Incident.status | String | The current status of the incident. Possible values are: Active, Resolved, and Redirected. | 
| Microsoft365Defender.Incident.severity | String | Severity of the incident. Possible values are: UnSpecified, Informational, Low, Medium, and High. | 
| Microsoft365Defender.Incident.alerts | Unknown | List of alerts relevant for the incidents. | 



### microsoft-365-defender-incident-update
***
Update the incident with the given ID.


#### Base Command

`microsoft-365-defender-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Categorize incidents (as Active, Resolved, or Redirected). Possible values are: Active, Resolved, Redirected. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| id | Incident's ID. | Required | 
| classification | The specification for the incident. Possible values are: Unknown, FalsePositive, TruePositive. | Optional | 
| determination | Determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other. | Optional | 
| tags | A comma-separated list of custom tags associated with an incident. For example: tag1,tag2,tag3. | Optional | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Incident.incidentId | Number | Incident's ID. | 
| Microsoft365Defender.Incident.redirectIncidentId | Unknown | Only populated in case an incident is grouped together with another incident, as part of the incident processing logic. | 
| Microsoft365Defender.Incident.incidentName | String | The name of the incident. | 
| Microsoft365Defender.Incident.createdTime | Date | The date and time \(in UTC\) the incident was created. | 
| Microsoft365Defender.Incident.lastUpdateTime | Date | The date and time \(in UTC\) the incident was last updated. | 
| Microsoft365Defender.Incident.assignedTo | String | Owner of the incident. | 
| Microsoft365Defender.Incident.classification | String | Specification of the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | 
| Microsoft365Defender.Incident.determination | String | The determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | 
| Microsoft365Defender.Incident.severity | String | Severity of the incident. Possible values are: UnSpecified, Informational, Low, Medium, and High. | 
| Microsoft365Defender.Incident.status | String | The current status of the incident. Possible values are: Active, Resolved, and Redirected. | 
| Microsoft365Defender.Incident.alerts | Unknown | List of alerts relevant for the incidents. | 


#### Command Example
```!microsoft-365-defender-incident-update id=264 tags=test5```

#### Human Readable Output
>### Updated incident No. 263:
>|Incident name|Tags|Severity|Incident ID|Categories|Impacted entities|Active alerts|Service sources|Detection sources|First activity|Last activity|Status|Assigned to|Classification|Device groups|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Automated investigation started manually on one endpoint | test5 | Informational | 263 | SuspiciousActivity |  | 10 / 12 | MicrosoftDefenderForEndpoint | AutomatedInvestigation | 2021-03-22T12:34:31.8123759Z | 2021-03-22T12:59:07.526847Z | Active | User | Unknown | computer |



### microsoft-365-defender-advanced-hunting
***
Advanced hunting is a threat-hunting tool that uses specially constructed queries to examine the past 30 days of event data in Microsoft 365 Defender.
Details on how to write queries you can find [here](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide).

#### Base Command

`microsoft-365-defender-advanced-hunting`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Advanced hunting query. | Required | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 
| limit | Number of entries.  Enter -1 for unlimited query. Default is 50. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Hunt.query | String | The query used, also acted as a key. | 
| Microsoft365Defender.Hunt.results. | Unknown | The results of the query. | 


#### Command Example
```!microsoft-365-defender-advanced-hunting query=AlertInfo```

#### Human Readable Output
>###  Result of query: AlertInfo:
>|Timestamp|AlertId|Title|Category|Severity|ServiceSource|DetectionSource|AttackTechniques|
>|---|---|---|---|---|---|---|---|
>| 2021-04-25T10:11:00Z | alertId | eDiscovery search started or exported | InitialAccess | Medium | Microsoft Defender for Office 365 | Microsoft Defender for Office 365 |  |

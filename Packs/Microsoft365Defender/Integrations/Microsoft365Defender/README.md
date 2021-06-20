Microsoft 365 Defender is a unified pre- and post-breach enterprise defense suite that natively coordinates detection,
prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated
protection against sophisticated attacks.

## Configure Microsoft365Defender on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft365Defender.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
       | --- | --- | --- |
   | APP ID | The API Key to use for connection | True |
   | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
   | Fetch incidents timeout | The time limit in seconds for fetch incidents to run. Leave this empty to cancel the timeout limit. | False |
   | Number of incidents for each fetch. | Due to API limitations, the maximum is 100 | False |
   | Trust any certificate (not secure) |  | False |
   | Use system proxy settings |  | False |
   | Incident type |  | False |
   | Fetch incidents |  | False |
   
4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### microsoft-365-defender-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

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
Run this command to complete the authorization process. Should be used after running the
microsoft-365-defender-auth-start command.

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
Run this command if you need to rerun the authentication process.

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
Tests the connectivity to the Azure SQL Management.


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
| status | Categorize incidents (as Active,  Resolved or Redirected). Possible values are: Active, Resolved, Redirected. | Optional | 
| assigned_to | Owner of the incident.	. | Optional | 
| limit | Number of incidents in the list (Max 100). Default is 100. | Optional | 
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


#### Command Example
```!ms-365-defender-incidents-list status=Active limit=10 assigned_to=user```

#### Human Readable Output
>### Incidents:
>|Incident name|Tags|Severity|Incident ID|Categories|Impacted entities|Active alerts|Service sources|Detection sources|First activity|Last activity|Status|Assigned to|Classification|Device groups|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Automated investigation started manually on one endpoint | tag1, tag2 | Informational | 263 | SuspiciousActivity | user | 5 / 12 | MicrosoftDefenderForEndpoint | AutomatedInvestigation | 2021-03-22T12:34:31.8123759Z | 2021-03-22T12:59:07.526847Z | Active | email| Unknown | computer |
>| Impossible travel activity involving one user |  | Medium | 264 | InitialAccess | user | 1 / 1 | MicrosoftCloudAppSecurity | MCAS | 2021-04-05T06:56:06.833Z | 2021-04-05T15:34:25.736Z | Resolved | email | Unknown |  |



### microsoft-365-defender-incident-update
***
Update incident with the given ID.


#### Base Command

`microsoft-365-defender-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Categorize incidents. Possible values are: Active, Resolved, and Redirected. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| id | Incident's ID. | Required | 
| classification | The specification for the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | Optional | 
| determination | Determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | Optional | 
| tags | A comma-separated list of custom tags associated with an incident. For example: tag1,tag2,tag3. | Optional | 
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
| timeout | The time limit in seconds for the http request to run. Default value is 30| Optional |

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

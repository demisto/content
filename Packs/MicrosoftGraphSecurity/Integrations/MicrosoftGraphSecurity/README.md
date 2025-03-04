Unified gateway to security insights - all from a unified Microsoft Graph Security API.
This integration was integrated and tested with version 1.0 of Microsoft Graph.

## Authentication

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication)  
*Note*: [The eDiscovery](#ediscovery-commands) and [Threat Assessment](#threat-assessment-commands) commands are only supported when using the `Authorization Code flow` with `Delegated (work or school account)` permission type.

When using the `Authorization Code flow` for this integration, the user needs to log in as an administrator or a user with administrative privileges (`Security Reader` or `Security Administrator`) after running the **msg-generate-login-url** command and the login window appears. For more information, see [here](https://learn.microsoft.com/en-us/graph/security-authorization).

## Important Notes:
- Due to API limitations, the ***message-search-alerts*** command does not filter Office 365 provider alerts.\
For more information, see: https://github.com/microsoftgraph/security-api-solutions/issues/56.
- When using Alerts V2, only the following properties are supported as filters for the *Fetched incidents filter* parameter and *filter* arguments: assignedTo, classification, determination, createdDateTime, lastUpdateDateTime, severity, serviceSource and status. See [Microsoft optional query parameters](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0&tabs=http#optional-query-parameters).
- As of July 2023, Microsoft Graph API does **not support** a solution to search for and delete emails. To do this, refer to the [Security & Compliance](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance) integration. 
- When using Threat Assessment, only the following properties are supported as filters for *filter* parameter: expectedAssessment, ContentType ,status and requestSource.
- When using Threat Assessment, for information protection, The following limits apply to any request on /informationProtection:
    - For email, the resource is a unique network message ID/recipient pair. For example, submitting an email with the same message ID sent to the same person multiple times in a 15 minutes period will trigger the limit per resource limits listed in the following table. However, you can submit up to 150 unique emails every 15 minutes (tenant limit).
     
  | **Operation** | **Limit per tenant** | **Limit per resource (email, URL, file)** |
    | --- | --- | --- |
    | POST | 150 requests per 15 minutes and 10000 requests per 24 hours. | 1 request per 15 minutes and 3 requests per 24 hours. |


### Required Permissions

**Legacy Alerts**:

1. SecurityEvents.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`)
2. SecurityEvents.ReadWrite.All - Application (required for updating alerts with the command: `msg-update-alert`)
3. User.Read.All - Application (Only required if using the deprecated commands: `msg-get-user` and `msg-get-users`)
4. SecurityIncident.Read.All - Delegated or Application (required for the command `msg-list-security-incident`)
5. SecurityIncident.ReadWrite.All - Delegated or Application (required for the command `msg-update-security-incident`)
6. ThreatHunting.Read.All - Delegated or Application (required for the command `msg-advanced-hunting`)

**Alerts v2**:

1. SecurityAlert.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`)
2. SecurityAlert.ReadWrite.All - Application (required for updating alerts with the commands: `msg-update-alert` and `msg-create-alert-comment`)

**eDiscovery**:

1. eDiscovery.Read.All - Delegated (Required for the `list-ediscovery` commands)
2. eDiscovery.ReadWrite.All - Delegated (Required for the `create/update-ediscovery` commands)

**Threat Assessment**:

1. Mail.Read.Shared - Delegated
2. ThreatAssessment.ReadWrite.All - Delegated
3. User.Read.All - Delegated

## Configure Microsoft Graph Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Security.
3. Click **Add instance** to create and configure a new integration instance.

     | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Host URL | The host URL. | True |
    | MS graph security version | MS graph security API version. | True |
    | Application ID or Client ID | The app registration ID. | True |
    | Token or Tenant ID | The tenant ID. | True |
    | Key or Client Secret | The app registration secret. | False |
    | Authorization code | Get the authorization code from steps 3-5 in the self deployed authorization process.| False |
    | Application redirect URI (for self-deployed mode) | The app registration redirect URI. | False |
    | Certificate Thumbprint | Used for certificate authentication, as it appears in the "Certificates & secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | Trust any certificate (not secure) | Whether to trust any certificate. If True, not secure. | False |
    | Use system proxy settings | Whether to use system proxy settings. | False |
    | Use a self-deployed Azure application | Whether to use a self-deployed application. | False |
    | Fetch incidents | Whether to fetch incidents. | False |
    | Incident type | The incident type to apply. | False |
    | First fetch timestamp (`<number> <time unit>`, e.g., 12 hours, 7 days) | `<number> <time unit>`, for example 1 hour, 30 minutes. | False |
    | Max incidents per fetch | The maximum number of incidents to fetch per iteration. | False |
    | Fetch incidents of the given providers only. | Relevant only for Legacy Alerts. Multiple providers can be inserted separated by a comma, for example "\{first_provider\},\{second_provider\}". If empty, incidents of all providers will be fetched. | False |
    | Fetch incidents of the given service sources only. | Relevant only for Alerts v2. Multiple serviceSource can be inserted separated by a comma, for example "microsoftDefenderForEndpoint,microsoftCloudAppSecurity",. If empty, incidents of all providers will be fetched. | False |
    | Fetched incidents filter | Use this field to filter fetched incidents according to any of the alert properties. Overrides the providers list, if given. Filter should be in the format "\{property\} eq '\{property-value\}'". Multiple filters can be applied separated with " and ", for example "createdDateTime eq YYYY-MM-DD and severity eq 'high'". | False |
    | Microsoft 365 Defender context | Check to save the hunt query result to also in the Microsoft 365 Defender context path. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msg-auth-test

***
Tests connectivity to Microsoft Graph Security.

#### Base Command

`msg-auth-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| permission_type | Which permissions the integration should have. Possible values are: ediscovery, alerts, alerts, ediscovery. Default is ediscovery. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-auth-test permission_type=ediscovery```

#### Human Readable Output

>Authentication was successful.

### msg-search-alerts

***
List alerts (security issues) within a customer's tenant that Microsoft or partner security solutions have identified.

#### Base Command

`msg-search-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_modified | When the alert was last modified in the following string format - YYYY-MM-DD. Possible values are: Last24Hours, Last48Hours, LastWeek. | Optional | 
| severity | Alert severity - set by vendor/provider. Possible values are: unknown, informational, low, medium, high. | Optional | 
| category | Category of the alert, e.g., credentialTheft, ransomware (Categories can be added or removed by vendors.). | Optional | 
| time_from | The start time (creation time of alert) for the search in the following string format - YYYY-MM-DD. | Optional | 
| time_to | The end time (creation time of alert) for the search in the following string format -  YYYY-MM-DD. | Optional | 
| filter | Use this field to filter on any of the alert properties in the format "{property} eq '{property-value}'", e.g. "category eq 'ransomware'". | Optional | 
| classification | Relevant only for Alerts v2. Use this field to filter by alert's classification. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| service_source | Relevant only for Alerts v2. Use this field to filter the alerts by the service or product that created this alert. Possible values are: microsoftDefenderForEndpoint, microsoftDefenderForIdentity, microsoftDefenderForOffice365, microsoft365Defender, microsoftAppGovernance, microsoftDefenderForCloudApps. | Optional | 
| status | Relevant only for Alerts v2. Use this field to filter by alert's status. Possible values are: unknown, new, inProgress, resolved. | Optional | 
| page | Page number to return, zero indexed. The maximum number of alerts that can be skipped for Legacy Alerts is 500 (i.e., page * page_size must be &lt;= 500). | Optional | 
| page_size | Number of results in a page. Default is 50, the limit for Legacy Alerts is 1000, the limit for Alerts v2 is 2000. When using Legacy Alerts, the response will provide <page_size> results for each provider. | Optional | 
| limit | Number of total results to return. Default is 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Title | string | Alert title. | 
| MsGraph.Alert.Category | string | Alert category. | 
| MsGraph.Alert.Severity | string | Alert severity. | 
| MsGraph.Alert.CreatedDate | date | Alert created date. | 
| MsGraph.Alert.EventDate | date | Relevant only for Legacy Alerts. Alert event time. | 
| MsGraph.Alert.Status | string | Alert status. | 
| MsGraph.Alert.Vendor | string | Relevant only for Legacy Alerts. Alert vendor. | 
| MsGraph.Alert.MalwareStates | string | Relevant only for Legacy Alerts. Alert malware states. |
| MsGraph.Alert.Provider | string | Relevant only for Legacy Alerts. Alert provider. | 
| MsGraph.Alert.ActorDisplayName | Unknown | Relevant only for Alerts v2. Alert actor name. | 
| MsGraph.Alert.AlertWebUrl | String | Relevant only for Alerts v2. Alert web URL. | 
| MsGraph.Alert.AssignedTo | Unknown | Relevant only for Alerts v2. Alert assignee. | 
| MsGraph.Alert.Classification | Unknown | Relevant only for Alerts v2. Alert classification. | 
| MsGraph.Alert.Description | String | Relevant only for Alerts v2. Alert description. | 
| MsGraph.Alert.DetectionSource | String | Relevant only for Alerts v2. Alert detection source. | 
| MsGraph.Alert.DetectorId | String | Relevant only for Alerts v2. Alert detector ID. | 
| MsGraph.Alert.Determination | Unknown | Relevant only for Alerts v2. Alert determination. | 
| MsGraph.Alert.Evidence.@odata.Type | String | Relevant only for Alerts v2. Alert evidence. | 
| MsGraph.Alert.Evidence.AzureAdDeviceId | String | Relevant only for Alerts v2. Evidence Azure device ID. | 
| MsGraph.Alert.Evidence.CreatedDate | Date | Relevant only for Alerts v2. Evidence creation time. | 
| MsGraph.Alert.Evidence.DefenderAvStatus | String | Relevant only for Alerts v2. Evidence Defender AV status. | 
| MsGraph.Alert.Evidence.DeviceDnsName | String | Relevant only for Alerts v2. Evidence device DNS name. | 
| MsGraph.Alert.Evidence.FirstSeenDateTime | Date | Relevant only for Alerts v2. Evidence first seen time. | 
| MsGraph.Alert.Evidence.HealthStatus | String | Relevant only for Alerts v2. Evidence health status. | 
| MsGraph.Alert.Evidence.MdeDeviceId | String | Relevant only for Alerts v2. Evidence MDE device ID. | 
| MsGraph.Alert.Evidence.OnboardingStatus | String | Relevant only for Alerts v2. Evidence onboarding status. | 
| MsGraph.Alert.Evidence.OsBuild | Number | Relevant only for Alerts v2. Evidence OS build. | 
| MsGraph.Alert.Evidence.OsPlatform | String | Relevant only for Alerts v2. Evidence OS platform. | 
| MsGraph.Alert.Evidence.RbacGroupId | Number | Relevant only for Alerts v2. Evidence RBAC group ID. | 
| MsGraph.Alert.Evidence.RbacGroupName | String | Relevant only for Alerts v2. Evidence RBAC group name. | 
| MsGraph.Alert.Evidence.RemediationStatus | String | Relevant only for Alerts v2. Evidence remediation status. | 
| MsGraph.Alert.Evidence.RemediationStatusDetails | Unknown | Relevant only for Alerts v2. Evidence remediation status details. | 
| MsGraph.Alert.Evidence.RiskScore | String | Relevant only for Alerts v2. Evidence risk score. | 
| MsGraph.Alert.Evidence.Tags | String | Relevant only for Alerts v2. Evidence tags. | 
| MsGraph.Alert.Evidence.Verdict | String | Relevant only for Alerts v2. Evidence verdict. | 
| MsGraph.Alert.Evidence.Version | String | Relevant only for Alerts v2. Evidence version. | 
| MsGraph.Alert.Evidence.VmMetadata | Unknown | Relevant only for Alerts v2. Evidence VM metadata. | 
| MsGraph.Alert.FirstActivityDateTime | Date | Relevant only for Alerts v2. Evidence first activity time. | 
| MsGraph.Alert.IncidentId | String | Relevant only for Alerts v2. Alert incident ID. | 
| MsGraph.Alert.IncidentWebUrl | String | Relevant only for Alerts v2. Alert incident URL. | 
| MsGraph.Alert.LastActivityDateTime | Date | Relevant only for Alerts v2. Alert last activity time. | 
| MsGraph.Alert.LastUpdateDateTime | Date | Relevant only for Alerts v2. Alert last update time. | 
| MsGraph.Alert.ProviderAlertId | String | Relevant only for Alerts v2. Alert provider ID. | 
| MsGraph.Alert.RecommendedActions | String | Relevant only for Alerts v2. Alert recommended action. | 
| MsGraph.Alert.ResolvedDateTime | Date | Relevant only for Alerts v2. Alert closing time. | 
| MsGraph.Alert.ServiceSource | String | Relevant only for Alerts v2. Alert service source. | 
| MsGraph.Alert.TenantId | String | Relevant only for Alerts v2. Alert tenant ID. | 
| MsGraph.Alert.ThreatDisplayName | Unknown | Relevant only for Alerts v2. Alert threat display name. | 
| MsGraph.Alert.ThreatFamilyName | Unknown | Relevant only for Alerts v2. Alert threat family name. | 

#### Human Readable Output

>## Using Legacy Alerts:

>### Microsoft Security Graph Alerts

>|ID|Vendor|Provider|Title|Category|Severity|CreatedDate|EventDate|Status|
>|---|---|---|---|---|---|---|---|---|
>| id | Microsoft | IPC | Atypical travel | ImpossibleTravel | high | 2023-03-30T20:45:14.259Z | 2023-03-30T15:07:21.4705248Z | newAlert |

>## Using Alerts v2:

>### Microsoft Security Graph Alerts

>|ID|IncidentId|Status|Severity|DetectionSource|ServiceSource|Title|Category|CreatedDate|LastUpdateDateTime|
>|---|---|---|---|---|---|---|---|---|---|
>| id | <incident_id> | new | medium | customTi | microsoftDefenderForEndpoint | test alert | None | 2022-10-03T03:39:21.7562976Z | 2023-04-17T11:01:31.7566667Z |

### msg-get-alert-details

***
Get details for a specific alert.

#### Base Command

`msg-get-alert-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID - Provider-generated GUID/unique identifier. | Required | 
| fields_to_include | Relevant only for Legacy Alerts. Fields to fetch for a specified alert apart from the basic properties, given as comma separated values, e.g., NetworkConnections,Processes. The possible values are: All, NetworkConnections, Processes, RegistryKeys, UserStates, HostStates, FileStates, CloudAppStates, MalwareStates, CustomerComments, Triggers, VendorInformation, VulnerabilityStates. Default is All. | Optional |  

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Title | string | Alert title. | 
| MsGraph.Alert.Category | string | Alert category. | 
| MsGraph.Alert.Severity | string | Alert severity. | 
| MsGraph.Alert.CreatedDate | date | Relevant only for Legacy Alerts. Alert created date. | 
| MsGraph.Alert.EventDate | date | Relevant only for Legacy Alerts. Alert event time. | 
| MsGraph.Alert.Status | string | Alert status. | 
| MsGraph.Alert.Vendor | string | Relevant only for Legacy Alerts. Alert vendor. | 
| MsGraph.Alert.Provider | string | Relevant only for Legacy Alerts. Alert provider. | 
| MsGraph.Alert.@odata.Context | String | Relevant only for Alerts v2. Alert odata context. | 
| MsGraph.Alert.ActorDisplayName | Unknown | Relevant only for Alerts v2. Alert actor name. | 
| MsGraph.Alert.AlertWebUrl | String | Relevant only for Alerts v2. Alert web URL. | 
| MsGraph.Alert.AssignedTo | Unknown | Relevant only for Alerts v2. Alert assignee. | 
| MsGraph.Alert.Classification | Unknown | Relevant only for Alerts v2. Alert classification. | 
| MsGraph.Alert.Comments.Comment | String | Relevant only for Alerts v2. Alert comment. | 
| MsGraph.Alert.Comments.CreatedByDisplayName | String | Relevant only for Alerts v2. Alert comment creator name. | 
| MsGraph.Alert.Comments.CreatedDate | Date | Relevant only for Alerts v2. Alert comment creation time. | 
| MsGraph.Alert.CreatedDate | Date | Relevant only for Alerts v2. Alert creation time. | 
| MsGraph.Alert.Description | String | Relevant only for Alerts v2. Alert description. | 
| MsGraph.Alert.DetectionSource | String | Relevant only for Alerts v2. Alert detection source. | 
| MsGraph.Alert.DetectorId | String | Relevant only for Alerts v2. Alert detector ID. | 
| MsGraph.Alert.Determination | Unknown | Relevant only for Alerts v2. Alert determination. | 
| MsGraph.Alert.Evidence.@odata.Type | String | Relevant only for Alerts v2. Alert evidence. | 
| MsGraph.Alert.Evidence.CreatedDate | Date | Relevant only for Alerts v2. Evidence creation time. | 
| MsGraph.Alert.Evidence.DetectionStatus | Unknown | Relevant only for Alerts v2. Evidence detection status. | 
| MsGraph.Alert.Evidence.ImageFile.FileName | String | Relevant only for Alerts v2. Evidence image file name. | 
| MsGraph.Alert.Evidence.ImageFile.FilePath | String | Relevant only for Alerts v2. Evidence image file path. | 
| MsGraph.Alert.Evidence.ImageFile.FilePublisher | Unknown | Relevant only for Alerts v2. Evidence image file publisher. | 
| MsGraph.Alert.Evidence.ImageFile.FileSize | Unknown | Relevant only for Alerts v2. Evidence image file size. | 
| MsGraph.Alert.Evidence.ImageFile.Issuer | Unknown | Relevant only for Alerts v2. Evidence image file issuer. | 
| MsGraph.Alert.Evidence.ImageFile.Sha1 | String | Relevant only for Alerts v2. Evidence image file SHA1 hash. | 
| MsGraph.Alert.Evidence.ImageFile.Sha256 | String | Relevant only for Alerts v2. Evidence image file SHA256 hash. | 
| MsGraph.Alert.Evidence.ImageFile.Signer | Unknown | Relevant only for Alerts v2. Evidence image file signer. | 
| MsGraph.Alert.Evidence.MdeDeviceId | Unknown | Relevant only for Alerts v2. Evidence MDE device ID. | 
| MsGraph.Alert.Evidence.ParentProcessCreationDateTime | Date | Relevant only for Alerts v2. Evidence parent process creation time. | 
| MsGraph.Alert.Evidence.ParentProcessId | Number | Relevant only for Alerts v2. Evidence parent process process ID. | 
| MsGraph.Alert.Evidence.ParentProcessImageFile | Unknown | Relevant only for Alerts v2. Evidence parent process image file. | 
| MsGraph.Alert.Evidence.ProcessCommandLine | String | Relevant only for Alerts v2. Evidence process command line. | 
| MsGraph.Alert.Evidence.ProcessCreationDateTime | Date | Relevant only for Alerts v2.  Evidence process creation time. | 
| MsGraph.Alert.Evidence.ProcessId | Number | Relevant only for Alerts v2.  Evidence process ID. | 
| MsGraph.Alert.Evidence.RemediationStatus | String | Relevant only for Alerts v2. Evidence remediation status. | 
| MsGraph.Alert.Evidence.RemediationStatusDetails | Unknown | Relevant only for Alerts v2. Evidence remediation status details. | 
| MsGraph.Alert.Evidence.UserAccount.AccountName | String | Relevant only for Alerts v2. Evidence user account name. | 
| MsGraph.Alert.Evidence.UserAccount.AzureAdUserId | Unknown | Relevant only for Alerts v2. Evidence user account Azure AD user ID. | 
| MsGraph.Alert.Evidence.UserAccount.DisplayName | String | Relevant only for Alerts v2. Evidence user account display name. | 
| MsGraph.Alert.Evidence.UserAccount.DomainName | Unknown | Relevant only for Alerts v2. Evidence user account domain name. | 
| MsGraph.Alert.Evidence.UserAccount.UserPrincipalName | Unknown | Relevant only for Alerts v2. Evidence user account user principal name. | 
| MsGraph.Alert.Evidence.UserAccount.UserSid | String | Relevant only for Alerts v2. Evidence user account user SID. | 
| MsGraph.Alert.Evidence.Verdict | String | Relevant only for Alerts v2. Evidence verdict. | 
| MsGraph.Alert.Evidence.FileDetails.FileName | String | Relevant only for Alerts v2. Evidence file details file name. | 
| MsGraph.Alert.Evidence.FileDetails.FilePath | String | Relevant only for Alerts v2. Evidence file details file path. | 
| MsGraph.Alert.Evidence.FileDetails.FilePublisher | Unknown | Relevant only for Alerts v2. Evidence file details file publisher. | 
| MsGraph.Alert.Evidence.FileDetails.FileSize | Unknown | Relevant only for Alerts v2. Evidence file details file size. | 
| MsGraph.Alert.Evidence.FileDetails.Issuer | Unknown | Relevant only for Alerts v2. Evidence file details file issuer. | 
| MsGraph.Alert.Evidence.FileDetails.Sha1 | String | Relevant only for Alerts v2. Evidence file details SHA1 hash. | 
| MsGraph.Alert.Evidence.FileDetails.Sha256 | String | Relevant only for Alerts v2. Evidence file details SHA256 hash. | 
| MsGraph.Alert.Evidence.FileDetails.Signer | Unknown | Relevant only for Alerts v2. Evidence file details file signer. | 
| MsGraph.Alert.Evidence.CֹountryLetterCode | Unknown | Relevant only for Alerts v2. Evidence country letter code. | 
| MsGraph.Alert.Evidence.IpAddress | String | Relevant only for Alerts v2. Evidence IP address. | 
| MsGraph.Alert.Evidence.AzureAdDeviceId | Unknown | Relevant only for Alerts v2. Evidence Azure AD device ID. | 
| MsGraph.Alert.Evidence.DefenderAvStatus | String | Relevant only for Alerts v2. Evidence Defender AV status. | 
| MsGraph.Alert.Evidence.DeviceDnsName | String | Relevant only for Alerts v2. Evidence device DNS name. | 
| MsGraph.Alert.Evidence.FirstSeenDateTime | Date | Relevant only for Alerts v2. Evidence first seen time. | 
| MsGraph.Alert.Evidence.HealthStatus | String | Relevant only for Alerts v2. Evidence health status. | 
| MsGraph.Alert.Evidence.OnboardingStatus | String | Relevant only for Alerts v2. Evidence onboarding status. | 
| MsGraph.Alert.Evidence.OsBuild | Unknown | Relevant only for Alerts v2. Evidence OS build. | 
| MsGraph.Alert.Evidence.OsPlatform | String | Relevant only for Alerts v2. Evidence OS platform. | 
| MsGraph.Alert.Evidence.RbacGroupId | Number | Relevant only for Alerts v2. Evidence RBAC group ID. | 
| MsGraph.Alert.Evidence.RbacGroupName | String | Relevant only for Alerts v2. Evidence RBAC group name. | 
| MsGraph.Alert.Evidence.RiskScore | String | Relevant only for Alerts v2. Evidence risk score. | 
| MsGraph.Alert.Evidence.Version | String | Relevant only for Alerts v2. Evidence version. | 
| MsGraph.Alert.Evidence.VmMetadata | Unknown | Relevant only for Alerts v2. Evidence VM metadata. | 
| MsGraph.Alert.FirstActivityDateTime | Date | Relevant only for Alerts v2. Evidence first activity time. | 
| MsGraph.Alert.IncidentId | String | Relevant only for Alerts v2. Alert incident ID. | 
| MsGraph.Alert.IncidentWebUrl | String | Relevant only for Alerts v2. Alert incident URL. | 
| MsGraph.Alert.LastActivityDateTime | Date | Relevant only for Alerts v2. Alert last activity time. | 
| MsGraph.Alert.LastUpdateDateTime | Date | Relevant only for Alerts v2. Alert last update time. | 
| MsGraph.Alert.ProviderAlertId | String | Relevant only for Alerts v2. Alert provider ID. | 
| MsGraph.Alert.RecommendedActions | String | Relevant only for Alerts v2. Alert recommended action. | 
| MsGraph.Alert.ResolvedDateTime | Date | Relevant only for Alerts v2. Alert closing time. | 
| MsGraph.Alert.ServiceSource | String | Relevant only for Alerts v2. Alert service source. | 
| MsGraph.Alert.TenantId | String | Relevant only for Alerts v2. Alert tenant ID. | 
| MsGraph.Alert.ThreatDisplayName | Unknown | Relevant only for Alerts v2. Alert threat display name. | 
| MsGraph.Alert.ThreatFamilyName | Unknown | Relevant only for Alerts v2. Alert threat family name. | 

#### Human Readable Output

>## Using Legacy Alerts:

>### Microsoft Security Graph Alerts

>## Microsoft Security Graph Alert Details - <alert_id>

>### Basic Properties

>|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status|Title|
>|---|---|---|---|---|---|---|---|---|
>| <azure_tenant_id> | None | 2022-10-03T03:39:21.7562976Z | Created for test | 2022-09-26T05:01:02.839216Z | 2022-09-26T05:01:02.839216Z | medium | newAlert | test alert |

>### Customer Provided Comments for Alert

>- comment
>- comment

>### File Security States for Alert

>|FileHash|Name|Path|
>|---|---|---|
>| <file_hash> | crond | /usr/sbin |

>### Host Security States for Alert

>|Fqdn|OS|PrivateIPAddress|PublicIPAddress|RiskScore|
>|---|---|---|---|---|
>| `<fqdn>` | CentOS | <private_ip_address> | <public_ip_address> | medium |

>### User Security States for Alert

>|AccountName|EmailRole|
>|---|---|
>| root | unknown |

>### Vendor Information for Alert

>|Provider|SubProvider|Vendor|
>|---|---|---|
>| Microsoft Defender ATP | MicrosoftDefenderATP | Microsoft |

>## Using Alerts v2:

>### Microsoft Security Graph Alerts

>## Microsoft Security Graph Alert Details - <alert_id>

>|ID|IncidentId|Status|Severity|DetectionSource|ServiceSource|Title|Category|CreatedDate|LastUpdateDateTime|
>|---|---|---|---|---|---|---|---|---|---|
>| <alert_id> | <incident_id> | new | medium | customTi | microsoftDefenderForEndpoint | test alert | None | 2022-10-03T03:39:21.7562976Z | 2023-04-17T11:01:31.7566667Z |

### msg-update-alert

***
Update an editable alert property within any integrated solution to keep alert status and assignments in sync across solutions using its reference ID.

#### Base Command

`msg-update-alert`

#### Input

| **Argument Name**    | **Description**                                                                                                                                                                                                                                  | **Required** |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| alert_id             | The Alert ID. Provider-generated GUID/unique identifier.                                                                                                                                                                                         | Required     | 
| assigned_to          | Name of the analyst the alert is assigned to for triage, investigation, or remediation.                                                                                                                                                          | Optional     | 
| closed_date_time     | Relevant only for Legacy Alerts. Time the alert was closed in the string format MM/DD/YYYY.                                                                                                                                                      | Optional     | 
| comments             | Relevant only for Legacy Alerts. Analyst comments on the alert (for customer alert management).                                                                                                                                                  | Optional     | 
| feedback             | Relevant only for Legacy Alerts. Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive.                                                                                                       | Optional     | 
| status               | Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved, new.                                                                                                                                               | Optional     | 
| tags                 | Relevant only for Legacy Alerts. User-definable labels that can be applied to an alert and can serve as filter conditions, for example "HVA", "SAW).                                                                                             | Optional     | 
| vendor_information   | Relevant only for Legacy Alerts. Details about the security service vendor, for example Microsoft.                                                                                                                                               | Optional     | 
| provider_information | Relevant only for Legacy Alerts. Details about the security service vendor, for example Windows Defender ATP.                                                                                                                                    | Optional     | 
| classification       | Relevant only for Alerts v2. Use this field to update the alert's classification. Possible values are: unknown, truePositive, falsePositive, informationalExpectedActivity.                                                                      | Optional     | 
| determination        | Relevant only for Alerts v2. Use this field to update the alert's determination. Possible values are: unknown, malware, phishing, other, securityTesting, multiStagedAttack, maliciousUserActivity, lineOfBusinessApplication, unwantedSoftware. | Optional     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Status | string | Alert status, will appear only if changed. | 

#### Human Readable Output

>Alert <alert_id> has been successfully updated.

### msg-create-alert-comment

***
Relevant only for Alerts v2, create a comment for an existing alert.

#### Base Command

`msg-create-alert-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The Alert ID - Provider-generated GUID/unique identifier. | Required | 
| comment | The comment to add to each alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.AlertComment.ID | String | The alert ID that the comment was added to. | 
| MsGraph.AlertComment.Comments.Comment | String | The comment itself | 
| MsGraph.AlertComment.Comments.CreatedByDisplayName | String | The comment's creator display name | 
| MsGraph.AlertComment.Comments.CreatedDate | Date | The comment's creation time | 

#### Human Readable Output

>### Microsoft Security Graph Create Alert Comment - <alert_id>

>|comment|createdByDisplayName|createdDate|
>|---|---|---|
>| comment | Cortex XSOAR MS Graph Dev | 2023-04-17T10:57:18.5231438Z |
>| comment | Cortex XSOAR MS Graph Dev | 2023-04-17T11:01:31.7427859Z |
>| comment | Cortex XSOAR MS Graph Dev | 2023-04-17T13:30:22.3995128Z |


### ms-graph-security-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`ms-graph-security-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### eDiscovery Commands
### msg-list-ediscovery-cases

***
Lists edicovery cases.

#### Base Command

`msg-list-ediscovery-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. If provided, only this id will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCase.CaseId | String | The ID of the eDiscovery case. | 
| MsGraph.eDiscoveryCase.CaseStatus | String | The case status. Possible values are: unknown, active, pendingDelete, closing, closed, and closedWithError. | 
| MsGraph.eDiscoveryCase.CreatedDateTime | Date | The date and time when the entity was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 
| MsGraph.eDiscoveryCase.Description | String | The case description. | 
| MsGraph.eDiscoveryCase.DisplayName | String | The case name. | 
| MsGraph.eDiscoveryCase.ExternalId | String | The external case number for customer reference. | 
| MsGraph.eDiscoveryCase.LastModifiedDateTime | Date | The latest date and time when the case was modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 
| MsGraph.eDiscoveryCase.ClosedBy.User.DisplayName | String | The user who closed the case. | 
| MsGraph.eDiscoveryCase.LastModifiedBy.User.DisplayName | String | The user who last modified the case. | 
| MsGraph.eDiscoveryCase.ClosedDateTime | Date | The date and time when the case was closed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 

#### Command example

```!msg-list-ediscovery-cases limit=5```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCase": [
            {
                "CaseId": "06386565-47d4-410b-96f9-007978319c02",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-18T10:55:12.63Z",
                "Description": "",
                "DisplayName": "a",
                "ExternalId": "123",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-20T12:25:05.797Z"
            },
            {
                "CaseId": "44bbe68b-0da1-42b4-9ad0-00e8b52f64e2",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-18T11:59:33.44Z",
                "Description": "",
                "DisplayName": "asassdda",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-18T11:59:33.44Z"
            },
            {
                "CaseId": "f108b7fa-d177-438e-9679-01cd79e3df3f",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-20T07:08:01.95Z",
                "Description": "wrking",
                "DisplayName": "justw orkok?",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-20T07:08:01.95Z"
            },
            {
                "CaseId": "f346c6f5-1d66-4fab-a46b-0abc99c2cef0",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-18T11:54:59.873Z",
                "Description": "",
                "DisplayName": "asasdda",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-18T11:54:59.873Z"
            },
            {
                "CaseId": "1a346a94-5220-46ae-a821-0bbbadf4009d",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-12T07:05:27.557Z",
                "Description": "Test Case 104 description",
                "DisplayName": "Test Case 104",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-12T07:05:27.557Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Description|External Id|Case Status|Case Id|Created Date Time|Last Modified Date Time|Last Modified By Name|
>|---|---|---|---|---|---|---|---|
>| a |  | 123 | active | 06386565-47d4-410b-96f9-007978319c02 | 2023-06-18T10:55:12.63Z | 2023-06-20T12:25:05.797Z | Content Test |
>| asassdda |  |  | active | 44bbe68b-0da1-42b4-9ad0-00e8b52f64e2 | 2023-06-18T11:59:33.44Z | 2023-06-18T11:59:33.44Z | Content Test |
>| justw orkok? | wrking |  | active | f108b7fa-d177-438e-9679-01cd79e3df3f | 2023-06-20T07:08:01.95Z | 2023-06-20T07:08:01.95Z | Content Test |
>| asasdda |  |  | active | f346c6f5-1d66-4fab-a46b-0abc99c2cef0 | 2023-06-18T11:54:59.873Z | 2023-06-18T11:54:59.873Z | Content Test |
>| Test Case 104 | Test Case 104 description |  | active | 1a346a94-5220-46ae-a821-0bbbadf4009d | 2023-06-12T07:05:27.557Z | 2023-06-12T07:05:27.557Z | Content Test |

### msg-create-ediscovery-case

***
Create a new eDiscovery case. This command only creates an eDiscovery (Premium) case using the new case format. To learn more about the new case format in eDiscovery, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/advanced-ediscovery-new-case-format>.

#### Base Command

`msg-create-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The name of the eDiscovery case. | Required | 
| description | The case description. | Optional | 
| external_id | The external case number for customer reference. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCase.CaseId | String | The ID of the eDiscovery case. | 
| MsGraph.eDiscoveryCase.CaseStatus | String | The case status. Possible values are unknown, active, pendingDelete, closing, closed, and closedWithError. | 
| MsGraph.eDiscoveryCase.CreatedDateTime | Date | The date and time when the entity was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 
| MsGraph.eDiscoveryCase.Description | String | The case description. | 
| MsGraph.eDiscoveryCase.DisplayName | String | The case name. | 
| MsGraph.eDiscoveryCase.ExternalId | String | The external case number for customer reference. | 
| MsGraph.eDiscoveryCase.LastModifiedDateTime | Date | The latest date and time when the case was modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 

#### Command example

```!msg-create-ediscovery-case display_name=`my case name11234` external_id=123 description=`description of the case````

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCase": {
            "CaseId": "6dfd17fe-43c5-411f-a194-abdc9492bfa0",
            "CaseStatus": "active",
            "CreatedDateTime": "2023-07-06T07:42:34.897Z",
            "Description": "description of the case",
            "DisplayName": "my case name11234",
            "ExternalId": "123",
            "LastModifiedDateTime": "2023-07-06T07:42:34.897Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Description|External Id|Case Status|Case Id|Created Date Time|Last Modified Date Time|
>|---|---|---|---|---|---|---|
>| my case name11234 | description of the case | 123 | active | 6dfd17fe-43c5-411f-a194-abdc9492bfa0 | 2023-07-06T07:42:34.897Z | 2023-07-06T07:42:34.897Z |

### msg-update-ediscovery-case

***
Update an eDiscovery case.

#### Base Command

`msg-update-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| display_name | The name of the eDiscovery case. | Required | 
| description | The case description. | Optional | 
| external_id | The external case number for customer reference. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-update-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0 display_name=`new display name` external_id=123 description=`new description of the case````

#### Human Readable Output

>Case with id 6dfd17fe-43c5-411f-a194-abdc9492bfa0 was updated successfully.

### msg-close-ediscovery-case

***
Close an eDiscovery case. 
When the legal case or investigation supported by a eDiscovery (Standard) case is completed, you can close the case. Here's what happens when you close a case:
      If the case contains any eDiscovery holds, they'll be turned off. After the hold is turned off, a 30-day grace period (called a delay hold) is applied to content locations that were on hold. This helps prevent content from being immediately deleted and provides admins the opportunity to search for and restore content before it may be permanently deleted after the delay hold period expires. For more information, see Removing content locations from an eDiscovery hold.
      Closing a case only turns off the holds that are associated with that case. If other holds are placed on a content location (such as a Litigation Hold, a retention policy, or a hold from a different eDiscovery (Standard) case) those holds will still be maintained.
      The case is still listed on the eDiscovery (Standard) page in the Microsoft Purview compliance portal. The details, holds, searches, and members of a closed case are retained.
      You can edit a case after it's closed. For example, you can add or remove members, create searches, and export search results. The primary difference between active and closed cases is that eDiscovery holds are turned off when a case is closed.

#### Base Command

`msg-close-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-close-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0```

#### Human Readable Output

>Case with id 6dfd17fe-43c5-411f-a194-abdc9492bfa0 was closed successfully.

### msg-reopen-ediscovery-case

***
Reopen an eDiscovery case. When you reopen an eDiscovery (Premium) case, any holds that were in place when the case was closed won't be automatically reinstated. After the case is reopened, you'll have to go to the Holds tab and turn on the previous holds. To turn on a hold, select it to display the flyout page, and then set the Status toggle to On.

#### Base Command

`msg-reopen-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-reopen-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0```

#### Human Readable Output

>Case with id 6dfd17fe-43c5-411f-a194-abdc9492bfa0 was reopened successfully.

### msg-delete-ediscovery-case

***
Delete an eDiscovery case. Before you can delete a case, you must first delete all holds listed on the holds page of the case. That includes deleting holds with a status of Off. Default hold policies can only be deleted when the hold is turned off. You must close an active case to turn off any default hold policies in the case. Once the holds are turned off for default hold policies, they can be deleted.

#### Base Command

`msg-delete-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-delete-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0```

#### Human Readable Output

>Case was deleted successfully.

### msg-create-ediscovery-custodian

***
Create a new ediscoveryCustodian object. After the custodian object is created, you will need to create the custodian's userSource to reference their mailbox and OneDrive for Business site.

#### Base Command

`msg-create-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| email | Custodian's primary SMTP address. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCustodian.CreatedDateTime | Date | Date and time when the custodian was added to the case. | 
| MsGraph.eDiscoveryCustodian.CustodianId | String | The ID for the custodian in the specified case. Read-only. | 
| MsGraph.eDiscoveryCustodian.CustodianStatus | String | Status of the custodian. Possible values are: active, released. | 
| MsGraph.eDiscoveryCustodian.DisplayName | String | Display name of the custodian. | 
| MsGraph.eDiscoveryCustodian.Email | String | Email address of the custodian. | 
| MsGraph.eDiscoveryCustodian.HoldStatus | String | The hold status of the custodian.The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.eDiscoveryCustodian.LastModifiedDateTime | Date | Date and time the custodian object was last modified. | 

#### Command example

```!msg-create-ediscovery-custodian case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 email=testbox2@yoursite.onmicrosoft.com```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCustodian": {
            "CreatedDateTime": "2023-07-06T07:53:36.9441479Z",
            "CustodianId": "0af7ca2b84bc4cff930d5d301cc4caf3",
            "CustodianStatus": "active",
            "DisplayName": "testbox2",
            "Email": "yourmail@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T07:53:36.9441479Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name| Email                             |Custodian Status|Custodian Id|Created Date Time|Last Modified Date Time|Hold Status|
>|-----------------------------------|---|---|---|---|---|---|
>| testbox2 | yourmail@yoursite.onmicrosoft.com | active | 0af7ca2b84bc4cff930d5d301cc4caf3 | 2023-07-06T07:53:36.9441479Z | 2023-07-06T07:53:36.9441479Z | notApplied |

### msg-list-ediscovery-custodians

***
List custodians on a given eDiscovery case.

#### Base Command

`msg-list-ediscovery-custodians`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the custodian on the given eDiscovery case. If provided, only this ID will be returned. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCustodian.CreatedDateTime | Date | Date and time when the custodian was added to the case. | 
| MsGraph.eDiscoveryCustodian.CustodianId | String | The ID for the custodian in the specified case. Read-only. | 
| MsGraph.eDiscoveryCustodian.CustodianStatus | String | Status of the custodian. Possible values are: active, released. | 
| MsGraph.eDiscoveryCustodian.DisplayName | String | Display name of the custodian. | 
| MsGraph.eDiscoveryCustodian.Email | String | Email address of the custodian. | 
| MsGraph.eDiscoveryCustodian.HoldStatus | String | The hold status of the custodian. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.eDiscoveryCustodian.LastModifiedDateTime | Date | Date and time the custodian object was last modified. | 
| MsGraph.eDiscoveryCustodian.ReleasedDateTime | Date | Date and time the custodian was released from the case. | 

#### Command example

```!msg-list-ediscovery-custodians all_results=true case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCustodian": {
            "CreatedDateTime": "2023-07-06T07:53:36.9441479Z",
            "CustodianId": "0af7ca2b84bc4cff930d5d301cc4caf3",
            "CustodianStatus": "active",
            "DisplayName": "testbox2",
            "Email": "mail@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T07:53:36.9441479Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name| Email                         |Custodian Status|Custodian Id|Created Date Time|Last Modified Date Time|Hold Status|
>|-------------------------------|---|---|---|---|---|---|
>| testbox2 | mail@yoursite.onmicrosoft.com | active | 0af7ca2b84bc4cff930d5d301cc4caf3 | 2023-07-06T07:53:36.9441479Z | 2023-07-06T07:53:36.9441479Z | notApplied |

### msg-activate-ediscovery-custodian

***
Activate a custodian that has been released from a case to make them part of the case again. For details, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/ediscovery-manage-new-custodians?view=o365-worldwide#re-activate-custodian>.

#### Base Command

`msg-activate-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-activate-ediscovery-custodian custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Custodian with id 0af7ca2b84bc4cff930d5d301cc4caf3 Case was reactivated on case with id 84abfff1-dd69-4559-8f4e-8225e0d505c5 successfully.

### msg-release-ediscovery-custodian

***
Release a custodian from a case. For details, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/manage-new-custodians#release-a-custodian-from-a-case>.

#### Base Command

`msg-release-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-release-ediscovery-custodian custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Custodian with id 0af7ca2b84bc4cff930d5d301cc4caf3 was released from case with id 84abfff1-dd69-4559-8f4e-8225e0d505c5 successfully.

### msg-create-ediscovery-custodian-site-source

***
Create a new siteSource object associated with an eDiscovery custodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-create-ediscovery-custodian-site-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| site | URL of the site; for example, <https://contoso.sharepoint.com/sites/HumanResources>. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianSiteSource.CreatedBy.Application.DisplayName | String | The name of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.Application.ID | String | The ID of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.DisplayName | String | The name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.ID | String | The ID of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedDateTime | Date | The date and time the siteSource was created. | 
| MsGraph.CustodianSiteSource.DisplayName | String | The display name of the siteSource. This will be the name of the SharePoint site. | 
| MsGraph.CustodianSiteSource.HoldStatus | String | The hold status of the siteSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianSiteSource.SiteSourceId | String | The ID of the siteSource. | 

#### Command example

```!msg-create-ediscovery-custodian-site-source custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5  site=https://yourdev.sharepoint.com/sites/site_test_1```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianSiteSource": {
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "0001-01-01T00:00:00Z",
            "DisplayName": "site_test_1",
            "HoldStatus": "notApplied",
            "SiteSourceId": "862f0a64-e7db-46e0-a97f-9156b4f693ee"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Site Source Id|Hold Status|Created Date Time|Created By Name|Created By UPN|Created By App Name|
>|---|---|---|---|---|---|---|
>| site_test_1 | 862f0a64-e7db-46e0-a97f-9156b4f693ee | notApplied | 0001-01-01T00:00:00Z | Content Test | ContentTest@yoursite.onmicrosoft.com | Cortex XSOAR - MS Graph Security Dev |

### msg-create-ediscovery-custodian-user-source

***
Create a new userSource object associated with an eDiscovery custodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-create-ediscovery-custodian-user-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| email | SMTP address of the user. | Required | 
| included_sources | Specifies which sources are included in this group. Possible values are: mailbox, site, mailbox, site. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianUserSource.CreatedBy.Application.DisplayName | String | The name of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.Application.ID | String | The ID of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.DisplayName | String | The name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.ID | String | The ID of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedDateTime | Date | The date and time the userSource was created. | 
| MsGraph.CustodianUserSource.DisplayName | String | The display name associated with the mailbox and site. | 
| MsGraph.CustodianUserSource.Email | String | Email address of the user's mailbox. | 
| MsGraph.CustodianUserSource.HoldStatus | String | The hold status of the userSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianUserSource.IncludedSources | String | Specifies which sources are included in this group. Possible values are: mailbox, site. | 
| MsGraph.CustodianUserSource.UserSourceId | String | The ID of the userSource. This is not The ID of the actual group. | 

#### Command example

```!msg-create-ediscovery-custodian-user-source custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5  email=testbox2@yoursite.onmicrosoft.com included_sources="mailbox, site"```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianUserSource": {
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "0001-01-01T00:00:00Z",
            "DisplayName": "testbox2",
            "Email": "testbox2@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "IncludedSources": "mailbox,site",
            "UserSourceId": "0af7ca2b-84bc-4cff-930d-5d301cc4caf3"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Email|User Source Id|Hold Status|Created Date Time|Created By Name|Created By UPN|Created By App Name|Included Sources|
>|---|---|---|---|---|---|---|---|---|
>| testbox2 | testbox2@yoursite.onmicrosoft.com | 0af7ca2b-84bc-4cff-930d-5d301cc4caf3 | notApplied | 0001-01-01T00:00:00Z | Content Test | ContentTest@yoursite.onmicrosoft.com | Cortex XSOAR - MS Graph Security Dev | mailbox,site |

### msg-list-ediscovery-custodian-user-sources

***
Get a list of the userSource objects associated with an eDiscoveryCustodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-list-ediscovery-custodian-user-sources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| user_source_id | The ID of the userSource. If provided, only this id will be returned. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianUserSource.CreatedBy.Application.DisplayName | String | The name of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.Application.ID | String | The ID of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.DisplayName | String | The name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.ID | String | The ID of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedDateTime | Date | The date and time the userSource was created. | 
| MsGraph.CustodianUserSource.DisplayName | String | The display name associated with the mailbox and site. | 
| MsGraph.CustodianUserSource.Email | String | Email address of the user's mailbox. | 
| MsGraph.CustodianUserSource.HoldStatus | String | The hold status of the userSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianUserSource.IncludedSources | String | Specifies which sources are included in this group. Possible values are: mailbox, site. | 
| MsGraph.CustodianUserSource.SiteWebUrl | String | The URL of the user's OneDrive for Business site. Read-only. | 
| MsGraph.CustodianUserSource.UserSourceId | String | The ID of the userSource. This is not The ID of the actual group. | 

#### Command example

```!msg-list-ediscovery-custodian-user-sources custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianUserSource": {
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "2023-07-06T08:04:21.1548801Z",
            "DisplayName": "testbox2",
            "Email": "testbox2@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "IncludedSources": "mailbox,site",
            "SiteWebUrl": "https://yourdev-my.sharepoint.com/personal/testbox2_yourdev_onmicrosoft_com",
            "UserSourceId": "0af7ca2b-84bc-4cff-930d-5d301cc4caf3"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Email|User Source Id|Hold Status|Created Date Time|Created By Name|Created By UPN|Created By App Name|Site Web Url|Included Sources|
>|---|---|---|---|---|---|---|---|---|---|
>| testbox2 | testbox2@yoursite.onmicrosoft.com | 0af7ca2b-84bc-4cff-930d-5d301cc4caf3 | notApplied | 2023-07-06T08:04:21.1548801Z | Content Test | ContentTest@yoursite.onmicrosoft.com | Cortex XSOAR - MS Graph Security Dev | https://yourdev-my.sharepoint.com/personal/testbox2_yourdev_onmicrosoft_com | mailbox,site |

### msg-list-ediscovery-custodian-site-sources

***
Get a list of the siteSource objects associated with an eDiscoveryCustodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-list-ediscovery-custodian-site-sources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| site_source_id | The ID of the siteSource. If provided, only this id will be returned. | Optional | 
| limit | Number of total results to return. Default is 50. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianSiteSource.CreatedBy.Application.DisplayName | String | The name of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.Application.ID | String | The ID of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.DisplayName | String | The name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.ID | String | The ID of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedDateTime | Date | The date and time the siteSource was created. | 
| MsGraph.CustodianSiteSource.DisplayName | String | The display name of the siteSource. This will be the name of the SharePoint site. | 
| MsGraph.CustodianSiteSource.HoldStatus | String | The hold status of the siteSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianSiteSource.SiteSourceId | String | The ID of the siteSource. | 
| MsGraph.CustodianSiteSource.Site.ID | String | The unique identifier of the item. Read-only. | 
| MsGraph.CustodianSiteSource.Site.WebUrl | String | URL that displays the item in the browser. Read-only. | 
| MsGraph.CustodianSiteSource.Site.CreatedDate | Date | The date and time the siteSource was created. | 

#### Command example

```!msg-list-ediscovery-custodian-site-sources custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5  site_source_id=862f0a64-e7db-46e0-a97f-9156b4f693ee```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianSiteSource": {
            "CreatedBy": {
                "User": {
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b"
                }
            },
            "CreatedDateTime": "2023-07-06T08:02:28.5670187Z",
            "DisplayName": "site_test_1",
            "HoldStatus": "removing",
            "Site": {
                "CreatedDate": "2023-07-06T08:02:28.5670187Z",
                "ID": "862f0a64-e7db-46e0-a97f-9156b4f693ee",
                "WebUrl": "https://yourdev.sharepoint.com/sites/site_test_1"
            },
            "SiteSourceId": "862f0a64-e7db-46e0-a97f-9156b4f693ee"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Site Source Id|Hold Status|Created Date Time|
>|---|---|---|---|
>| site_test_1 | 862f0a64-e7db-46e0-a97f-9156b4f693ee | removing | 2023-07-06T08:02:28.5670187Z |


### msg-apply-hold-ediscovery-custodian

***
Start the process of applying hold on eDiscovery custodians.
Available return statuses: 
notApplied - The custodian is not on hold (all sources in it are not on hold).
applied - The custodian is on hold (all sources are on hold).
applying - The custodian is in applying hold state (applyHold operation triggered).
removing - The custodian is in removing the hold state(removeHold operation triggered).
partial - The custodian is in mixed state where some sources are on hold and some not on hold or error state.

#### Base Command

`msg-apply-hold-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | A comma-seperated list of custodians ids to apply a hold to. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-apply-hold-ediscovery-custodian custodian_id=09f05c43ffc54ff88cf5c5e89699375d,0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Apply hold status is running.

### msg-remove-hold-ediscovery-custodian

***
Start the process of removing hold from eDiscovery custodians.

#### Base Command

`msg-remove-hold-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | A comma-seperated list of custodians ids to remove a hold from. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-remove-hold-ediscovery-custodian custodian_id=09f05c43ffc54ff88cf5c5e89699375d,0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Remove hold status is running.

### msg-create-ediscovery-non-custodial-data-source

***
Create a new eDiscoveryNoncustodialDataSource object.

#### Base Command

`msg-create-ediscovery-non-custodial-data-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| site | URL of the site, for example, <https://contoso.sharepoint.com/sites/HumanResources>. | Optional | 
| email | Email address of the user's mailbox. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.NoncustodialDataSource.CreatedDateTime | Date | Created date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceId | String | Unique identifier of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceStatus | String | Latest status of the nonCustodialDataSource. Possible values are: Active, Released. | 
| MsGraph.NoncustodialDataSource.DisplayName | String | Display name of the noncustodialDataSource. | 
| MsGraph.NoncustodialDataSource.HoldStatus | String | The hold status of the nonCustodialDataSource.The possible values are: notApplied, applied, applying, removing, partial | 
| MsGraph.NoncustodialDataSource.LastModifiedDateTime | Date | Last modified date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.ReleasedDateTime | Date | Date and time that the nonCustodialDataSource was released from the case. | 

#### Command example

```!msg-create-ediscovery-non-custodial-data-source case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 site=https://yourdev.sharepoint.com/sites/site_test_1```

#### Context Example

```json
{
    "MsGraph": {
        "NoncustodialDataSource": {
            "CreatedDateTime": "2023-07-06T08:22:32.3121523Z",
            "DataSourceId": "38394332433939353236344630434633",
            "DataSourceStatus": "active",
            "DisplayName": "site_test_1",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T08:22:32.3121523Z",
            "ReleasedDateTime": "0001-01-01T00:00:00Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Created Date Time|Data Source Id|Data Source Status|Display Name|Hold Status|Last Modified Date Time|Released Date Time|
>|---|---|---|---|---|---|---|
>| 2023-07-06T08:22:32.3121523Z | 38394332433939353236344630434633 | active | site_test_1 | notApplied | 2023-07-06T08:22:32.3121523Z | 0001-01-01T00:00:00Z |

### msg-list-ediscovery-non-custodial-data-sources

***
Get a list of the non-custodial data sources and their properties.

#### Base Command

`msg-list-ediscovery-non-custodial-data-sources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| data_source_id | The ID of the dataSource. If provided, only this id will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.NoncustodialDataSource.CreatedDateTime | Date | Created date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceId | String | Unique identifier of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceStatus | String | Latest status of the nonCustodialDataSource. Possible values are: Active, Released. | 
| MsGraph.NoncustodialDataSource.DisplayName | String | Display name of the noncustodialDataSource. | 
| MsGraph.NoncustodialDataSource.HoldStatus | String | The hold status of the nonCustodialDataSource.The possible values are: notApplied, applied, applying, removing, partial | 
| MsGraph.NoncustodialDataSource.LastModifiedDateTime | Date | Last modified date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.ReleasedDateTime | Date | Date and time that the nonCustodialDataSource was released from the case. | 

#### Command example

```!msg-list-ediscovery-non-custodial-data-sources case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "NoncustodialDataSource": {
            "CreatedDateTime": "2023-07-06T08:22:32.3121523Z",
            "DataSourceId": "38394332433939353236344630434633",
            "DisplayName": "site_test_1",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T08:22:32.3121523Z",
            "ReleasedDateTime": "0001-01-01T00:00:00Z",
            "Status": "active"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Data Source Id|Hold Status|Created Date Time|Last Modified Date Time|Released Date Time|Status|
>|---|---|---|---|---|---|---|
>| site_test_1 | 38394332433939353236344630434633 | notApplied | 2023-07-06T08:22:32.3121523Z | 2023-07-06T08:22:32.3121523Z | 0001-01-01T00:00:00Z | active |

### msg-create-ediscovery-search

***
Create a new eDiscoverySearch object.

#### Base Command

`msg-create-ediscovery-search`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                   | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| case_id | The ID of the eDiscovery case.                                                                                                                                                                                                                                                                                                                    | Required | 
| display_name | The display name of the search.                                                                                                                                                                                                                                                                                                                   | Required | 
| description | The description of the search.                                                                                                                                                                                                                                                                                                                    | Optional | 
| content_query | The query string used for the search. The query string format is KQL (Keyword Query Language). For details, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/keyword-queries-and-search-conditions.>. You can refine searches by using fields paired with values; for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | Optional | 
| data_source_scopes | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources.                                                                                                                                               | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoverySearch.ContentQuery | String | The query string in KQL \(Keyword Query Language\) query. For details, see  see <https://learn.microsoft.com/en-us/microsoft-365/compliance/keyword-queries-and-search-conditions.>. You can refine searches by using fields paired with values; for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.DisplayName | String | Name of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.ID | String | ID of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.DisplayName | String | Name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.ID | String | ID of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedDateTime | Date | The date and time the eDiscovery search was created. | 
| MsGraph.eDiscoverySearch.DataSourceScopes | String | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources. | 
| MsGraph.eDiscoverySearch.Description | String | The description of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.DisplayName | String | The display name of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedDateTime | Date | The last date and time the eDiscovery search was modified. | 
| MsGraph.eDiscoverySearch.SearchId | String | The ID for the eDiscovery search. | 

#### Command example

```!msg-create-ediscovery-search case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 display_name=`my search` data_source_scopes=allCaseNoncustodialDataSources```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoverySearch": {
            "ContentQuery": "",
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "2023-07-06T08:25:36.9874937Z",
            "DataSourceScopes": "allCaseNoncustodialDataSources",
            "Description": "",
            "DisplayName": "my search",
            "LastModifiedDateTime": "2023-07-06T08:25:36.9874937Z",
            "SearchId": "e7282eff-ba81-43cb-9027-522a343f6692"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Data Source Scopes|Search Id|Created By Name|Created By App Name|Created By UPN|Created Date Time|Last Modified Date Time|
>|---|---|---|---|---|---|---|---|
>| my search | allCaseNoncustodialDataSources | e7282eff-ba81-43cb-9027-522a343f6692 | Content Test | Cortex XSOAR - MS Graph Security Dev | ContentTest@yoursite.onmicrosoft.com | 2023-07-06T08:25:36.9874937Z | 2023-07-06T08:25:36.9874937Z |

### msg-update-ediscovery-search

***
Update an eDiscoverySearch object.

#### Base Command

`msg-update-ediscovery-search`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                   | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| case_id | The ID of the eDiscovery case.                                                                                                                                                                                                                                                                                                                    | Required | 
| search_id | The ID of the eDiscovery search.                                                                                                                                                                                                                                                                                                                  | Required | 
| display_name | The display name of the search.                                                                                                                                                                                                                                                                                                                   | Required | 
| description | The description of the search.                                                                                                                                                                                                                                                                                                                    | Optional | 
| content_query | The query string used for the search. The query string format is KQL (Keyword Query Language). For details, see Keyword queries and search conditions for Content Search and eDiscovery. You can refine searches by using fields paired with values, for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | Optional | 
| data_source_scopes | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources.                                                                                                                                               | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-update-ediscovery-search case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 display_name=newname search_id=e7282eff-ba81-43cb-9027-522a343f6692```

#### Human Readable Output

>eDiscovery search e7282eff-ba81-43cb-9027-522a343f6692 was updated successfully.

### msg-list-ediscovery-searchs

***
Get the list of eDiscoverySearch resources from an eDiscovery case.

#### Base Command

`msg-list-ediscovery-searchs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| search_id | The ID of the eDiscovery search. If provided, only this id will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoverySearch.ContentQuery | String | The query string in KQL \(Keyword Query Language\) query. For details, see Keyword queries and search conditions for Content Search and eDiscovery. You can refine searches by using fields paired with values; for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.DisplayName | String | Name of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.ID | String | ID of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.DisplayName | String | Name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.ID | String | ID of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedDateTime | Date | The date and time the eDiscovery search was created. | 
| MsGraph.eDiscoverySearch.DataSourceScopes | String | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources. | 
| MsGraph.eDiscoverySearch.Description | String | The description of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.DisplayName | String | The display name of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.SearchId | String | The ID for the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedDateTime | String | The last date and time the eDiscovery search was modified. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.Application.DisplayName | String | Name of the application who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.Application.ID | String | ID of the application who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.User.DisplayName | String | Name of the user who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.User.ID | String | ID of the user who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.User.UserPrincipalName | String | Internet-style login name of the user who last modified the eDiscovery search. | 

#### Command example

```!msg-list-ediscovery-searchs case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoverySearch": {
            "ContentQuery": "",
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "2023-07-06T08:25:36.9874937Z",
            "DataSourceScopes": "allCaseNoncustodialDataSources",
            "Description": "",
            "DisplayName": "newname",
            "LastModifiedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "LastModifiedDateTime": "2023-07-06T08:27:51.5611704Z",
            "SearchId": "e7282eff-ba81-43cb-9027-522a343f6692"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Data Source Scopes|Search Id|Created By Name|Created By App Name|Created By UPN|Created Date Time|Last Modified Date Time|
>|---|---|---|---|---|---|---|---|
>| newname | allCaseNoncustodialDataSources | e7282eff-ba81-43cb-9027-522a343f6692 | Content Test | Cortex XSOAR - MS Graph Security Dev | ContentTest@yoursite.onmicrosoft.com | 2023-07-06T08:25:36.9874937Z | 2023-07-06T08:27:51.5611704Z |

### msg-purge-ediscovery-data

***
Delete Microsoft Teams messages contained in an eDiscovery search.
Note: This request purges Teams data only. It does not purge other types of data such as mailbox items.

You can collect and purge the following categories of Teams content:

Teams 1:1 chats - Chat messages, posts, and attachments shared in a Teams conversation between two people. Teams 1:1 chats are also called conversations.
Teams group chats - Chat messages, posts, and attachments shared in a Teams conversation between three or more people. Also called 1:N chats or group conversations.
Teams channels - Chat messages, posts, replies, and attachments shared in a standard Teams channel.
Private channels - Message posts, replies, and attachments shared in a private Teams channel.
Shared channels - Message posts, replies, and attachments shared in a shared Teams channel.

#### Base Command

`msg-purge-ediscovery-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| search_id | The ID of the eDiscovery search. | Required | 
| purge_type | The ID of the eDiscovery search. Possible values are: permanentlyDelete. | Optional | 
| purge_areas | The ID of the eDiscovery search. Possible values are: teamsMessages. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-purge-ediscovery-data case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 search_id=e7282eff-ba81-43cb-9027-522a343f6692```

#### Human Readable Output

>eDiscovery purge status is running.

### msg-delete-ediscovery-search

***
Delete an eDiscoverySearch object.

#### Base Command

`msg-delete-ediscovery-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| search_id | The ID of the eDiscovery search. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-delete-ediscovery-search case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 search_id=e7282eff-ba81-43cb-9027-522a343f6692```

#### Human Readable Output

>eDiscovery search e7282eff-ba81-43cb-9027-522a343f6692 was deleted successfully.


### Threat Assessment Commands
### msg-create-mail-assessment-request

***
Create and retrieve a mail threat assessment.

Note:
- The message given in the command's argument *message_id* has to contain *X-MS-Exchange-Organization-Network-Message-Id* header in the message or in the *X-MS-Office365-Filtering-Correlation-Id* header in quarantined messages.
- Delegated Mail permissions (Mail.Read or Mail.Read.Shared) are required to access the mail received by the user (recipient email and message user), which means that if the authenticated user is different from the user specified in the recipient_email and message_user, then *Read and manage permissions* on behalf of the given user need to be added for the authenticated user via [Microsoft 365 admin center](https://admin.microsoft.com/Adminportal/Home#/users).

  - Go to [Microsoft 365 admin center](https://admin.microsoft.com/Adminportal/Home#/users).
  - Choose the user email which will be provided in the command's arguments.
  - Click on *Manage product licenses*.
  - Go to *Mail*.
  - Under *Mailbox permissions*, click on *Read and manage permissions*.
  - click on *Add permissions*.
  - Choose the authenticated user email from the list of given users.
  - Click on *add*.

#### Base Command

`msg-create-mail-assessment-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_email | The email of the user who recieved the mail. | Required | 
| expected_assessment | the expected assessment: blocked or unblocked | Required | 
| category | The category of the threat: phishing, malware or spam. | Required | 
| message_user | Message user, the user's id or the user's email. | Required | 
| message_id | Message id, Message has to contain 'X-MS-Exchange-Organization-Network-Message-Id' header in the message or the 'X-MS-Office365-Filtering-Correlation-Id' header in quarantined messages. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.MailAssessment.ID | String | Request id. |
| MSGraphMail.MailAssessment.CreatedDateTime | Date | Created data of the threat assessment request. | 
| MSGraphMail.MailAssessment.ContentType | String | The content type of threat assessment. | 
| MSGraphMail.MailAssessment.ExpectedAssessment | String | The expected assessment from submitter. Possible values are: block, unblock. | 
| MSGraphMail.MailAssessment.Category | String | The threat category. Possible values are: spam, phishing, malware. | 
| MSGraphMail.MailAssessment.Status | String | The assessment process status. Possible values are: pending, completed. | 
| MSGraphMail.MailAssessment.RequestSource | String | The source of threat assessment request. Possible values are: administrator. | 
| MSGraphMail.MailAssessment.RecipientEmail | String | The mail recipient whose policies are used to assess the mail. | 
| MSGraphMail.MailAssessment.DestinationRoutingReason | String | The reason for mail routed to its destination. Possible values are: none, mailFlowRule, safeSender, blockedSender, advancedSpamFiltering, domainAllowList, domainBlockList, notInAddressBook, firstTimeSender, autoPurgeToInbox, autoPurgeToJunk, autoPurgeToDeleted, outbound, notJunk, junk. | 
| MSGraphMail.MailAssessment.MessageID | String | Extracted from the message URI which is The resource URI of the mail message for assessment. | 
| MSGraphMail.MailAssessment.CreatedUserID | String | User id. | 
| MSGraphMail.MailAssessment.CreatedUsername | String | Username. | 
| MSGraphMail.MailAssessment.ResultType | String | Result of the request. | 
| MSGraphMail.MailAssessment.ResultMessage | String | Message of the result. | 

#### Command example

```!msg-create-mail-assessment-request recipient_email="avishai@demistodev.onmicrosoft.com" expectedAssessment=unblock category=spam user_id=3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 user_message=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAY5aBb-AAA=```

#### Context Example

```json
{

    "id": "11922306-b25b-4605-ff0d-08d772fcf996",
    "createdDateTime": "2019-11-27T05:45:14.0962061Z",
    "contentType": "mail",
    "expectedAssessment": "unblock",
    "category": "spam",
    "status": "completed",
    "requestSource": "administrator",
    "recipientEmail": "avishai@demistodev.onmicrosoft.com",
    "destinationRoutingReason": "notJunk",
    "messageUri": "",
    "createdBy": {
      "user": {
        "id": "c52ce8db-3e4b-4181-93c4-7d6b6bffaf60",
        "displayName": "Ronald Admin"
      }
    },
    "results": [
        {
            "id": "63798129-a62c-4f9e-2c6d-08d772fcfb0e",
            "createdDateTime": "2019-11-27T05:45:16.55Z",
            "resultType": "checkPolicy",
            "message": "No policy was hit."
        },
        {
            "id": "d38c2448-79eb-467e-2495-08d772fdb7d1",
            "createdDateTime": "2019-11-27T05:50:33.243Z",
            "resultType": "rescan",
            "message": "Not Spam"
        }
    ]
}
```

#### Human Readable Output

>### Mail assessment request:

>|ID|Created DateTime|Content Type|Expected Assessment|Category|Status|Request Source|Recipient Email|Destination Routing Reason|Created User ID|Created Username|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 11922306-b25b-4605-ff0d-08d772fcf996 | "2019-11-27T05:45:14.0962061Z"| mail | unblock| spam| completed | administrator | avishai@demistodev.onmicrosoft.com |notJunk|63798129-a62c-4f9e-2c6d-08d772fcfb0e|No policy was hit.|


### msg-create-email-file-assessment-request

***
Create and retrieve an email file threat assessment.

Note: File has to contain X-MS-Exchange-Organization-Network-Message-Id header in the message or in the X-MS-Office365-Filtering-Correlation-Id header in quarantined messages.

#### Base Command

`msg-create-email-file-assessment-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_email | The email of the user who recieved the mail. | Required | 
| expected_assessment | the expected assessment: blocked or unblocked | Required | 
| category | The category of the threat: phishing, malware or spam. | Required | 
| content_data | content of an email file. | Optional | 
| entry_id | entry id of file uploaded in the war room. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.EmailAssessment.ID | String | Request id. |
| MSGraphMail.EmailAssessment.CreatedDateTime | Date | Created data of the threat assessment request. | 
| MSGraphMail.EmailAssessment.ContentType | String | The content type of threat assessment. | 
| MSGraphMail.EmailAssessment.ExpectedAssessment | String | The expected assessment from submitter. Possible values are: block, unblock. | 
| MSGraphMail.EmailAssessment.Category | String | The threat category. Possible values are: spam, phishing, malware. | 
| MSGraphMail.EmailAssessment.Status | String | The assessment process status. Possible values are: pending, completed. | 
| MSGraphMail.EmailAssessment.RequestSource | String | The source of threat assessment request. Possible values are: administrator. | 
| MSGraphMail.EmailAssessment.RecipientEmail | String | The mail recipient whose policies are used to assess the mail. | 
| MSGraphMail.EmailAssessment.DestinationRoutingReason | String | The reason for mail routed to its destination. Possible values are: none, mailFlowRule, safeSender, blockedSender, advancedSpamFiltering, domainAllowList, domainBlockList, notInAddressBook, firstTimeSender, autoPurgeToInbox, autoPurgeToJunk, autoPurgeToDeleted, outbound, notJunk, junk. | 
| MSGraphMail.EmailAssessment.CreatedUserID | String | User id. | 
| MSGraphMail.EmailAssessment.CreatedUsername | String | Username. | 
| MSGraphMail.EmailAssessment.ResultType | String | Result of the request. | 
| MSGraphMail.EmailAssessment.ResultMessage | String | Message of the result. | 

#### Command example

```!msg-create-email-file-assessment-request recipient_email="avishai@demistodev.onmicrosoft.com" expectedAssessment=unblock category=phishing entry_id=12359704829584```

#### Context Example

```json
{

    "id": "76598306-b25b-4605-ff0d-03kgmtfcf996",
    "createdDateTime": "2019-11-27T05:45:14.0962061Z",
    "contentType": "mail",
    "expectedAssessment": "unblock",
    "category": "phishing",
    "status": "completed",
    "requestSource": "administrator",
    "recipientEmail": "avishai@demistodev.onmicrosoft.com",
    "destinationRoutingReason": "notJunk",
    "createdBy": {
      "user": {
        "id": "c52ce8db-3e4b-4181-93c4-7d6b6bffaf60",
        "displayName": "Ronald Admin"
      }
    },
    "results": [
        {
            "id": "63798129-a62c-4f9e-2c6d-08d772fcfb0e",
            "createdDateTime": "2019-11-27T05:45:16.55Z",
            "resultType": "checkPolicy",
            "message": "Phishing attempt."
        }
    ]
}
```

#### Human Readable Output

>### Mail assessment request:

>|ID|Created DateTime|Content Type|Expected Assessment|Category|Status|Request Source|Recipient Email|Destination Routing Reason|Created User ID|Created Username|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 76598306-b25b-4605-ff0d-03kgmtfcf996 | "2019-11-27T05:45:14.0962061Z"| mail | unblock| phishing| completed | administrator | avishai@demistodev.onmicrosoft.com |notJunk|63798129-a62c-4f9e-2c6d-08d772fcfb0e|Phishing attempt.|


### msg-create-file-assessment-request

***
Create and retrieve a file threat assessment.

#### Base Command

`msg-create-file-assessment-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | The file name. | Required | 
| expected_assessment | the expected assessment: blocked or unblocked | Required | 
| category | The category of the threat: phishing, malware or spam. | Required | 
| content_data | content of an email file. | Optional | 
| entry_id | entry id of file uploaded in the war room. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.FileAssessment.ID | String | Request id. |
| MSGraphMail.FileAssessment.CreatedDateTime | Date | Created data of the threat assessment request. | 
| MSGraphMail.FileAssessment.ContentType | String | The content type of threat assessment. | 
| MSGraphMail.FileAssessment.ExpectedAssessment | String | The expected assessment from submitter. Possible values are: block, unblock. | 
| MSGraphMail.FileAssessment.Category | String | The threat category. Possible values are: phishing, malware. | 
| MSGraphMail.FileAssessment.Status | String | The assessment process status. Possible values are: pending, completed. | 
| MSGraphMail.FileAssessment.RequestSource | String | The source of threat assessment request. Possible values are: administrator. | 
| MSGraphMail.FileAssessment.FileName | String | The file name. | 
| MSGraphMail.FileAssessment.CreatedUserID | String | User id. | 
| MSGraphMail.FileAssessment.CreatedUsername | String | Username. | 
| MSGraphMail.FileAssessment.ResultType | String | Result of the request. | 
| MSGraphMail.FileAssessment.ResultMessage | String | Message of the result. | 

#### Command example

```!msg-create-file-assessment-request file_name="test_file.txt" expectedAssessment=block category=phishing entry_id=1235970482958bkf4```

#### Context Example

```json
{

    "id": "0796306-b456-4605-ff0d-03kgmtfcf876",
    "createdDateTime": "2019-11-27T05:45:14.0962061Z",
    "contentType": "file",
    "expectedAssessment": "block",
    "category": "phishing",
    "status": "completed",
    "requestSource": "administrator",
    "fileName": "test_file.txt",
    "createdBy": {
      "user": {
        "id": "c52ce8db-3e4b-4181-93c4-7d6b6bffaf60",
        "displayName": "Ronald Admin"
      }
    },
    "results": [
        {
            "id": "63798129-a62c-4f9e-2c6d-08d772fcfb0e",
            "createdDateTime": "2019-11-27T05:45:16.55Z",
            "resultType": "checkPolicy",
            "message": "Phishing attempt."
        }
    ]
}
```

#### Human Readable Output

>### Mail assessment request:

>|ID|Created DateTime|Content Type|Expected Assessment|Category|Status|Request Source|File Name|Created User ID|Created Username|
>|---|---|---|---|---|---|---|---|---|---|
>| 0796306-b456-4605-ff0d-03kgmtfcf876 | "2019-11-27T05:45:14.0962061Z"| file | block| phishing| completed | administrator | test_file.txt |63798129-a62c-4f9e-2c6d-08d772fcfb0e|Phishing attempt.|

### msg-create-url-assessment-request

***
Create and retrieve url threat assessment.

#### Base Command

`msg-create-url-assessment-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL. | Required | 
| expected_assessment | the expected assessment: blocked or unblocked | Required | 
| category | The category of the threat: phishing, malware or spam. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.UrlAssessment.ID | String | Request id. |
| MSGraphMail.UrlAssessment.CreatedDateTime | Date | Created data of the threat assessment request. |
| MSGraphMail.UrlAssessment.ContentType | String | The content type of threat assessment. |
| MSGraphMail.UrlAssessment.ExpectedAssessment | String | The expected assessment from submitter. Possible values are: block, unblock. |
| MSGraphMail.UrlAssessment.Category | String | The threat category. Possible values are: spam, phishing, malware. |
| MSGraphMail.UrlAssessment.Status | String | The assessment process status. Possible values are: pending, completed. |
| MSGraphMail.UrlAssessment.RequestSource | String | The source of threat assessment request. Possible values are: administrator. |
| MSGraphMail.UrlAssessment.Url | String | The url. |
| MSGraphMail.UrlAssessment.CreatedUserID | String | User id. |
| MSGraphMail.UrlAssessment.CreatedUsername | String | Username. |
| MSGraphMail.UrlAssessment.ResultType | String | Result of the request. |
| MSGraphMail.UrlAssessment.ResultMessage | String | Message of the result. |
| MSGraphMail.UrlAssessment.RecipientEmail | String | Recipient Email. |
| MSGraphMail.UrlAssessment.DestinationRoutingReason | String | Destination Routing Reason. |


#### Command example

```!msg-create-url-assessment-request url="httpp://support.clean-mx.de/clean-mx/viruses.php" expectedAssessment=block category=malware```

#### Context Example

```json
{

    "id": "0796306-b456-4605-ff0d-03okmtgcf876",
    "createdDateTime": "2019-11-27T05:45:14.0962061Z",
    "contentType": "url",
    "expectedAssessment": "block",
    "category": "malware",
    "status": "completed",
    "requestSource": "administrator",
    "url": "httpp://support.clean-mx.de/clean-mx/viruses.php",
    "createdBy": {
      "user": {
        "id": "c52ce8db-3e4b-4181-93c4-7d6b6bffaf60",
        "displayName": "Ronald Admin"
      }
    },
    "results": [
        {
            "id": "63798129-a62c-4f9e-2c6d-08d772fcfb0e",
            "createdDateTime": "2019-11-27T05:45:16.55Z",
            "resultType": "checkPolicy",
            "message": "Malware attempt."
        }
    ]
}
```

#### Human Readable Output

>### Mail assessment request:

>|ID|Created DateTime|Content Type|Expected Assessment|Category|Status|Request Source|URL|Created User ID|Created Username|
>|---|---|---|---|---|---|---|---|---|---|
>| 0796306-b456-4605-ff0d-03okmtgcf876 | "2019-11-27T05:45:14.0962061Z"| url | block| malware| completed | administrator | httpp://support.clean-mx.de/clean-mx/viruses.php |63798129-a62c-4f9e-2c6d-08d772fcfb0e|Malware attempt.|


### msg-list-threat-assessment-requests

***
Retrieve all threat assessment requests.

#### Base Command

`msg-list-threat-assessment-requests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The request id. | Optional | 
| filter | Available fields for filter  are:expectedAssessment,ContentType,status,requestSource. Example:category eq 'malware’| Optional | 
| order_by | Drop -down: id, createdDateTime, ContentType, expectedAssessment, category, status, requestSource, category | Optional | 
| sort_order | desc or asc. | Optional |
| limit | Default is 50. | Optional |
| next_token | the retrieved token from first run when there's more data to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.AssessmentRequest.ID | String | Request id. |
| MSGraphMail.AssessmentRequest.CreatedDateTime | Date | Created data of the threat assessment request. | 
| MSGraphMail.AssessmentRequest.ContentType | String | The content type of threat assessment. | 
| MSGraphMail.AssessmentRequest.ExpectedAssessment | String | The expected assessment from submitter. Possible values are: block, unblock. | 
| MSGraphMail.AssessmentRequest.Category | String | The threat category. Possible values are: spam, phishing, malware. | 
| MSGraphMail.AssessmentRequest.Status | String | The assessment process status. Possible values are: pending, completed. | 
| MSGraphMail.AssessmentRequest.RequestSource | String | The source of threat assessment request. Possible values are: administrator. | 
| MSGraphMail.AssessmentRequest.DestinationRoutingReason | String | The destination Routing Reason. |
| MSGraphMail.AssessmentRequest.RecipientEmail | String | The recipient email. |
| MSGraphMail.AssessmentRequest.URL | String | The url. |
| MSGraphMail.AssessmentRequest.FileName | String | The file name. |
| MSGraphMail.AssessmentRequest.CreatedUserID | String | User id. | 
| MSGraphMail.AssessmentRequest.CreatedUsername | String | Username. | 
| MSGraphMail.AssessmentRequest.ResultType | String | Result of the request. | 
| MSGraphMail.AssessmentRequest.ResultMessage | String | Message of the result. | 
| MsGraph.AssessmentRequestNextToken.next_token |String |the next token from the previous run.|

#### Command example

```!msg-list-threat-assessment-requests```

#### Context Example

```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#informationProtection/threatAssessmentRequests",
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/informationProtection/threatAssessmentRequests?$skiptoken=eyJQYWdlQ29va2llIjoiPHJvdyBpZF9JZGVudGl0",
  "value": [
    {
      "@odata.type": "#microsoft.graph.mailAssessmentRequest",
      "id": "49c5ef5b-1f65-444a-e6b9-08d772ea2059",
      "createdDateTime": "2019-11-27T03:30:18.6890937Z",
      "contentType": "mail",
      "expectedAssessment": "block",
      "category": "spam",
      "status": "pending",
      "requestSource": "administrator",
      "recipientEmail": "avishaibrandies@microsoft.com",
      "destinationRoutingReason": "notJunk",
      "messageUri": "https://graph.microsoft.com/v1.0/users/c52ce8db-3e4b-4181-93c4-7d6b6bffaf60/messages/AAMkADU3MWUxOTU0LWNlOTEt=",
      "createdBy": {
        "user": {
          "id": "c52ce8db-3e4b-4181-93c4-7d6b6bffaf60",
          "displayName": "Ronald Admin"
        }
      }
    },
    {
      "@odata.type": "#microsoft.graph.emailFileAssessmentRequest",
      "id": "ab2ad9b3-2213-4091-ae0c-08d76ddbcacf",
      "createdDateTime": "2019-11-20T17:05:06.4088076Z",
      "contentType": "mail",
      "expectedAssessment": "block",
      "category": "malware",
      "status": "completed",
      "requestSource": "administrator",
      "recipientEmail": "tifc@a830edad9050849EQTPWBJZXODQ.onmicrosoft.com",
      "destinationRoutingReason": "notJunk",
      "contentData": "",
      "createdBy": {
        "user": {
          "id": "c52ce8db-3e4b-4181-93c4-7d6b6bffaf60",
          "displayName": "Ronald Admin"
        }
      }
    }
  ]
}
```

#### Human Readable Output
>###Next Token is: eyJQYWdlQ29va2llIjoiPHJvdyBpZF9JZGVudGl
>### Mail assessment request:

>|ID|Created DateTime|Content Type|Expected Assessment|Category|Status|Request Source|Recipient Email|Created User ID|Created Username|destinationRoutingReason|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 49c5ef5b-1f65-444a-e6b9-08d772ea2059 | "2019-11-27T03:30:18.6890937Z"| mail | block| spam| pending| administrator | avishaibrandies@microsoft.com |63798129-a62c-4f9e-2c6d-08d772fcfb0e|spam attempt.|notJunk|
>| ab2ad9b3-2213-4091-ae0c-08d76ddbcacf | 2019-11-20T17:05:06.4088076Z| mail | block| malware| pending| administrator | avishaibrandies@microsoft.com |63798129-a62c-4f9e-2c6d-08d772fcfb0e|Malware attempt.|notJunk|


### msg-generate-login-url

***
Generate the login URL used for the authorization code flow.

#### Base Command

`msg-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

#### Human Readable Output
>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
>```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.

### msg-advanced-hunting

***
Advanced hunting is a threat-hunting tool that uses specially constructed queries to examine the past 30 days of event data in Microsoft Graph Security.
To save result in context to 'Microsoft365Defender' as well, you can check the 'Microsoft 365 Defender context' checkbox in Instance Setting.

#### Base Command

`msg-advanced-hunting`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Advanced hunting query. | Required | 
| limit | Number of entries. Enter -1 for unlimited query, In case a limit also appears in the query, priority will be given to the query. | Optional | 
| timeout | The time limit in seconds for the http request to run | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Hunt.query | String | The query used, also acted as a key. | 
| MsGraph.Hunt.results | Unknown | The results of the query. | 
| Microsoft365Defender.Hunt.query | String | The query used, also acted as a key. | 
| Microsoft365Defender.Hunt.results | Unknown | The results of the query. | 

#### Command example
```!msg-advanced-hunting query=AlertInfo limit=1```
#### Context Example
```json
{
    "Microsoft365Defender": {
        "Hunt": {
            "query": "AlertInfo | limit 1 ",
            "results": [
                {
                    "AlertId": "abc123",
                    "AttackTechniques": "",
                    "Category": "Exfiltration",
                    "DetectionSource": "Microsoft Data Loss Prevention",
                    "ServiceSource": "Microsoft Data Loss Prevention",
                    "Severity": "Medium",
                    "Timestamp": "2024-03-19T03:00:08Z",
                    "Title": "DLP policy (Custom policy) matched for email with subject (Splunk Report: High Or Critical Priority Host With Malware - 15 min)"
                }
            ]
        }
    },
    "MsGraph": {
        "Hunt": {
            "query": "AlertInfo | limit 1 ",
            "results": [
                {
                    "AlertId": "abc123",
                    "AttackTechniques": "",
                    "Category": "Exfiltration",
                    "DetectionSource": "Microsoft Data Loss Prevention",
                    "ServiceSource": "Microsoft Data Loss Prevention",
                    "Severity": "Medium",
                    "Timestamp": "2024-03-19T03:00:08Z",
                    "Title": "DLP policy (Custom policy) matched for email with subject (Splunk Report: High Or Critical Priority Host With Malware - 15 min)"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>See Results Above

### msg-list-security-incident

***
Get a list of incident objects that Microsoft 365 Defender created to track attacks in an organization. If you want a specific incident, enter an incident ID.

#### Base Command

`msg-list-security-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident's ID. | Optional | 
| limit | Number of incidents in the list. Maximum is 50. Default is 50. | Optional | 
| timeout | The time limit in seconds for the http request to run. Default is 50. | Optional | 
| status | The status of the incident. Possible values are: active, redirected, resolved, inProgress, unknownFutureValue, awaitingAction. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| severity | Indicates the possible impact on assets. The higher the severity, the greater the impact. Typically higher severity items require the most immediate attention. Possible values are: unknown, informational, low, medium, high, unknownFutureValue. | Optional | 
| classification | The specification for the incident. | Optional | 
| odata | Filter incidents using 'odata' query. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Incident.assignedTo | string | Owner of the incident, or null if no owner is assigned. Free editable text. | 
| MsGraph.Incident.classification | string | The specification for the incident. Possible values are unknown, falsePositive, truePositive, informationalExpectedActivity, unknownFutureValue. | 
| MsGraph.Incident.comments | string | Array of comments created by the Security Operations \(SecOps\) team when the incident is managed. | 
| MsGraph.Incident.createdDateTime | date | Time when the incident was first created. | 
| MsGraph.Incident.customTags | string | Array of custom tags associated with an incident. | 
| MsGraph.Incident.description | string | Description of the incident. | 
| MsGraph.Incident.determination | string | Specifies the determination of the incident. Possible values are unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedUser, phishing, maliciousUserActivity, clean, insufficientData, confirmedUserActivity, lineOfBusinessApplication, unknownFutureValue. | 
| MsGraph.Incident.displayName | string | The incident name. | 
| MsGraph.Incident.id | number | Unique identifier to represent the incident. | 
| MsGraph.Incident.incidentWebUrl | string | The URL for the incident page in the Microsoft 365 Defender portal. | 
| MsGraph.Incident.lastModifiedBy | string | The identity that last modified the incident. | 
| MsGraph.Incident.lastUpdateDateTime | string | Time when the incident was last updated. | 
| MsGraph.Incident.redirectIncidentId | string | Only populated in case an incident is grouped with another incident, as part of the logic that processes incidents. In such a case, the status property is redirected. | 
| MsGraph.Incident.severity | string | Indicates the possible impact on assets. The higher the severity, the greater the impact. Typically higher severity items require the most immediate attention. Possible values are unknown, informational, low, medium, high, unknownFutureValue. | 
| MsGraph.Incident.status | string | The status of the incident. Possible values are active, resolved, inProgress, redirected, unknownFutureValue, and awaitingAction. | 
| MsGraph.Incident.tenantId | string | The Microsoft Entra tenant in which the alert was created. | 
| MsGraph.Incident.systemTags | string | The system tags associated with the incident. | 

#### Command example
```!msg-list-security-incident limit=1```
#### Context Example
```json
{
    "MsGraph": {
        "Incident": {
            "@odata.count": 26176,
            "value": [
                {
                    "Assigned to": null,
                    "Classification": "unknown",
                    "Created date time": "2024-03-19T08:08:33.2533333Z",
                    "Custom tags": "",
                    "Determination": "unknown",
                    "Display name": "DLP policy (Custom policy) matched for email with subject (Splunk Report: High Or Critical Priority Host With Malware - 15 min) involving one user",
                    "Severity": "medium",
                    "Status": "active",
                    "System tags": "",
                    "Updated date time": "2024-03-19T08:08:33.36Z",
                    "id": "12345"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incidents:
>|Display name|id|Severity|Status|Assigned to|Custom tags|System tags|Classification|Determination|Created date time|Updated date time|
>|---|---|---|---|---|---|---|---|---|---|---|
>| DLP policy (Custom policy) matched for email with subject (Splunk Report: High Or Critical Priority Host With Malware - 15 min) involving one user | 12345 | medium | active |  |  |  | unknown | unknown | 2024-03-19T08:08:33.2533333Z | 2024-03-19T08:08:33.36Z |


### msg-update-security-incident

***
Update the incident with the given ID.

#### Base Command

`msg-update-security-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident's ID. | Required | 
| status | Categorize incidents (as Active, Resolved, or Redirected). Possible values are: active, resolved, redirected, unknownFutureValue. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| determination | Determination of the incident. Possible values are: unknown, apt, malware, securityPersonnel, unwantedSoftware, other, multiStagedAttack, compromisedUser, phishing, maliciousUserActivity, notMalicious. | Optional | 
| classification | The specification for the incident. Possible values are: unknown, falsePositive, truePositive, informationalExpectedActivity, unknownFutureValue. | Optional | 
| custom_tags | Array of custom tags associated with an incident. | Optional | 
| timeout | The time limit in seconds for the http request to run. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Incident.assignedTo | String | Owner of the incident, or null if no owner is assigned. Free editable text. | 
| MsGraph.Incident.classification | String | The specification for the incident. Possible values are unknown, falsePositive, truePositive, informationalExpectedActivity, unknownFutureValue. | 
| MsGraph.Incident.comments | String | Array of comments created by the Security Operations \(SecOps\) team when the incident is managed. | 
| MsGraph.Incident.createdDateTime | Date | Time when the incident was first created. | 
| MsGraph.Incident.customTags | String | Array of custom tags associated with an incident. | 
| MsGraph.Incident.description | String | Description of the incident. | 
| MsGraph.Incident.determination | String | Specifies the determination of the incident. Possible values are unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedUser, phishing, maliciousUserActivity, clean, insufficientData, confirmedUserActivity, lineOfBusinessApplication, unknownFutureValue. | 
| MsGraph.Incident.displayName | String | The incident name. | 
| MsGraph.Incident.id | String | Unique identifier to represent the incident. | 
| MsGraph.Incident.incidentWebUrl | String | The URL for the incident page in the Microsoft 365 Defender portal. | 
| MsGraph.Incident.lastModifiedBy | String | The identity that last modified the incident. | 
| MsGraph.Incident.lastUpdateDateTime | Date | Time when the incident was last updated. | 
| MsGraph.Incident.redirectIncidentId | String | Only populated in case an incident is grouped with another incident, as part of the logic that processes incidents. In such a case, the status property is redirected. | 
| MsGraph.Incident.severity | String | Indicates the possible impact on assets. The higher the severity, the greater the impact. Typically higher severity items require the most immediate attention. Possible values are unknown, informational, low, medium, high, unknownFutureValue. | 
| MsGraph.Incident.status | String | The status of the incident. Possible values are active, resolved, inProgress, redirected, unknownFutureValue, and awaitingAction. | 
| MsGraph.Incident.tenantId | String | The Microsoft Entra tenant in which the alert was created. | 
| MsGraph.Incident.systemTags | String collection | The system tags associated with the incident. | 

#### Command example
```!msg-update-security-incident incident_id=12345```
#### Context Example
```json
{
    "MsGraph": {
        "Incidents": {
            "assignedTo": "test5",
            "classification": "unknown",
            "comments": [],
            "createdDateTime": "2024-03-17T15:50:31.9033333Z",
            "customTags": [],
            "description": null,
            "determination": "unknown",
            "displayName": "Exfiltration incident involving one user",
            "id": "12345",
            "incidentWebUrl": "https://security.microsoft.com/incidents/12345?tid=abc123",
            "lastModifiedBy": "Microsoft 365 Defender-AlertCorrelation",
            "lastUpdateDateTime": "2024-03-19T07:24:34.7066667Z",
            "redirectIncidentId": null,
            "severity": "medium",
            "status": "active",
            "systemTags": [],
            "tenantId": "abc123"
        }
    }
}
```

#### Human Readable Output

>### Updated incident No. 12345:
>|Display name|id|Severity|Status|Assigned to|Custom tags|System tags|Classification|Determination|Created date time|Updated date time|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Exfiltration incident involving one user | 12345 | medium | active | test5 |  |  | unknown | unknown | 2024-03-17T15:50:31.9033333Z | 2024-03-19T07:24:34.7066667Z |

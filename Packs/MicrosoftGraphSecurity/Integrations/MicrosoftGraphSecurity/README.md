Unified gateway to security insights - all from a unified Microsoft Graph Security API.
This integration was integrated and tested with version 1.0 of Microsoft Graph.

## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication)

## Note
The `message-search-alerts` command does not filter alerts of the `Office 365` provider because of API limitations.\
For more info, see: https://github.com/microsoftgraph/security-api-solutions/issues/56.

### Required Permissions
Legacy Alerts:
1. SecurityEvents.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`)
2. SecurityEvents.ReadWrite.All - Application (required for updating alerts with the command: `msg-update-alert`)
3. User.Read.All - Application (Only required if using the deprecated commands: `msg-get-user` and `msg-get-users`)

Alerts v2:
1. SecurityAlert.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`)
2. SecurityAlert.ReadWrite.All - Application (required for updating alerts with the commands: `msg-update-alert` and `msg-create-alert-comment`)

    #### Note
#### Note
- The `message-search-alerts` command does not filter alerts of the `Office 365` provider because of API limitations.\
For more info, see: https://github.com/microsoftgraph/security-api-solutions/issues/56.
- When using Alerts V2: only the following properties are supported as filters on the *Fetched incidents filter* parameter and *filter* argument: assignedTo, classification, determination, createdDateTime, lastUpdateDateTime, severity, serviceSource and status. As per [Microsoft's documentation](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0&tabs=http#optional-query-parameters).

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

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The Alert ID. Provider-generated GUID/unique identifier. | Required | 
| assigned_to | Name of the analyst the alert is assigned to for triage, investigation, or remediation. | Optional | 
| closed_date_time | Relevant only for Legacy Alerts. Time the alert was closed in the string format MM/DD/YYYY. | Optional | 
| comments | Relevant only for Legacy Alerts. Analyst comments on the alert (for customer alert management). | Optional | 
| feedback | Relevant only for Legacy Alerts. Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| status | Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved, new. | Optional | 
| tags | Relevant only for Legacy Alerts. User-definable labels that can be applied to an alert and can serve as filter conditions, for example "HVA", "SAW). | Optional | 
| vendor_information | Relevant only for Legacy Alerts. Details about the security service vendor, for example Microsoft. | Optional | 
| provider_information | Relevant only for Legacy Alerts. Details about the security service vendor, for example Windows Defender ATP. | Optional | 
| classification | Relevant only for Alerts v2. Use this field to update the alert's classification. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| determination | Relevant only for Alerts v2. Use this field to update the alert's determination. Possible values are: unknown, apt, malware, phishing, other, securityPersonnel, securityTesting, multiStagedAttack, maliciousUserActivity, lineOfBusinessApplication, unwantedSoftware. | Optional | 

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
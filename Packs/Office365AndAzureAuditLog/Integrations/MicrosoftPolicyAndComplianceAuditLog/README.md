Use the integration to get logs from the O365 service.

## Configure Microsoft Policy And Compliance (Audit Log) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Policy And Compliance (Audit Log).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Exchange Online URL |  | True |
    | Certificate | A pfx certificate encoded in Base64. | True |
    | Password |  | True |
    | The organization used in app-only authentication. |  | True |
    | The application ID from the Azure portal |  | True |

4. Click **Test** to validate the URLs, token, and connection.

## Required Permissions To Search Audit Logs
- The minimum required Exchange permissions are **Audit Logs** or **View-Only Audit Logs**.
- Go to [The Microsoft Admin Portal](https://admin.microsoft.com/Adminportal#/homepage).
- Click **Roles** --> **Admin Roles** --> **Organization Management**.
- Click **Add** --> Choose the name and description --> Select the **Audit Logs** or **View-Only Audit Logs** roles --> Select the members to apply the role(s) to --> Click **Add role group**.
- For more information --> [How to assign permissions to search the audit log](https://docs.microsoft.com/en-us/microsoft-365/compliance/set-up-basic-audit?view=o365-worldwide#step-2-assign-permissions-to-search-the-audit-log).
## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### o365-auditlog-search

***
Use the o365-search-auditlog command to search the unified audit log. This log contains events from Exchange Online, SharePoint Online, OneDrive for Business, Azure Active Directory, Microsoft Teams, Power BI, and other Microsoft 365 services. You can search for all events in a specified date range, or you can filter the results based on specific criteria, such as the action, the user who performed the action, or the target object.

#### Base Command

`o365-auditlog-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The start date of the date range or a date range (3 days, 1 year, etc.). Entries are stored in the unified audit log in Coordinated Universal Time (UTC). If you specify a date/time value without a time zone, the value is in UTC. Default is 24 hours. | Optional | 
| end_date | The end date of the date range. Entries are stored in the unified audit log in Coordinated Universal Time (UTC). If you specify a date/time value without a time zone, the value is in UTC. If empty, wll take current time. | Optional | 
| free_text | The text string by which to filter the log entries.\ \ If the value contains spaces, enclose the value in quotation\ \ marks (for example: "Invalid logon"). | Optional | 
| record_type | The record type by which to filter the log entries.\ \ Available record types: https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype. | Optional | 
| ip_addresses | A comma-separated list of IP addresses by which to filter the log entries. | Optional | 
| operations | The operations by which to filter the log entries. The available values for this parameter depend on the record_types value. Refer to https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide#audited-activities. | Optional | 
| user_ids | A comma-separated list of ID of the users who performed the action by which to filter the log entries. The list of user IDs can be acquired by running the ews-users-list command. | Optional | 
| result_size | The maximum number of results to return. Default is 10. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365AuditLog.Actor.ID | String | The ID of the actor. | 
| O365AuditLog.Actor.Type | Number | The type of the actor. | 
| O365AuditLog.ActorContextId | String | The GUID of the organization that the actor belongs to. | 
| O365AuditLog.ActorIpAddress | String | The actor's IP address in IPV4 or IPV6 address format. | 
| O365AuditLog.ApplicationId | String | The GUID that represents the application that is requesting the login. The display name can be looked up using the Azure Active Directory Graph API. | 
| O365AuditLog.AzureActiveDirectoryEventType | Number | The type of Azure Active Directory event. | 
| O365AuditLog.ClientIP | String | The IP address of the device that was used when the activity was logged. The IP address is displayed in IPv4 or IPv6 address format. | 
| O365AuditLog.CreationTime | Date | The date and time in Coordinated Universal Time \(UTC\) when the user performed the activity. | 
| O365AuditLog.ExtendedProperties.Name | String | Name of the extended properties. | 
| O365AuditLog.ExtendedProperties.Value | String | Value of the extended properties. | 
| O365AuditLog.ModifiedProperties.Name | String | Name of the modified properties. | 
| O365AuditLog.ModifiedProperties.NewValue | String | The updated value of the property. | 
| O365AuditLog.ModifiedProperties.OldValue | String | The previous value of the property. | 
| O365AuditLog.Id | String | The unique ID of the log. | 
| O365AuditLog.InterSystemsId | String | The GUID that tracked the actions across components within the Office 365 service. | 
| O365AuditLog.IntraSystemId | String | The GUID that's generated by Azure Active Directory to track the action. | 
| O365AuditLog.LogonError | String | For failed logins, a user-readable description of the reason for the failure. | 
| O365AuditLog.ObjectId | String | For SharePoint and OneDrive for Business activity, the full path name of the file or folder accessed by the user. For Exchange admin audit logging, the name of the object that was modified by the cmdlet. | 
| O365AuditLog.Operation | String | The operation used in the log. | 
| O365AuditLog.OrganizationId | String | The GUID for your organization's Office 365 tenant. This value will always be the same for your organization, regardless of the Office 365 service in which it occurs. | 
| O365AuditLog.RecordType | Number | The type of operation indicated by the record. See the AuditLogRecordType table \(https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema\#auditlogrecordtype\)for details on the types of audit log records. | 
| O365AuditLog.ResultStatus | String | Whether the action \(specified in the Operation property\) was successful. Possible values are Succeeded, PartiallySucceeded, or Failed. For Exchange admin activity, the value is either True or False. | 
| O365AuditLog.SupportTicketId | String | The customer support ticket ID for the action in "act-on-behalf-of" situations. | 
| O365AuditLog.Target.ID | String | The ID of the user on whom the action \(identified by the Operation property\) was performed. | 
| O365AuditLog.Target.Type | Number | The type of the user on whom the action \(identified by the Operation property\) was performed. | 
| O365AuditLog.TargetContextId | String | The GUID of the organization that the targeted user belongs to. | 
| O365AuditLog.UserId | String | Identifier \(for example, email address\) for the user who clicked on the URL. | 
| O365AuditLog.UserKey | String | An alternative ID for the user identified in the UserId property. For example, this property is populated with the passport unique ID \(PUID\) for events performed by users in SharePoint, OneDrive for Business, and Exchange. | 
| O365AuditLog.UserType | Number | The type of user who performed the operation. | 
| O365AuditLog.Version | Number | The version of the log. | 
| O365AuditLog.Workload | String | The Office 365 service where the activity occurred. | 

#### Command example
```!o365-auditlog-search start_date="3 days"```
#### Context Example
```json
{
    "O365AuditLog": [
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:37:30",
            "DataType": "Alert",
            "Id": "000d975e-dda0-418e-7379-08db7c830cd4",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T10:06:57Z%20and%20createdDateTime%20lt%202023-07-04T10:07:28Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:36:13",
            "DataType": "Alert",
            "Id": "0d753828-3bf8-46eb-2f3d-08db7c82df05",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T10:05:40Z%20and%20createdDateTime%20lt%202023-07-04T10:06:11Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:33:49",
            "DataType": "Alert",
            "Id": "a3766fb6-4f7a-4ba3-26e7-08db7c828997",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T10:03:17Z%20and%20createdDateTime%20lt%202023-07-04T10:03:48Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:20:20",
            "DataType": "Alert",
            "Id": "77afbaf5-f267-49c0-a27e-08db7c80a713",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T09:49:47Z%20and%20createdDateTime%20lt%202023-07-04T09:50:19Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:16:59",
            "DataType": "Alert",
            "Id": "7fedddc9-a876-41b7-4281-08db7c802f88",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T09:46:27Z%20and%20createdDateTime%20lt%202023-07-04T09:46:58Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AdditionalActionsAndResults": [
                "OriginalDelivery: [N/A]"
            ],
            "AttachmentData": [
                {
                    "FileName": "High_Or_Critical_Priority_Host_With_Malware_-_15_m-2023-07-04.csv",
                    "FileType": "txt;text",
                    "FileVerdict": 0,
                    "SHA256": "DEB083C07B5A3E9F6542A253931D1343403AD10EDC1F770DB309FB69064230C7"
                }
            ],
            "AuthDetails": [
                {
                    "Name": "SPF",
                    "Value": "None"
                },
                {
                    "Name": "DKIM",
                    "Value": "None"
                },
                {
                    "Name": "DMARC",
                    "Value": "None"
                },
                {
                    "Name": "Comp Auth",
                    "Value": "fail"
                }
            ],
            "CreationTime": "2023-07-04T11:16:04",
            "DeliveryAction": "DeliveredAsSpam",
            "DetectionMethod": "Spoof external domain",
            "DetectionType": "Inline",
            "Directionality": "Inbound",
            "EventDeepLink": "https://security.microsoft.com/?hash=/threatexplorer?messageParams=d3d1ecd6-52e8-42a7-9029-08db7c7febfc,d3d1ecd6-52e8-42a7-9029-08db7c7febfc-4613299951868376388-1,2023-07-04T00:00:00,2023-07-04T23:59:59&view=Phish",
            "Id": "933c4e85-59d6-d6a0-635e-0df5985013ce",
            "InternetMessageId": "<202307041115.364BF5Xb008349@ip-172-31-44-193.eu-central-1.compute.internal>",
            "LatestDeliveryLocation": "JunkFolder",
            "MessageTime": "2023-07-04T11:15:13",
            "NetworkMessageId": "d3d1ecd6-52e8-42a7-9029-08db7c7febfc",
            "ObjectId": "d3d1ecd6-52e8-42a7-9029-08db7c7febfc46132999518683763881",
            "Operation": "TIMailData",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "OriginalDeliveryLocation": "JunkFolder",
            "P1Sender": "splunk@ip-172-31-44-193.eu-central-1.compute.internal",
            "P2Sender": "splunk@ip-172-31-44-193.eu-central-1.compute.internal",
            "PhishConfidenceLevel": "Normal",
            "Policy": "Spoof",
            "PolicyAction": "MoveToJmf",
            "Recipients": [
                "avishai@demistodev.onmicrosoft.com"
            ],
            "RecordType": 28,
            "SenderIp": "18.197.250.188",
            "Subject": "Splunk Report: High Or Critical Priority Host With Malware - 15 min",
            "SystemOverrides": [],
            "ThreatsAndDetectionTech": [
                "Phish: [Spoof external domain]",
                "Spam: [Advanced filter]"
            ],
            "UserId": "ThreatIntel",
            "UserKey": "ThreatIntel",
            "UserType": 4,
            "Verdict": "Phish",
            "Version": 1,
            "Workload": "ThreatIntelligence"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:15:25",
            "DataType": "Alert",
            "Id": "d68f3496-acde-4263-74d9-08db7c7ff725",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T09:44:52Z%20and%20createdDateTime%20lt%202023-07-04T09:45:24Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:14:53",
            "DataType": "Alert",
            "Id": "f722952f-e86d-4d70-415e-08db7c7fe47f",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T09:44:21Z%20and%20createdDateTime%20lt%202023-07-04T09:44:52Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:13:28",
            "DataType": "Alert",
            "Id": "510c9c2b-2eb1-4276-ab36-08db7c7fb167",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T09:42:55Z%20and%20createdDateTime%20lt%202023-07-04T09:43:27Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        },
        {
            "AadAppId": "1e4f0464-a39c-4898-b443-bfa375c50cc1",
            "CreationTime": "2023-07-04T11:12:56",
            "DataType": "Alert",
            "Id": "b829290a-df51-44a0-7a37-08db7c7f9eb3",
            "Operation": "Search",
            "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "RecordType": 52,
            "RelativeUrl": "/DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023-07-04T09:42:24Z%20and%20createdDateTime%20lt%202023-07-04T09:42:55Z&$orderby=lastModifiedDateTime%20desc",
            "ResultCount": "0",
            "UserId": "NOT-FOUND",
            "UserKey": "0000000000000000",
            "UserType": 5,
            "Version": 1,
            "Workload": "SecurityComplianceCenter"
        }
    ]
}
```

#### Human Readable Output

>### Audit log from 07/01/2023 12:10:35 to 07/04/2023 12:10:35
>| AadAppId | CreationTime | DataType | Id | Operation | OrganizationId | RecordType | RelativeUrl | ResultCount | UserId | UserKey | UserType | Version | Workload
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:37:30" | Alert | 000d975e\-dda0\-418e\-7379\-08db7c830cd4 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T10:06:57Z%20and%20createdDateTime%20lt%202023\-07\-04T10:07:28Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:36:13" | Alert | 0d753828\-3bf8\-46eb\-2f3d\-08db7c82df05 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T10:05:40Z%20and%20createdDateTime%20lt%202023\-07\-04T10:06:11Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:33:49" | Alert | a3766fb6\-4f7a\-4ba3\-26e7\-08db7c828997 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T10:03:17Z%20and%20createdDateTime%20lt%202023\-07\-04T10:03:48Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:20:20" | Alert | 77afbaf5\-f267\-49c0\-a27e\-08db7c80a713 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T09:49:47Z%20and%20createdDateTime%20lt%202023\-07\-04T09:50:19Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:16:59" | Alert | 7fedddc9\-a876\-41b7\-4281\-08db7c802f88 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T09:46:27Z%20and%20createdDateTime%20lt%202023\-07\-04T09:46:58Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| "OriginalDelivery: \[N/A\]" | \{"FileName":"High\_Or\_Critical\_Priority\_Host\_With\_Malware\_\-\_15\_m\-2023\-07\-04.csv","FileType":"txt;text","FileVerdict":0,"SHA256":"DEB083C07B5A3E9F6542A253931D1343403AD10EDC1F770DB309FB69064230C7"\} | \[\{"Name":"SPF","Value":"None"\},\{"Name":"DKIM","Value":"None"\},\{"Name":"DMARC","Value":"None"\},\{"Name":"Comp Auth","Value":"fail"\}\] | "2023\-07\-04T11:16:04" | DeliveredAsSpam | Spoof external domain | Inline | Inbound | https:<span>//</span>security.microsoft.com/?hash=/threatexplorer?messageParams=d3d1ecd6\-52e8\-42a7\-9029\-08db7c7febfc,d3d1ecd6\-52e8\-42a7\-9029\-08db7c7febfc\-4613299951868376388\-1,2023\-07\-04T00:00:00,2023\-07\-04T23:59:59&view=Phish | 933c4e85\-59d6\-d6a0\-635e\-0df5985013ce | <202307041115.364BF5Xb008349@ip\-172\-31\-44\-193.eu\-central\-1.compute.internal> | JunkFolder | "2023\-07\-04T11:15:13" | d3d1ecd6\-52e8\-42a7\-9029\-08db7c7febfc | d3d1ecd6\-52e8\-42a7\-9029\-08db7c7febfc46132999518683763881 | TIMailData | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | JunkFolder | splunk@ip\-172\-31\-44\-193.eu\-central\-1.compute.internal | splunk@ip\-172\-31\-44\-193.eu\-central\-1.compute.internal | Normal | Spoof | MoveToJmf | "avishai@demistodev.onmicrosoft.com" | 28 | 18.197.250.188 | Splunk Report: High Or Critical Priority Host With Malware \- 15 min | \["Phish: \[Spoof external domain\]","Spam: \[Advanced filter\]"\] | ThreatIntel | ThreatIntel | 4 | Phish | 1 | ThreatIntelligence
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:15:25" | Alert | d68f3496\-acde\-4263\-74d9\-08db7c7ff725 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T09:44:52Z%20and%20createdDateTime%20lt%202023\-07\-04T09:45:24Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:14:53" | Alert | f722952f\-e86d\-4d70\-415e\-08db7c7fe47f | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T09:44:21Z%20and%20createdDateTime%20lt%202023\-07\-04T09:44:52Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:13:28" | Alert | 510c9c2b\-2eb1\-4276\-ab36\-08db7c7fb167 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T09:42:55Z%20and%20createdDateTime%20lt%202023\-07\-04T09:43:27Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter
>| 1e4f0464\-a39c\-4898\-b443\-bfa375c50cc1 | "2023\-07\-04T11:12:56" | Alert | b829290a\-df51\-44a0\-7a37\-08db7c7f9eb3 | Search | ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999 | 52 | /DataInsights/security/alerts?$top=200&$filter=createdDateTime%20ge%202023\-07\-04T09:42:24Z%20and%20createdDateTime%20lt%202023\-07\-04T09:42:55Z&$orderby=lastModifiedDateTime%20desc | 0 | NOT\-FOUND | 0000000000000000 | 5 | 1 | SecurityComplianceCenter


#### Command example
```!o365-auditlog-search start_date="3 days" result_size=5 ip_addresses="8.8.8.8,8.4.4.8"```
#### Human Readable Output

>Audit log from 07/01/2023 12:10:52 to 07/04/2023 12:10:52 is empty

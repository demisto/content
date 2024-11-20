Use the integration to get logs from the O365 service.
## Configure Microsoft Policy And Compliance (Audit Log) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Exchange Online URL |  | True |
| Certificate | A pfx certificate encoded in Base64. | True |
| Password |  | True |
| The organization used in app-only authentication. |  | True |
| The application ID from the Azure portal |  | True |


## Required Permissions To Search Audit Logs
- The minimum required Exchange permissions are **Audit Logs** or **View-Only Audit Logs**.
- Go to [The Microsoft Admin Portal](https://admin.microsoft.com/Adminportal#/homepage).
- Click **Show All** --> **Roles** --> **Roles Assignments** --> **Exchange section**.
- Click **Add role group** --> Choose the name and description --> Select the **Audit Logs** or **View-Only Audit Logs** roles --> Select the members to apply the role(s) to --> Click **Add role group**.
- For more information --> [How to assign permissions to search the audit log](https://docs.microsoft.com/en-us/microsoft-365/compliance/set-up-basic-audit?view=o365-worldwide#step-2-assign-permissions-to-search-the-audit-log).

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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


#### Command Example
```!o365-auditlog-search start_date="01/01/21" end_date="01/02/21" result_size=1```

#### Context Example
```json
{
    "O365AuditLog": {
        "Actor": [
            {
                "ID": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "Type": 0
            },
            {
                "ID": "user@example.com",
                "Type": 5
            }
        ],
        "ActorContextId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
        "ActorIpAddress": "ClientIP",
        "ApplicationId": "00000002-0000-0ff1-ce00-000000000000",
        "AzureActiveDirectoryEventType": 1,
        "ClientIP": "ClientIP",
        "CreationTime": "2021-01-01T23:59:56",
        "ExtendedProperties": [
            {
                "Name": "UserAgent",
                "Value": "python-requests/2.18.4"
            },
            {
                "Name": "UserAuthenticationMethod",
                "Value": "1"
            },
            {
                "Name": "RequestType",
                "Value": "OAuth2:Token"
            },
            {
                "Name": "ResultStatusDetail",
                "Value": "UserError"
            },
            {
                "Name": "KeepMeSignedIn",
                "Value": "false"
            }
        ],
        "Id": "8133912e-b888-4849-b8fb-070710b35400",
        "InterSystemsId": "4bf55773-4137-4d68-b7f8-ef8ef9c0235f",
        "IntraSystemId": "8133912e-b888-4849-b8fb-070710b35400",
        "LogonError": "InvalidUserNameOrPassword",
        "ModifiedProperties": [],
        "ObjectId": "00000002-0000-0ff1-ce00-000000000000",
        "Operation": "UserLoginFailed",
        "OrganizationId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
        "RecordType": 15,
        "ResultStatus": "Failed",
        "SupportTicketId": "",
        "Target": [
            {
                "ID": "00000002-0000-0ff1-ce00-000000000000",
                "Type": 0
            }
        ],
        "TargetContextId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
        "UserId": "user@example.com",
        "UserKey": "user@example.com",
        "UserType": 0,
        "Version": 1,
        "Workload": "AzureActiveDirectory"
    }
}
```

#### Human Readable Output

>### Audit log from 01/01/2021 00:00:00 to 01/02/2021 00:00:00
>| Actor | ActorContextId | ActorIpAddress | ApplicationId | AzureActiveDirectoryEventType | ClientIP | CreationTime | ExtendedProperties | Id | InterSystemsId | IntraSystemId | LogonError | ModifiedProperties | ObjectId | Operation | OrganizationId | RecordType | ResultStatus | SupportTicketId | Target | TargetContextId | UserId | UserKey | UserType | Version | Workload
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| \[\{"ID":"ID","Type":0\},\{"ID":"user@example.com","Type":5\}\] | "ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999" | "ClientIP" | "00000002\-0000\-0ff1\-ce00\-000000000000" | 1 | "ClientIP" | \{"value":"2021\-01\-01T23:59:56","DateTime":"Friday, January 1, 2021 11:59:56 PM"\} | \[\{"Name":"UserAgent","Value":"python\-requests/2.18.4"\},\{"Name":"UserAuthenticationMethod","Value":"1"\},\{"Name":"RequestType","Value":"OAuth2:Token"\},\{"Name":"ResultStatusDetail","Value":"UserError"\},\{"Name":"KeepMeSignedIn","Value":"false"\}\] | "8133912e\-b888\-4849\-b8fb\-070710b35400" | "4bf55773\-4137\-4d68\-b7f8\-ef8ef9c0235f" | "8133912e\-b888\-4849\-b8fb\-070710b35400" | "InvalidUserNameOrPassword" | "00000002\-0000\-0ff1\-ce00\-000000000000" | "UserLoginFailed" | "ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999" | 15 | "Failed" | "" | \{"ID":"00000002\-0000\-0ff1\-ce00\-000000000000","Type":0\} | "ebac1a16\-81bf\-449b\-8d43\-5732c3c1d999" | "user@example.com" | "user@example.com" | 0 | 1 | "AzureActiveDirectory"

Deprecated. Use ***EWS Extension Online Powershell v3*** instead.

Use the EWS Extension Online Powershell v2 integration to get information about mailboxes and users in your organization.
This integration was integrated and tested with version v2 of EWS Extension Online Powershell v2

**Note:** This integration does not replace the **O365 - EWS - Extension** integration, but an additional EWS extension integration
which utilizes the [EXO v2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps).

## Configure EWS Extension Online Powershell v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Exchange Online URL |  | True |
| Certificate | A pfx certificate encoded in Base64. | True |
| The organization used in app-only authentication. |  | True |
| The application ID from the Azure portal |  | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ews-mailbox-list
***
Displays mailbox objects and attributes, populate property pages, or supplies mailbox information to other tasks.


#### Base Command

`ews-mailbox-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the mailbox you want to view. | Optional | 
| organizational_unit | The object's location in Active Directory by which to filter the results. | Optional | 
| primary_smtp_address | The primary SMTP email address of the mailbox you want to view. Cannot be used with the user_principal_name argument. Can be retrieved using the ews-user-list command. | Optional | 
| user_principal_name | The UPN of the mailbox you want to view. Cannot be used with the primary_smtp_address argument. Can be retrieved using the ews-user-list command. | Optional | 
| property_sets | A comma-separated list of property sets to fetch. These property sets will supplement the outputs of this integration. Default is "Minimum".  Available properties are: "All", "Minimum", "AddressList", "Archive", "Audit", "Delivery", "Hold", "Moderation", "Move", "Policy", "PublicFolder", "Quota", "Resource", "Retention", "SCL", "SoftDelete", "StatisticsSeed". | Optional
| limit | The maximum number of results to retrieve. Default is 10. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Mailbox.EmailAddresses | String | Email addresses of the mailbox. | 
| EWS.Mailbox.AuditBypassEnabled | Boolean | Whether audit bypass is enabled. | 
| EWS.Mailbox.DistinguishedName | String | Distinguished name of the mailbox. | 
| EWS.Mailbox.ExchangeObjectId | String | Exchange object ID of the mailbox. | 
| EWS.Mailbox.ExchangeVersion | String | Exchange version of the mailbox. | 
| EWS.Mailbox.Guid | String | GUID of the mailbox. | 
| EWS.Mailbox.Id | String | ID of the mailbox. | 
| EWS.Mailbox.Identity | String | Identity of the mailbox. | 
| EWS.Mailbox.IsValid | Boolean | Whether the mailbox is valid. | 
| EWS.Mailbox.Name | String | Name of the mailbox. | 
| EWS.Mailbox.ObjectCategory | String | Object category of the mailbox. | 
| EWS.Mailbox.ObjectClass | String | Object class of the mailbox. | 
| EWS.Mailbox.ObjectId | String | Object ID of the of the mailbox. | 
| EWS.Mailbox.ObjectState | String | Object state of the mailbox. | 
| EWS.Mailbox.OrganizationId | String | Organization ID of the mailbox. | 
| EWS.Mailbox.OriginatingServer | String | Originating server of the mailbox. | 
| EWS.Mailbox.PSComputerName | String | PowerShell computer name of the mailbox. | 
| EWS.Mailbox.PSShowComputerName | Boolean | PowerShell show computer name of the mailbox. | 
| EWS.Mailbox.RunspaceId | String | Run space ID of the mailbox. | 
| EWS.Mailbox.WhenChanged | Date | Local time of when the mailbox was last changed. | 
| EWS.Mailbox.WhenChangedUTC | Date | UTC time of when the mailbox was last changed. | 
| EWS.Mailbox.WhenCreated | Date | Local time of when the mailbox was created. | 
| EWS.Mailbox.WhenCreatedUTC | Date | UTC time of when the mailbox was created. | 


#### Command Example
```!ews-mailbox-list limit=1```

#### Context Example
```json
{
    "EWS": {
        "Mailbox": {
            "Alias": "user",
            "DisplayName": "User User",
            "DistinguishedName": "CN=user,OU=example.com,OU=Microsoft Exchange Hosted Organizations,DC=EURPR07A005,DC=PROD,DC=OUTLOOK,DC=COM",
            "EmailAddresses": [
                "SPO:SPO_SPO0@SPO_SPO1",
                "SIP:user@example.com",
                "SMTP:user@example.com"
            ],
            "ExchangeVersion": "0.20 (15.0.0)",
            "ExternalDirectoryObjectId": "<ExternalDirectoryObjectId>",
            "Guid": "<Guid>",
            "Id": "user",
            "Identity": "user",
            "Name": "user",
            "OrganizationId": "EURPR07A005.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/example.com - EURPR07A005.PROD.OUTLOOK.COM/ConfigurationUnits/example.com/Configuration",
            "PrimarySmtpAddress": "user@example.com",
            "RecipientType": "UserMailbox",
            "RecipientTypeDetails": "UserMailbox",
            "UserPrincipalName": "user@example.com"
        }
    }
}
```

#### Human Readable Output

>### Results of ews-mailbox-list
>| Alias | DisplayName | DistinguishedName | EmailAddresses | ExchangeVersion | ExternalDirectoryObjectId | Guid | Id | Identity | Name | OrganizationId | PrimarySmtpAddress | RecipientType | RecipientTypeDetails | UserPrincipalName
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| "user" | "User User" | "CN=user,OU=example.com,OU=Microsoft Exchange Hosted Organizations,DC=EURPR07A005,DC=PROD,DC=OUTLOOK,DC=COM" | \["SPO:SPO\_cac4b654\-5fcf\-44f0\-818e\-479cf8ae42ac@SPO\_SP01","SIP:user@example.com","SMTP:user@example.com"\] | "0.20 \(15.0.0\)" | "3fa9f28b\-eb0e\-463a\-ba7b\-8089fe9991e2" | \{"value":"042e60ea\-0683\-41a2\-a149\-ca4b682dcdda","Guid":"042e60ea\-0683\-41a2\-a149\-ca4b682dcdda"\} | "user" | "user" | "user" | "EURPR07A005.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/example.com \- EURPR07A005.PROD.OUTLOOK.COM/ConfigurationUnits/example.com/Configuration" | "user@example.com" | "UserMailbox" | "UserMailbox" | "user@example.com"


### ews-cas-mailbox-list
***
Displays Client Access settings that are configured on mailboxes.


#### Base Command

`ews-cas-mailbox-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the mailbox you want to view. | Optional | 
| organizational_unit | The object's location in Active Directory by which to filter the results. | Optional | 
| primary_smtp_address | The primary SMTP email address of the mailbox you want to view. Cannot be used with the user_principal_name argument. Can be retrieved using the ews-user-list command. | Optional | 
| user_principal_name | The UPN of the mailbox you want to view. Cannot be used with the primary_smtp_address argument. Can be retrieved using the ews-user-list command. | Optional | 
| limit | The maximum number of results to retrieve. Default is 10. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.CASMailbox.ActiveSyncEnabled | Boolean | Whether active sync is enabled. | 
| EWS.CASMailbox.DisplayName | String | The display name of the mailbox. | 
| EWS.CASMailbox.ECPEnabled | Boolean | Whether the Exchange Control Panel \(ECP\) is enabled. | 
| EWS.CASMailbox.EmailAddresses | String | The email addresses retrieved. | 
| EWS.CASMailbox.EwsEnabled | Boolean | Whether the Exchange Web Services \(EWS\) is enabled. | 
| EWS.CASMailbox.ExchangeVersion | String | Exchange version of the client access server mailbox. | 
| EWS.CASMailbox.ExternalDirectoryObjectId | String | External directory object ID of the client access server mailbox. | 
| EWS.CASMailbox.Guid | String | The GUID of the client access server mailbox. | 
| EWS.CASMailbox.Identity | String | Identity of the client access server mailbox. | 
| EWS.CASMailbox.ImapEnabled | Boolean | Whether the Internet Message Access Protocol \(IMAP\) is enabled. | 
| EWS.CASMailbox.MAPIEnabled | Boolean | Whether the Messaging Application Programming Interface is enabled. | 
| EWS.CASMailbox.Name | String | Name of the client access server mailbox. | 
| EWS.CASMailbox.OWAEnabled | Boolean | Whether Outlook on the web \(OWA\) is enabled. | 
| EWS.CASMailbox.OrganizationId | String | Organization ID | 
| EWS.CASMailbox.PopEnabled | Boolean | Whether Post Office Protocol \(POP\) is enabled. | 
| EWS.CASMailbox.PrimarySmtpAddress | String | Primary SMTP address. | 
| EWS.CASMailbox.ServerLegacyDN | String | Server legacy distinguished name \(DN\). | 


#### Command Example
```!ews-cas-mailbox-list limit=1```

#### Context Example
```json
{
    "EWS": {
        "CASMailbox": {
            "ActiveSyncEnabled": true,
            "DisplayName": "User User",
            "ECPEnabled": true,
            "EmailAddresses": [
                "SPO:SPO_SPO0@SPO_SPO1",
                "SIP:user@example.com",
                "SMTP:user@example.com"
            ],
            "EwsEnabled": true,
            "ExchangeVersion": "0.20 (15.0.0)",
            "ExternalDirectoryObjectId": "<ExternalDirectoryObjectId>",
            "Guid": "<Guid>",
            "Identity": "user",
            "ImapEnabled": true,
            "MAPIEnabled": true,
            "Name": "user",
            "OWAEnabled": true,
            "OrganizationId": "EURPR07A005.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/example.com - EURPR07A005.PROD.OUTLOOK.COM/ConfigurationUnits/example.com/Configuration",
            "PopEnabled": true,
            "PrimarySmtpAddress": "user@example.com",
            "ServerLegacyDN": "/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=DBXPR07MB383"
        }
    }
}
```

#### Human Readable Output

>### Results of ews-cas-mailbox-list
>| ActiveSyncEnabled | DisplayName | ECPEnabled | EmailAddresses | EwsEnabled | ExchangeVersion | ExternalDirectoryObjectId | Guid | Identity | ImapEnabled | MAPIEnabled | Name | OrganizationId | OWAEnabled | PopEnabled | PrimarySmtpAddress | ServerLegacyDN
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| true | "User User" | true | \["SPO:SPO\_cac4b654\-5fcf\-44f0\-818e\-479cf8ae42ac@SPO\_SP01","SIP:user@example.com","SMTP:user@example.com"\] | true | "0.20 \(15.0.0\)" | "3fa9f28b\-eb0e\-463a\-ba7b\-8089fe9991e2" | \{"value":"042e60ea\-0683\-41a2\-a149\-ca4b682dcdda","Guid":"042e60ea\-0683\-41a2\-a149\-ca4b682dcdda"\} | "user" | true | true | "user" | "EURPR07A005.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/example.com \- EURPR07A005.PROD.OUTLOOK.COM/ConfigurationUnits/example.com/Configuration" | true | true | "user@example.com" | "/o=ExchangeLabs/ou=Exchange Administrative Group \(FYDIBOHF23SPDLT\)/cn=Configuration/cn=Servers/cn=DBXPR07MB383

### ews-mailbox-permission-list
***
Retrieves permissions on a mailbox.


#### Base Command

`ews-mailbox-permission-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the mailbox you want to view. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.MailboxPermission.Identity | String | The specified identity of the mailbox. | 
| EWS.MailboxPermission.Permission.AccessRights | String | Access rights of the mailbox. | 
| EWS.MailboxPermission.Permission.Deny.IsPresent | Boolean | Whether permission is denied. | 
| EWS.MailboxPermission.Permission.Identity | String | The permission identity. | 
| EWS.MailboxPermission.Permission.InheritanceType | String | Permission inheritance type. | 
| EWS.MailboxPermission.Permission.IsInherited | Boolean | Whether permission is inherited. | 
| EWS.MailboxPermission.Permission.User | String | The permission of the user. | 


#### Command Example
```!ews-mailbox-permission-list identity=user```

#### Context Example
```json
{
    "EWS": {
        "MailboxPermission": {
            "Identity": "user",
            "Permission": {
                "AccessRights": [
                    "FullAccess",
                    "ReadPermission"
                ],
                "Deny": {
                    "IsPresent": false
                },
                "Identity": "user",
                "InheritanceType": "All",
                "IsInherited": false,
                "User": "NT AUTHORITY\\SELF"
            }
        }
    }
}
```

#### Human Readable Output

>### Results of ews-mailbox-permission-list
>| AccessRights | Deny | Identity | InheritanceType | IsInherited | User
>| --- | --- | --- | --- | --- | ---
>| \["FullAccess","ReadPermission"\] | \{"IsPresent":false\} | "user" | "All" | false | "NT AUTHORITY\\SELF"

### ews-recipient-permission-list
***
Displays information about SendAs permissions that are configured for users.


#### Base Command

`ews-recipient-permission-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the mailbox you want to view. | Optional | 
| limit | The maximum number of results to retrieve. Default is 10. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.RecipientPermission.AccessControlType | String | Access control type of the recipient permission. | 
| EWS.RecipientPermission.AccessRights | Number | Access rights of the recipient permission. | 
| EWS.RecipientPermission.Identity | String | Identity of the recipient permission. | 
| EWS.RecipientPermission.InheritanceType | String | Inheritance type of the recipient permission. | 
| EWS.RecipientPermission.IsInherited | Boolean | Whether the recipient permission is inherited. | 
| EWS.RecipientPermission.Trustee | String | Trustee of the recipient permission. | 


#### Command Example
```!ews-recipient-permission-list identity=<Guid>```

#### Context Example
```json
{
    "EWS": {
        "RecipientPermission": {
            "AccessControlType": "Allow",
            "AccessRights": [
                1
            ],
            "Identity": "user",
            "InheritanceType": "None",
            "IsInherited": false,
            "Trustee": "NT AUTHORITY\\SELF"
        }
    }
}
```

#### Human Readable Output

>### Results of ews-mailbox-permission-list
>| AccessRights | Deny | Identity | InheritanceType | IsInherited | User
>| --- | --- | --- | --- | --- | ---
>| \["FullAccess","ReadPermission"\] | \{"IsPresent":false\} | "user" | "All" | false | "NT AUTHORITY\\SELF"

### ews-recipient-list
***
Displays existing recipient objects in your organization. This command returns all mail-enabled objects (for example, mailboxes, mail users, mail contacts, and distribution groups).


#### Base Command

`ews-recipient-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the mailbox you want to view. | Optional | 
| limit | The maximum number of results to retrieve. Default is 10. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Recipient.Alias | String | Recipient alias. | 
| EWS.Recipient.DisplayName | String | Recipient display name. | 
| EWS.Recipient.DistinguishedName | String | Recipient distinguished name. | 
| EWS.Recipient.EmailAddresses | String | Recipient email addresses. | 
| EWS.Recipient.ExchangeVersion | String | Recipient exchange version. | 
| EWS.Recipient.ExternalDirectoryObjectId | String | Recipient external directory object ID. | 
| EWS.Recipient.Identity | String | Recipient identity. | 
| EWS.Recipient.Name | String | Recipient name. | 
| EWS.Recipient.OrganizationId | String | Recipient organization ID. | 
| EWS.Recipient.PrimarySmtpAddress | String | Recipient primary SMTP address. | 
| EWS.Recipient.RecipientType | String | Recipient type. | 
| EWS.Recipient.RecipientTypeDetails | String | Recipient type details. | 


#### Command Example
```!ews-recipient-list identity=<ExternalDirectoryObjectId>```

#### Context Example
```json
{
    "EWS": {
        "Recipient": {
            "Alias": "user",
            "DisplayName": "User User",
            "DistinguishedName": "CN=user,OU=example.com,OU=Microsoft Exchange Hosted Organizations,DC=EURPR07A005,DC=PROD,DC=OUTLOOK,DC=COM",
            "EmailAddresses": [
                "SPO:SPO_SPO0@SPO_SPO1",
                "SIP:user@example.com",
                "SMTP:user@example.com"
            ],
            "ExchangeVersion": "0.20 (15.0.0)",
            "ExternalDirectoryObjectId": "<ExternalDirectoryObjectId>",
            "Identity": "user",
            "Name": "user",
            "OrganizationId": "EURPR07A005.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/example.com - EURPR07A005.PROD.OUTLOOK.COM/ConfigurationUnits/example.com/Configuration",
            "PrimarySmtpAddress": "user@example.com",
            "RecipientType": "UserMailbox",
            "RecipientTypeDetails": "UserMailbox"
        }
    }
}
```

#### Human Readable Output

>### Results of ews-recipient-list
>| Alias | DisplayName | DistinguishedName | EmailAddresses | ExchangeVersion | ExternalDirectoryObjectId | Identity | Name | OrganizationId | PrimarySmtpAddress | RecipientType | RecipientTypeDetails
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| "user" | "user" | "CN=user\_Identity,OU=example.com,OU=Microsoft Exchange Hosted Organizations,DC=EURPR07A005,DC=PROD,DC=OUTLOOK,DC=COM" | \["SPO:SPO\_SP00@SPO\_SP01","SMTP:user@example.com"\] | "0.10 \(14.0.100\)" | "Identity" | "user\_Identity" | "user\_Identity" | "EURPR07A005.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/example.com \- EURPR07A005.PROD.OUTLOOK.COM/ConfigurationUnits/example.com/Configuration" | "user@example.com" | "MailUniversalDistributionGroup" | "GroupMailbox"




### ews-new-tenant-allow-block-list-items
***
Add new items to the Tenant Allow/Block Lists.  Uses PowerShell New-TenantAllowBlockListItems cmdlet.

Official PowerShell cmdlet documentation [here](https://docs.microsoft.com/en-us/powershell/module/exchange/new-tenantallowblocklistitems?view=exchange-ps)


#### Base Command

`ews-new-tenant-allow-block-list-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entries | Entries to add to the list.  Separate multiple entries with a comma (e.g. "Item1,Item2"). | Required |
| list_type | List type to add items to. | Required |
| list_subtype | List subtype to add items to.  | Optional |
| action | Action to set for new entries | Required |
| notes | Notes to include on new list entries | Optional |
| expiration_date | Enter a specific date and time for the new entries to expire using format "YYYY-MM-DD HH:MM:SSz" for UTC time.  Alternately, a PowerShell **GetDate** statement can be used. | Optional |
| no_expiration | Specify whether to create list entries with no expiration date.  Cannot be used with "expiration_date".  If left false and no expiration date is set, default of 30 days will be used. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.NewTenantBlocks.Action | String | List type ('Block' or 'Allow') |
| EWS.NewTenantBlocks.EntryValueHash | String | Entry Value Hash |
| EWS.NewTenantBlocks.Error | String | Error (if any) returned by remote command |
| EWS.NewTenantBlocks.ExpirationDate | String | DateTime the entry will expire and be removed |
| EWS.NewTenantBlocks.Identity | String | Unique identifier for the entry |
| EWS.NewTenantBlocks.LastModifiedDateTime | String | DateTime of last modification |
| EWS.NewTenantBlocks.ListSubType | String | List sub type (Tenant or AdvancedDelivery) |
| EWS.NewTenantBlocks.ModifiedBy | String | User / App Registration which last modified this entry |
| EWS.NewTenantBlocks.Notes | String | Custom notes added to the entry. |
| EWS.NewTenantBlocks.ObjectState | String | State of the object (e.g. New/Modified/Deleted) |
| EWS.NewTenantBlocks.PSComputerName | String | Name of Remote Powershell endpoint |
| EWS.NewTenantBlocks.PSShowComputerName | Bool | Flag whether or not remote computer name is shown in PS prompt |
| EWS.NewTenantBlocks.RunspaceId | String | RunspaceID of the entry |
| EWS.NewTenantBlocks.SubmissionID | String | SubmissionID of the entry |
| EWS.NewTenantBlocks.SysManaged | Bool | SysManaged property of the entry |
| EWS.NewTenantBlocks.Value | String | The value of the new entry created |


#### Command Example
```!ews-new-tenant-allow-block-list-items action=Block list_type=sender entries="attacker@phishingsite.com" notes="Email observed in a phishing campaign."```

#### Context Example
```json
{
    "Action": "Block",
    "EntryValueHash": "d568L6iokOxrYqB2L1CxcKy6S6A/tCDoQQJal33AFWo=",
    "Error": null,
    "ExpirationDate": "2022-06-15T19:30:52.6071551Z",
    "Identity": "RgAAAAAuoyIuRcZsTKgZbIQyJWZUBwA02rlnO0nOR5RO-QI-xRP9AAAAAAEVAAA02rlnO0nOR5RO-QI-xRP9AAADfzPhAAAA0",
    "LastModifiedDateTime": "2022-05-16T19:30:52.7320883Z",
    "ListSubType": "Tenant",
    "ModifiedBy": "",
    "Notes": "Email observed in a phishing campaign.",
    "ObjectState": "New",
    "PSComputerName": "outlook.office365.com",
    "PSShowComputerName": false,
    "RunspaceId": "fe0186a8-6ce6-487d-bd65-a9869f60ffcd",
    "SubmissionID": "",
    "SysManaged": false,
    "Value": "attacker@phishingsite.com"
}
```

#### Human Readable Output

>### Results of ews-new-tenant-allow-block-list-items
| Action | EntryValueHash | Error | ExpirationDate | Identity | LastModifiedDateTime | ListSubType | ModifiedBy | Notes | ObjectState | PSComputerName | PSShowComputerName | RunspaceId | SubmissionID | SysManaged | Value
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
| Block | d568L6iokOxrYqB2L1CxcKy6S6A/tCDoQQJal33AFWo= |  | \{"value":"2022\-06\-15T19:34:01.2028448Z","DateTime":"Wednesday, June 15, 2022 7:34:01 PM"\} | RgAAAAAuoyIuRcZsTKgZbIQyJWZUBwA02rlnO0nOR5RO\-QI\-xRP9AAAAAAEVAAA02rlnO0nOR5RO\-QI\-xRP9AAADfzPiAAAA0 | \{"value":"2022\-05\-16T19:34:01.2652934Z","DateTime":"Monday, May 16, 2022 7:34:01 PM"\} | Tenant |  | Email observed in a phishing campaign. | New | outlook.office365.com | false | \{"value":"8f736b87\-f951\-4b6b\-aa21\-e358720c44e3","Guid":"8f736b87\-f951\-4b6b\-aa21\-e358720c44e3"\} |  | false | attacker@phishingsite.com



### ews-get-tenant-allow-block-list-items
***
Retrieve current Tenant Allow/Block List items.  Uses Get-TenantAllowBlockListItems cmdlet.

Official PowerShell cmdlet documentation [here](https://docs.microsoft.com/en-us/powershell/module/exchange/get-tenantallowblocklistitems?view=exchange-ps)


#### Base Command

`ews-get-tenant-allow-block-list-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | List type to retrieve items from. | Required |
| list_subtype | List subtype to retrieve items from.  | Optional |
| action | Action to filter entries by. | Required |
| expiration_date | Enter a specific date and time to filter entries by using format "YYYY-MM-DD HH:MM:SSz" for UTC time.  Alternately, a PowerShell **GetDate** statement can be used. | Optional |
| no_expiration | Filter list items that are set to never expire. | Optional |
| entry | Specif8ic entry value to retrieve. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.CurrentTenantBlocks.Action | String | List type ('Block' or 'Allow') |
| EWS.CurrentTenantBlocks.EntryValueHash | String | Entry Value Hash |
| EWS.CurrentTenantBlocks.Error | Bool | Error (if any) returned by remote command |
| EWS.CurrentTenantBlocks.ExpirationDate | String | DateTime the entry will expire and be removed |
| EWS.CurrentTenantBlocks.Identity | String | Unique identifier for the entry |
| EWS.CurrentTenantBlocks.LastModifiedDateTime | String | DateTime of last modification |
| EWS.CurrentTenantBlocks.ListSubType | String | List sub type (Tenant or AdvancedDelivery) |
| EWS.CurrentTenantBlocks.ModifiedBy | String | User / App Registration which last modified this entry |
| EWS.CurrentTenantBlocks.Notes | String | Custom notes added to the entry. |
| EWS.CurrentTenantBlocks.ObjectState | String | State of the object (e.g. New/Modified/Deleted) |
| EWS.CurrentTenantBlocks.PSComputerName | String | Name of Remote Powershell endpoint |
| EWS.CurrentTenantBlocks.PSShowComputerName | Bool | Flag whether or not remote computer name is shown in PS prompt |
| EWS.CurrentTenantBlocks.RunspaceId | String | RunspaceID of the entry |
| EWS.CurrentTenantBlocks.SubmissionID | String | SubmissionID of the entry |
| EWS.CurrentTenantBlocks.SysManaged | Bool | SysManaged property of the entry |
| EWS.CurrentTenantBlocks.Value | String | The value of the new entry created |


#### Command Example
```!ews-get-tenant-allow-block-list-items action=Block list_type=sender```

#### Context Example
```json
[
    {
        "Action": "Block",
        "EntryValueHash": "d568L6iokOxrYqB2L1CxcKy6S6A/tCDoQQJal33AFWo=",
        "Error": null,
        "ExpirationDate": "2022-06-15T19:34:01.2028448Z",
        "Identity": "RgAAAAAuoyIuRcZsTKgZbIQyJWZUBwA02rlnO0nOR5RO-QI-xRP9AAAAAAEVAAA02rlnO0nOR5RO-QI-xRP9AAADfzPiAAAA0",
        "LastModifiedDateTime": "2022-05-16T19:34:01.2652934Z",
        "ListSubType": "Tenant",
        "ModifiedBy": "",
        "Notes": "Email observed in a phishing campaign.",
        "ObjectState": "Unchanged",
        "PSComputerName": "outlook.office365.com",
        "PSShowComputerName": false,
        "RunspaceId": "010da4cf-2d47-4b8a-a882-4bd6885faff1",
        "SubmissionID": "",
        "SysManaged": false,
        "Value": "attacker@phishingsite.com"
    }
]
```

#### Human Readable Output
### Results of ews-get-tenant-allow-block-list-items
| Action | EntryValueHash | Error | ExpirationDate | Identity | LastModifiedDateTime | ListSubType | ModifiedBy | Notes | ObjectState | PSComputerName | PSShowComputerName | RunspaceId | SubmissionID | SysManaged | Value
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
| Block | d568L6iokOxrYqB2L1CxcKy6S6A/tCDoQQJal33AFWo= |  | \{"value":"2022\-06\-15T19:34:01.2028448Z","DateTime":"Wednesday, June 15, 2022 7:34:01 PM"\} | RgAAAAAuoyIuRcZsTKgZbIQyJWZUBwA02rlnO0nOR5RO\-QI\-xRP9AAAAAAEVAAA02rlnO0nOR5RO\-QI\-xRP9AAADfzPiAAAA0 | \{"value":"2022\-05\-16T19:34:01.2652934Z","DateTime":"Monday, May 16, 2022 7:34:01 PM"\} | Tenant |  | Email observed in a phishing campaign. | Unchanged | outlook.office365.com | false | \{"value":"feada07c\-99b7\-48e9\-a562\-a755073522ff","Guid":"feada07c\-99b7\-48e9\-a562\-a755073522ff"\} |  | false | attacker@phishingsite.com


### ews-get-tenant-allow-block-list-count
***
Retrieve current count of defined Tenant Allow/Block List items.  Uses Get-TenantAllowBlockListItems cmdlet.

Official PowerShell cmdlet documentation [here](https://docs.microsoft.com/en-us/powershell/module/exchange/get-tenantallowblocklistitems?view=exchange-ps)


#### Base Command

`ews-get-tenant-allow-block-list-count`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | List type to retrieve items from. | Optional |
| list_subtype | List subtype to retrieve items from. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.CurrentListCount.Count | Number | Number of entries presently in the specified list |
| EWS.CurrentListCount.ListSubType | String | List sub type (Tenant or AdvancedDelivery) |
| EWS.CurrentListCount.ListType | String | List type |


#### Command Example
```!ews-get-tenant-allow-block-list-count list_type=sender```

#### Context Example
```json
{
    "Count": 2,
    "ListSubType": "Tenant",
    "ListType": "sender"
}
```

#### Human Readable Output
### Results of ews-get-tenant-allow-block-list-count
| Count | ListSubType | ListType
| --- | --- | ---
| 2 | Tenant | sender


### ews-remove-tenant-allow-block-list-items
***
Remove items from the Tenant Allow/Block Lists.   You can delete items by their value or by unique ID.  Uses PowerShell cmdlet Remove-TenantAllowBlockListItems cmdlet.

Official PowerShell cmdlet documentation [here](https://docs.microsoft.com/en-us/powershell/module/exchange/remove-tenantallowblocklistitems?view=exchange-ps)


#### Base Command

`ews-remove-tenant-allow-block-list-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entries | Entries to remove from the list.  Either use this OR 'ids' to specify items to remove.  Separate multiple entries with a comma (e.g. "Item1,Item2"). | Optional |
| ids | Entry IDs to remove from the list.  Either use this OR 'entries' to specify items to remove.  Separate multiple entries with a comma (e.g. "Item1,Item2"). | Optional |
| list_type | List type to remove items from. | Required |
| list_subtype | List subtype to remove items from. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.RemovedTenantBlocks.Action | String | Action |
| EWS.RemovedTenantBlocks.EntryValueHash | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.Error | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.ExpirationDate | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.Identity | String | Blank for deleted items. |
| EWS.RemovedTenantBlocks.LastModifiedDateTime | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.ListSubType | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.ModifiedBy | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.Notes | String | Null for deleted items. |
| EWS.RemovedTenantBlocks.ObjectState | String | State of the object (Deleted) |
| EWS.RemovedTenantBlocks.PSComputerName | String | Name of Remote Powershell endpoint |
| EWS.RemovedTenantBlocks.PSShowComputerName | Bool | Flag whether or not remote computer name is shown in PS prompt |
| EWS.RemovedTenantBlocks.RunspaceId | String | RunspaceID of the entry |
| EWS.RemovedTenantBlocks.SubmissionID | String | SubmissionID of the entry |
| EWS.RemovedTenantBlocks.SysManaged | Bool | SysManaged property of the entry |
| EWS.RemovedTenantBlocks.Value | String | The value of the entry that was removed |

#### Command Example
```!ews-remove-tenant-allow-block-list-items list_type=sender entries="attacker2@phishingsite.com"```

#### Context Example
```json
{
    "Action": "0",
    "EntryValueHash": null,
    "Error": null,
    "ExpirationDate": null,
    "Identity": "",
    "LastModifiedDateTime": null,
    "ListSubType": null,
    "ModifiedBy": null,
    "Notes": null,
    "ObjectState": "Deleted",
    "PSComputerName": "outlook.office365.com",
    "PSShowComputerName": false,
    "RunspaceId": "efa88be5-7342-4b77-af2f-99dd2d914300",
    "SubmissionID": null,
    "SysManaged": null,
    "Value": "attacker2@phishingsite.com"
}
```

#### Human Readable Output
### Results of ews-remove-tenant-allow-block-list-items
| Action | EntryValueHash | Error | ExpirationDate | Identity | LastModifiedDateTime | ListSubType | ModifiedBy | Notes | ObjectState | PSComputerName | PSShowComputerName | RunspaceId | SubmissionID | SysManaged | Value
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
| 0 |  |  |  |  |  |  |  |  | Deleted | outlook.office365.com | false | \{"value":"cd58060e\-d033\-4cdb\-814e\-9f9748fdf78c","Guid":"cd58060e\-d033\-4cdb\-814e\-9f9748fdf78c"\} |  |  | attacker@phishingsite.com
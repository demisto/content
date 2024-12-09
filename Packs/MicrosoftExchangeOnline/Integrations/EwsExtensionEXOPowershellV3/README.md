Use the EWS Extension Online Powershell v3 integration to get information about mailboxes and users in your organization.
This integration was integrated and tested with version v3 of EWS Extension Online Powershell v3

**Note:** This integration does not replace the **O365 - EWS - Extension** integration, but an additional EWS extension integration
which utilizes the [EXO v3 module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps).

## Configure EWS Extension Online Powershell v3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | The name of the integration | True |
| Exchange Online URL | https://outlook.office365.com | True |
| Certificate | A txt certificate encoded in Base64. | True |
| The organization used in app-only authentication. |  | True |
| The application ID from the Azure portal |  | True |



### Important Notes
---
* It is strongly recommended to follow the [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide), to prevent the docker container from utilizing excessive memory. Details about the known memory leak can be found [here](https://github.com/MicrosoftDocs/office-docs-powershell/issues/6924).
* If your instance does experience memory management issues, please configure your playbooks to use *Retry on error*.

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
>| Action | EntryValueHash | Error | ExpirationDate | Identity | LastModifiedDateTime | ListSubType | ModifiedBy | Notes | ObjectState | PSComputerName | PSShowComputerName | RunspaceId | SubmissionID | SysManaged | Value
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Block | d568L6iokOxrYqB2L1CxcKy6S6A/tCDoQQJal33AFWo= |  | \{"value":"2022\-06\-15T19:34:01.2028448Z","DateTime":"Wednesday, June 15, 2022 7:34:01 PM"\} | RgAAAAAuoyIuRcZsTKgZbIQyJWZUBwA02rlnO0nOR5RO\-QI\-xRP9AAAAAAEVAAA02rlnO0nOR5RO\-QI\-xRP9AAADfzPiAAAA0 | \{"value":"2022\-05\-16T19:34:01.2652934Z","DateTime":"Monday, May 16, 2022 7:34:01 PM"\} | Tenant |  | Email observed in a phishing campaign. | New | outlook.office365.com | false | \{"value":"8f736b87\-f951\-4b6b\-aa21\-e358720c44e3","Guid":"8f736b87\-f951\-4b6b\-aa21\-e358720c44e3"\} |  | false | attacker@phishingsite.com



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
>### Results of ews-get-tenant-allow-block-list-items
>| Action | EntryValueHash | Error | ExpirationDate | Identity | LastModifiedDateTime | ListSubType | ModifiedBy | Notes | ObjectState | PSComputerName | PSShowComputerName | RunspaceId | SubmissionID | SysManaged | Value
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Block | d568L6iokOxrYqB2L1CxcKy6S6A/tCDoQQJal33AFWo= |  | \{"value":"2022\-06\-15T19:34:01.2028448Z","DateTime":"Wednesday, June 15, 2022 7:34:01 PM"\} | RgAAAAAuoyIuRcZsTKgZbIQyJWZUBwA02rlnO0nOR5RO\-QI\-xRP9AAAAAAEVAAA02rlnO0nOR5RO\-QI\-xRP9AAADfzPiAAAA0 | \{"value":"2022\-05\-16T19:34:01.2652934Z","DateTime":"Monday, May 16, 2022 7:34:01 PM"\} | Tenant |  | Email observed in a phishing campaign. | Unchanged | outlook.office365.com | false | \{"value":"feada07c\-99b7\-48e9\-a562\-a755073522ff","Guid":"feada07c\-99b7\-48e9\-a562\-a755073522ff"\} |  | false | attacker@phishingsite.com


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
>### Results of ews-get-tenant-allow-block-list-count
>| Count | ListSubType | ListType
>| --- | --- | ---
>| 2 | Tenant | sender


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
>### Results of ews-remove-tenant-allow-block-list-items
>| Action | EntryValueHash | Error | ExpirationDate | Identity | LastModifiedDateTime | ListSubType | ModifiedBy | Notes | ObjectState | PSComputerName | PSShowComputerName | RunspaceId | SubmissionID | SysManaged | Value
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 0 |  |  |  |  |  |  |  |  | Deleted | outlook.office365.com | false | \{"value":"cd58060e\-d033\-4cdb\-814e\-9f9748fdf78c","Guid":"cd58060e\-d033\-4cdb\-814e\-9f9748fdf78c"\} |  |  | attacker@phishingsite.com

### ews-export-quarantinemessage
***
Export quarantine messages.


#### Base Command

`ews-export-quarantinemessage`
#### Input
| **Argument Name** | **Description** | **Required**
| --- | --- | --- |
identities | A comma-separated list of identities of the messages to export. | Optional |
identity | The identity of a single message to export. | Optional |
compress_output | Specify whether the output should be compressed. | Optional |
entity_type | The type of entity being exported. | Optional |
force_conversion_to_mime | Specify whether to force conversion to MIME format. | Optional |
password | Password to encrypt the exported file. | Optional |
reason_for_export | Reason for exporting the message. | Optional |
recipient_address | Email address to send the exported message to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.ExportQuarantineMessage.BodyEncoding | String | Encoding used for the body of the message. |
| EWS.ExportQuarantineMessage.Eml | String | The email message in Base64 encoding. |
| EWS.ExportQuarantineMessage.Identity | String | Unique identifier for the retrieved message. |
| EWS.ExportQuarantineMessage.Organization | Boolean | Identifier for the organization associated with the message. |


#### Command Example
```!ews-export-quarantinemessage identity="12345678-beef-dead-beef-0123456789ab\\c0ffee13-beef-dead-beef-0123456789ab"```

#### Context Example
```json
{
    "BodyEncoding": "Base64",
    "Eml": "TmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAsIG5ldmVyIGdvbm5hIGxldCB5b3UgZG93biwgbmV2ZXIgZ29ubmEgcnVuIGFyb3VuZCBhbmQgZGVzZXJ0IHlvdQo=",
    "Identity": "12345678-beef-dead-beef-0123456789ab\\c0ffee13-beef-dead-beef-0123456789ab",
    "Organization": "c0ffee13-beef-dead-beef-0123456789ab"
}
```

#### Human Readable Output
>>### Results of ews-export-quarantinemessage
>| **BodyEncoding** | **Eml** | **Identity** | **Organization** |
>| --- | --- | --- | --- |
>| Base64 | TmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAsIG5ldmVyIGdvbm5hIGxldCB5b3UgZG93biwgbmV2ZXIgZ29ubmEgcnVuIGFyb3VuZCBhbmQgZGVzZXJ0IHlvdQo= | 12345678-beef-dead-beef-0123456789ab\\c0ffee13-beef-dead-beef-0123456789ab | c0ffee13-beef-dead-beef-0123456789ab |

### ews-get-quarantinemessage
***
Retrieve quarantine messages.

#### Base Command

`ews-get-quarantinemessage`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of a single message to retrieve. | Optional |
| entity_type | The type of entity being retrieved. | Optional |
| recipient_address | Email address of the recipient. | Optional |
| sender_address | Email address of the sender. | Optional |
| teams_conversation_types | Types of Teams conversations to retrieve. | Optional |
| direction | Direction of the message (Inbound/Outbound). | Optional |
| domain | Domain associated with the message. | Optional |
| end_expires_date | End date for the message expiration. | Optional |
| end_received_date | End date for when the message was received. | Optional |
| include_messages_from_blocked_sender_address | Include messages from blocked sender addresses. | Optional |
| message_id | ID of the message. | Optional |
| my_items | Include only items belonging to the user. | Optional |
| page | Page number for pagination. | Optional |
| page_size | Number of items per page. | Optional |
| policy_name | Name of the policy associated with the message. | Optional |
| policy_types | Types of policies associated with the message. | Optional |
| quarantine_types | Types of quarantine associated with the message. | Optional |
| recipient_tag | Tag associated with the recipient. | Optional |
| release_status | Release status of the message. | Optional |
| reported | Include only reported messages. | Optional |
| start_expires_date | Start date for the message expiration. | Optional |
| start_received_date | Start date for when the message was received. | Optional |
| subject | Subject of the message. | Optional |
| type | Type of the message. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.GetQuarantineMessage.ApprovalId | string | Approval ID of the message. |
| EWS.GetQuarantineMessage.ApprovalUPN | string | User Principal Name (UPN) of the approver. |
| EWS.GetQuarantineMessage.CustomData | unknown | Custom data associated with the message. |
| EWS.GetQuarantineMessage.DeletedForRecipients | string | List of recipients for whom the message was deleted. |
| EWS.GetQuarantineMessage.Direction | string | Direction of the message (Inbound/Outbound). |
| EWS.GetQuarantineMessage.EntityType | string | Entity type of the message. |
| EWS.GetQuarantineMessage.Expires | date | Expiry date of the message. |
| EWS.GetQuarantineMessage.Identity | string | Unique identifier for the message. |
| EWS.GetQuarantineMessage.MessageId | string | Message ID of the email. |
| EWS.GetQuarantineMessage.MoveToQuarantineAdminActionTakenBy | string | Admin action taken by. |
| EWS.GetQuarantineMessage.MoveToQuarantineApprovalId | string | Approval ID for moving to quarantine. |
| EWS.GetQuarantineMessage.Organization | string | Identifier for the organization associated with the message. |
| EWS.GetQuarantineMessage.OverrideReason | string | Reason for overriding the message. |
| EWS.GetQuarantineMessage.OverrideReasonIntValue | number | Integer value of the override reason. |
| EWS.GetQuarantineMessage.PermissionToAllowSender | boolean | Permission to allow the sender. |
| EWS.GetQuarantineMessage.PermissionToBlockSender | boolean | Permission to block the sender. |
| EWS.GetQuarantineMessage.PermissionToDelete | boolean | Permission to delete the message. |
| EWS.GetQuarantineMessage.PermissionToDownload | boolean | Permission to download the message. |
| EWS.GetQuarantineMessage.PermissionToPreview | boolean | Permission to preview the message. |
| EWS.GetQuarantineMessage.PermissionToRelease | boolean | Permission to release the message. |
| EWS.GetQuarantineMessage.PermissionToRequestRelease | boolean | Permission to request release of the message. |
| EWS.GetQuarantineMessage.PermissionToViewHeader | boolean | Permission to view the header of the message. |
| EWS.GetQuarantineMessage.PolicyName | string | Name of the policy applied to the message. |
| EWS.GetQuarantineMessage.PolicyType | string | Type of the policy applied to the message. |
| EWS.GetQuarantineMessage.QuarantineTypes | string | Types of quarantine applied to the message. |
| EWS.GetQuarantineMessage.QuarantinedUser | string | List of users quarantined. |
| EWS.GetQuarantineMessage.ReceivedTime | date | Time the message was received. |
| EWS.GetQuarantineMessage.RecipientAddress | string | List of recipient email addresses. |
| EWS.GetQuarantineMessage.RecipientCount | number | Number of recipients. |
| EWS.GetQuarantineMessage.RecipientTag | string | Tags associated with the recipient. |
| EWS.GetQuarantineMessage.ReleaseStatus | string | Release status of the message. |
| EWS.GetQuarantineMessage.Released | boolean | Whether the message was released. |
| EWS.GetQuarantineMessage.ReleasedBy | string | List of users who released the message. |
| EWS.GetQuarantineMessage.ReleasedCount | number | Number of times the message was released. |
| EWS.GetQuarantineMessage.ReleasedUser | string | List of users who released the message. |
| EWS.GetQuarantineMessage.Reported | boolean | Whether the message was reported. |
| EWS.GetQuarantineMessage.SenderAddress | string | Email address of the sender. |
| EWS.GetQuarantineMessage.Size | number | Size of the message in bytes. |
| EWS.GetQuarantineMessage.SourceId | string | Source ID of the message. |
| EWS.GetQuarantineMessage.Subject | string | Subject of the message. |
| EWS.GetQuarantineMessage.SystemReleased | boolean | Whether the system released the message. |
| EWS.GetQuarantineMessage.TagName | string | Tag name associated with the message. |
| EWS.GetQuarantineMessage.TeamsConversationType | string | Teams conversation type associated with the message. |
| EWS.GetQuarantineMessage.Type | string | Type of the message. |


#### Command Example
```!ews-get-quarantinemessage```

#### Context Example
```json
{
[
    {
        "ApprovalId": "",
        "ApprovalUPN": "",
        "CustomData": null,
        "DeletedForRecipients": [],
        "Direction": "Outbound",
        "EntityType": "Email",
        "Expires": "2024-07-18T13:20:02.7166413+00:00",
        "Identity": "12345678-beef-dead-beef-0123456789ab\\c0ffee13-beef-dead-beef-0123456789ab",
        "MessageId": "\u003c12345678-beef-dead-beef-0123456789ab@123456.789a.bcde.example.com\u003e",
        "MoveToQuarantineAdminActionTakenBy": "",
        "MoveToQuarantineApprovalId": "",
        "Organization": "c0ffee13-beef-dead-beef-0123456789ab",
        "OverrideReason": "None",
        "OverrideReasonIntValue": 0,
        "PermissionToAllowSender": true,
        "PermissionToBlockSender": false,
        "PermissionToDelete": true,
        "PermissionToDownload": true,
        "PermissionToPreview": true,
        "PermissionToRelease": true,
        "PermissionToRequestRelease": false,
        "PermissionToViewHeader": false,
        "PolicyName": "Default",
        "PolicyType": "HostedContentFilterPolicy",
        "QuarantineTypes": "HighConfPhish",
        "QuarantinedUser": [],
        "ReceivedTime": "2024-07-02T13:20:02.7166413+00:00",
        "RecipientAddress": [
            "admin@example.com"
        ],
        "RecipientCount": 1,
        "RecipientTag": [
            ""
        ],
        "ReleaseStatus": "NOTRELEASED",
        "Released": false,
        "ReleasedBy": [],
        "ReleasedCount": 0,
        "ReleasedUser": [],
        "Reported": false,
        "SenderAddress": "alerts@example.com",
        "Size": 31218,
        "SourceId": "",
        "Subject": "Informational-severity alert: Tenant Allow/Block List entry is about to expire",
        "SystemReleased": false,
        "TagName": "AdminOnlyAccessPolicy",
        "TeamsConversationType": "",
        "Type": "High Confidence Phish"
    },
    {
        "ApprovalId": "",
        "ApprovalUPN": "",
        "CustomData": null,
        "DeletedForRecipients": [],
        "Direction": "Inbound",
        "EntityType": "Email",
        "Expires": "2024-07-13T10:59:12.7581841+00:00",
        "Identity": "12345678-beef-dead-beef-0123456789ac\\c0ffee13-beef-dead-beef-0123456789ac",
        "MessageId": "\u003c12345678-beef-dead-beef-0123456789ac@123456.789a.bcde.example.com\u003e",
        "MoveToQuarantineAdminActionTakenBy": "",
        "MoveToQuarantineApprovalId": "",
        "Organization": "c0ffee13-beef-dead-beef-0123456789ac",
        "OverrideReason": "None",
        "OverrideReasonIntValue": 0,
        "PermissionToAllowSender": true,
        "PermissionToBlockSender": false,
        "PermissionToDelete": true,
        "PermissionToDownload": true,
        "PermissionToPreview": true,
        "PermissionToRelease": true,
        "PermissionToRequestRelease": false,
        "PermissionToViewHeader": false,
        "PolicyName": "testing_quarantine_release",
        "PolicyType": "HostedContentFilterPolicy",
        "QuarantineTypes": "HighConfPhish",
        "QuarantinedUser": [],
        "ReceivedTime": "2024-06-28T10:59:12.7581841+00:00",
        "RecipientAddress": [
            "user@example.com"
        ],
        "RecipientCount": 1,
        "RecipientTag": [
            ""
        ],
        "ReleaseStatus": "RELEASED",
        "Released": true,
        "ReleasedBy": [
            "SystemMailbox{deadbeef-dead-beef-dead-beefdeadbeef}@example.com"
        ],
        "ReleasedCount": 1,
        "ReleasedUser": [],
        "Reported": false,
        "SenderAddress": "sender@example.com",
        "Size": 14781,
        "SourceId": "",
        "Subject": "Check the inbox",
        "SystemReleased": false,
        "TagName": "testing_release",
        "TeamsConversationType": "",
        "Type": "High Confidence Phish"
    }
]
}
```
#### Human Readable Output

>### Results of ews-get-quarantinemessage
>| ApprovalId | ApprovalUPN | CustomData | DeletedForRecipients | Direction | EntityType | Expires | Identity | MessageId | MoveToQuarantineAdminActionTakenBy | MoveToQuarantineApprovalId | Organization | OverrideReason | OverrideReasonIntValue | PermissionToAllowSender | PermissionToBlockSender | PermissionToDelete | PermissionToDownload | PermissionToPreview | PermissionToRelease | PermissionToRequestRelease | PermissionToViewHeader | PolicyName | PolicyType | QuarantineTypes | QuarantinedUser | ReceivedTime | RecipientAddress | RecipientCount | RecipientTag | ReleaseStatus | Released | ReleasedBy | ReleasedCount | ReleasedUser | Reported | SenderAddress | Size | SourceId | Subject | SystemReleased | TagName | TeamsConversationType | Type |
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  |  | Outbound | Email | 2024-07-18T13:20:02.7166413+00:00 | 12345678-beef-dead-beef-0123456789ab\c0ffee13-beef-dead-beef-0123456789ab | \u003c12345678-beef-dead-beef-0123456789ab@123456.789a.bcde.example.com\u003e |  |  | c0ffee13-beef-dead-beef-0123456789ab | None | 0 | true | false | true | true | true | true | false | false | Default | HostedContentFilterPolicy | HighConfPhish | [] | 2024-07-02T13:20:02.7166413+00:00 | ["admin@example.com"] | 1 | [""] | NOTRELEASED | false | [] | 0 | [] | false | alerts@example.com | 31218 |  | Informational-severity alert: Tenant Allow/Block List entry is about to expire | false | AdminOnlyAccessPolicy |  | High Confidence Phish |
>|  |  |  |  | Inbound | Email | 2024-07-13T10:59:12.7581841+00:00 | 12345678-beef-dead-beef-0123456789ac\\c0ffee13-beef-dead-beef-0123456789ac | \u003c12345678-beef-dead-beef-0123456789ac@123456.789a.bcde.example.com\u003e |  |  | c0ffee13-beef-dead-beef-0123456789ac | None | 0 | true | false | true | true | true | true | false | false | testing_quarantine_release | HostedContentFilterPolicy | HighConfPhish | [] | 2024-06-28T10:59:12.7581841+00:00 | ["user@example.com"] | 1 | [""] | RELEASED | true | ["SystemMailbox{deadbeef-dead-beef-dead-beefdeadbeef}@example.com"] | 1 | [] | false | sender@example.com | 14781 |  | Check the inbox | false | testing_release |  | High Confidence Phish |

### ews-release-quarantinemessage
***
Release quarantine messages.

#### Base Command
```ews-release-quarantinemessage```

#### Input
| **Argument Name**      | **Description**                                            | **Required** |
|------------------------|------------------------------------------------------------|--------------|
| user                   | The user associated with the quarantine message.           | Optional |
| identities             | A comma-separated list of identities of the messages to release. | Optional |
| identity               | The identity of a single message to release.               | Optional |
| release_to_all         | Specify whether to release the message to all recipients.  | Optional |
| allow_sender           | Specify whether to allow the sender.                       | Optional |
| entity_type            | The type of entity being released.                         | Optional |
| force                  | Specify whether to force the release.                      | Optional |
| report_false_positive  | Specify whether to report the message as a false positive. | Optional |
| action_type            | The type of action to take when releasing the message.     | Optional |

#### Context Output
There are no context outputs for this command.

#### Human Readable Output
>The message with identity 12345678-beef-dead-beef-0123456789ab\\c0ffee13-beef-dead-beef-0123456789ab has been sent for release from quarantine.

### ews-junk-rules-get
***
Gets junk rules for the specified mailbox.


#### Base Command

`ews-junk-rules-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | ID of the mailbox for which to get junk rules. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Rule.Junk.BlockedSendersAndDomains | String | Blocked senders and domains list. | 
| EWS.Rule.Junk.ContactsTrusted | Boolean | If true, contacts are trusted by default. | 
| EWS.Rule.Junk.Email | String | Junk rule mailbox. | 
| EWS.Rule.Junk.Enabled | Boolean | If true, junk rule is enabled. | 
| EWS.Rule.Junk.Identity | String | Junk rule identity. | 
| EWS.Rule.Junk.MailboxOwnerId | String | Mail box owner ID. | 
| EWS.Rule.Junk.TrustedListsOnly | Boolean | If true, only a list defined in the trusted lists are trusted. | 
| EWS.Rule.Junk.TrustedRecipientsAndDomains | String | List of trusted recipients and domains. | 
| EWS.Rule.Junk.TrustedSendersAndDomains | String | List of trusted senders and domains. | 


#### Command Example
```!ews-junk-rules-get mailbox="xsoar@dev.onmicrosoft.com"```

#### Context Example
```json
{
    "EWS": {
        "Rule": {
            "Junk": {
                "BlockedSendersAndDomains": [
                    "user1@gmail.com",
                    "user2@gmail.com"
                ],
                "ContactsTrusted": false,
                "Enabled": false,
                "Identity": "xsoar",
                "MailboxOwnerId": "xsoar",
                "TrustedListsOnly": false,
                "TrustedRecipientsAndDomains": [
                  "user1@gmail.com",
                  "user2@gmail.com"
                ],
                "TrustedSendersAndDomains": [
                  "user1@gmail.com",
                  "user2@gmail.com"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### EWS extension - 'xsoar@dev.onmicrosoft.com' Junk rules
>| BlockedSendersAndDomains | ContactsTrusted | Enabled | TrustedListsOnly | TrustedSendersAndDomains
>| --- | --- | --- | --- | ---
>| \["user1@gmail.com","user2@gmail.com"\] | False | False | False | \["user1@gmail.com","user2@gmail.com"\]


### ews-junk-rules-set
***
Sets junk rules for the specified mailbox.


#### Base Command

`ews-junk-rules-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | ID of the mailbox for which to set junk rules. | Required | 
| add_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to add to the mailbox. | Optional | 
| remove_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to remove from the mailbox. | Optional | 
| add_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to add to the mailbox. | Optional | 
| remove_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to remove from the mailbox. | Optional | 
| trusted_lists_only | If true, trust only lists defined in the trusted lists. Can be "true" or "false". Possible values are: true, false. | Optional | 
| contacts_trusted | If true, contacts are trusted by default. Can be "true" or "false". Possible values are: true, false. | Optional | 
| enabled | If true, the junk rule is enabled. Can be "true" or "false". Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ews-junk-rules-set mailbox="xsoar@dev.onmicrosoft.com" add_blocked_senders_and_domains="test@gmail.com" add_trusted_senders_and_domains="dev.onmicrosoft.com"```

#### Human Readable Output

>EWS extension - 'xsoar@dev.onmicrosoft.com' Junk rules **modified**!

### ews-global-junk-rules-set
***
Sets junk rules in all managed accounts.


#### Base Command

`ews-global-junk-rules-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to add to the mailbox. | Optional | 
| remove_blocked_senders_and_domains | Comma-separated list of blocked senders and domains to remove from the mailbox. | Optional | 
| add_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to add to the mailbox. | Optional | 
| remove_trusted_senders_and_domains | Comma-separated list of trusted senders and domains to remove from the mailbox. | Optional | 
| trusted_lists_only | If true, trust only lists defined in the trusted lists. Can be "true" or "false". Possible values are: true, false. | Optional | 
| contacts_trusted | If true, contacts are trusted by default. Can be "true" or "false". Possible values are: true, false. | Optional | 
| enabled | If true, the junk rule is enabled. Can be "true" or "false". Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ews-global-junk-rules-set add_blocked_senders_and_domains="test@demisto.com" add_trusted_senders_and_domains="demisto.com"```

#### Human Readable Output

>EWS extension - Junk rules globally **modified**!

### ews-message-trace-get
***
Searches message data for the last 10 days. If you run this command without any arguments, only data from the last 48 hours is returned.
If you enter a start date that is older than 10 days, you will receive an error and the command will return no results.
This command returns a maximum of 1,000,000 results, and will timeout on very large queries. If your query returns too many results, consider splitting it up using shorter start_date and end_date intervals.



#### Base Command

`ews-message-trace-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sender_address | The sender_address parameter filters the results by the sender's email address. You can specify multiple values separated by commas.<br/>. | Optional | 
| recipient_address | The recipient_address parameter filters the results by the recipient's email address. You can specify multiple values separated by commas.<br/>. | Optional | 
| from_ip | The from_ip parameter filters the results by the source IP address.<br/>For incoming messages, the value of from_ip is the public IP address of the SMTP email server that sent the message.<br/>For outgoing messages from Exchange Online, the value is blank.<br/>. | Optional | 
| to_ip | The to_ip parameter filters the results by the destination IP address.<br/>For outgoing messages, the value of to_ip is the public IP address in the resolved MX record for the destination domain.<br/>For incoming messages to Exchange Online, the value is blank.<br/>. | Optional | 
| message_id | The message_id parameter filters the results by the Message-ID header field of the message.<br/>This value is also known as the Client ID. The format of the Message-ID depends on the messaging server that sent the message.<br/>The value should be unique for each message. However, not all messaging servers create values for the Message-ID in the same way.<br/>Be sure to include the full Message ID string (which may include angle brackets) and enclose the value in quotation marks (for example,"d9683b4c-127b-413a-ae2e-fa7dfb32c69d@DM3NAM06BG401.Eop-nam06.prod.protection.outlook.com").<br/>. | Optional | 
| message_trace_id | The message_trace_id parameter can be used with the recipient address to uniquely identify a message trace and obtain more details.<br/>A message trace ID is generated for every message that's processed by the system.<br/>. | Optional | 
| page | The page number of the results you want to view.<br/>Can be an integer between 1 and 1000. The default value is 1.<br/>. Default is 1. | Optional | 
| page_size | The maximum number of entries per page.<br/>Can be an integer between 1 and 5000. The default value is 100.<br/>. Default is 100. | Optional | 
| start_date | The start date of the date range.<br/>Use the short date format that's defined in the Regional Options settings on the computer where you're running the command. For example, if the computer is configured to use the short date format mm/dd/yyyy,<br/>enter 09/01/2018 to specify September 1, 2018. You can enter the date only, or you can enter the date and time of day.<br/>If you enter the date and time of day, enclose the value in quotation marks ("), for example, "09/01/2018 5:00 PM".<br/>Valid input for this parameter is from 10 days - now ago. The default value is 48 hours ago.<br/>. | Optional | 
| end_date | The end date of the date range.<br/>Use the short date format that's defined in the Regional Options settings on the computer where you're running the command.<br/>For example, if the computer is configured to use the short date format mm/dd/yyyy, enter 09/01/2018 to specify September 1, 2018.<br/>You can enter the date only, or you can enter the date and time of day.<br/>If you enter the date and time of day, enclose the value in quotation marks ("), for example, "09/01/2018 5:00 PM".<br/>Valid input for this parameter is from start_date - now. The default value is now.<br/>. | Optional | 
| status | The status of the message. Can be one of the following:<br/>  * GettingStatus: The message is waiting for status update.<br/>  * Failed: Message delivery was attempted and it failed or the message was filtered as spam or malware, or by transport rules.<br/>  * Pending: Message delivery is underway or was deferred and is being retried.<br/>  * Delivered: The message was delivered to its destination.<br/>  * Expanded: There was no message delivery because the message was addressed to a distribution group and the membership of the distribution was expanded.<br/>  * Quarantined: The message was quarantined.<br/>  * FilteredAsSpam: The message was marked as spam.<br/>. Possible values are: GettingStatus, Failed, Pending, Delivered, Expanded, Quarantined, FilteredAsSpam. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.MessageTrace.FromIP | String | The public IP address of the SMTP email server that sent the message. | 
| EWS.MessageTrace.ToIP | String | The public IP address in the resolved MX record for the destination domain. For incoming messages to Exchange Online, the value is blank. | 
| EWS.MessageTrace.Index | Number | Message index in pagination. \(Index starts from 0\) | 
| EWS.MessageTrace.MessageId | String | Message-ID header field of the message. | 
| EWS.MessageTrace.MessageTraceId | String | Message trace ID of the message. | 
| EWS.MessageTrace.Organization | String | Message trace organization source. | 
| EWS.MessageTrace.Received | Date | Message receive time. | 
| EWS.MessageTrace.RecipientAddress | String | Message recipients address. | 
| EWS.MessageTrace.SenderAddress | String | Message sender address. | 
| EWS.MessageTrace.Size | Number | Message size in bytes. | 
| EWS.MessageTrace.StartDate | Date | Message trace start date. | 
| EWS.MessageTrace.EndDate | Date | Message trace end date. | 
| EWS.MessageTrace.Status | String | Message status. | 
| EWS.MessageTrace.Subject | String | Message subject. | 


#### Command Example
```!ews-message-trace-get```

#### Context Example
```json
{
    "EWS": {
        "MessageTrace": [
            {
                "EndDate": "2021-01-03T06:14:14.9596257Z",
                "FromIP": "8.8.8.8",
                "Index": 1,
                "MessageId": "xxx",
                "MessageTraceId": "xxxx",
                "Organization": "dev.onmicrosoft.com",
                "Received": "2021-01-03T04:45:36.4662406",
                "RecipientAddress": "xsoar@dev.onmicrosoft.com",
                "SenderAddress": "xsoar@dev.onmicrosoft.com",
                "Size": 1882,
                "StartDate": "2021-01-01T06:14:14.9596257Z",
                "Status": "GettingStatus",
                "Subject": "Test mail",
                "ToIP": null
            },
            {
                "EndDate": "2021-01-03T06:15:14.9596257Z",
                "FromIP": "8.8.8.8",
                "Index": 2,
                "MessageId": "xxx",
                "MessageTraceId": "xxxx",
                "Organization": "dev.onmicrosoft.com",
                "Received": "2021-01-03T04:46:36.4662406",
                "RecipientAddress": "xsoar@dev.onmicrosoft.com",
                "SenderAddress": "xsoar@dev.onmicrosoft.com",
                "Size": 1882,
                "StartDate": "2021-01-01T06:15:14.9596257Z",
                "Status": "GettingStatus",
                "Subject": "Test mail",
                "ToIP": null
            }
        ]
    }
}
```

#### Human Readable Output

>### EWS extension - Messages trace
>| EndDate | FromIP | Index | MessageId | MessageTraceId | Organization | Received | RecipientAddress | SenderAddress | Size | StartDate | Status | Subject | ToIP
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 1/3/2021 6:14:14 AM | 8.8.8.8 | 0 | xxx | xxxx | microsoft.com | 1/3/2021 4:45:36 AM | xsoar@dev.microsoft.com | xsoar@dev.onmicrosoft.com | 6975 | 1/1/2021 6:14:14 AM | Delivered | Test mail |
>| 1/3/2021 6:15:14 AM | 8.8.8.8 | 1 | xxx | xxxx | microsoft.com | 1/3/2021 4:46:36 AM | xsoar@dev.microsoft.com | xsoar@dev.onmicrosoft.com | 6975 | 1/1/2021 6:15:14 AM | Delivered | Test mail | 


### ews-federation-trust-get
***
Displays the federation trust configured for the Exchange organization.


#### Base Command

`ews-federation-trust-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_controller | The domain controller identified by its fully qualified domain name (FQDN). For example, dc01.example.com. This argument is available only in on-premises Exchange. | Optional | 
| identity | The federation trust ID. If not specified, the command returns all federation trusts configured for the Exchange organization. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.FederationTrust.AdminDisplayName | String | Administrator display name of the federation trust. | 
| EWS.FederationTrust.ApplicationIdentifier | String | Application identifier of the federation trust. | 
| EWS.FederationTrust.ApplicationUri | String | Application URI of the federation trust. | 
| EWS.FederationTrust.DistinguishedName | String | Distinguished name of the federation trust. | 
| EWS.FederationTrust.ExchangeObjectId | String | Exchange object ID of the federation trust. | 
| EWS.FederationTrust.ExchangeVersion | String | Exchange version of the federation trust. | 
| EWS.FederationTrust.Guid | String | GUID of the federation trust. | 
| EWS.FederationTrust.Id | String | ID of the federation trust. | 
| EWS.FederationTrust.Identity | String | Identity of the federation trust. | 
| EWS.FederationTrust.IsValid | Boolean | Whether the federation trust is valid. | 
| EWS.FederationTrust.MetadataEpr | String | Metadata EPR of the federation trust. | 
| EWS.FederationTrust.MetadataPollInterval | Date | Metadata poll interval of the federation trust. | 
| EWS.FederationTrust.MetadataPutEpr | Unknown | Metadata put EPR of the federation trust. | 
| EWS.FederationTrust.Name | String | Name of the federation trust. | 
| EWS.FederationTrust.NamespaceProvisioner | String | Namespace provisioner of the federation trust. | 
| EWS.FederationTrust.ObjectCategory | String | Object category of the federation trust. | 
| EWS.FederationTrust.ObjectClass | String | Object class of the federation trust. | 
| EWS.FederationTrust.ObjectState | String | Object state of the federation trust. | 
| EWS.FederationTrust.OrgCertificate.Archived | Boolean | Whether the organization certificate of the federation trust is archived. | 
| EWS.FederationTrust.OrgCertificate.Extensions.Critical | Boolean | Whether the extensions of the organization certificate are critical. | 
| EWS.FederationTrust.OrgCertificate.Extensions.Oid.FriendlyName | String | Friendly name of the OID of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.Oid.Value | String | Value of the OID of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.RawData | Number | Raw data of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.SubjectKeyIdentifier | String | Subject key identifier of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.KeyUsages | Number | Key usages of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.EnhancedKeyUsages.FriendlyName | String | Friendly name of the enhanced key usages of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.EnhancedKeyUsages.Value | String | Value of the enhanced key usages of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.Extensions.CertificateAuthority | Boolean | Whether the organization certificate extensions have a certificate authority. | 
| EWS.FederationTrust.OrgCertificate.Extensions.HasPathLengthConstraint | Boolean | Whether the organization certificate extensions have a path length constraint. | 
| EWS.FederationTrust.OrgCertificate.Extensions.PathLengthConstraint | Number | Path length constraint of the organization certificate extensions. | 
| EWS.FederationTrust.OrgCertificate.FriendlyName | String | Friendly name of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.Handle.value | Number | The handle value of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.HasPrivateKey | Boolean | Whether the organization certificate has a private key. | 
| EWS.FederationTrust.OrgCertificate.Issuer | String | Issuer of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.IssuerName.Name | String | Name of the issuer of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.IssuerName.Oid.FriendlyName | Unknown | Friendly Name of the OID of the issuer name of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.IssuerName.Oid.Value | Unknown | Value of the OID of the issuer name of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.IssuerName.RawData | Number | Raw data of the issuer name of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.NotAfter | Date | The date until when the organization certificate is valid. | 
| EWS.FederationTrust.OrgCertificate.NotBefore | Date | The date the organization certificate became valid. | 
| EWS.FederationTrust.OrgCertificate.PrivateKey | Unknown | Private key of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.EncodedKeyValue.Oid.FriendlyName | String | Friendly name of the OID of the encoded key value of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.EncodedKeyValue.Oid.Value | String | Value of the OID of the encoded key value of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.EncodedKeyValue.RawData | Number | Raw data of the encoded key value of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.EncodedParameters.Oid.FriendlyName | String | Friendly name of the OID of the encoded parameters of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.EncodedParameters.Oid.Value | String | Value of the OID of the encoded parameters of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.EncodedParameters.RawData | Number | Raw data of the encoded parameters of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Key.KeyExchangeAlgorithm | String | Key exchange algorithm of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Key.LegalKeySizes.MaxSize | Number | Maximum size of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Key.LegalKeySizes.MinSize | Number | Minimum size of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Key.LegalKeySizes.SkipSize | Number | SkipSize of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Key.SignatureAlgorithm | String | Signature algorithm of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Oid.FriendlyName | String | Friendly name of the OID of the public key. | 
| EWS.FederationTrust.OrgCertificate.PublicKey.Oid.Value | String | Value of the OID of the public key. | 
| EWS.FederationTrust.OrgCertificate.RawData | Number | Raw data of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.SerialNumber | String | Serial number of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.SignatureAlgorithm.FriendlyName | String | Friendly name of the signature algorithm. | 
| EWS.FederationTrust.OrgCertificate.SignatureAlgorithm.Value | String | Value of the signature algorithm. | 
| EWS.FederationTrust.OrgCertificate.Subject | String | Subject of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.SubjectName.Name | String | Name of the subject of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.SubjectName.Oid.FriendlyName | Unknown | Friendly name of the OID of the subject name. | 
| EWS.FederationTrust.OrgCertificate.SubjectName.Oid.Value | Unknown | Value of the OID of the subject name. | 
| EWS.FederationTrust.OrgCertificate.SubjectName.RawData | Number | Raw Data of the subject name. | 
| EWS.FederationTrust.OrgCertificate.Thumbprint | String | Thumbprint of the organization certificate. | 
| EWS.FederationTrust.OrgCertificate.Version | Number | Version of the organization certificate. | 
| EWS.FederationTrust.OrgNextCertificate | Unknown | Next organization certificate. | 
| EWS.FederationTrust.OrgNextPrivCertificate | String | Next organization private certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.Archived | Boolean | Whether to archive the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.Critical | Boolean | Whether the extensions of the previous organization certificate are critical. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.Oid.FriendlyName | String | Friendly name of the OID of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.Oid.Value | String | Value of the OID of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.RawData | Number | Raw data of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.SubjectKeyIdentifier | String | Subject key identifier of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.KeyUsages | Number | Key usages of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.EnhancedKeyUsages.FriendlyName | String | Friendly name of the enhanced key usages of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.Extensions.EnhancedKeyUsages.Value | String | Value of the enhanced key usages of the previous organization certificate extensions. | 
| EWS.FederationTrust.OrgPrevCertificate.FriendlyName | String | Friendly name of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.Handle.value | Number | Value of the handle of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.HasPrivateKey | Boolean | Whether the previous organization certificate has a private key. | 
| EWS.FederationTrust.OrgPrevCertificate.Issuer | String | Issuer of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.IssuerName.Name | String | Name of the issuer of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.IssuerName.Oid.FriendlyName | Unknown | Friendly name of the OID of the issuer of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.IssuerName.Oid.Value | Unknown | Value of the OID of the issuer of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.IssuerName.RawData | Number | Raw data of the issuer of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.NotAfter | Date | The date until when the previous organization certificate is valid. | 
| EWS.FederationTrust.OrgPrevCertificate.NotBefore | Date | The date the previous organization certificate became valid. | 
| EWS.FederationTrust.OrgPrevCertificate.PrivateKey | Unknown | Private Key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.EncodedKeyValue.Oid.FriendlyName | String | Friendly Name of the OID of the encoded key value of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.EncodedKeyValue.Oid.Value | String | Value of the OID of the encoded key value of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.EncodedKeyValue.RawData | Number | Raw Data of the encoded key value of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.EncodedParameters.Oid.FriendlyName | String | Friendly name of the OID of the encoded parameters of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.EncodedParameters.Oid.Value | String | Value of the OID of the encoded parameters of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.EncodedParameters.RawData | Number | Raw Data of the encoded parameters of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Key.KeyExchangeAlgorithm | String | Key exchange algorithm of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Key.LegalKeySizes.MaxSize | Number | Maximum size of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Key.LegalKeySizes.MinSize | Number | Minimum size of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Key.LegalKeySizes.SkipSize | Number | SkiPSize of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Key.SignatureAlgorithm | String | Signature algorithm of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Oid.FriendlyName | String | Friendly name of the OID of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.PublicKey.Oid.Value | String | Value of the OID of the public key of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.RawData | Number | Raw Data of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SerialNumber | String | Serial number of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SignatureAlgorithm.FriendlyName | String | Friendly name of the signature algorithm of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SignatureAlgorithm.Value | String | Value of the signature algorithm of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.Subject | String | Subject of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SubjectName.Name | String | Name of the subject of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SubjectName.Oid.FriendlyName | Unknown | Friendly name of the OID of the subject of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SubjectName.Oid.Value | Unknown | Value of the OID of the subject name of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.SubjectName.RawData | Number | Raw Data of the subject name of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.Thumbprint | String | Thumbprint of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevCertificate.Version | Number | Version of the previous organization certificate. | 
| EWS.FederationTrust.OrgPrevPrivCertificate | String | Organization previous private certificate. | 
| EWS.FederationTrust.OrgPrivCertificate | String | Organization private certificate. | 
| EWS.FederationTrust.OrganizationId | String | Organization ID. | 
| EWS.FederationTrust.OriginatingServer | String | Originating server. | 
| EWS.FederationTrust.PSComputerName | String | PowerShell computer name. | 
| EWS.FederationTrust.PSShowComputerName | Boolean | Whether to show the PowerShell computer name. | 
| EWS.FederationTrust.PolicyReferenceUri | String | Policy Reference URI. | 
| EWS.FederationTrust.RunspaceId | String | Runspace ID. | 
| EWS.FederationTrust.TimesOfUnmatchPartner | Number | Times Of unmatch partner. | 
| EWS.FederationTrust.TokenIssuerCertReference | String | Token issuer certificate reference. | 
| EWS.FederationTrust.TokenIssuerCertificate.Archived | Boolean | Whether the token issuer certificate is archived. | 
| EWS.FederationTrust.TokenIssuerCertificate.Extensions.Critical | Boolean | Whether the extensions of the token issuer certificate are critical. | 
| EWS.FederationTrust.TokenIssuerCertificate.Extensions.Oid.FriendlyName | String | Friendly name of the OID of the extensions of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Extensions.Oid.Value | String | Value of the OID of the extensions of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Extensions.RawData | Number | Raw Data of the extensions of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Extensions.SubjectKeyIdentifier | String | Subject key identifier of the extensions of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Extensions.KeyUsages | Number | Key usages of the extensions of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.FriendlyName | String | Friendly name of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Handle.value | Number | Value of the handle of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.HasPrivateKey | Boolean | Whether the token issuer certificate has a private key. | 
| EWS.FederationTrust.TokenIssuerCertificate.Issuer | String | Issuer of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.IssuerName.Name | String | Name of the issuer of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.IssuerName.Oid.FriendlyName | Unknown | Friendly name of the OID of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.IssuerName.Oid.Value | Unknown | Value of the OID of the issuer of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.IssuerName.RawData | Number | Raw data of the issuer of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.NotAfter | Date | The date until when the token issuer certificate is valid. | 
| EWS.FederationTrust.TokenIssuerCertificate.NotBefore | Date | The date the token issuer certificate became valid. | 
| EWS.FederationTrust.TokenIssuerCertificate.PrivateKey | Unknown | Private key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.EncodedKeyValue.Oid.FriendlyName | String | Friendly name of the OID of the encoded key value of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.EncodedKeyValue.Oid.Value | String | Value of the OID of the encoded key value of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.EncodedKeyValue.RawData | Number | Raw data of the encoded key value of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.EncodedParameters.Oid.FriendlyName | String | Friendly name of the OID of the encoded parameters of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.EncodedParameters.Oid.Value | String | Value of the OID of the encoded parameters of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.EncodedParameters.RawData | Number | Raw Data of the encoded parameters of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Key.KeyExchangeAlgorithm | String | Key exchange algorithm of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Key.LegalKeySizes.MaxSize | Number | Maximum size of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Key.LegalKeySizes.MinSize | Number | Minimum size of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Key.LegalKeySizes.SkipSize | Number | SkiPSize of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Key.SignatureAlgorithm | String | Signature algorithm of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Oid.FriendlyName | String | Friendly name of the OID of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.PublicKey.Oid.Value | String | Value of the OID of the public key of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.RawData | Number | Raw Data of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SerialNumber | String | Serial number of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SignatureAlgorithm.FriendlyName | String | Friendly name of the signature algorithm of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SignatureAlgorithm.Value | String | Value of the signature algorithm of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Subject | String | Subject of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SubjectName.Name | String | Name of the subject of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SubjectName.Oid.FriendlyName | Unknown | Friendly name of the OID of the subject of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SubjectName.Oid.Value | Unknown | Value of the OID of the subject of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.SubjectName.RawData | Number | Raw data of the subject of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Thumbprint | String | Thumbprint of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerCertificate.Version | Number | Version of the token issuer certificate. | 
| EWS.FederationTrust.TokenIssuerEpr | String | Token issuer EPR. | 
| EWS.FederationTrust.TokenIssuerMetadataEpr | String | Token issuer metadata EPR. | 
| EWS.FederationTrust.TokenIssuerPrevCertReference | String | Token issuer previous certificate reference. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Archived | Boolean | Whether the token issuer previous certificate was archived. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Extensions.Critical | Boolean | Whether the extensions of the token issuer previous certificate was critical. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Extensions.Oid.FriendlyName | String | Friendly name of the OID of the extensions of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Extensions.Oid.Value | String | Value of the OID of the extensions of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Extensions.RawData | Number | Raw data of the extensions of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Extensions.SubjectKeyIdentifier | String | Subject key identifier of the extensions of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Extensions.KeyUsages | Number | Key usages of the extensions of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.FriendlyName | String | Friendly name of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Handle.value | Number | The handle value of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.HasPrivateKey | Boolean | Whether the token issuer previous certificate has a private key. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Issuer | String | Issuer of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.IssuerName.Name | String | Name of the issuer of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.IssuerName.Oid.FriendlyName | Unknown | Friendly name of the OID of the issuer name of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.IssuerName.Oid.Value | Unknown | Value of the OID of the issuer name of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.IssuerName.RawData | Number | Raw Data of the issuer name of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.NotAfter | Date | The date until when the token issuer previous certificate is valid. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.NotBefore | Date | The date the token issuer previous certificate became valid. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PrivateKey | Unknown | Private Key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.EncodedKeyValue.Oid.FriendlyName | String | Friendly name of the OID of the encoded key value of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.EncodedKeyValue.Oid.Value | String | Value of the OID of the encoded key value of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.EncodedKeyValue.RawData | Number | Raw data of the encoded key value of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.EncodedParameters.Oid.FriendlyName | String | Friendly name of the OID of the encoded parameters of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.EncodedParameters.Oid.Value | String | Value of the OID of the encoded parameters of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.EncodedParameters.RawData | Number | Raw data of the encoded parameters of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Key.KeyExchangeAlgorithm | String | Key exchange algorithm of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Key.LegalKeySizes.MaxSize | Number | Maximum size of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Key.LegalKeySizes.MinSize | Number | Minimum size of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Key.LegalKeySizes.SkipSize | Number | SkiPSize of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Key.SignatureAlgorithm | String | Signature algorithm of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Oid.FriendlyName | String | Friendly Name of the OID of the public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.PublicKey.Oid.Value | String | Value of the OID of teh public key of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.RawData | Number | Raw Data of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SerialNumber | String | Serial number of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SignatureAlgorithm.FriendlyName | String | Friendly name of the signature algorithm of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SignatureAlgorithm.Value | String | Value of the signature algorithm of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Subject | String | Subject of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SubjectName.Name | String | Name of the subject of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SubjectName.Oid.FriendlyName | Unknown | Friendly Name of the OID of the subject of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SubjectName.Oid.Value | Unknown | Value of the OID of the subject name of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.SubjectName.RawData | Number | Raw data of the subject name of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Thumbprint | String | Thumbprint of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerPrevCertificate.Version | Number | Version of the token issuer previous certificate. | 
| EWS.FederationTrust.TokenIssuerType | String | Token issuer type of the federation trust. | 
| EWS.FederationTrust.TokenIssuerUri | String | Token Issuer UIR of the federation trust. | 
| EWS.FederationTrust.WebRequestorRedirectEpr | String | Web requestor redirect EPR of the federation trust. | 
| EWS.FederationTrust.WhenChanged | Date | The date the federation trust was changed. | 
| EWS.FederationTrust.WhenChangedUTC | Date | The date in UTC format of when the federation trust was changed. | 
| EWS.FederationTrust.WhenCreated | Date | The date the federation trust was created. | 
| EWS.FederationTrust.WhenCreatedUTC | Date | The date in UTC format of when the federation trust was created. | 

### ews-federation-configuration-get
***
Retrieves the Exchange organization's federated organization identifier and related details, such as federated domains, organization contact, and status.


#### Base Command

`ews-federation-configuration-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_controller | The fully qualified domain name (FQDN) of the domain controller. For example, dc01.example.com. This argument is available only in on-premises Exchange. | Optional | 
| identity | The federation trust ID. If not specified, all federation trusts configured for the Exchange organization are returned. | Optional | 
| include_extended_domain_info | The IncludeExtendedDomainInfo switch specifies that the command query Microsoft Federation Gateway for the status of each accepted domain that's federated. The status is returned with each domain in the Domains property. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.FederationConfiguration.AccountNamespace | String | Account namespace of the federation configuration. | 
| EWS.FederationConfiguration.DefaultDomain | Unknown | Default domain of the federation configuration. | 
| EWS.FederationConfiguration.DelegationTrustLink | String | Delegation trust link of the federation configuration. | 
| EWS.FederationConfiguration.DistinguishedName | String | Distinguished name of the federation configuration. | 
| EWS.FederationConfiguration.Domains | String | Domains of the federation configuration. | 
| EWS.FederationConfiguration.Enabled | Boolean | Whether the federation configuration is enabled. | 
| EWS.FederationConfiguration.ExchangeObjectId | String | Exchange object ID of the federation configuration. | 
| EWS.FederationConfiguration.ExchangeVersion | String | Exchange version of the federation configuration. | 
| EWS.FederationConfiguration.Guid | String | GUID of the federation configuration. | 
| EWS.FederationConfiguration.Id | String | ID of the federation configuration. | 
| EWS.FederationConfiguration.Identity | String | Identity of the federation configuration. | 
| EWS.FederationConfiguration.IsValid | Boolean | Whether the federation configration is valid. | 
| EWS.FederationConfiguration.Name | String | Name of the federation configuration. | 
| EWS.FederationConfiguration.ObjectCategory | String | Object category of the federation configuration. | 
| EWS.FederationConfiguration.ObjectClass | String | Object class of the federation configuration. | 
| EWS.FederationConfiguration.ObjectState | String | Object state of the federation configuration. | 
| EWS.FederationConfiguration.OrganizationContact | String | Organization contact of the federation configuration. | 
| EWS.FederationConfiguration.OrganizationId | String | Organization ID of the federation configuration. | 
| EWS.FederationConfiguration.OriginatingServer | String | Originating server of the federation configuration. | 
| EWS.FederationConfiguration.PSComputerName | String | PowerShell computer name of the federation configuration. | 
| EWS.FederationConfiguration.PSShowComputerName | Boolean | Whether to show the PowerShell computer name of the federation configuration. | 
| EWS.FederationConfiguration.RunspaceId | String | Runspace ID of the federation configuration. | 
| EWS.FederationConfiguration.WhenChanged | Date | The date the federation configuration was changed. | 
| EWS.FederationConfiguration.WhenChangedUTC | Date | The date in UTC format of when the federation configuration was changed. | 
| EWS.FederationConfiguration.WhenCreated | Date | The date the federation configuration was created. | 
| EWS.FederationConfiguration.WhenCreatedUTC | Date | The date in UTC format of when the federation configuration was created. | 

### ews-remote-domain-get
***
Gets the configuration information for the remote domains configured in your organization. This command is available only in the Exchange Online PowerShell V3 module.


#### Base Command

`ews-remote-domain-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_controller | The fully qualified domain name (FQDN) of the domain controller. For example, dc01.example.com.<br/>This argument is available only in on-premises Exchange. | Optional | 
| identity | The remote domain that you want to view. You can use the GUID, ID, or any other identifier. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.RemoteDomain.AdminDisplayName | String | Admin display name of the remote domain. | 
| EWS.RemoteDomain.AllowedOOFType | String | Allowed OOF type of the remote domain. | 
| EWS.RemoteDomain.AutoForwardEnabled | Boolean | Whether auto forward is enabled for the remote domain. | 
| EWS.RemoteDomain.AutoReplyEnabled | Boolean | Whether auto reply is enabled for the remote domain.. | 
| EWS.RemoteDomain.ByteEncoderTypeFor7BitCharsets | String | Byte encoder type For 7-bit charsets of the remote domain. | 
| EWS.RemoteDomain.CharacterSet | String | Character set of the remote domain. | 
| EWS.RemoteDomain.ContentType | String | Content type of the remote domain. | 
| EWS.RemoteDomain.DeliveryReportEnabled | Boolean | Whether delivery report is enabled for the remote domain. | 
| EWS.RemoteDomain.DisplaySenderName | Boolean | Whether to display the sender name for the remote domain. | 
| EWS.RemoteDomain.DistinguishedName | String | Distinguished name of the remote domain. | 
| EWS.RemoteDomain.DomainName | String | Domain name of the remote domain. | 
| EWS.RemoteDomain.ExchangeObjectId | String | Exchange object ID of the remote domain. | 
| EWS.RemoteDomain.ExchangeVersion | String | Exchange version of the remote domain. | 
| EWS.RemoteDomain.Guid | String | GUID of the remote domain. | 
| EWS.RemoteDomain.Id | String | ID of the remote domain. | 
| EWS.RemoteDomain.Identity | String | Identity of the remote domain. | 
| EWS.RemoteDomain.IsInternal | Boolean | Whether the remote domain is internal. | 
| EWS.RemoteDomain.IsValid | Boolean | Whether the remote domain is valid. | 
| EWS.RemoteDomain.LineWrapSize | String | Line wrap size for the remote domain. | 
| EWS.RemoteDomain.MeetingForwardNotificationEnabled | Boolean | Whether meeting forward notification is enabled for the remote domain. | 
| EWS.RemoteDomain.MessageCountThreshold | Number | Message count threshold  of the remote domain. | 
| EWS.RemoteDomain.NDRDiagnosticInfoEnabled | Boolean | Whether NDR diagnostic information is enabled for the remote domain. | 
| EWS.RemoteDomain.NDREnabled | Boolean | Whether NDR is enabled for the remote domain. | 
| EWS.RemoteDomain.Name | String | Name of the remote domain. | 
| EWS.RemoteDomain.NonMimeCharacterSet | String | Non-mime character set of the remote domain. | 
| EWS.RemoteDomain.ObjectCategory | String | Object category of the remote domain. | 
| EWS.RemoteDomain.ObjectClass | String | Object class of the remote domain. | 
| EWS.RemoteDomain.ObjectState | String | Object state of the remote domain. | 
| EWS.RemoteDomain.OrganizationId | String | Organization ID of the remote domain. | 
| EWS.RemoteDomain.OriginatingServer | String | Originating server of the remote domain. | 
| EWS.RemoteDomain.PSComputerName | String | PowerShell computer name of the remote domain. | 
| EWS.RemoteDomain.PSShowComputerName | Boolean | Whether to show the PowerShell computer name for the remote domain. | 
| EWS.RemoteDomain.PreferredInternetCodePageForShiftJis | String | Preferred internet code page for shift JIS for the remote domain. | 
| EWS.RemoteDomain.RequiredCharsetCoverage | Unknown | Required charset coverage for the remote domain. | 
| EWS.RemoteDomain.RunspaceId | String | Runspace ID for the remote domain. | 
| EWS.RemoteDomain.TNEFEnabled | Unknown | Whether TNEF is enabled for the remote domain. | 
| EWS.RemoteDomain.TargetDeliveryDomain | Boolean | Whether the remote domain is used for the target email address of mail users that represent the users in the other forest. | 
| EWS.RemoteDomain.TrustedMailInboundEnabled | Boolean | Whether inbound trusted mail is enabled. | 
| EWS.RemoteDomain.TrustedMailOutboundEnabled | Boolean | Whether outbound trusted mail is enabled. | 
| EWS.RemoteDomain.UseSimpleDisplayName | Boolean | Whether to use the simple display name. | 
| EWS.RemoteDomain.WhenChanged | Date | The date the remote domain was changed. | 
| EWS.RemoteDomain.WhenChangedUTC | Date | The date in UTC format of when the remote domain was changed. | 
| EWS.RemoteDomain.WhenCreated | Date | The date the remote domain was created. | 
| EWS.RemoteDomain.WhenCreatedUTC | Date | The date in UTC format of when the remote domain was created. | 

### ews-user-list
***
Displays the existing user objects in your organization.


#### Base Command

`ews-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The mailbox you want to view. | Optional | 
| organizational_unit | The object's location in Active Directory by which to filter the results. | Optional | 
| limit | Maximum number of users to get. A value of 0 means to get all users. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.User.AccountDisabled | Boolean | Whether the user account is disabled. | 
| EWS.User.AllowUMCallsFromNonUsers | Boolean | Whether to allow Unified Messaging calls from non-users. | 
| EWS.User.ArchiveRelease | String | The archive release of the user object. | 
| EWS.User.AssistantName | String | The assistant name of the user object. | 
| EWS.User.AuthenticationPolicy | Unknown | The authentication policy of the user object. | 
| EWS.User.CanHaveCloudCache | Boolean | Whether the user object can have cloud cache. | 
| EWS.User.City | String | The city of the user object. | 
| EWS.User.CloudCacheAccountType | String | Cloud cache account type of the user object. | 
| EWS.User.CloudCacheProvider | Number | Cloud cache provider of the user object. | 
| EWS.User.CloudCacheRemoteEmailAddress | String | Cloud cache remote email address of the user object. | 
| EWS.User.CloudCacheScope | Number | Cloud cache scope of the user object. | 
| EWS.User.CloudCacheUserName | String | Cloud cache user name of the user object. | 
| EWS.User.Company | String | Company of the user object. | 
| EWS.User.ConsumerNetID | Unknown | Consumer net ID of the user object. | 
| EWS.User.CountryOrRegion | String | Country or region of the . | 
| EWS.User.DefaultMailboxWorkloadsMask | Unknown | Default mailbox workloads mask of the user object. | 
| EWS.User.Department | String | Department of the user object. | 
| EWS.User.DesiredMailboxWorkloads | Unknown | Desired mailbox workloads of the user object. | 
| EWS.User.DesiredMailboxWorkloadsGracePeriod | Unknown | Desired mailbox workloads grace period of the user object. | 
| EWS.User.DesiredMailboxWorkloadsModified | Unknown | Modified desired mailbox workloads of the user object. | 
| EWS.User.DisplayName | String | Display name of the user object. | 
| EWS.User.DistinguishedName | String | Distinguished name of the user object. | 
| EWS.User.ExchangeObjectId | String | Exchange object ID of the user object. | 
| EWS.User.ExchangeVersion | String | Exchange version of the user object. | 
| EWS.User.ExternalDirectoryObjectId | String | External Directory Object ID of the user object. | 
| EWS.User.Fax | String | Fax of the user object. | 
| EWS.User.FirstName | String | First name of the user object. | 
| EWS.User.GeoCoordinates | Unknown | Geo coordinates of the user object. | 
| EWS.User.Guid | String | GUID of the user object. | 
| EWS.User.HomePhone | String | Home phone of the user object. | 
| EWS.User.Id | String | ID of the user object. | 
| EWS.User.Identity | String | Identity of the user object. | 
| EWS.User.Initials | String | Initials of the user object. | 
| EWS.User.IsCloudCache | Boolean | Whether there is a cloud cache for the user object. | 
| EWS.User.IsCloudCacheBlocked | Boolean | Whether the cloud cache is blocked. | 
| EWS.User.IsCloudCacheProvisioningComplete | Boolean | Whether cloud cache provisioning is complete. | 
| EWS.User.IsDirSynced | Boolean | Whether the directory is synched. | 
| EWS.User.IsInactiveMailbox | Boolean | Whether the mailbox is inactive. | 
| EWS.User.IsLinked | Boolean | Whether the user object is linked. | 
| EWS.User.IsSecurityPrincipal | Boolean | Whether there is a security principal. | 
| EWS.User.IsSoftDeletedByDisable | Boolean | Whether soft delete is disabled and hard \(permanent\) delete occurs. | 
| EWS.User.IsSoftDeletedByRemove | Boolean | When the Exchange Online mailbox is deleted \(soft delete\), this property is set to True. | 
| EWS.User.IsValid | Boolean | Whether the user object is valid. | 
| EWS.User.LastName | String | Last name of the user object. | 
| EWS.User.LegacyExchangeDN | String | Legacy exchange distinguished name of the user object. | 
| EWS.User.LegalAgeGroup | Unknown | Legal age group of the user object. | 
| EWS.User.LinkedMasterAccount | String | Linked master account of the user object. | 
| EWS.User.MailboxLocations | String | Mailbox locations of the user object. | 
| EWS.User.MailboxProvisioningConstraint | Unknown | Mailbox provisioning constraint of the user object. | 
| EWS.User.MailboxRegion | Unknown | Mailbox region of the user object. | 
| EWS.User.MailboxRegionLastUpdateTime | Unknown | Last time the mailbox region  of the user object was updated. | 
| EWS.User.MailboxRegionSuffix | String | Mailbox region suffix of the user object. | 
| EWS.User.MailboxRelease | String | Mailbox release of the user object. | 
| EWS.User.MailboxWorkloads | String | Mailbox workloads of the user object. | 
| EWS.User.Manager | Unknown | Manager of the user object. | 
| EWS.User.MicrosoftOnlineServicesID | String | Microsoft Online Services ID of the user object. | 
| EWS.User.MobilePhone | String | Mobile phone of the user object. | 
| EWS.User.Name | String | Name of the user object. | 
| EWS.User.NetID | String | Network ID of the user object. | 
| EWS.User.Notes | String | Notes for the user object. | 
| EWS.User.ObjectCategory | String | Object category of the user object. | 
| EWS.User.ObjectClass | String | Object class of the user object. | 
| EWS.User.ObjectState | String | Object state of the user object. | 
| EWS.User.Office | String | Office of the user object. | 
| EWS.User.OrganizationId | String | Organization ID of the user object. | 
| EWS.User.OrganizationalUnit | String | Organizational unit of the user object. | 
| EWS.User.OriginatingServer | String | Originating server of the user object. | 
| EWS.User.PSComputerName | String | PowerShell computer name of the user object. | 
| EWS.User.PSShowComputerName | Boolean | Whether to show the PowerShell computer name of the user object. | 
| EWS.User.Pager | String | Pager of the user object. | 
| EWS.User.Phone | String | Phone of the user object. | 
| EWS.User.PhoneticDisplayName | String | Phonetic display name of the user object. | 
| EWS.User.PostalCode | String | Postal Code of the user object. | 
| EWS.User.PreviousRecipientTypeDetails | String | Details of the previous recipient type of the user object. | 
| EWS.User.RecipientType | String | Recipient type of the user object. | 
| EWS.User.RecipientTypeDetails | String | Details of the recipient type of the user object. | 
| EWS.User.RemotePowerShellEnabled | Boolean | Whether remote PowerShell is enabled for the user object. | 
| EWS.User.ResetPasswordOnNextLogon | Boolean | Whether to reset the password on next logon. | 
| EWS.User.RunspaceId | String | Runspace ID of the user object. | 
| EWS.User.SKUAssigned | Boolean | Whether SKU is assigned. | 
| EWS.User.SamAccountName | String | sAMAccountName of the user object. | 
| EWS.User.SeniorityIndex | Unknown | Seniority index of the user object. | 
| EWS.User.Sid | String | SID of the user object. | 
| EWS.User.SimpleDisplayName | String | Simple display name of the user object. | 
| EWS.User.StateOrProvince | String | State or province of the user object. | 
| EWS.User.StreetAddress | String | Street address of the user object. | 
| EWS.User.StsRefreshTokensValidFrom | Date | The validation start date for the Security Token Service \(STS\) refresh tokens of the user object. | 
| EWS.User.TelephoneAssistant | String | Telephone assistant of the user object. | 
| EWS.User.Title | String | Title of the user object. | 
| EWS.User.UMDialPlan | Unknown | Unified Messaging \(UM\) dial plan of the user object. | 
| EWS.User.UMDtmfMap | String | Unified Messaging \(UM\) dual tone multi-frequency \(DTMF\) map of the user object. | 
| EWS.User.UpgradeDetails | Unknown | Upgrade details of the user object. | 
| EWS.User.UpgradeMessage | Unknown | Upgrade message of the user object. | 
| EWS.User.UpgradeRequest | String | Upgrade request of the user object. | 
| EWS.User.UpgradeStage | Unknown | Upgrade stage of the user object. | 
| EWS.User.UpgradeStageTimeStamp | Unknown | Upgrade stage time stamp of the user object. | 
| EWS.User.UpgradeStatus | String | Upgrade status of the user object. | 
| EWS.User.UserAccountControl | String | User account control of the user object. | 
| EWS.User.UserPrincipalName | String | User principal name of the user object. | 
| EWS.User.WebPage | String | Web page of the user object. | 
| EWS.User.WhenChanged | Date | The date the user object was changed. | 
| EWS.User.WhenChangedUTC | Date | The date in UTC format of when the user object was changed. | 
| EWS.User.WhenCreated | Date | The date the user object was created. | 
| EWS.User.WhenCreatedUTC | Date | The date in UTC format of when the user object was created. | 
| EWS.User.WhenSoftDeleted | Unknown | When the user object was soft deleted. | 
| EWS.User.WindowsEmailAddress | String | Windows email address of the user object. | 
| EWS.User.WindowsLiveID | String | Windows live ID of the user object. | 
| EWS.User.DirectReports | String | Direct reports of the user object. | 

### ews-mailbox-audit-bypass-association-list
***
Retrieves information about the AuditBypassEnabled property value for user accounts (on-premises Exchange and the cloud) and computer accounts (on-premises Exchange only).


#### Base Command

`ews-mailbox-audit-bypass-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The mailbox you want to view. | Optional | 
| domain_controller | The domain controller that's used by this cmdlet to read data from or write data to Active Directory. You identify the domain controller by its fully qualified domain name (FQDN). This argument is available only in on-premises Exchange. | Optional | 
| limit | Maximum number of users to get. A value of 0 means to get all users. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.MailboxAuditBypassAssociation.AuditBypassEnabled | Boolean | Whether the mailbox audit bypass association is enabled. | 
| EWS.MailboxAuditBypassAssociation.DistinguishedName | String | Distinguished name of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.ExchangeObjectId | String | Exchange object ID of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.ExchangeVersion | String | The version of the exchanged server. | 
| EWS.MailboxAuditBypassAssociation.Guid | String | The GUID of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.Id | String | ID of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.Identity | String | The unique identity of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.IsValid | Boolean | Whether the mailbox audit bypass association property is enabled. | 
| EWS.MailboxAuditBypassAssociation.Name | String | Name of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.ObjectCategory | String | Object category of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.ObjectClass | String | Object class of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.ObjectId | String | Object ID of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.ObjectState | String | Object state of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.OrganizationId | String | Organization ID of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.OriginatingServer | String | Originating server of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.PSComputerName | String | PowerShell computer name of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.PSShowComputerName | Boolean | Whether to show the computer name of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.RunspaceId | String | Runspace ID of the mailbox audit bypass association. | 
| EWS.MailboxAuditBypassAssociation.WhenChanged | unknown | The date the mailbox audit bypass association was changed. | 
| EWS.MailboxAuditBypassAssociation.WhenChangedUTC | Date | The date in UTC of when the mailbox audit bypass association was changed. | 
| EWS.MailboxAuditBypassAssociation.WhenCreated | Date | The date the mailbox audit bypass association was created. | 
| EWS.MailboxAuditBypassAssociation.WhenCreatedUTC | Date | The date in UTC format of when the mailbox audit bypass association was created. | 


### ews-rule-list
***
Get a list of all mailbox rules.

#### Base Command

`ews-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | The mailbox that contains the Inbox rule. | Required | 
| limit | Maximum number of rules to get. A value of 0 means to get all rules | Optional | 


#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Rule.RuleIdentity | String | The rule identity. | 
| EWS.Rule.Name | String | The rule name. | 
| EWS.Rule.Enabled | Boolean| Whether the rule is enabled or not. | 
| EWS.Rule.Priority | String | the rule priority. | 


#### Human Readable Output

>### Results of ews-rule-list
>| Enabled | Name | Priority | RuleIdentity |
>| --- | --- | --- | --- |
>| true | CheckActionRequired	 | 1 | 1268829516541722625 |
>| true | ews phishing test	| 8 | 1845290268845146113 |

### ews-get-rule
***
Get a mailbox rule.

#### Base Command

`ews-get-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | The mailbox that contains the Inbox rule. | Required | 
| identity | The ID of the rule. | Required |

#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Rule.Rule | String | The rule identity. | 
| EWS.Rule.RuleName | String | The rule name. | 
| EWS.Rule.IsEnabled | Boolean| Whether the rule is enabled or not. | 
| EWS.Rule.Priority | String | The rule priority. |
| EWS.Rule.Description | String | The description of the rule. | 
| EWS.Rule.StopProcessingRules | Boolean| Whether to stop processing the rule or not. | 
| EWS.Rule.IsValid | Boolean | Whether the rule is valid or not. | 


#### Human Readable Output

>### Results of ews-rule-list
>| Enabled | Name | Priority | RuleIdentity | Description | IsValid	| StopProcessingRules|
>| --- | --- | --- | --- | --- | --- | ---|
>| true | CheckActionRequired | 1 | 1268829516541722625 | If the message: the sender requested any action and my name is in the To box | true| false |

### ews-remove-rule
***
Remove a mailbox rule.

#### Base Command

`ews-remove-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | The mailbox that contains the Inbox rule. | Required | 
| identity | The ID of the rule. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output

>Rule 1845290268845146113 has been deleted successfully

### ews-rule-disable
***
Disable an existing inbox rule in a given mailbox.

#### Base Command

`ews-rule-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | The mailbox that contains the inbox rule. | Required | 
| identity | The inbox rule that you want to disable. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output

>Rule 1845290268845146113 has been disabled successfully

### ews-rule-enable
***
Enable an existing inbox rule in a given mailbox.

#### Base Command

`ews-rule-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | The mailbox that contains the inbox rule. | Required | 
| identity | The inbox rule that you want to enable. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output

>Rule 1845290268845146113  has been enabled successfully

### ews-mail-flow-rules-list
***
List all mail flow rules (transport rules) in the organization.

#### Base Command

`ews-mail-flow-rules-list`
#### Input
| **Argument Name** | **Description**                                                | **Possible Values** | **Is Array** | **Required** | **Note**        |
|-------------------|----------------------------------------------------------------|---------------------|--------------| --- |-----------------|
| extended_output   | Determine whether the output will be in verbose format or not. | Boolean             | No           | No | Default = False |
| limit             | The amount of mail flow rules to return. | Number             | No           | No | Default is 1000  |

#### Context Output
| **Path** | **Type** | **Description** |
| --- |----------| --- |
| EWS.MailFlowRule.Size | Number   | The size of the mail flow rule in bytes, typically related to the storage or data usage of the rule. |
| EWS.MailFlowRule.ExpiryDate | Date     | The date and time when the mail flow rule is set to expire and no longer apply. |
| EWS.MailFlowRule.Mode | String   | The operational mode of the rule, indicating whether it is active (`Enforce`), in testing mode (`Test`), or disabled. |
| EWS.MailFlowRule.Quarantine | Boolean  | Specifies whether the rule actions include quarantining messages that match the rule. |
| EWS.MailFlowRule.Guid | String   | The unique identifier (Globally Unique Identifier) for the mail flow rule. |
| EWS.MailFlowRule.OrganizationId | String   | The identifier for the organization where the mail flow rule is configured, typically used in multi-tenant environments. |
| EWS.MailFlowRule.DistinguishedName | String   | The distinguished name of the mail flow rule in the Exchange directory structure. |
| EWS.MailFlowRule.IsValid | Boolean  | Indicates whether the mail flow rule is valid and functional. |
| EWS.MailFlowRule.Conditions | Array    | The conditions that trigger the mail flow rule, such as specific senders, recipients, or message properties. |
| EWS.MailFlowRule.Comments | Unknown  | Free-form text field for adding comments or notes about the rule, typically used for documentation. |
| EWS.MailFlowRule.WhenChanged | Date     | The date and time when the mail flow rule was last modified. |
| EWS.MailFlowRule.Description | String   | A brief description of the mail flow rule's purpose or functionality. |
| EWS.MailFlowRule.Actions |    Array      | The actions taken when a message matches the rule's conditions, such as redirecting, blocking, or adding headers. |
| EWS.MailFlowRule.ImmutableId |   String       |  A persistent, unchangeable identifier for the mail flow rule, ensuring it remains identifiable across modifications. |
| EWS.MailFlowRule.Identity |   String       |The identity of the rule, often combining the name and unique identifiers, used to reference the rule programmatically.  |
| EWS.MailFlowRule.Name |   String       |  The user-friendly name of the mail flow rule, typically used for easy identification. |
| EWS.MailFlowRule.CreatedBy |     String     | The user or process that created the mail flow rule. |
| EWS.MailFlowRule.RouteMessageOutboundConnector |   Unknown       | Specifies whether messages matching the rule should be routed through a specific outbound connector. |

#### Human Readable Output

>### Results of ews-rule-list
>| Name      | State    | Priority | Comment | WhenChanged                | CreatedBy|
>|-----------|----------|----------|---------|----------------------------| --- |
>| demisto   | Disabled | 1        | comment | 2019-10-14T07:25:04+00:00  | Edwin Becker
>| demisto-2 | Enabled  | 2        | comment | 2019-11-15T010:21:45+00:00 | Kemp Kimmons
>| demisto-3 | Enabled  | 3        | comment | 2019-11-16T016:26:46+00:00 | Barbara Wagner

### ews-mail-flow-rule-get
***
Get a mail flow rule (transport rules) in the organization.

#### Base Command

`ews-mail-flow-rule-get`
#### Input

| **Argument Name** | **Description**                                                | **Possible Values** | **Is Array** | **Required** | **Note** |
| --- |----------------------------------------------------------------|---------------------| --- | --- | --- |
| extended_output | Determine whether the output will be in verbose format or not. | Boolean             | No | No | Default = False |
| identity | Specifies the rule that you want to view.                      | string             | No | No |  |


#### Context Output
| **Path** | **Type** | **Description** |
| --- |----------| --- |
| EWS.MailFlowRule.Size | Number   | The size of the mail flow rule in bytes, typically related to the storage or data usage of the rule. |
| EWS.MailFlowRule.ExpiryDate | Date     | The date and time when the mail flow rule is set to expire and no longer apply. |
| EWS.MailFlowRule.Mode | String   | The operational mode of the rule, indicating whether it is active (`Enforce`), in testing mode (`Test`), or disabled. |
| EWS.MailFlowRule.Quarantine | Boolean  | Specifies whether the rule actions include quarantining messages that match the rule. |
| EWS.MailFlowRule.Guid | String   | The unique identifier (Globally Unique Identifier) for the mail flow rule. |
| EWS.MailFlowRule.OrganizationId | String   | The identifier for the organization where the mail flow rule is configured, typically used in multi-tenant environments. |
| EWS.MailFlowRule.DistinguishedName | String   | The distinguished name of the mail flow rule in the Exchange directory structure. |
| EWS.MailFlowRule.IsValid | Boolean  | Indicates whether the mail flow rule is valid and functional. |
| EWS.MailFlowRule.Conditions | Array    | The conditions that trigger the mail flow rule, such as specific senders, recipients, or message properties. |
| EWS.MailFlowRule.Comments | Unknown  | Free-form text field for adding comments or notes about the rule, typically used for documentation. |
| EWS.MailFlowRule.WhenChanged | Date     | The date and time when the mail flow rule was last modified. |
| EWS.MailFlowRule.Description | String   | A brief description of the mail flow rule's purpose or functionality. |
| EWS.MailFlowRule.Actions |    Array      | The actions taken when a message matches the rule's conditions, such as redirecting, blocking, or adding headers. |
| EWS.MailFlowRule.ImmutableId |   String       |  A persistent, unchangeable identifier for the mail flow rule, ensuring it remains identifiable across modifications. |
| EWS.MailFlowRule.Identity |   String       |The identity of the rule, often combining the name and unique identifiers, used to reference the rule programmatically.  |
| EWS.MailFlowRule.Name |   String       |  The user-friendly name of the mail flow rule, typically used for easy identification. |
| EWS.MailFlowRule.CreatedBy |     String     | The user or process that created the mail flow rule. |
| EWS.MailFlowRule.RouteMessageOutboundConnector |   Unknown       | Specifies whether messages matching the rule should be routed through a specific outbound connector. |

#### Human Readable Output

>### Results of ews-rule-list
>| Name      | State    | Priority | Comment | WhenChanged                | CreatedBy|
>|-----------|----------|----------|---------|----------------------------| --- |
>| demisto   | Disabled | 1        | comment | 2019-10-14T07:25:04+00:00  | Edwin Becker

### ews-mail-flow-rule-remove
***
Remove a mail flow rule (transport rule) from the organization.

#### Base Command

`ews-mail-flow-rule-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The rule that you want to remove. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output
>Mail flow rule 1845290268845146113 has been removed successfully

### ews-mail-flow-rule-disable
***
Disable a mail flow rule (transport rule) in the organization.

#### Base Command

`ews-mail-flow-rule-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The rule that you want to disable. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output
>Mail flow rule 1845290268845146113 has been disabled successfully

### ews-mail-flow-rule-enable
***
Enable a mail flow rule (transport rule) in the organization.

#### Base Command

`ews-mail-flow-rule-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The rule that you want to enable. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output
>Mail flow rule 1845290268845146113 has been enabled successfully

### ews-mail-forwarding-disable
***
Disable mail forwarding for a given user.

#### Base Command

`ews-mail-forwarding-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The mailbox that you want to modify. | Required | 


#### Context Output
There are no context outputs for this command.

#### Human Readable Output
>Mail forwarding for user 1845290268845146113 has been disabled successfully


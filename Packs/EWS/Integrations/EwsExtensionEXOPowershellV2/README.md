Use the EWS Extension Online Powershell v2 integration to get information about mailboxes and users in your organization.
This integration was integrated and tested with version v2 of EWS Extension Online Powershell v2

**Note:** This integration does not replace the **O365 - EWS - Extension** integration, but an additional EWS extension integration
which utilizes the [EXO v2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps).

## Configure EWS Extension Online Powershell v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EWS Extension Online Powershell v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Exchange Online URL |  | True |
    | Certificate | A pfx certificate encoded in Base64. | True |
    | The organization used in app-only authentication. |  | True |
    | The application ID from the Azure portal |  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

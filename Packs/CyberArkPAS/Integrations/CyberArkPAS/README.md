Use this integration to create, list, modify and delete entities in the PAS solution. This integration was integrated and tested with version 11.4 of CyberArk Privileged Account Security
This integration was integrated and tested with version xx of CyberArkPAS
## Configure CyberArkPAS on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberArkPAS.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberark-list-accounts
***
A command to list CyberArk Accounts


#### Base Command

`cyberark-list-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Offset of the first account that is returned in the collection of results. If not specified, the default value is 0 | Optional | 
| limit | Maximum number of returned accounts. If not specified, the default value is 50. The maximum number that can be specified is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArk.Accounts.AccountID | String | CyberArk Accounts ID | 
| CyberArk.Accounts.AccountName | String | CyberArk Accounts Name | 
| CyberArk.Accounts.UserName | String | CyberArk Accounts Username | 
| CyberArk.Accounts.PlatformID | String | CyberArk Platform ID | 
| CyberArk.Accounts.SafeName | String | CyberArk Safe Name | 
| CyberArk.Accounts.CreatedTime | String | CyberArk Created Time | 


#### Command Example
```!cyberark-list-accounts```

#### Context Example
```
{
    "CyberArk": {
        "Accounts": [
            {
                "AccountID": "10_36",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11",
                "CreatedTime": 1594190145,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_37",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11 (1)",
                "CreatedTime": 1594190222,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_38",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11 (2)",
                "CreatedTime": 1594191955,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_39",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11 (3)",
                "CreatedTime": 1594195006,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_40",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11 (4)",
                "CreatedTime": 1594195907,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_41",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11 (5)",
                "CreatedTime": 1594198751,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_42",
                "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user11 (6)",
                "CreatedTime": 1594200062,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user11"
            },
            {
                "AccountID": "10_23",
                "AccountName": "Operating System-WinDesktopLocal-machine1-ayman321",
                "CreatedTime": 1593507829,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "ayman321"
            },
            {
                "AccountID": "10_16",
                "AccountName": "test12345",
                "CreatedTime": 1593597975,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "1234"
            },
            {
                "AccountID": "10_26",
                "AccountName": "user1",
                "CreatedTime": 1593592167,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user1"
            },
            {
                "AccountID": "10_28",
                "AccountName": "user10",
                "CreatedTime": 1593598006,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user10"
            },
            {
                "AccountID": "10_29",
                "AccountName": "user12",
                "CreatedTime": 1593598605,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user12"
            },
            {
                "AccountID": "10_5",
                "AccountName": "user2",
                "CreatedTime": 1593592209,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user2"
            },
            {
                "AccountID": "10_27",
                "AccountName": "user3",
                "CreatedTime": 1593592222,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|AccountID|AccountName|CreatedTime|PlatformID|SafeName|UserName|
>|---|---|---|---|---|---|
>| 10_36 | Operating System-WinDesktopLocal-20.20.20.20-user11 | 1594190145 | WinDesktopLocal | Labs | user11 |
>| 10_37 | Operating System-WinDesktopLocal-20.20.20.20-user11 (1) | 1594190222 | WinDesktopLocal | Labs | user11 |
>| 10_38 | Operating System-WinDesktopLocal-20.20.20.20-user11 (2) | 1594191955 | WinDesktopLocal | Labs | user11 |
>| 10_39 | Operating System-WinDesktopLocal-20.20.20.20-user11 (3) | 1594195006 | WinDesktopLocal | Labs | user11 |
>| 10_40 | Operating System-WinDesktopLocal-20.20.20.20-user11 (4) | 1594195907 | WinDesktopLocal | Labs | user11 |
>| 10_41 | Operating System-WinDesktopLocal-20.20.20.20-user11 (5) | 1594198751 | WinDesktopLocal | Labs | user11 |
>| 10_42 | Operating System-WinDesktopLocal-20.20.20.20-user11 (6) | 1594200062 | WinDesktopLocal | Labs | user11 |
>| 10_23 | Operating System-WinDesktopLocal-machine1-ayman321 | 1593507829 | WinDesktopLocal | Labs | ayman321 |
>| 10_16 | test12345 | 1593597975 | WinDesktopLocal | Labs | 1234 |
>| 10_26 | user1 | 1593592167 | WinDesktopLocal | Labs | user1 |
>| 10_28 | user10 | 1593598006 | WinDesktopLocal | Labs | user10 |
>| 10_29 | user12 | 1593598605 | WinDesktopLocal | Labs | user12 |
>| 10_5 | user2 | 1593592209 | WinDesktopLocal | Labs | user2 |
>| 10_27 | user3 | 1593592222 | WinDesktopLocal | Labs | user3 |


### cyberark-add-account
***
A command to add a new CyberArk Account


#### Base Command

`cyberark-add-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | An Identifier of the CyberArk Account | Optional | 
| address | The name or address of the machine where the account will be used, vDNS/IP/URL where the account is managed | Required | 
| user_name | Account user's name | Required | 
| platform_Id | The platform assigned to this account, Valid platform IDs, example: WinServerLocal | Required | 
| safe_name | The Safe where the account will be created. | Required | 
| secret | The password value, password or private SSH key | Optional | 
| secret_type | The type of password, password or key | Optional | 
| platform_account_properties | Object containing key-value pairs to associate with the account, as defined by the account platform. These properties are validated against the mandatory and optional properties of the specified platform's definition; example: {"Location": "IT", "OwnerName": "MSSPAdmin"} | Optional | 
| automatic_management_enabled | Whether the account secret is automatically managed by the CPM.<br/>True or False | Optional | 
| manual_management_reason | Reason for disabling automatic secret management. | Optional | 
| remote_machines | List of remote machines, separated by semicolons.Example | Optional | 
| access_restricted_to_remote_machines | Whether or not to restrict access only to specified remote machines | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArk.Accounts.AccountID | String | CyberArk Accounts ID | 
| CyberArk.Accounts.AccountName | String | CyberArk Accounts Name | 
| CyberArk.Accounts.UserName | String | CyberArk Accounts Username | 
| CyberArk.Accounts.PlatformID | String | CyberArk Platform ID | 
| CyberArk.Accounts.SafeName | String | CyberArk Safe Name | 
| CyberArk.Accounts.CreatedTime | String | CyberArk Created Time | 


#### Command Example
```!cyberark-add-account address="20.20.20.20" user_name="user12" platform_Id="WinDesktopLocal" safe_name="Labs" platform_account_properties=`{"Location": "IT", "OwnerName": "MSSPAdmin"}````

#### Context Example
```
{
    "CyberArk": {
        "Accounts": {
            "AccountID": "10_43",
            "AccountName": "Operating System-WinDesktopLocal-20.20.20.20-user12",
            "CreatedTime": 1594200598,
            "PlatformID": "WinDesktopLocal",
            "SafeName": "Labs",
            "UserName": "user12"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AccountID|AccountName|CreatedTime|PlatformID|SafeName|UserName|
>|---|---|---|---|---|---|
>| 10_43 | Operating System-WinDesktopLocal-20.20.20.20-user12 | 1594200598 | WinDesktopLocal | Labs | user12 |


### cyberark-delete-account
***
A command to delete a CyberArk Account


#### Base Command

`cyberark-delete-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | CyberArk Account ID | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-delete-account account_id="10_36"```

#### Context Example
```
{}
```

#### Human Readable Output

>Account is Deleted

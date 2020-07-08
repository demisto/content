Use this integration to create, list, modify and delete entities in the PAS solution. 
This integration was integrated and tested with version 11.4 of CyberArk Privileged Account Security
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
| authType | Authentication Type | False |

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
| CyberArk.Accounts | Unknown | CyberArk Accounts | 


#### Command Example
```!cyberark-list-accounts```

#### Context Example
```
{
    "CyberArk": {
        "Accounts": [
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

>### CyberArk PAS - List of the Accounts
>|AccountID|AccountName|CreatedTime|PlatformID|SafeName|UserName|
>|---|---|---|---|---|---|
>| 10_23 | Operating System-WinDesktopLocal-machine1-ayman321 | 1593507829 | WinDesktopLocal | Labs | ayman321 |
>| 10_16 | test12345 | 1593597975 | WinDesktopLocal | Labs | 1234 |
>| 10_26 | user1 | 1593592167 | WinDesktopLocal | Labs | user1 |
>| 10_28 | user10 | 1593598006 | WinDesktopLocal | Labs | user10 |
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
| name | The name of the account. | Optional | 
| address | The name or address of the machine where the account will be used, vDNS/IP/URL where the account is managed | Required | 
| user-name | Account user's name | Required | 
| platform-Id | The platform assigned to this account, Valid platform IDs, example: WinServerLocal | Required | 
| safe-name | The Safe where the account will be created. | Required | 
| secret | The password value, password or private SSH key | Optional | 
| secret-type | The type of password, password or key | Optional | 
| platform-account-properties | Object containing key-value pairs to associate with the account, as defined by the account platform. These properties are validated against the mandatory and optional properties of the specified platform's definition; example: {"Location": "IT", "OwnerName": "MSSPAdmin"} | Optional | 
| automatic-management-enabled | Whether the account secret is automatically managed by the CPM.True or False | Optional | 
| manual-management-reason | Reason for disabling automatic secret management. | Optional | 
| remote-machines | List of remote machines, separated by semicolons.Example: server1.cyberark.com;server2.cyberark.com | Optional | 
| access-restricted-to-remote-machines | Whether or not to restrict access only to specified remote machines | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArk.Accounts | Unknown | CyberArk Accounts | 


#### Command Example
```!cyberark-add-account name="user12" address="20.20.20.20" user-name="user12" platform-Id="WinDesktopLocal" safe-name="Labs" platform-account-properties=`{"Location": "IT", "OwnerName": "MSSPAdmin"}````

#### Context Example
```
{
    "CyberArk": {
        "Accounts": [
            {
                "AccountID": "10_29",
                "AccountName": "user12",
                "CreatedTime": 1593598605,
                "PlatformID": "WinDesktopLocal",
                "SafeName": "Labs",
                "UserName": "user12"
            }
        ]
    }
}
```

#### Human Readable Output

>### CyberArk PAS - Add a New Account
>|AccountID|AccountName|CreatedTime|PlatformID|SafeName|UserName|
>|---|---|---|---|---|---|
>| 10_29 | user12 | 1593598605 | WinDesktopLocal | Labs | user12 |

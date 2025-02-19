The CyberArk Central Credential Provider (CCP) provides a secure safe in which to store your account credentials. Use this integration to retrieve the account credentials in CyberArk CCP. This integration fetches credentials. For more information, see [Managing Credentials](https://xsoar.pan.dev/docs/reference/articles/managing-credentials).

## Authentication Options
The integration uses the `Central Credential Provider` and supports the following authentication methods:
* **OS User (Windows NTLM Authentication)**: Set the domain user and password in the credentials field. Make sure your CyberArk Server is configured to support `NTLM` authentication as documented [here](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-CP/Latest/en/Content/CCP/Configure_CCPWindows.htm#ConfigureWindowsDomainAuthentication). Note that the `user` option may require specifying full `domain\user`.
* **Client Certificate Authentication**: Enter the Certificate and Private key in the integration instance configuration parameters. Make sure to follow the instructions [here](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-CP/Latest/en/Content/CCP/Configure_CCPWindows.htm#SecurecommunicationbetweenapplicationsandtheCentralCredentialProvider) to enable the `Central Credential Provider` to accept client authentication with client certificates.
* **Allowed Machines**: Leave all authentication methods empty. Follow CyberArk's instructions [here](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-CP/Latest/en/Content/CP%20and%20ASCP/Application-Authentication-Methods-general.htm?tocpath=Administration%7CManage%20applications%7CApplication%20authentication%7CApplication%20authentication%20methods%7C_____0#allowed) to accept the `Cortex XSOAR Server IP` for the configured AppID.

Further information is available from CyberArk at:
* https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-CP/Latest/en/Content/CP%20and%20ASCP/Application-Authentication-Methods-general.htm
* https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-CP/Latest/en/Content/CCP/Configure_CCPWindows.htm

## Configure CyberArkAIM v2 in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberArkCCP.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description**                                                                                              | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------| --- |
| url | Server URL and Port \(e.g., https://example.net:1234\)                                                       | True |
| app_id | AppID as configured in CCP                                                                                   | False |
| folder | Folder to search in safe                                                                                     | True |
| safe | Safe to search in                                                                                            | True |
| credential_names | Credential names \- comma\-separated list of credentials names in the safe. Partial names are not supported. | False |
| credentials | Username                                                                                                     | False |
| cert_text | Certificate file as text                                                                                     | False |
| key_text | Key file as text                                                                                             | False |
| isFetchCredentials | Fetches credentials                                                                                          | False |
| insecure | Trust any certificate \(not secure\)                                                                         | False |
| proxy | Use system proxy settings                                                                                    | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberark-aim-list-credentials
***
Lists all available credentials according to the list of credential names configured. 


#### Base Command

`cyberark-aim-list-credentials`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkAIM.AccountType | String | The type of the account. | 
| CyberArkAIM.Address | String | The address of the account. | 
| CyberArkAIM.CPMStatus | String | The CMP status of the account. | 
| CyberArkAIM.Domain | String | The domain of the account. | 
| CyberArkAIM.Name | String | The credential name of the account. | 


#### Command Example
```!cyberark-aim-list-credentials```

#### Context Example
```
{
    "CyberArkAIM": {
        "AccountCategory": "True",
        "AccountDescription": "Built-in account for administering the computer/domain",
        "AccountDiscoveryDate": "1573128798",
        "AccountEnabled": "True",
        "AccountExpirationDate": "0",
        "AccountOSGroups": "Administrators",
        "AccountType": "Domain",
        "Address": "AIM.COM",
        "CPMDisabled": "(CPM)Newly discovered dependency",
        "CPMStatus": "success",
        "CreationMethod": "AutoDetected",
        "DeviceType": "Operating System",
        "DiscoveryPlatformType": "Windows Domain",
        "Domain": "AIM.COM",
        "Folder": "Root",
        "LastLogonDate": "1572451901",
        "LastPasswordSetDate": "1566376303",
        "LastSuccessChange": "1575910475",
        "LastSuccessReconciliation": "1583521898",
        "LastSuccessVerification": "1583256386",
        "LastTask": "ReconcileTask",
        "LogonDomain": "domain1",
        "MachineOSFamily": "Server",
        "Name": "name1",
        "OSVersion": "Windows Server 2016 Standard",
        "OU": "CN=Users,DC=COM",
        "PasswordChangeInProcess": "False",
        "PasswordNeverExpires": "True",
        "PolicyID": "WinDomain",
        "RetriesCount": "-1",
        "SID": "sid",
        "Safe": "Windows Domain Admins",
        "SequenceID": "1",
        "Tags": "DAdmin",
        "UserName": "username1"
    }
}
```

#### Human Readable Output

>### Results
>|AccountCategory|AccountDescription|AccountDiscoveryDate|AccountEnabled|AccountExpirationDate|AccountOSGroups|AccountType|Address|CPMDisabled|CPMStatus|CreationMethod|DeviceType|DiscoveryPlatformType|Domain|Folder|LastLogonDate|LastPasswordSetDate|LastSuccessChange|LastSuccessReconciliation|LastSuccessVerification|LastTask|LogonDomain|MachineOSFamily|Name|OSVersion|OU|PasswordChangeInProcess|PasswordNeverExpires|PolicyID|RetriesCount|SID|Safe|SequenceID|Tags|UserName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| True | Built-in account for administering the computer/domain | 1573128798 | True | 0 | Administrators | Domain | AIM.COM | (CPM)Newly discovered dependency | success | AutoDetected | Operating System | Windows Domain | AIM.COM | Root | 1572451901 | 1566376303 | 1575910475 | 1583521898 | 1583256386 | ReconcileTask | domain1 | Server | name1 | Windows Server 2016 Standard | CN=Users,DC=COM | False | True | WinDomain | -1 | sid | Windows Domain Admins | 1 | DAdmin | username1 |
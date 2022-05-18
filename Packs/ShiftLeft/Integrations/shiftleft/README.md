Integrate ShiftLeft CORE code analysis platform with Cortex XSOAR.
This integration was integrated and tested with v4 api of ShiftLeft CORE.

## Configure ShiftLeft CORE on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ShiftLeft CORE.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | ShiftLeft Organization Id | You can find this under Account Settings -&amp;gt; Org ID | True |
    | ShiftLeft Access Token | You can find this under Account Settings -&amp;gt; Access Token | True |
    | Use system proxy settings | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### shiftleft-list-apps
***
Return list of apps.


#### Base Command

`shiftleft-list-apps`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.


#### Command Example
```!shiftleft-list-apps```

#### Human Readable Output



### shiftleft-list-app-findings
***
Return list of app findings.


#### Base Command

`shiftleft-list-app-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | App name. | Required | 
| severity | Severity of findings. Possible values are: critical, moderate, info. Default is critical. | Optional | 
| type | Findings Type. Possible values are: vuln, secret, insight, extscan, oss_vuln. Default is vuln. | Optional | 
| version | App version. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !shiftleft-list-app-findings ```

#### Human Readable Output



### shiftleft-list-app-secrets
***
Return list of app secrets.


#### Base Command

`shiftleft-list-app-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | App name. | Required | 
| version | App version. | Optional | 
| entropy | Entropy. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !shiftleft-list-app-secrets app_name=myapp123```

#### Human Readable Output



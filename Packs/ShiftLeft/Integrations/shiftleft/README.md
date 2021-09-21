See high risk vulnerabilities in your application before they go into production.

ShiftLeft CORE provides static application security testing (SAST) that can be integrated into your CI/CD for automated scans.  Each test is completed in minutes and, depending on the complexity of your application, can be run at each pull request.  Known open source vulnerabilities are automatically checked against data flow analysis to tell whether or not an attacker can “reach” them from the attack surface of the application.

A single scan combines:

- static analysis for risk in custom code
- software composition analysis for known issues in open source libraries
- secrets detection

High-risk issues are listed with their corresponding OWASP Top Ten and attacker-reachable CVE categories.

With ShiftLeft CORE and Cortex XSOAR, Application Security engineers can run playbooks to:

- Gather application threat intelligence to help prioritize bug fixes
- Identify and create incidents to rotate secrets discovered in code
- Proactively monitor applications for critical attacker-reachable vulnerabilities that enter production


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
List Apps


#### Base Command

`shiftleft-list-apps`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShiftLeft | unknown | API response | 


#### Command Example
``` ```

#### Human Readable Output



### shiftleft-list-app-findings
***
List App Findings


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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShiftLeft | unknown | API response | 


#### Command Example
``` ```

#### Human Readable Output



### shiftleft-list-app-secrets
***
List App secrets


#### Base Command

`shiftleft-list-app-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | App name. | Required | 
| version | App version. | Optional | 
| entropy | Entropy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ShiftLeft | unknown | API response | 


#### Command Example
``` ```

#### Human Readable Output



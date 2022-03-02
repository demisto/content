Accenture CTI provides intelligence regarding security threats and vulnerabilities.
This integration was integrated and tested with version v2.89.0 of ACTI
## Configure ACTI ThreatIntel Report on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ACTI ThreatIntel Report.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| api_token | API Token | True |
| Source Reliability | Reliability of the source providing the intelligence data. | B - Usually reliable |
| insecure | Trust any certificate \(not secure\) | False |
| use_proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### acti-getThreatIntelReport
***
Fetches intelligence alerts and reports from ACTI IntelGraph to XSOAR platform.


#### Base Command

`acti-getThreatIntelReport`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acti-getThreatIntelReport | Fetches Intelligence Alerts & Intelligence Reports. | Optional | 


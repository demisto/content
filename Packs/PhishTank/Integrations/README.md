PhishTank is a free community site where anyone can submit, verify, track and share phishing data
This integration was integrated and tested with version xx of PhishTank
## Configure PhishTank on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PhishTank.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| fetchIntervalHours | Database refresh interval \(hours\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
Check URL Reputation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs found | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason for the vendor to make the decision | 
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 


#### Command Example
```!url url=https://www.demisto.com```

#### Human Readable Output
<br>PhishTank Database - URL Query </br>
<br> No matches for URL https://www.demisto.com </br>


### phishtank-reload
***
Reload PhishTank database


#### Base Command

`phishtank-reload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!phishtank-reload```

#### Human Readable Output
<br>PhishTank Database reloaded</br>
<br>Total 15939 URLs loaded.</br>


### phishtank-status
***
Show PhishTank database status


#### Base Command

`phishtank-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!phishtank-status```

#### Human Readable Output
<br>PhishTank Database Status<br>
<br>Total 15939 URLs loaded.<br>
<br>Last load time Sun Jul 26 2020 18:56:10 GMT+0300 (IDT)<br>


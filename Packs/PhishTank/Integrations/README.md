PhishTank is a free community site where anyone can submit, verify, track and share phishing data

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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| URL.Data | String | Bad URLs found | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | String | For malicious URLs, the reason for the vendor to make the decision | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


#### Command Example
```!url url=http://komonghjpl[.]000webhostapp.com```

#### Human Readable Output
### PhishTank Database - URL Query
#### Found matches for URL http://komonghjpl[.]000webhostapp[.]com
|Key|Value|
|---|---|
online|yes|
phish_id|6698036|
submission_time|2020-07-26T18:14:46+00:00|
target|Facebook|
verification_time|2020-07-26T18:43:06+00:00|
verified|yes|
Additional details at [http://www.phishtank.com/phish_detail.php?phish_id=6698036](http://www.phishtank.com/phish_detail.php?phish_id=6698036)


### phishtank-reload
***
Reload PhishTank database


#### Base Command

`phishtank-reload`
#### Input

This command does not require inputs.


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

This command does not require inputs.


#### Context Output

There is no context output for this command.

#### Command Example
```!phishtank-status```

#### Human Readable Output
<br>PhishTank Database Status</br>
<br>Total 15939 URLs loaded.</br>
<br>Last load time Sun Jul 26 2020 18:56:10 GMT+0300 (IDT)</br>


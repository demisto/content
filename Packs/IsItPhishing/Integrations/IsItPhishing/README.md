Collaborative web service that provides validation on whether a URL is a phishing page or not by analyzing the content of the webpage.

## Configure IsItPhishing in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. <https://192.168.0.1>) |  | False |
| Customer's name |  | True |
| Customer's License |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### url

***
Checks if URL is phishing

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to be checked if phishing. | Required | 
| force | Set true to analyze URL, or false to check whether URL may cause collateral damage to the end user. Default is false. | Optional | 
| smart | Set true to force checks on URLs that may cause collateral damage to the end user, or false to ignore the argument. Default is true. | Optional | 
| area | The regional area to force using a proxy. | Optional | 
| timeout | Timeout in milliseconds. Default value set to 10000, with a minimum value of 1000. Once timeout is reached, TIMEOUT response is returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Status | unknown | URL identification result. | 
| URL.Url | unknown | The URL that was tested. | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason for the vendor to make the decision. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 
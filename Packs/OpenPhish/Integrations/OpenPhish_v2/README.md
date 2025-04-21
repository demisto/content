OpenPhish uses proprietary Artificial Intelligence algorithms to automatically identify zero-day phishing sites and provide comprehensive, actionable, real-time threat intelligence.
## Configure OpenPhish_v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| https | Use HTTPS connection | False |
| fetchIntervalHours | Database refresh interval \(hours\) | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
Checks the reputation of a URL.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | The URL | 
| URL.Malicious.Vendor | unknown | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | unknown | A description of the malicious URL. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 


#### Command Example
```!url using-brand=OpenPhish_v2 url="google.com, hxxp://hang3clip.ddns.net/"```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "google.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "OpenPhish"
        },
        {
            "Indicator": "hxxp://hang3clip.ddns.net/",
            "Score": 3,
            "Type": "url",
            "Vendor": "OpenPhish"
        }
    ],
    "URL": [
        {
            "Data": "google.com"
        },
        {
            "Data": "hxxp://hang3clip.ddns.net/",
            "Malicious": {
                "Description": "Match found in OpenPhish database",
                "Vendor": "OpenPhish"
            }
        }
    ]
}
```

#### Human Readable Output

>### OpenPhish Database - URL Query
>#### No matches for URL google.com
>#### Found matches for given URL hxxp://hang3clip.ddns.net/


### openphish-reload
***
Reload OpenPhish database


#### Base Command

`openphish-reload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Command Example
```!openphish-reload```


#### Human Readable Output

>updated successfully

### openphish-status
***
Show OpenPhish database status


#### Base Command

`openphish-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!openphish-status```


#### Human Readable Output

![image](../../doc_files/94807766-c5c92a80-03f8-11eb-9339-d8e399d895c5.png)

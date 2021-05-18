Search Safe Browsing v4

## Configure GoogleSafeBrowsing on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GoogleSafeBrowsing.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key |  | True |
    | Client ID |  | True |
    | Client Version |  | True |
    | Base URL |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

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
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | int | The actual score | 
| DBotScore.Reliability | string | Reliability of the source providing the intelligence data. |
| GoogleSafeBrowsing.URL.cacheDuration | string | The URL cache duration time. |
| GoogleSafeBrowsing.URL.threatType | string | The URL threat type. |
| GoogleSafeBrowsing.URL.threatEntryType | string | The URL threat entry type. |
| GoogleSafeBrowsing.URL.platformType | string | The URL platform type. |
| URL.Data | string | Bad URLs found | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | string | For malicious URLs, the reason for the vendor to make the decision | 


#### Command Example
```!url url="http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "GoogleSafeBrowsing"
    },
    "URL": {
        "Data": "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
        "Malicious": {
            "Description": "Match found: MALWARE/ANY_PLATFORM,MALWARE/WINDOWS,MALWARE/LINUX,MALWARE/ALL_PLATFORMS,MALWARE/OSX,MALWARE/CHROME",
            "Vendor": "GoogleSafeBrowsing"
        }
    }
}
```

#### Human Readable Output

>### Google Safe Browsing APIs - URL Query
>#### Found matches for URL http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/
>cacheDuration|platformType|threat|threatEntryType|threatType
>---|---|---|---|---
>300s | ANY_PLATFORM | {"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"} | URL | MALWARE
>300s | WINDOWS | {"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"} | URL | MALWARE
>300s | LINUX | {"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"} | URL | MALWARE
>300s | ALL_PLATFORMS | {"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"} | URL | MALWARE
>300s | OSX | {"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"} | URL | MALWARE
>300s | CHROME | {"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"} | URL | MALWARE

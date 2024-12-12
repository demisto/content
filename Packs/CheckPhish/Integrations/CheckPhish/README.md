Check any URL to detect supsicious behavior.
## Configure CheckPhish in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| CheckPhish API URL |  | False |
| API Token |  | True |
| Good Dispositions (CheckPhish labels for non-phishing URLs. Default is "clean") |  | False |
| Suspicious dispositions (CheckPhish labels for suspicious phishing URLs). Default is "drug_spam", "gambling", "hacked_website", "streaming", "suspicious" |  | False |
| Bad dispositions (CheckPhish labels for phishing URLs). Defaults are "cryptojacking", "phish", "likely_phish", "scam". |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### CheckPhish-check-urls
***
Checks URLs against the CheckPhish database and returns the results.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`CheckPhish-check-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A CSV list of URLs to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPhish.URL.url | String | URL that was submitted. | 
| CheckPhish.URL.status | String | CheckPhish job status of the URL. | 
| CheckPhish.URL.jobID | String | CheckPhish jobID that was assigned to the URL when it was submitted. | 
| CheckPhish.URL.disposition | String | The CheckPhish category \(disposition\) of the URL. | 
| CheckPhish.URL.brand | String | The brand \(attack target\) countered by the URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URL.Data | String | URL that was submitted. | 
| URL.Malicious.Vendor | String | CheckPhish. | 
| URL.Malicious.Description | String | The brand \(attack target\) countered by the URL. | 


#### Command Example
```!CheckPhish-check-urls url=`test.com```

#### Context Example
```json
{
    "CheckPhish": {
        "URL": {
            "brand": "unknown",
            "disposition": "clean",
            "jobID": "49a3a20b-ec4b-4581-9a55-56716d9e0c6e",
            "status": "DONE",
            "url": "http://test.com/"
        }
    },
    "DBotScore": {
        "Indicator": "http://test.com/",
        "Reliability": "B - Usually reliable",
        "Score": 1,
        "Type": "url",
        "Vendor": "CheckPhish"
    },
    "URL": {
        "Data": "http://test.com/"
    }
}
```

#### Human Readable Output

>### CheckPhish reputation for http://test.com/
>|url|disposition|brand|status|jobID|
>|---|---|---|---|---|
>| http://test.com/ | clean | unknown | DONE | 49a3a20b-ec4b-4581-9a55-56716d9e0c6e |


### url
***
Retrieves URL information from CheckPhish.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPhish.URL.url | String | URL that was submitted. | 
| CheckPhish.URL.status | String | CheckPhish job status of the URL. | 
| CheckPhish.URL.jobID | String | CheckPhish jobID that was assigned to the URL when it was submitted. | 
| CheckPhish.URL.disposition | String | The CheckPhish category \(disposition\) of the URL. | 
| CheckPhish.URL.brand | String | The brand \(attack target\) countered by the URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URL.Data | String | URL that was submitted. | 
| URL.Malicious.Vendor | String | CheckPhish. | 
| URL.Malicious.Description | String | The brand \(attack target\) countered by the URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 


#### Command Example
```!url url=test.com```

#### Context Example
```json
{
    "CheckPhish": {
        "URL": {
            "brand": "unknown",
            "disposition": "clean",
            "jobID": "6df1ebef-3be3-48a9-8970-c5afeda8d58d",
            "status": "DONE",
            "url": "http://test.com/"
        }
    },
    "DBotScore": {
        "Indicator": "http://test.com/",
        "Reliability": "B - Usually reliable",
        "Score": 1,
        "Type": "url",
        "Vendor": "CheckPhish"
    },
    "URL": {
        "Data": "http://test.com/"
    }
}
```

#### Human Readable Output

>### CheckPhish reputation for http://test.com/
>|url|disposition|brand|status|jobID|
>|---|---|---|---|---|
>| http://test.com/ | clean | unknown | DONE | 6df1ebef-3be3-48a9-8970-c5afeda8d58d |

Use Anomali Match to search indicators and enrich domains.

## Configure Anomali Match in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://www.test.com\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### anomali-enterprise-retro-forensic-search

***
Initiates a forensic search of the indicators.


#### Base Command

`anomali-enterprise-retro-forensic-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | The time the indicators first appeared, in the format: &lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes. Default is 1 day ago. | Optional | 
| to | The time the indicators last appeared, in the format: &lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes. Default is now. | Optional | 
| indicators | A comma-separated list of indicators to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliEnterprise.ForensicSearch.job_id | String | The job ID of the search. | 
| AnomaliEnterprise.ForensicSearch.status | String | The status of the search. | 


#### Command Example

```!anomali-enterprise-retro-forensic-search indicators=1.1.1.1 from="1 month"```

#### Context Example

```json
{
    "AnomaliEnterprise": {
        "ForensicSearch": {
            "job_id": "job1271604409989806",
            "status": "in progress"
        }
    }
}
```

#### Human Readable Output

>### Forensic search started:

>|job_id|status|
>|---|---|
>| job1271604409989806 | in progress |


### anomali-enterprise-retro-forensic-search-results

***
Retrieves the forensic search results.


#### Base Command

`anomali-enterprise-retro-forensic-search-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The forensic search job ID. | Required | 
| limit | Limit the stream results to return. Default is 20. | Optional | 
| verbose | Whether to print the stream results to the War Room. Default is "true". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliEnterprise.ForensicSearch.job_id | String | The job ID of the search. | 
| AnomaliEnterprise.ForensicSearch.status | String | The status of the search. | 
| AnomaliEnterprise.ForensicSearch.scannedEvents | Number | The number of scanned events. | 
| AnomaliEnterprise.ForensicSearch.processedFiles | Number | The number of processed files. | 
| AnomaliEnterprise.ForensicSearch.result_file_name | String | The matched file name. | 
| AnomaliEnterprise.ForensicSearch.totalMatches | Number | The number of total matches. | 
| AnomaliEnterprise.ForensicSearch.complete | Bool | Whether the search was complete. | 
| AnomaliEnterprise.ForensicSearch.category | String | The search category. | 
| AnomaliEnterprise.ForensicSearch.streamResults | Unknown | The stream results for the search. | 


#### Command Example

```!anomali-enterprise-retro-forensic-search-results job_id=job1251604409794526```

#### Context Example

```json
{
    "AnomaliEnterprise": {
        "ForensicSearch": {
            "category": "forensic_api_result",
            "complete": true,
            "job_id": "job1251604409794526",
            "processedFiles": 1,
            "result_file_name": "org0_20201103_job1251604409794526_result.tar.gz",
            "scannedEvents": 361295,
            "status": "completed",
            "streamResults": [
                {
                    "age": "",
                    "confidence": "",
                    "count": "1",
                    "event.dest": "1.1.1.1",
                    "event.src": "1.1.1.1",
                    "event_time": "2020-10-14T09:10:00.000+0000",
                    "indicator": "",
                    "itype": "",
                    "severity": ""
                }
            ],
            "totalFiles": 1,
            "totalMatches": 1
        }
    }
}
```

#### Human Readable Output

>### Forensic search metadata:

>|status|job_id|category|totalFiles|scannedEvents|
>|---|---|---|---|---|
>| completed | job1251604409794526 | forensic_api_result | 1 | 361295 |

>### Forensic search results:

>|count|event.dest|event.src|event_time|
>|---|---|---|---|
>| 1 | 1.1.1.1 | 1.1.1.1 | 2020-10-14T09:10:00.000+0000 |


### anomali-enterprise-dga-domain-status

***
The search domains Domain Generation Algorithm (DGA).


#### Base Command

`anomali-enterprise-dga-domain-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | A comma-separated list of domains to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliEnterprise.DGA.domain | String | The domain that was checked. | 
| AnomaliEnterprise.DGA.malware_family | String | The malware family associated with the domain. | 
| AnomaliEnterprise.DGA.domain | Number | The probability of the domain being malicious. | 


#### Command Example

```!anomali-enterprise-dga-domain-status domains=amazon.com```

#### Context Example

```json
{
    "AnomaliEnterprise": {
        "DGA": {
            "domain": "amazon.com",
            "malware_family": "",
            "probability": 0
        }
    }
}
```

#### Human Readable Output

>### Domains DGA:

>|domain|probability|
>|---|---|
>| amazon.com | 0 |


### domain

***
The search domains Domain Generation Algorithm (DGA). Includes DBotScore and domain information.
There is no distinction between benign to unknown domains in Anomali Enterprise.
The Domain reputation is calculated per the product documentation.
if malware family exists and prob > 0.6 the reputation is Malicious,
if malware family exists and prob < 0.6 the reputation is Suspicious,
else, the reputation is Unknown.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliEnterprise.DGA.domain | String | The domain that was checked. | 
| AnomaliEnterprise.DGA.malware_family | String | The malware family associated with the domain. | 
| AnomaliEnterprise.DGA.domain | Number | The probability of the domain being malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| Domain.Name | String | The domain name. For example, "google.com". | 
| Domain.Malicious.Vendor | String | The vendor that reported that the domain is malicious. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 


#### Command Example

```!domain domain=google.com```

#### Context Example

```json
{
    "AnomaliEnterprise": {
        "DGA": {
            "domain": "google.com",
            "malware_family": "",
            "probability": 0
        }
    },
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Anomali Enterprise"
    },
    "Domain": {
        "Name": "google.com"
    }
}
```

#### Human Readable Output

>### Domains DGA:

>|domain|probability|
>|---|---|
>| google.com | 0 |

TruSTAR is an Intelligence Management Platform that helps you operationalize data across tools and teams, helping you prioritize investigations and accelerate incident response.
This integration was integrated and tested with version 0.3.31 of TruSTAR v2
## Configure TruSTAR v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. https://api.trustar.co\) | True |
| station | Station URL \(e.g. https://station.trustar.co\) |  |
| key | TruSTAR API Key | True |
| secret | TruSTAR API Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trustar-search-indicators
***
Searches for all indicators that contain the given search term.


#### Base Command

`trustar-search-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | The term to search for (e.g. covid-19) | Optional | 
| enclave_ids | Comma-separated list of enclave ids; (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). Defaults is all enclaves the user has READ access to. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| from_time | Start of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| to_time | End of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| indicator_types | comma-separated indicator types to filter by. e.g. "URL, IP" | Optional | 
| tags | Name (or list of names) of tag(s) to filter indicators by. (i.e. &lt;tag1&gt;,&lt;tag2&gt;,&lt;tag3&gt;). Only indicators containing ALL of these tags will be returned. | Optional | 
| excluded_tags | Indicators containing ANY of these tags will be excluded from the results. Can be a single tag or a list of tags. i.e. &lt;tag1&gt;,&lt;tag2&gt;,&lt;tag3&gt;). | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.indicatorType | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
```!trustar-search-indicators```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "7aef3cfa5a71fb2010d8b7ffca95ccf0",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://api.intel471.com/v1/download/malwareintel/b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "f5b9b2828b1cc279700e403b1da7ae6087160c61",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "6b642c67b51809a851c08a019312a84073e5fd2e",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "33cda57b3af3856a31fec725ecad44f9",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://api.intel471.com/v1/download/malwareintel/bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://api.intel471.com/v1/download/malwareintel/1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "22c864a9597b0112b345ecc2f39b96b39e055728",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "61b73375a486e3ca1a8d3e98434a9623",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://api.intel471.com/v1/download/malwareintel/b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "75040606c388b7675adaa17b91fe6e9c",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "9ad5b0aec764c0a9c42b019fdbeac672030ec64d",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "017008c65929cf54ee4a035b490c5f4b",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "c5429e1391d52404eaca77289ead47853e68263d",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://api.intel471.com/v1/download/malwareintel/2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://api.intel471.com/v1/download/malwareintel/26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "4f4af35ed47d965bcd1012f2da2d75cd",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "da3111fb65f02659d52900412c8968a342fd19ae",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        }
    ],
    "File": [
        {
            "MD5": "7aef3cfa5a71fb2010d8b7ffca95ccf0"
        },
        {
            "SHA1": "f5b9b2828b1cc279700e403b1da7ae6087160c61"
        },
        {
            "SHA256": "b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860"
        },
        {
            "SHA1": "6b642c67b51809a851c08a019312a84073e5fd2e"
        },
        {
            "MD5": "33cda57b3af3856a31fec725ecad44f9"
        },
        {
            "SHA256": "bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d"
        },
        {
            "SHA1": "22c864a9597b0112b345ecc2f39b96b39e055728"
        },
        {
            "SHA256": "1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21"
        },
        {
            "MD5": "61b73375a486e3ca1a8d3e98434a9623"
        },
        {
            "SHA256": "b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87"
        },
        {
            "MD5": "75040606c388b7675adaa17b91fe6e9c"
        },
        {
            "SHA1": "9ad5b0aec764c0a9c42b019fdbeac672030ec64d"
        },
        {
            "MD5": "017008c65929cf54ee4a035b490c5f4b"
        },
        {
            "SHA1": "c5429e1391d52404eaca77289ead47853e68263d"
        },
        {
            "SHA256": "2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab"
        },
        {
            "SHA256": "26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430"
        },
        {
            "MD5": "4f4af35ed47d965bcd1012f2da2d75cd"
        },
        {
            "SHA1": "da3111fb65f02659d52900412c8968a342fd19ae"
        }
    ],
    "TruSTAR": {
        "Indicators": [
            {
                "indicatorType": "MD5",
                "value": "7aef3cfa5a71fb2010d8b7ffca95ccf0"
            },
            {
                "indicatorType": "URL",
                "value": "https://api.intel471.com/v1/download/malwareintel/b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860.zip"
            },
            {
                "indicatorType": "MALWARE",
                "value": "SMOKELOADER"
            },
            {
                "indicatorType": "SHA1",
                "value": "f5b9b2828b1cc279700e403b1da7ae6087160c61"
            },
            {
                "indicatorType": "SHA256",
                "value": "b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860"
            },
            {
                "indicatorType": "SHA1",
                "value": "6b642c67b51809a851c08a019312a84073e5fd2e"
            },
            {
                "indicatorType": "MD5",
                "value": "33cda57b3af3856a31fec725ecad44f9"
            },
            {
                "indicatorType": "SHA256",
                "value": "bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d"
            },
            {
                "indicatorType": "URL",
                "value": "https://api.intel471.com/v1/download/malwareintel/bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d.zip"
            },
            {
                "indicatorType": "URL",
                "value": "https://api.intel471.com/v1/download/malwareintel/1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21.zip"
            },
            {
                "indicatorType": "SHA1",
                "value": "22c864a9597b0112b345ecc2f39b96b39e055728"
            },
            {
                "indicatorType": "SHA256",
                "value": "1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21"
            },
            {
                "indicatorType": "MD5",
                "value": "61b73375a486e3ca1a8d3e98434a9623"
            },
            {
                "indicatorType": "URL",
                "value": "https://api.intel471.com/v1/download/malwareintel/b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87.zip"
            },
            {
                "indicatorType": "SHA256",
                "value": "b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87"
            },
            {
                "indicatorType": "MD5",
                "value": "75040606c388b7675adaa17b91fe6e9c"
            },
            {
                "indicatorType": "SHA1",
                "value": "9ad5b0aec764c0a9c42b019fdbeac672030ec64d"
            },
            {
                "indicatorType": "MD5",
                "value": "017008c65929cf54ee4a035b490c5f4b"
            },
            {
                "indicatorType": "SHA1",
                "value": "c5429e1391d52404eaca77289ead47853e68263d"
            },
            {
                "indicatorType": "URL",
                "value": "https://api.intel471.com/v1/download/malwareintel/2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab.zip"
            },
            {
                "indicatorType": "SHA256",
                "value": "2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab"
            },
            {
                "indicatorType": "SHA256",
                "value": "26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430"
            },
            {
                "indicatorType": "URL",
                "value": "https://api.intel471.com/v1/download/malwareintel/26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430.zip"
            },
            {
                "indicatorType": "MD5",
                "value": "4f4af35ed47d965bcd1012f2da2d75cd"
            },
            {
                "indicatorType": "SHA1",
                "value": "da3111fb65f02659d52900412c8968a342fd19ae"
            }
        ]
    },
    "URL": [
        {
            "Data": "https://api.intel471.com/v1/download/malwareintel/b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860.zip"
        },
        {
            "Data": "https://api.intel471.com/v1/download/malwareintel/bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d.zip"
        },
        {
            "Data": "https://api.intel471.com/v1/download/malwareintel/1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21.zip"
        },
        {
            "Data": "https://api.intel471.com/v1/download/malwareintel/b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87.zip"
        },
        {
            "Data": "https://api.intel471.com/v1/download/malwareintel/2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab.zip"
        },
        {
            "Data": "https://api.intel471.com/v1/download/malwareintel/26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430.zip"
        }
    ]
}
```

#### Human Readable Output

>### Results
>|indicatorType|value|
>|---|---|
>| MD5 | 7aef3cfa5a71fb2010d8b7ffca95ccf0 |
>| URL | https://api.intel471.com/v1/download/malwareintel/b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860.zip |
>| MALWARE | SMOKELOADER |
>| SHA1 | f5b9b2828b1cc279700e403b1da7ae6087160c61 |
>| SHA256 | b5b10e9b7dc006800dda70d2538d487a737490631b15bd2f5b0448aff6a7b860 |
>| SHA1 | 6b642c67b51809a851c08a019312a84073e5fd2e |
>| MD5 | 33cda57b3af3856a31fec725ecad44f9 |
>| SHA256 | bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d |
>| URL | https://api.intel471.com/v1/download/malwareintel/bb5e7e6f1b1bedd9759b1d16d9f34ff97722706c85df7feb9a7f772121d4508d.zip |
>| URL | https://api.intel471.com/v1/download/malwareintel/1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21.zip |
>| SHA1 | 22c864a9597b0112b345ecc2f39b96b39e055728 |
>| SHA256 | 1bb1a78d2366930a83f94932dc481ec5d24309b3c676902ef2d755c430a67f21 |
>| MD5 | 61b73375a486e3ca1a8d3e98434a9623 |
>| URL | https://api.intel471.com/v1/download/malwareintel/b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87.zip |
>| SHA256 | b45fc4e1523c2bde997dd0c76e7d5124d940b06601556fdd4a42b9cf20357c87 |
>| MD5 | 75040606c388b7675adaa17b91fe6e9c |
>| SHA1 | 9ad5b0aec764c0a9c42b019fdbeac672030ec64d |
>| MD5 | 017008c65929cf54ee4a035b490c5f4b |
>| SHA1 | c5429e1391d52404eaca77289ead47853e68263d |
>| URL | https://api.intel471.com/v1/download/malwareintel/2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab.zip |
>| SHA256 | 2234bc82dd0aa9586b664c4bb679988b653afd8b367f3c8e29f181c37028feab |
>| SHA256 | 26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430 |
>| URL | https://api.intel471.com/v1/download/malwareintel/26113fb83b96dbea7ada873cc84c2a5b66e1bc6761f7011b14e11f1567d4e430.zip |
>| MD5 | 4f4af35ed47d965bcd1012f2da2d75cd |
>| SHA1 | da3111fb65f02659d52900412c8968a342fd19ae |




### trustar-get-enclaves
***
Returns the list of all enclaves that the user has access to, as well as whether they can read, create, and update reports in that enclave.


#### Base Command

`trustar-get-enclaves`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Enclaves.id | string | Enclave type | 
| TruSTAR.Enclaves.name | string | Enclave name | 
| TruSTAR.Enclaves.type | string | Enclave type | 
| TruSTAR.Enclaves.create | Bool | True if I have create permissions on enclave | 
| TruSTAR.Enclaves.update | Bool | True if I have update permissions on enclave | 
| TruSTAR.Enclaves.read | Bool | True if I have read permissions on enclave | 


#### Command Example
```!trustar-get-enclaves```

#### Context Example
```
{
    "TruSTAR": {
        "Enclave": [
            {
                "create": false,
                "id": "ed35f85a-d6bf-4e74-a0f8-61651abf705e",
                "name": "IBM X-Force",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "1e530a47-c3c0-4d53-b473-9d32fbc096df",
                "name": "Intel 471 Malware List",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "c12f55c2-7a9e-47a7-951a-6a67d742f72a",
                "name": "Intel 471 Alerts",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "d2c80d0e-0310-4bdf-9301-b77e660d919d",
                "name": "NCFTA CyFin",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "19b79707-40a8-4d50-80d0-ce563f1d053d",
                "name": "SpyCloud",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "82c899e4-1031-4e5a-bb0b-c91a4e95150c",
                "name": "Flashpoint",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "8335131d-c2e5-4257-8c1b-5bce7991e431",
                "name": "IT-ISAC",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "e93f119a-7883-4417-bab0-17e7aa593f39",
                "name": "CrowdStrike Falcon Detection",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "28177710-9cb8-aa2f-29e8-135c14365e80",
                "name": "Community",
                "read": true,
                "type": "COMMUNITY",
                "update": false
            },
            {
                "create": false,
                "id": "c49f4e9b-478a-451f-9509-af29572b380c",
                "name": "H-ISAC TLP Amber Alerts",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "919879d7-88b3-4605-9464-b2a8fca5473a",
                "name": "US-CERT",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "83279ba8-1d6a-4da1-b8cb-696b857668a3",
                "name": "RiskIQ PassiveTotal",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "7a33144f-aef3-442b-87d4-dbf70d8afdb0",
                "name": "RH-ISAC",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "fdd13b75-a672-47b7-9957-2ee76d429346",
                "name": "Digital Shadows",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "b18292c7-ccf1-42f8-912b-37fdbdddcb78",
                "name": "NCU-ISAO",
                "read": true,
                "type": "INTERNAL",
                "update": false
            },
            {
                "create": false,
                "id": "011ad71b-fd7d-44c2-834a-0d751299fb1f",
                "name": "VirusTotal",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "c879f089-ffbd-4a2f-8144-d3e8bdbd6981",
                "name": "Acme SOC - Vetted",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "ed9d7459-dd90-414f-96ee-5e37f232cd18",
                "name": "Bambenek",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "170c3077-f502-4b1a-b8f7-7538f83a66c1",
                "name": "Abuse Ransomware",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "fb8dcceb-b1aa-45cd-a5b2-b75352d321dc",
                "name": "FS-ISAC",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "d2cf82f0-5aba-4cf4-ba3b-fc990829b663",
                "name": "Packetstorm",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "5d5d1eee-f65f-4fd9-a14b-43c597d9af9e",
                "name": "Malwarebytes",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": true,
                "id": "3688a99c-0272-4ca6-848a-104dfe929555",
                "name": "ND_ISAC",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "b0a7be7b-a847-4597-9e1d-20ae18c344ea",
                "name": "COVID-19 OSINT Community Enclave",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "0092174d-25c0-4d9e-ae7e-7d5031643df0",
                "name": "Blackfish",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "71001c42-2d05-4491-bf35-ee7c678b92da",
                "name": "Acme QRadar",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "00cbe17f-8d3c-4dd8-84ac-3c0c4e6a7c02",
                "name": "Abuse SSL IP Blacklist",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": true,
                "id": "50bbdeea-c18e-4a8f-ba5e-19c2660c6127",
                "name": "Acme Splunk ES Matches",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "e7f4907a-2909-48e8-9c2d-74ffc4b22e8c",
                "name": "EU-CERT",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": true,
                "id": "83439f0f-549a-41ca-9c17-5a496e02d3bc",
                "name": "Sharing Group",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": true,
                "id": "58050264-8d13-4b3b-9596-ce13dcd6c2fa",
                "name": "Jayson Demo Private",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": true,
                "id": "080234eb-d818-4507-a676-dae5c5927d94",
                "name": "Hernan private enclave",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "c6cadd98-0dc1-4148-b074-bdcd7a09faf4",
                "name": "NCFTA TNT",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "d5ae5120-a99d-4f28-bdaa-7261c43e3f3a",
                "name": "Silobreaker",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": true,
                "id": "70381c7e-83b4-4911-9b40-d9b440f3c113",
                "name": "Salesforce_TI",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "fa17005e-714b-4bb9-bd56-11ec337ad458",
                "name": "Internal Test IBM Vetted Indicators",
                "read": true,
                "type": "INTERNAL",
                "update": false
            },
            {
                "create": false,
                "id": "7819c8d1-2b7b-48ac-b127-c71d8e7de612",
                "name": "Hail A TAXII",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "2eeccced-c740-4ad9-aa5c-82744cd1f6aa",
                "name": "Hybrid Analysis Public Feed",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": true,
                "id": "d915e45a-d0c8-4a75-987a-775649020c96",
                "name": "Acme Phishing",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "0618ee04-0c17-417f-a9ad-52a66ec1a5db",
                "name": "RiskIQ Blacklist",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "d2eec321-34bc-4db6-aa20-2ad0a52135fc",
                "name": "NIST NVD",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "77abf4bd-c67b-4016-a8f1-fd8c7e8b07bb",
                "name": "IBM Premier Threat Intelligence",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "71f337a0-9696-4331-988a-5679271656a0",
                "name": "Acme Investigations",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "eec779f5-7abc-48ea-ad19-4c5a5f8f5822",
                "name": "Infosecisland",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "699c6ffc-86c0-48f2-964a-c77dc949c2f1",
                "name": "Dragos",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "5392b0a7-32fb-4825-aac7-1e6c6d437de3",
                "name": "H-ISAC TLP Green & White Alerts",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "59cd8570-5dce-4e5b-b09c-9807530a7086",
                "name": "RH-ISAC Vetted Indicators ",
                "read": true,
                "type": "INTERNAL",
                "update": false
            },
            {
                "create": false,
                "id": "931a7386-ed4f-4acd-bda0-b13b2b6b8f71",
                "name": "Alienvault OTX Pulse",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "11125bbd-ca70-4f16-bce2-7e361693ceb2",
                "name": "Unit 42",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "182057fe-4867-4d5e-b49b-fa495f1e7c52",
                "name": "MISP",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "07429af5-a943-4fbc-87b8-49d6c26e472b",
                "name": "CrowdStrike Falcon Intelligence",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": true,
                "id": "e3ad52ed-ee3b-4446-9177-5c0f6258b8f0",
                "name": "Acme Resilient",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": true,
                "id": "85654534-24ae-45c1-ae33-970443377932",
                "name": "CSA Intel Exchange",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": true,
                "id": "6ef1078c-a74a-4b42-9344-56c6adea0bda",
                "name": "Acme ServiceNow",
                "read": true,
                "type": "INTERNAL",
                "update": true
            },
            {
                "create": false,
                "id": "0e4443fc-2b50-4756-b5e0-4ea30030bcb3",
                "name": "Broadanalysis",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "d039cebb-fb2a-411f-bbc8-7e6a80af105f",
                "name": "URLhaus",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "eecdff2d-22ae-4e4a-b924-42da4e7ccd4b",
                "name": "Internet Storm Center",
                "read": true,
                "type": "OPEN",
                "update": false
            },
            {
                "create": false,
                "id": "0e450b84-d96f-41de-be51-495af574c1a5",
                "name": "CrowdStrike Falcon Reports",
                "read": true,
                "type": "CLOSED",
                "update": false
            },
            {
                "create": false,
                "id": "379be0e7-86df-4403-900e-d5e59b9022ae",
                "name": "Intel 471 Adversary List ",
                "read": true,
                "type": "CLOSED",
                "update": false
            }
        ]
    }
}
```

#### Human Readable Output

>### TruSTAR Enclaves
>|create|id|name|read|type|update|
>|---|---|---|---|---|---|
>| false | ed35f85a-d6bf-4e74-a0f8-61651abf705e | IBM X-Force | true | CLOSED | false |
>| false | 1e530a47-c3c0-4d53-b473-9d32fbc096df | Intel 471 Malware List | true | CLOSED | false |
>| false | c12f55c2-7a9e-47a7-951a-6a67d742f72a | Intel 471 Alerts | true | CLOSED | false |
>| false | d2c80d0e-0310-4bdf-9301-b77e660d919d | NCFTA CyFin | true | CLOSED | false |
>| false | 19b79707-40a8-4d50-80d0-ce563f1d053d | SpyCloud | true | CLOSED | false |
>| false | 82c899e4-1031-4e5a-bb0b-c91a4e95150c | Flashpoint | true | CLOSED | false |
>| true | 8335131d-c2e5-4257-8c1b-5bce7991e431 | IT-ISAC | true | INTERNAL | true |
>| false | e93f119a-7883-4417-bab0-17e7aa593f39 | CrowdStrike Falcon Detection | true | CLOSED | false |
>| true | 28177710-9cb8-aa2f-29e8-135c14365e80 | Community | true | COMMUNITY | false |
>| false | c49f4e9b-478a-451f-9509-af29572b380c | H-ISAC TLP Amber Alerts | true | CLOSED | false |
>| false | 919879d7-88b3-4605-9464-b2a8fca5473a | US-CERT | true | OPEN | false |
>| false | 83279ba8-1d6a-4da1-b8cb-696b857668a3 | RiskIQ PassiveTotal | true | CLOSED | false |
>| true | 7a33144f-aef3-442b-87d4-dbf70d8afdb0 | RH-ISAC | true | INTERNAL | true |
>| false | fdd13b75-a672-47b7-9957-2ee76d429346 | Digital Shadows | true | CLOSED | false |
>| true | b18292c7-ccf1-42f8-912b-37fdbdddcb78 | NCU-ISAO | true | INTERNAL | false |
>| false | 011ad71b-fd7d-44c2-834a-0d751299fb1f | VirusTotal | true | CLOSED | false |
>| true | c879f089-ffbd-4a2f-8144-d3e8bdbd6981 | Acme SOC - Vetted | true | INTERNAL | true |
>| false | ed9d7459-dd90-414f-96ee-5e37f232cd18 | Bambenek | true | OPEN | false |
>| false | 170c3077-f502-4b1a-b8f7-7538f83a66c1 | Abuse Ransomware | true | OPEN | false |
>| false | fb8dcceb-b1aa-45cd-a5b2-b75352d321dc | FS-ISAC | true | CLOSED | false |
>| false | d2cf82f0-5aba-4cf4-ba3b-fc990829b663 | Packetstorm | true | OPEN | false |
>| false | 5d5d1eee-f65f-4fd9-a14b-43c597d9af9e | Malwarebytes | true | OPEN | false |
>| true | 3688a99c-0272-4ca6-848a-104dfe929555 | ND_ISAC | true | INTERNAL | true |
>| false | b0a7be7b-a847-4597-9e1d-20ae18c344ea | COVID-19 OSINT Community Enclave | true | OPEN | false |
>| false | 0092174d-25c0-4d9e-ae7e-7d5031643df0 | Blackfish | true | CLOSED | false |
>| true | 71001c42-2d05-4491-bf35-ee7c678b92da | Acme QRadar | true | INTERNAL | true |
>| false | 00cbe17f-8d3c-4dd8-84ac-3c0c4e6a7c02 | Abuse SSL IP Blacklist | true | OPEN | false |
>| true | 50bbdeea-c18e-4a8f-ba5e-19c2660c6127 | Acme Splunk ES Matches | true | INTERNAL | true |
>| false | e7f4907a-2909-48e8-9c2d-74ffc4b22e8c | EU-CERT | true | OPEN | false |
>| true | 83439f0f-549a-41ca-9c17-5a496e02d3bc | Sharing Group | true | INTERNAL | true |
>| true | 58050264-8d13-4b3b-9596-ce13dcd6c2fa | Jayson Demo Private | true | INTERNAL | true |
>| true | 080234eb-d818-4507-a676-dae5c5927d94 | Hernan private enclave | true | INTERNAL | true |
>| false | c6cadd98-0dc1-4148-b074-bdcd7a09faf4 | NCFTA TNT | true | CLOSED | false |
>| true | d5ae5120-a99d-4f28-bdaa-7261c43e3f3a | Silobreaker | true | INTERNAL | true |
>| true | 70381c7e-83b4-4911-9b40-d9b440f3c113 | Salesforce_TI | true | INTERNAL | true |
>| false | fa17005e-714b-4bb9-bd56-11ec337ad458 | Internal Test IBM Vetted Indicators | true | INTERNAL | false |
>| false | 7819c8d1-2b7b-48ac-b127-c71d8e7de612 | Hail A TAXII | true | OPEN | false |
>| false | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | Hybrid Analysis Public Feed | true | OPEN | false |
>| true | d915e45a-d0c8-4a75-987a-775649020c96 | Acme Phishing | true | INTERNAL | true |
>| false | 0618ee04-0c17-417f-a9ad-52a66ec1a5db | RiskIQ Blacklist | true | CLOSED | false |
>| false | d2eec321-34bc-4db6-aa20-2ad0a52135fc | NIST NVD | true | OPEN | false |
>| false | 77abf4bd-c67b-4016-a8f1-fd8c7e8b07bb | IBM Premier Threat Intelligence | true | CLOSED | false |
>| true | 71f337a0-9696-4331-988a-5679271656a0 | Acme Investigations | true | INTERNAL | true |
>| false | eec779f5-7abc-48ea-ad19-4c5a5f8f5822 | Infosecisland | true | OPEN | false |
>| false | 699c6ffc-86c0-48f2-964a-c77dc949c2f1 | Dragos | true | CLOSED | false |
>| false | 5392b0a7-32fb-4825-aac7-1e6c6d437de3 | H-ISAC TLP Green & White Alerts | true | OPEN | false |
>| false | 59cd8570-5dce-4e5b-b09c-9807530a7086 | RH-ISAC Vetted Indicators  | true | INTERNAL | false |
>| false | 931a7386-ed4f-4acd-bda0-b13b2b6b8f71 | Alienvault OTX Pulse | true | CLOSED | false |
>| false | 11125bbd-ca70-4f16-bce2-7e361693ceb2 | Unit 42 | true | OPEN | false |
>| false | 182057fe-4867-4d5e-b49b-fa495f1e7c52 | MISP | true | CLOSED | false |
>| false | 07429af5-a943-4fbc-87b8-49d6c26e472b | CrowdStrike Falcon Intelligence | true | CLOSED | false |
>| true | e3ad52ed-ee3b-4446-9177-5c0f6258b8f0 | Acme Resilient | true | INTERNAL | true |
>| true | 85654534-24ae-45c1-ae33-970443377932 | CSA Intel Exchange | true | INTERNAL | true |
>| true | 6ef1078c-a74a-4b42-9344-56c6adea0bda | Acme ServiceNow | true | INTERNAL | true |
>| false | 0e4443fc-2b50-4756-b5e0-4ea30030bcb3 | Broadanalysis | true | OPEN | false |
>| false | d039cebb-fb2a-411f-bbc8-7e6a80af105f | URLhaus | true | OPEN | false |
>| false | eecdff2d-22ae-4e4a-b924-42da4e7ccd4b | Internet Storm Center | true | OPEN | false |
>| false | 0e450b84-d96f-41de-be51-495af574c1a5 | CrowdStrike Falcon Reports | true | CLOSED | false |
>| false | 379be0e7-86df-4403-900e-d5e59b9022ae | Intel 471 Adversary List  | true | CLOSED | false |



### trustar-related-indicators
***
Finds all reports that contain any of the given indicators and returns correlated indicators from those reports.


#### Base Command

`trustar-related-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave_ids | Comma-separated list of enclave IDs; (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). Defaults is all enclaves the user has READ access to. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.indicatorType | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 



#### Command Example
```!trustar-related-indicators indicators=WANNACRY```

#### Context Example
```
{
    "CVE": {
        "ID": "CVE-2017-0147"
    },
    "DBotScore": [
        {
            "Indicator": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://urlhaus.abuse.ch/url/407033/",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "http://demo.singhealth.xyz/files/wannacry/generalelectioncandidates.pdf.exe",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "demo.singhealth.xyz",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://urlhaus-api.abuse.ch/v1/download/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "84c82835a5d21bbcf75a61706d8ab549",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "http://demo.singhealth.xyz/files/wannacry/ransomware.wannacry.zip",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "efe76bf09daba2c594d2bc173d9b5cf0",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://urlhaus.abuse.ch/url/407034/",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://urlhaus-api.abuse.ch/v1/download/707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a/",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "ce997cff0db912bf873636856b883915ebbbb9d2672a31539710e2b301fdea51",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "201.35.192.251",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "84.53.130.120",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "5.60.69.78",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "mssecsvc.exe.5efd7894.bin",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "8c860331167f51989cf2153b9bca47271e01bf1b57483aacd3b8b234b3bf7b2c",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "37.26.41.210",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "52.253.113.206",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "3fa4912eb43fc304652d7b01f118589259861e2d628fa7c86193e54d5f987670",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "15.132.199.102",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "175.192.84.144",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "138.30.41.7",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "196.37.251.244",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "CVE-2017-0147",
            "Score": 0,
            "Type": "cve",
            "Vendor": null
        }
    ],
    "File": [
        {
            "SHA256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        },
        {
            "MD5": "84c82835a5d21bbcf75a61706d8ab549"
        },
        {
            "MD5": "efe76bf09daba2c594d2bc173d9b5cf0"
        },
        {
            "SHA256": "707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a"
        },
        {
            "SHA256": "ce997cff0db912bf873636856b883915ebbbb9d2672a31539710e2b301fdea51"
        },
        {
            "Name": "mssecsvc.exe.5efd7894.bin"
        },
        {
            "SHA256": "8c860331167f51989cf2153b9bca47271e01bf1b57483aacd3b8b234b3bf7b2c"
        },
        {
            "SHA256": "3fa4912eb43fc304652d7b01f118589259861e2d628fa7c86193e54d5f987670"
        }
    ],
    "IP": [
        {
            "Address": "201.35.192.251"
        },
        {
            "Address": "84.53.130.120"
        },
        {
            "Address": "5.60.69.78"
        },
        {
            "Address": "37.26.41.210"
        },
        {
            "Address": "52.253.113.206"
        },
        {
            "Address": "15.132.199.102"
        },
        {
            "Address": "175.192.84.144"
        },
        {
            "Address": "138.30.41.7"
        },
        {
            "Address": "196.37.251.244"
        }
    ],
    "TruSTAR": {
        "Indicators": [
            {
                "indicatorType": "SHA256",
                "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
            },
            {
                "indicatorType": "URL",
                "value": "https://urlhaus.abuse.ch/url/407033/"
            },
            {
                "indicatorType": "URL",
                "value": "http://demo.singhealth.xyz/files/wannacry/generalelectioncandidates.pdf.exe"
            },
            {
                "indicatorType": "URL",
                "value": "demo.singhealth.xyz"
            },
            {
                "indicatorType": "URL",
                "value": "https://urlhaus-api.abuse.ch/v1/download/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/"
            },
            {
                "indicatorType": "MD5",
                "value": "84c82835a5d21bbcf75a61706d8ab549"
            },
            {
                "indicatorType": "URL",
                "value": "http://demo.singhealth.xyz/files/wannacry/ransomware.wannacry.zip"
            },
            {
                "indicatorType": "MD5",
                "value": "efe76bf09daba2c594d2bc173d9b5cf0"
            },
            {
                "indicatorType": "URL",
                "value": "https://urlhaus.abuse.ch/url/407034/"
            },
            {
                "indicatorType": "URL",
                "value": "https://urlhaus-api.abuse.ch/v1/download/707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a/"
            },
            {
                "indicatorType": "SHA256",
                "value": "707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a"
            },
            {
                "indicatorType": "SHA256",
                "value": "ce997cff0db912bf873636856b883915ebbbb9d2672a31539710e2b301fdea51"
            },
            {
                "indicatorType": "IP",
                "value": "201.35.192.251"
            },
            {
                "indicatorType": "IP",
                "value": "84.53.130.120"
            },
            {
                "indicatorType": "IP",
                "value": "5.60.69.78"
            },
            {
                "indicatorType": "SOFTWARE",
                "value": "mssecsvc.exe.5efd7894.bin"
            },
            {
                "indicatorType": "SHA256",
                "value": "8c860331167f51989cf2153b9bca47271e01bf1b57483aacd3b8b234b3bf7b2c"
            },
            {
                "indicatorType": "IP",
                "value": "37.26.41.210"
            },
            {
                "indicatorType": "IP",
                "value": "52.253.113.206"
            },
            {
                "indicatorType": "SHA256",
                "value": "3fa4912eb43fc304652d7b01f118589259861e2d628fa7c86193e54d5f987670"
            },
            {
                "indicatorType": "IP",
                "value": "15.132.199.102"
            },
            {
                "indicatorType": "IP",
                "value": "175.192.84.144"
            },
            {
                "indicatorType": "IP",
                "value": "138.30.41.7"
            },
            {
                "indicatorType": "IP",
                "value": "196.37.251.244"
            },
            {
                "indicatorType": "CVE",
                "value": "CVE-2017-0147"
            }
        ]
    },
    "URL": [
        {
            "Data": "https://urlhaus.abuse.ch/url/407033/"
        },
        {
            "Data": "http://demo.singhealth.xyz/files/wannacry/generalelectioncandidates.pdf.exe"
        },
        {
            "Data": "demo.singhealth.xyz"
        },
        {
            "Data": "https://urlhaus-api.abuse.ch/v1/download/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/"
        },
        {
            "Data": "http://demo.singhealth.xyz/files/wannacry/ransomware.wannacry.zip"
        },
        {
            "Data": "https://urlhaus.abuse.ch/url/407034/"
        },
        {
            "Data": "https://urlhaus-api.abuse.ch/v1/download/707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a/"
        }
    ]
}
```

#### Human Readable Output

>### Results
>|indicatorType|value|
>|---|---|
>| SHA256 | ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa |
>| URL | https://urlhaus.abuse.ch/url/407033/ |
>| URL | http://demo.singhealth.xyz/files/wannacry/generalelectioncandidates.pdf.exe |
>| URL | demo.singhealth.xyz |
>| URL | https://urlhaus-api.abuse.ch/v1/download/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/ |
>| MD5 | 84c82835a5d21bbcf75a61706d8ab549 |
>| URL | http://demo.singhealth.xyz/files/wannacry/ransomware.wannacry.zip |
>| MD5 | efe76bf09daba2c594d2bc173d9b5cf0 |
>| URL | https://urlhaus.abuse.ch/url/407034/ |
>| URL | https://urlhaus-api.abuse.ch/v1/download/707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a/ |
>| SHA256 | 707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a |
>| SHA256 | ce997cff0db912bf873636856b883915ebbbb9d2672a31539710e2b301fdea51 |
>| IP | 201.35.192.251 |
>| IP | 84.53.130.120 |
>| IP | 5.60.69.78 |
>| SOFTWARE | mssecsvc.exe.5efd7894.bin |
>| SHA256 | 8c860331167f51989cf2153b9bca47271e01bf1b57483aacd3b8b234b3bf7b2c |
>| IP | 37.26.41.210 |
>| IP | 52.253.113.206 |
>| SHA256 | 3fa4912eb43fc304652d7b01f118589259861e2d628fa7c86193e54d5f987670 |
>| IP | 15.132.199.102 |
>| IP | 175.192.84.144 |
>| IP | 138.30.41.7 |
>| IP | 196.37.251.244 |
>| CVE | CVE-2017-0147 |

### trustar-trending-indicators
***
Find indicators that are trending in the community.


#### Base Command

`trustar-trending-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The types of indicators to be returned. If other, then all indicator types except for CVE and MALWARE will be returned. | Optional | 
| days_back | The number of days back to count correlations for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.correlationCount | Number | Indicator correlation count | 
| TruSTAR.Indicators.indicatorType | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 



#### Command Example
```!trustar-trending-indicators days_back=1 indicator_type=MALWARE```

#### Context Example
```
{
    "TruSTAR": {
        "Indicators": [
            {
                "correlationCount": 85,
                "indicatorType": "MALWARE",
                "value": "TRICKBOT"
            },
            {
                "correlationCount": 31,
                "indicatorType": "MALWARE",
                "value": "AMADEY"
            },
            {
                "correlationCount": 29,
                "indicatorType": "MALWARE",
                "value": "EMOTET"
            },
            {
                "correlationCount": 27,
                "indicatorType": "MALWARE",
                "value": "SMOKELOADER"
            },
            {
                "correlationCount": 14,
                "indicatorType": "MALWARE",
                "value": "SALITY"
            },
            {
                "correlationCount": 10,
                "indicatorType": "MALWARE",
                "value": "ZLOADER"
            },
            {
                "correlationCount": 5,
                "indicatorType": "MALWARE",
                "value": "NIVDORT"
            },
            {
                "correlationCount": 5,
                "indicatorType": "MALWARE",
                "value": "WANNACRY"
            },
            {
                "correlationCount": 4,
                "indicatorType": "MALWARE",
                "value": "KRYPTIK"
            },
            {
                "correlationCount": 4,
                "indicatorType": "MALWARE",
                "value": "ANDROMEDA"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|correlationCount|indicatorType|value|
>|---|---|---|
>| 85 | MALWARE | TRICKBOT |
>| 31 | MALWARE | AMADEY |
>| 29 | MALWARE | EMOTET |
>| 27 | MALWARE | SMOKELOADER |
>| 14 | MALWARE | SALITY |
>| 10 | MALWARE | ZLOADER |
>| 5 | MALWARE | NIVDORT |
>| 5 | MALWARE | WANNACRY |
>| 4 | MALWARE | KRYPTIK |
>| 4 | MALWARE | ANDROMEDA |


### trustar-indicators-metadata
***
Provide metadata associated with a list of indicators, including value, indicatorType, noteCount, sightings, lastSeen, enclaveIds, and tags. The metadata is determined based on the enclaves the user making the request has READ access to.


#### Base Command

`trustar-indicators-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave_ids | CSV of enclave IDs to restrict to. (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). By default, uses all of the user’s enclaves. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.IndicatorsMetadata.notes | string | Indicator notes | 
| TruSTAR.IndicatorsMetadata.indicatorType | string | Indicator type | 
| TruSTAR.IndicatorsMetadata.firstSeen | Date | Indicator first seen value | 
| TruSTAR.IndicatorsMetadata.correlationCount | Number | Indicator correlation count | 
| TruSTAR.IndicatorsMetadata.value | string | Indicator value | 
| TruSTAR.IndicatorsMetadata.lastSeen | Date | Indicator last seen value | 
| TruSTAR.IndicatorsMetadata.tags | string | Indicator tags | 
| TruSTAR.IndicatorsMetadata.enclaveIds | string | Enclave IDs where indicator is present | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
```!trustar-indicators-metadata indicators=37.26.41.210```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "37.26.41.210",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        }
    ],
    "IP": {
        "Address": "37.26.41.210"
    },
    "TruSTAR": {
        "IndicatorsMetadata": {
            "correlationCount": 0,
            "enclaveIds": [
                "2eeccced-c740-4ad9-aa5c-82744cd1f6aa"
            ],
            "firstSeen": "2020-07-02 04:59:03",
            "indicatorType": "IP",
            "lastSeen": "2020-07-02 04:59:03",
            "notes": [],
            "tags": [],
            "value": "37.26.41.210"
        }
    }
}
```

#### Human Readable Output

>### Results
>|correlationCount|enclaveIds|firstSeen|indicatorType|lastSeen|notes|tags|value|
>|---|---|---|---|---|---|---|---|
>| 0 | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 2020-07-02 04:59:03 | IP | 2020-07-02 04:59:03 |  |  | 37.26.41.210 |


### trustar-indicator-summaries
***
Provides structured summaries about indicators, which are derived from intelligence sources on the TruSTAR Marketplace.


#### Base Command

`trustar-indicator-summaries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave_ids | CSV of enclaves to search for indicator summaries in. (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). These should be enclaves containing data from sources on the TruSTAR Marketplace. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.IndicatorSummaries.severityLevel | string | Indicator severity level | 
| TruSTAR.IndicatorSummaries.reportId | string | Indicator report ID | 
| TruSTAR.IndicatorSummaries.value | string | Indicator value | 
| TruSTAR.IndicatorSummaries.score.name | string | Indicator score name | 
| TruSTAR.IndicatorSummaries.score.value | string | Indicator score value | 
| TruSTAR.IndicatorSummaries.attributes | String | Indicator attributes | 
| TruSTAR.IndicatorSummaries.enclaveId | string | Indicator enclave ID | 
| TruSTAR.IndicatorSummaries.type | string | Indicator type | 
| TruSTAR.IndicatorSummaries.source.key | string | Indicator source key | 
| TruSTAR.IndicatorSummaries.source.name | string | Indicator source name | 
| TruSTAR.IndicatorSummaries.updated | string | Indicator last update value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 



#### Command Example
```!trustar-indicator-summaries values=LOCKY,23.121.54.102```

#### Human Readable Output


### trustar-get-whitelisted-indicators
***
Gets a list of indicators that the user’s company has added to allow list.


#### Base Command

`trustar-get-whitelisted-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.WhitelistedIndicators.indicatorType | string | File MD5 | 
| TruSTAR.WhitelistedIndicators.value | string | File SHA1 | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 



#### Command Example
```!trustar-get-whitelisted-indicators```

#### Context Example
```
{
    "Account": {
        "Email": [
            {
                "Address": "htain@trustar.co"
            }
        ]
    },
    "DBotScore": [
        {
            "Indicator": "savc.net",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "22.37.45.53",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "1.1.1.1",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "88.249.181.198",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "1e82dd741e908d02e4eff82461f1297e",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://www.binarydefense.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "docusign.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "www.badsite.net",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "safrica24.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://my.silobreaker.com/5_2273991310555742265",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "test123.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://my.silobreaker.com/5_2273903231513919758",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://urlscan.io/search/#lihkg.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "3b05383323d4c1485f5a4d5dddfe55275e441c66714cee101baee9cdd19b18cc",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://cf-p.falcon.crowdstrike.com/2017/04/26202230/chollima1.png",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "\\windows\\system32\\cmd.exe",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "109.120.214.195",
            "Score": 0,
            "Type": "ip",
            "Vendor": "TruSTAR"
        }
    ],
    "File": [
        {
            "MD5": "1e82dd741e908d02e4eff82461f1297e"
        },
        {
            "SHA256": "3b05383323d4c1485f5a4d5dddfe55275e441c66714cee101baee9cdd19b18cc"
        },
        {
            "Name": "\\windows\\system32\\cmd.exe"
        }
    ],
    "IP": [
        {
            "Address": "22.37.45.53"
        },
        {
            "Address": "1.1.1.1"
        },
        {
            "Address": "88.249.181.198"
        },
        {
            "Address": "109.120.214.195"
        }
    ],
    "TruSTAR": {
        "WhitelistedIndicators": [
            {
                "indicatorType": "EMAIL_ADDRESS",
                "value": "htain@trustar.co"
            },
            {
                "indicatorType": "URL",
                "value": "savc.net"
            },
            {
                "indicatorType": "IP",
                "value": "22.37.45.53"
            },
            {
                "indicatorType": "IP",
                "value": "1.1.1.1"
            },
            {
                "indicatorType": "IP",
                "value": "88.249.181.198"
            },
            {
                "indicatorType": "MD5",
                "value": "1e82dd741e908d02e4eff82461f1297e"
            },
            {
                "indicatorType": "URL",
                "value": "https://www.binarydefense.com"
            },
            {
                "indicatorType": "URL",
                "value": "docusign.com"
            },
            {
                "indicatorType": "URL",
                "value": "www.badsite.net"
            },
            {
                "indicatorType": "URL",
                "value": "safrica24.com"
            },
            {
                "indicatorType": "URL",
                "value": "https://my.silobreaker.com/5_2273991310555742265"
            },
            {
                "indicatorType": "URL",
                "value": "test123.com"
            },
            {
                "indicatorType": "URL",
                "value": "https://my.silobreaker.com/5_2273903231513919758"
            },
            {
                "indicatorType": "URL",
                "value": "https://urlscan.io/search/#lihkg.com"
            },
            {
                "indicatorType": "SHA256",
                "value": "3b05383323d4c1485f5a4d5dddfe55275e441c66714cee101baee9cdd19b18cc"
            },
            {
                "indicatorType": "URL",
                "value": "https://cf-p.falcon.crowdstrike.com/2017/04/26202230/chollima1.png"
            },
            {
                "indicatorType": "SOFTWARE",
                "value": "\\windows\\system32\\cmd.exe"
            },
            {
                "indicatorType": "IP",
                "value": "109.120.214.195"
            }
        ]
    },
    "URL": [
        {
            "Data": "savc.net"
        },
        {
            "Data": "https://www.binarydefense.com"
        },
        {
            "Data": "docusign.com"
        },
        {
            "Data": "www.badsite.net"
        },
        {
            "Data": "safrica24.com"
        },
        {
            "Data": "https://my.silobreaker.com/5_2273991310555742265"
        },
        {
            "Data": "test123.com"
        },
        {
            "Data": "https://my.silobreaker.com/5_2273903231513919758"
        },
        {
            "Data": "https://urlscan.io/search/#lihkg.com"
        },
        {
            "Data": "https://cf-p.falcon.crowdstrike.com/2017/04/26202230/chollima1.png"
        }
    ]
}
```

#### Human Readable Output

>### Results
>|indicatorType|value|
>|---|---|
>| EMAIL_ADDRESS | htain@trustar.co |
>| URL | savc.net |
>| IP | 22.37.45.53 |
>| IP | 1.1.1.1 |
>| IP | 88.249.181.198 |
>| MD5 | 1e82dd741e908d02e4eff82461f1297e |
>| URL | https://www.binarydefense.com |
>| URL | docusign.com |
>| URL | www.badsite.net |
>| URL | safrica24.com |
>| URL | https://my.silobreaker.com/5_2273991310555742265 |
>| URL | test123.com |
>| URL | https://my.silobreaker.com/5_2273903231513919758 |
>| URL | https://urlscan.io/search/#lihkg.com |
>| SHA256 | 3b05383323d4c1485f5a4d5dddfe55275e441c66714cee101baee9cdd19b18cc |
>| URL | https://cf-p.falcon.crowdstrike.com/2017/04/26202230/chollima1.png |
>| SOFTWARE | \windows\system32\cmd.exe |
>| IP | 109.120.214.195 |



### trustar-get-reports
***
Returns incident reports matching the specified filters. All parameters are optional: if nothing is specified, the latest 25 reports accessible by the user will be returned (matching the view the user would have by logging into Station).


#### Base Command

`trustar-get-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_time | Start of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| to_time | End of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| distribution_type | Whether to search for reports in the community, or only in enclaves | Optional | 
| enclave_ids | Comma separated list of enclave ids to search for reports in. (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Even if distributionType is COMMUNITY, these enclaves will still be searched as well. Default is All enclaves the user has READ access to. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| tags | a list of names of tags to filter by; only reports containing ALL of these tags will be returned. i.e. &lt;tag1&gt;,&lt;tag2&gt;,&lt;tag3&gt;). | Optional | 
| excluded_tags | reports containing ANY of these tags will be excluded from the results. Can be a single tag or a list of tags. i.e. &lt;tag1&gt;,&lt;tag2&gt;,&lt;tag3&gt;). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 



#### Command Example
```!trustar-get-reports enclave_ids=6ef1078c-a74a-4b42-9344-56c6adea0bda from_time="1 day ago"```

#### Context Example
```
{}
```

#### Human Readable Output

>No reports were found.


### trustar-get-indicators-for-report
***
Return a list of indicators extracted from a report.


#### Base Command

`trustar-get-indicators-for-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | the ID of the report to get the indicators from | Required | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.type | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 



#### Command Example
```!trustar-get-indicators-for-report report_id=6e00a714-379a-4db8-ac0c-812a629c8288```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "c5737f53ea049a88162297604b41c791dd8583b3",
            "Score": 0,
            "Type": "file",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "http://travellux.nl",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "travellux.nl",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://zenshin-talent.us4.list-manage.com/profile?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        },
        {
            "Indicator": "https://zenshin-talent.us4.list-manage.com/unsubscribe?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c&c=d1fe02d910",
            "Score": 0,
            "Type": "url",
            "Vendor": "TruSTAR"
        }
    ],
    "File": {
        "SHA1": "c5737f53ea049a88162297604b41c791dd8583b3"
    },
    "TruSTAR": {
        "Indicators": [
            {
                "indicatorType": "SHA1",
                "value": "c5737f53ea049a88162297604b41c791dd8583b3"
            },
            {
                "indicatorType": "URL",
                "value": "http://travellux.nl"
            },
            {
                "indicatorType": "URL",
                "value": "travellux.nl"
            },
            {
                "indicatorType": "URL",
                "value": "https://zenshin-talent.us4.list-manage.com/profile?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c"
            },
            {
                "indicatorType": "URL",
                "value": "https://zenshin-talent.us4.list-manage.com/unsubscribe?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c&c=d1fe02d910"
            }
        ]
    },
    "URL": [
        {
            "Data": "http://travellux.nl"
        },
        {
            "Data": "travellux.nl"
        },
        {
            "Data": "https://zenshin-talent.us4.list-manage.com/profile?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c"
        },
        {
            "Data": "https://zenshin-talent.us4.list-manage.com/unsubscribe?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c&c=d1fe02d910"
        }
    ]
}
```

#### Human Readable Output

>### Results
>|indicatorType|value|
>|---|---|
>| SHA1 | c5737f53ea049a88162297604b41c791dd8583b3 |
>| URL | http://travellux.nl |
>| URL | travellux.nl |
>| URL | https://zenshin-talent.us4.list-manage.com/profile?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c |
>| URL | https://zenshin-talent.us4.list-manage.com/unsubscribe?u=bf272ebe406152763de31f5a2&id=d178821f2b&e=0cbc95e07c&c=d1fe02d910 |


### trustar-move-report
***
Move a report from one enclave to another.


#### Base Command

`trustar-move-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | the ID of the report you want to move | Required | 
| dest-enclave-id | the ID of the destination enclave | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trustar-move-report report_id=20ce2d7f-4a25-4bed-a74e-ec99bf0b46db dest-enclave-id=71001c42-2d05-4491-bf35-ee7c678b92da```

#### Context Example
```
{}
```

#### Human Readable Output

>20ce2d7f-4a25-4bed-a74e-ec99bf0b46db has been moved to enclave id: 71001c42-2d05-4491-bf35-ee7c678b92da


### trustar-copy-report
***
Copies a report from one enclave to another.


#### Base Command

`trustar-copy-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | the ID of the report you want to move | Required | 
| dest_enclave_id | the ID of the destination enclave | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trustar-copy-report report_id=6e00a714-379a-4db8-ac0c-812a629c8288 dest_enclave_id=c879f089-ffbd-4a2f-8144-d3e8bdbd6981```

#### Context Example
```
{}
```

#### Human Readable Output

>6e00a714-379a-4db8-ac0c-812a629c8288 has been copied to enclave id: c879f089-ffbd-4a2f-8144-d3e8bdbd6981 with id: 9cc749a5-21b2-418d-8fa7-5e28fcf671ba



### trustar-submit-report
***
Submit a new incident report, and receive the ID it has been assigned in TruSTAR’s system.


#### Base Command

`trustar-submit-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title of the report | Required | 
| report_body | Text content of report | Required | 
| enclave_ids | CSV of TruSTAR-generated enclave ids. (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Use the enclave ID, NOT the enclave name. Mandatory if the distribution type is ENCLAVE. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| distribution_type | Distribution type of the report | Optional | 
| external_url | URL for the external report that this originated from, if one exists. Limit 500 alphanumeric characters. Must be unique across all reports for a given company. | Optional | 
| time_began | ISO-8601 formatted incident time with timezone, e.g. 2016-09-22T11:38:35+00:00. Default is current time. | Optional | 
| redact | YES OR NO. If redact is YES, all terms from user's company redaction library in TruSTAR will be applied before submitting. If NO, submits the report with body and title as written by the user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 


#### Command Example
```!trustar-submit-report title="foo title" report_body="the report body" enclave_ids=080234eb-d818-4507-a676-dae5c5927d94```

#### Context Example
```
{
    "TruSTAR": {
        "Report": {
            "id": "5cf979cb-aae6-4270-8295-52a2ed2b36a1",
            "reportBody": "the report body",
            "title": "foo title"
        }
    }
}
```

#### Human Readable Output

>### TruSTAR report was successfully created
>|distributionType|enclaveIds|id|reportBody|reportDeepLink|timeBegan|title|
>|---|---|---|---|---|---|---|
>| ENCLAVE | 080234eb-d818-4507-a676-dae5c5927d94 | 5cf979cb-aae6-4270-8295-52a2ed2b36a1 | the report body | https://station.trustar.co/constellation/reports/5cf979cb-aae6-4270-8295-52a2ed2b36a1 | 2020-07-02T20:51:05.817066+00:00 | foo title |


### trustar-delete-report
***
Deletes a report as specified by given id (id can be TruSTAR report id or external id).


#### Base Command

`trustar-delete-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Finds a report by its internal or external id. | Required | 
| id_type | Type of report ID | Optional | 


#### Context Output

There is no context output for this command.


#### Command Example
```!trustar-delete-report report_id=20ce2d7f-4a25-4bed-a74e-ec99bf0b46db```

#### Context Example
```
{}
```

#### Human Readable Output

>Report 20ce2d7f-4a25-4bed-a74e-ec99bf0b46db was successfully deleted


### trustar-correlated-reports
***
Returns a list of all reports that contain any of the provided indicator values.


#### Base Command

`trustar-correlated-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave-ids | Comma-separated list of enclave ids; (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). Defaults is all enclaves the user has READ access to. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 
| distribution_type | Distribution type of the report | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trustar-correlated-reports indicators=WANNACRY```

#### Context Example
```
{}
```

#### Human Readable Output

>No reports were found.



### trustar-report-details
***
Finds a report by its ID and returns the report details.


#### Base Command

`trustar-report-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Finds a report by its internal or external id. | Required | 
| id_type | Type of report ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 



#### Command Example
```!trustar-report-details report_id=6e00a714-379a-4db8-ac0c-812a629c8288```

#### Context Example
```
{
    "TruSTAR": {
        "Report": {
            "id": "6e00a714-379a-4db8-ac0c-812a629c8288",
            "reportBody": "\n==================================================\n EMAIL THREAD DATE: 2020-06-22 11:22:59\n==================================================\nFwd: Looking to hire?",
            "title": "The new title"
        }
    }
}
```

#### Human Readable Output

>### TruSTAR report ID 6e00a714-379a-4db8-ac0c-812a629c8288 details
>|created|distributionType|enclaveIds|externalTrackingId|id|reportBody|reportDeepLink|timeBegan|title|updated|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-06-22 15:25:04 | ENCLAVE | d915e45a-d0c8-4a75-987a-775649020c96 | PGJmMjcyZWJlNDA2MTUyNzYzZGUzMWY1YTIuMGNiYzk1ZTA3Yy4yMDIwMDYxNzEzMTQyNS5kMWZlMDJkOTEwLmNmYjY5Mjg1QG1haWwyMjYuc2VhODEubWNzdi5uZXQ+ | 6e00a714-379a-4db8-ac0c-812a629c8288 | <br/>==================================================<br/> EMAIL THREAD DATE: 2020-06-22 11:22:59<br/>==================================================<br/>Fwd: Looking to hire? | https://station.trustar.co/constellation/reports/6e00a714-379a-4db8-ac0c-812a629c8288 | 2020-06-22 15:25:04 | The new title | 2020-06-22 15:25:04 |


### trustar-update-report
***
Update the report with the specified ID. Either the internal TruSTAR report ID or an external tracking ID can be used. Only the fields passed will be updated. All others will be left unchanged.


#### Base Command

`trustar-update-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | TruSTAR report id or external tracking id. | Required | 
| title | Title of the report | Optional | 
| report-body | Text content of report | Optional | 
| enclave_ids | CSV of TruSTAR-generated enclave ids. (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Use the enclave ID, NOT the enclave name. Mandatory if the distribution type is ENCLAVE. You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| external_url | URL for the external report that this originated from, if one exists. Limit 500 alphanumeric characters. Must be unique across all reports for a given company. | Optional | 
| distribution_type | Distribution type of the report | Optional | 
| time_began | ISO-8601 formatted incident time with timezone, e.g. 2016-09-22T11:38:35+00:00. Default is current time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 



#### Command Example
```!trustar-update-report report_id=6e00a714-379a-4db8-ac0c-812a629c8288 title="The new title"```

#### Context Example
```
{
    "TruSTAR": {
        "Report": {
            "id": "6e00a714-379a-4db8-ac0c-812a629c8288",
            "reportBody": "\n==================================================\n EMAIL THREAD DATE: 2020-06-22 11:22:59\n==================================================\nFwd: Looking to hire?",
            "title": "The new title"
        }
    }
}
```

#### Human Readable Output

>### TruSTAR report was successfully updated
>|created|distributionType|enclaveIds|externalTrackingId|externalUrl|id|reportBody|reportDeepLink|timeBegan|title|updated|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-06-22 15:25:04 | ENCLAVE | d915e45a-d0c8-4a75-987a-775649020c96 | PGJmMjcyZWJlNDA2MTUyNzYzZGUzMWY1YTIuMGNiYzk1ZTA3Yy4yMDIwMDYxNzEzMTQyNS5kMWZlMDJkOTEwLmNmYjY5Mjg1QG1haWwyMjYuc2VhODEubWNzdi5uZXQ+ |  | 6e00a714-379a-4db8-ac0c-812a629c8288 | <br/>==================================================<br/> EMAIL THREAD DATE: 2020-06-22 11:22:59<br/>==================================================<br/>Fwd: Looking to hire? | https://station.trustar.co/constellation/reports/6e00a714-379a-4db8-ac0c-812a629c8288 | 2020-06-22 15:25:04 | The new title | 2020-06-22 15:25:04 |


### trustar-search-reports
***
Searches for all reports that contain the given search term.


#### Base Command

`trustar-search-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | The term to search for (e.g. covid-19) If empty, no search term will be applied. Otherwise, must be at least 3 characters. | Optional | 
| enclave_ids | Comma-separated list of enclave ids (i.e. &lt;enclave1&gt;,&lt;enclave2&gt;,&lt;enclave3&gt;). Only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). You can get a list of your enclave IDs executing the command '!trustar-get-enclaves' | Optional | 
| from_time | Start of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| to_time | End of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| tags | Name (or list of names) of tag(s) to filter indicators by. i.e. &lt;tag1&gt;,&lt;tag2&gt;,&lt;tag3&gt;). Only indicators containing ALL of these tags will be returned. | Optional | 
| excluded_tags | Indicators containing ANY of these tags will be excluded from the results. Can be a single tag or a list of tags. i.e. &lt;tag1&gt;,&lt;tag2&gt;,&lt;tag3&gt;). | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.id | string | ID of the report | 
| TruSTAR.Report.title | string | Report Title | 


#### Command Example
```!trustar-search-reports search_term=WANNACRY```

#### Context Example
```
{
    "TruSTAR": {
        "Report": [
            {
                "id": "319b7fa5-0be0-4ff0-aac8-f4455f7a99ce",
                "title": "URLhaus - http://demo.singhealth.xyz/files/WannaCry/GeneralElectionCandidates.pdf.exe"
            },
            {
                "id": "899d6193-0dab-40b6-9a23-7bc8ee7145ba",
                "title": "URLhaus - http://demo.singhealth.xyz/files/WannaCry/Ransomware.WannaCry.zip"
            },
            {
                "id": "5f0d4d95-834b-4ce2-8bfc-7c8ad109a88d",
                "title": "hybridanalysispublicfeed-5b7f02a9c9aae2fad269a1b00b4398ab-2020-07-02 03:56:51"
            },
            {
                "id": "a18578c1-3217-4401-80a5-97520bf484f2",
                "title": "hybridanalysispublicfeed-4e12d4af0963a8def144bf358e6bf6b7-2020-07-02 03:07:35"
            },
            {
                "id": "dea957a9-3b79-4976-ae29-12e86e6e799e",
                "title": "X-Force URL: https://searchsecurity.techtarget.com/news/252463452/wannacry-infections-continue-to-spread-2-years-later."
            },
            {
                "id": "9b5861b9-fdf2-4f22-a36a-cce2bdd9b6f0",
                "title": "Indonesia"
            },
            {
                "id": "e5831db3-17b7-44a7-bb24-ff0d1c64f1b3",
                "title": "India Global Spotlight (Analyst Knowledge Page)"
            },
            {
                "id": "9812510b-60ce-46fb-989b-85fbb5050b8e",
                "title": "hybridanalysispublicfeed-f25e024d175c1be65d6888412601ce32-2020-06-30 03:02:40"
            },
            {
                "id": "9d5b19f3-2ca2-473b-ab17-be328790a414",
                "title": "hybridanalysispublicfeed-9d745af56d0918db19c5ce7e31d531fd-2020-06-30 03:02:28"
            },
            {
                "id": "3e9f96e9-fbf0-4794-857e-0176b20acc1d",
                "title": "hybridanalysispublicfeed-a224c21a15c76cce128657286145113d-2020-06-26 07:08:22"
            },
            {
                "id": "f41ab1af-153e-4c3b-a634-93d5715f6d79",
                "title": "hybridanalysispublicfeed-1685c35cea07561d27d02ead16579b80-2020-06-26 07:08:12"
            },
            {
                "id": "eb67ce91-5206-4a2a-bec4-ffb30382b7fd",
                "title": "hybridanalysispublicfeed-23d365aaa5a9d0deebc8eb3ac1120119-2020-06-26 07:08:22"
            },
            {
                "id": "eab34a1a-7eda-40fa-a77f-8eaef75d5672",
                "title": "REvil/Sodinokibi Threatens to Release Documents on Law Firms and President Trump"
            },
            {
                "id": "f575bd0e-eff5-4be0-a37b-af97ef4b0757",
                "title": "virustotal-URL-https://www.seattletimes.com/business/boeing-aerospace/boeing-hit-by-wannacry-virus-fears-it-could-cripple-some-jet-production/."
            },
            {
                "id": "f854ab11-8c44-4438-9cd1-aeb882f90df2",
                "title": "X-Force URL: https://www.bloomberg.com/news/articles/2017-12-19/u-s-blames-north-korea-for-cowardly-wannacry-cyberattack."
            },
            {
                "id": "d6f75e4a-0f0c-4e9b-b798-ce5eaf3a3e2a",
                "title": "X-Force URL: https://www.dataprotectionreport.com/2017/05/wannacry-ransomware-attack-summary/"
            },
            {
                "id": "4c65b47c-a290-4a83-8cde-a23019ce0301",
                "title": "X-Force URL: https://www.forbes.com/sites/leemathews/2017/05/16/wannacry-ransomware-ms17-010/#1fe38b312609."
            },
            {
                "id": "9e524c31-918e-4888-b5f2-04d029433ee2",
                "title": "X-Force URL: https://www.seattletimes.com/business/boeing-aerospace/boeing-hit-by-wannacry-virus-fears-it-could-cripple-some-jet-production/."
            },
            {
                "id": "e152cbcd-d61b-4b16-875a-9cec8d232643",
                "title": "hybridanalysispublicfeed-6fd816cb36211fe24153420494319d86-2020-06-18 12:33:35"
            },
            {
                "id": "4d1b8092-35c2-42f4-853b-d4156ea0cfc0",
                "title": "hybridanalysispublicfeed-2e215373915334aafb1e6f0fd6e626c6-2020-06-18 06:15:42"
            },
            {
                "id": "0bc27068-ae06-41da-8721-000524fe45cf",
                "title": "hybridanalysispublicfeed-2da0875fd08114fec91e54a1bac0f142-2020-06-18 06:15:32"
            },
            {
                "id": "2d805eb5-0f4b-434f-8017-ad80f5ef795d",
                "title": "hybridanalysispublicfeed-84c82835a5d21bbcf75a61706d8ab549-2020-06-12 23:39:58"
            },
            {
                "id": "72a99972-02e2-4414-9e56-e3b2d170f7ae",
                "title": "Global Spotlight - North Korea (Analyst Knowledge Page)"
            },
            {
                "id": "e36505b3-de31-48f9-a39b-9dba57051fe2",
                "title": "URLhaus - https://github.com/71e6fd52/wannacry/raw/master/wannacry.exe"
            },
            {
                "id": "e218d224-c92f-4004-8614-580d8a02440b",
                "title": "Hungary Global Spotlight (Analyst Knowledge Page)"
            }
        ]
    }
}
```

#### Human Readable Output

>### TruSTAR reports that contain the term WANNACRY
>|created|distributionType|enclaveIds|id|title|updated|
>|---|---|---|---|---|---|
>| 2020-07-02 19:14:00 | ENCLAVE | d039cebb-fb2a-411f-bbc8-7e6a80af105f | 319b7fa5-0be0-4ff0-aac8-f4455f7a99ce | URLhaus - http://demo.singhealth.xyz/files/WannaCry/GeneralElectionCandidates.pdf.exe | 2020-07-02 19:14:00 |
>| 2020-07-02 15:11:01 | ENCLAVE | d039cebb-fb2a-411f-bbc8-7e6a80af105f | 899d6193-0dab-40b6-9a23-7bc8ee7145ba | URLhaus - http://demo.singhealth.xyz/files/WannaCry/Ransomware.WannaCry.zip | 2020-07-02 15:11:01 |
>| 2020-07-02 04:59:03 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 5f0d4d95-834b-4ce2-8bfc-7c8ad109a88d | hybridanalysispublicfeed-5b7f02a9c9aae2fad269a1b00b4398ab-2020-07-02 03:56:51 | 2020-07-02 04:59:03 |
>| 2020-07-02 04:59:00 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | a18578c1-3217-4401-80a5-97520bf484f2 | hybridanalysispublicfeed-4e12d4af0963a8def144bf358e6bf6b7-2020-07-02 03:07:35 | 2020-07-02 04:59:00 |
>| 2020-06-20 05:34:03 | ENCLAVE | ed35f85a-d6bf-4e74-a0f8-61651abf705e | dea957a9-3b79-4976-ae29-12e86e6e799e | X-Force URL: https://searchsecurity.techtarget.com/news/252463452/WannaCry-infections-continue-to-spread-2-years-later. | 2020-07-02 03:10:01 |
>| 2020-07-01 18:04:00 | ENCLAVE | 82c899e4-1031-4e5a-bb0b-c91a4e95150c | 9b5861b9-fdf2-4f22-a36a-cce2bdd9b6f0 | Indonesia | 2020-07-01 18:04:00 |
>| 2020-04-01 19:55:00 | ENCLAVE | 82c899e4-1031-4e5a-bb0b-c91a4e95150c | e5831db3-17b7-44a7-bb24-ff0d1c64f1b3 | India Global Spotlight (Analyst Knowledge Page) | 2020-06-30 13:21:00 |
>| 2020-06-30 04:23:01 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 9812510b-60ce-46fb-989b-85fbb5050b8e | hybridanalysispublicfeed-f25e024d175c1be65d6888412601ce32-2020-06-30 03:02:40 | 2020-06-30 04:23:01 |
>| 2020-06-30 04:19:05 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 9d5b19f3-2ca2-473b-ab17-be328790a414 | hybridanalysispublicfeed-9d745af56d0918db19c5ce7e31d531fd-2020-06-30 03:02:28 | 2020-06-30 04:19:05 |
>| 2020-06-26 08:04:06 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 3e9f96e9-fbf0-4794-857e-0176b20acc1d | hybridanalysispublicfeed-a224c21a15c76cce128657286145113d-2020-06-26 07:08:22 | 2020-06-26 08:04:06 |
>| 2020-06-26 08:02:03 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | f41ab1af-153e-4c3b-a634-93d5715f6d79 | hybridanalysispublicfeed-1685c35cea07561d27d02ead16579b80-2020-06-26 07:08:12 | 2020-06-26 08:02:03 |
>| 2020-06-26 07:56:03 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | eb67ce91-5206-4a2a-bec4-ffb30382b7fd | hybridanalysispublicfeed-23d365aaa5a9d0deebc8eb3ac1120119-2020-06-26 07:08:22 | 2020-06-26 07:56:03 |
>| 2020-05-15 00:03:18 | ENCLAVE | 82c899e4-1031-4e5a-bb0b-c91a4e95150c | eab34a1a-7eda-40fa-a77f-8eaef75d5672 | REvil/Sodinokibi Threatens to Release Documents on Law Firms and President Trump | 2020-06-24 16:56:00 |
>| 2020-06-20 07:01:01 | ENCLAVE | 011ad71b-fd7d-44c2-834a-0d751299fb1f | f575bd0e-eff5-4be0-a37b-af97ef4b0757 | virustotal-URL-https://www.seattletimes.com/business/boeing-aerospace/boeing-hit-by-wannacry-virus-fears-it-could-cripple-some-jet-production/. | 2020-06-20 07:01:01 |
>| 2020-06-20 05:34:04 | ENCLAVE | ed35f85a-d6bf-4e74-a0f8-61651abf705e | f854ab11-8c44-4438-9cd1-aeb882f90df2 | X-Force URL: https://www.bloomberg.com/news/articles/2017-12-19/u-s-blames-north-korea-for-cowardly-wannacry-cyberattack. | 2020-06-20 05:34:04 |
>| 2020-06-20 05:30:00 | ENCLAVE | ed35f85a-d6bf-4e74-a0f8-61651abf705e | d6f75e4a-0f0c-4e9b-b798-ce5eaf3a3e2a | X-Force URL: https://www.dataprotectionreport.com/2017/05/wannacry-ransomware-attack-summary/ | 2020-06-20 05:30:00 |
>| 2020-06-20 05:25:00 | ENCLAVE | ed35f85a-d6bf-4e74-a0f8-61651abf705e | 4c65b47c-a290-4a83-8cde-a23019ce0301 | X-Force URL: https://www.forbes.com/sites/leemathews/2017/05/16/wannacry-ransomware-ms17-010/#1fe38b312609. | 2020-06-20 05:25:00 |
>| 2020-06-20 05:05:02 | ENCLAVE | ed35f85a-d6bf-4e74-a0f8-61651abf705e | 9e524c31-918e-4888-b5f2-04d029433ee2 | X-Force URL: https://www.seattletimes.com/business/boeing-aerospace/boeing-hit-by-wannacry-virus-fears-it-could-cripple-some-jet-production/. | 2020-06-20 05:05:02 |
>| 2020-06-18 12:56:00 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | e152cbcd-d61b-4b16-875a-9cec8d232643 | hybridanalysispublicfeed-6fd816cb36211fe24153420494319d86-2020-06-18 12:33:35 | 2020-06-18 12:56:00 |
>| 2020-06-18 06:54:00 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 4d1b8092-35c2-42f4-853b-d4156ea0cfc0 | hybridanalysispublicfeed-2e215373915334aafb1e6f0fd6e626c6-2020-06-18 06:15:42 | 2020-06-18 06:54:00 |
>| 2020-06-18 06:46:40 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 0bc27068-ae06-41da-8721-000524fe45cf | hybridanalysispublicfeed-2da0875fd08114fec91e54a1bac0f142-2020-06-18 06:15:32 | 2020-06-18 06:46:40 |
>| 2020-06-13 00:57:02 | ENCLAVE | 2eeccced-c740-4ad9-aa5c-82744cd1f6aa | 2d805eb5-0f4b-434f-8017-ad80f5ef795d | hybridanalysispublicfeed-84c82835a5d21bbcf75a61706d8ab549-2020-06-12 23:39:58 | 2020-06-13 00:57:02 |
>| 2020-04-17 21:18:30 | ENCLAVE | 82c899e4-1031-4e5a-bb0b-c91a4e95150c | 72a99972-02e2-4414-9e56-e3b2d170f7ae | Global Spotlight - North Korea (Analyst Knowledge Page) | 2020-06-12 20:06:16 |
>| 2020-06-10 20:37:01 | ENCLAVE | d039cebb-fb2a-411f-bbc8-7e6a80af105f | e36505b3-de31-48f9-a39b-9dba57051fe2 | URLhaus - https://github.com/71e6fd52/wannacry/raw/master/wannacry.exe | 2020-06-10 20:37:01 |
>| 2020-03-25 17:41:22 | ENCLAVE | 82c899e4-1031-4e5a-bb0b-c91a4e95150c | e218d224-c92f-4004-8614-580d8a02440b | Hungary Global Spotlight (Analyst Knowledge Page) | 2020-06-09 20:48:08 |


### trustar-add-to-whitelist
***
Add to allow list a list of indicator values for the user’s company.


#### Base Command

`trustar-add-to-whitelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | CSV of indicators to add to allow list, i.e. evil.com,101.43.52.224 | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trustar-add-to-whitelist indicators=8.8.8.8```

#### Context Example
```
{}
```

#### Human Readable Output

>['8.8.8.8'] added to the allow list successfully

### trustar-remove-from-whitelist
***
Delete an indicator from the user’s company allow list.


#### Base Command

`trustar-remove-from-whitelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The value of the indicator to delete. | Required | 
| indicator_type | The type of the indicator to delete. | Required | 


#### Context Output

There is no context output for this command.


#### Command Example
```!trustar-remove-from-whitelist indicator=8.8.8.8 indicator_type=IP```

#### Context Example
```
{}
```

#### Human Readable Output

>8.8.8.8 removed from the allow list successfully


### trustar-get-phishing-submissions
***
Fetches all phishing submissions that fit the given criteria


#### Base Command

`trustar-get-phishing-submissions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| priority_event_score | List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3. (i.e. -1,0,2) | Optional | 
| from_time | Start of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| to_time | End of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| status | A list of triage statuses for submissions (UNRESOLVED,CONFIRMED,IGNORED); only email submissions marked with at least one of these statuses will be returned | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.PhishingSubmission.submissionId | string | The submission ID | 
| TruSTAR.PhishingSubmission.title | string | Submission title | 
| TruSTAR.PhishingSubmission.normalizedTriageScore | number | Submission triage score | 
| TruSTAR.PhishingSubmission.context.indicatorType | string | Indicator type | 
| TruSTAR.PhishingSubmission.context.sourceKey | string | Indicator source | 
| TruSTAR.PhishingSubmission.context.normalizedSourceScore | number | Indicator score | 
| TruSTAR.PhishingSubmission.context.originalIndicatorScore.name | string | Original Indicator score name | 
| TruSTAR.PhishingSubmission.context.originalIndicatorScore.value | string | Original Indicator score value | 


#### Command Example
```!trustar-get-phishing-submissions from_time="7 days ago"```

#### Context Example
```
{}
```

#### Human Readable Output

>No phishing submissions were found.



### trustar-set-triage-status
***
Marks a phishing email submission with one of the phishing namespace tags


#### Base Command

`trustar-set-triage-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_id | ID of the email submission | Required | 
| status | Submission status | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trustar-set-triage-status submission_id=6e00a714-379a-4db8-ac0c-812a629c8288 status=CONFIRMED```

#### Context Example
```
{}
```

#### Human Readable Output

>Submission ID 6e00a714-379a-4db8-ac0c-812a629c8288 is ['CONFIRMED']


### trustar-get-phishing-indicators
***
Get phishing indicators that match the given criteria.


#### Base Command

`trustar-get-phishing-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| normalized_indicator_score | List of Intel scores to restrict the query. Possible values are -1, 0, 1, 2, 3. (i.e. 0,2,3), | Optional | 
| priority_event_score | List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3. (i.e. 0,2,3), | Optional | 
| from_time | Start of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| to_time | End of time window (format can be absolute like YYYY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00; OR relative, i.e. '10 minutes ago', '5 days ago', etc). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| status | A list of triage statuses for submissions; only email submissions marked with at least one of these statuses will be returned. Options are 'UNRESOLVED', 'CONFIRMED', 'IGNORED' | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.PhishingIndicator.indicatorType | string | Indicator Type | 
| TruSTAR.PhishingIndicator.normalizedIndicatorScore | number | Indicator normalized score | 
| TruSTAR.PhishingIndicator.originalIndicatorScore.name | string | Indicator original score name | 
| TruSTAR.PhishingIndicator.originalIndicatorScore.value | string | Indicator original score value | 
| TruSTAR.PhishingIndicator.sourceKey | string | Indicator source key | 
| TruSTAR.PhishingIndicator.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
```!trustar-get-phishing-indicators from_time="7 days ago"```

#### Context Example
```
{}
```

#### Human Readable Output

>No phishing indicators were found.
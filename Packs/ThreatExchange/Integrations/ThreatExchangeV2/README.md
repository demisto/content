Receive threat intelligence about applications, IP addresses, URLs, and hashes. A service by Facebook
This integration was integrated and tested with API version v3.2 of ThreatExchange 

## Authentication
The ThreatExchange APIs perform authentication via access tokens consisting of App ID and App Secret.

In order to get your App ID and App Secret, Facebook must first confirm your App's access to ThreatExchange.

After Facebook notifies you that your App can access ThreatExchange, go to the App's **Settings** - **Basic** - and copy your App ID and App Secret.

When configuring ThreatExchange v2 on Cortex XSOAR, set the copied values in the *App ID* and *App Secret* fields. 

For more information see [the ThreatExchange API Overview](https://developers.facebook.com/docs/threat-exchange/api/v10.0)

For Cortex XSOAR versions 6.0 and below, the App Secret should be set in the *password* field.

## Configure ThreatExchange v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | -- | --- |
| App ID |  | True |
| App Secret | | True |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Share Level Type | A designation of how the indicator may be shared based on the US-CERT's Traffic Light Protocol | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Malicious Threshold | If the percentage of 'Malicious' reported statuses is above this threshold the indicator will be defined as malicious, otherwise suspicious. | False |
| Suspicious Threshold | If the number of 'Suspicious' reported statuses is above this threshold the indicator will be defined as suspicious. | False |
| Non Malicious Threshold | If the percentage of 'Non Malicious' reported statuses is above this threshold the indicator will be defined as good, otherwise unknown. | False |

 
## Changes compared to previous version
1. Dbot score calculation is different. See [DBot Score / Reputation scores](#dbot-score-/-Reputation-scores) for details. 

2. The context output of the ***threatexchange-query*** command appears under *ThreatExchange - Query* instead of under *queryResult*.

3. The output of reputation commands which was executed on an invalid input does not raise an exception, but provides an output that says no information was found for the given input. In addition a description of the error that occurred is added to the Cortex XSOAR server log.

## DBot Score / Reputation scores

The following information describes a DBot Score calculation logic which is new for this version:

If the percentage of 'Malicious' reported statuses is above the Malicious Threshold (50% by default),
the indicator will be defined as malicious.

If the percentage of 'Malicious' reported statuses is below the Malicious Threshold, but there exists at least one
'Malicious' status, the indicator will be defined as suspicious.

If there are no 'Malicious' statuses, but the number of 'Suspicious' statuses is above the Suspicious Threshold (1 by default),
the indicator will be defined as suspicious.

If there are no 'Malicious' statuses and the number of 'Suspicious' statuses is below the Suspicious Threshold,
and the percentage of 'Non Malicious' reported statuses is above the Non Malicious Threshold (50% by default),
the indicator will be defined as good.

Otherwise, the indicator will be defined as unknown.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Checks the file reputation of the given hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA1, and SHA256 hashes. | Required | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. | Optional | 
| headers | A comma-separated list of headers to display in human-readable format. For example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 
| until | The end timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the reason that the vendor made the decision. | 
| File.Malicious.Score | Number | For malicious files, the score from the vendor. | 
| ThreatExchange.File.share_level | String | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. | 
| ThreatExchange.File.privacy_type | String | The level of privacy applied to the descriptor. Also known as "visibility". | 
| ThreatExchange.File.status | String | If the indicator is known to be malicious. | 
| ThreatExchange.File.review_status | String | Describes how the indicator was vetted. | 
| ThreatExchange.File.id | String | Unique identifier of the threat descriptor. Automatically assigned at create time, and non-editable. | 
| ThreatExchange.File.description | String | A short summary of the indicator and threat. | 
| ThreatExchange.File.added_on | Date | The datetime this descriptor was first uploaded. Automatically computed; not directly editable. | 
| ThreatExchange.File.sha1 | String | The SHA1 hash of the file. | 
| ThreatExchange.File.sha256 | String | The SHA256 hash of the file. | 
| ThreatExchange.File.sample_size_compressed | Number | The size of the compressed sample. | 
| ThreatExchange.File.ssdeep | String | The SSDeep hash of the file. | 
| ThreatExchange.File.sample_type | String | The MIME type of the sample. | 
| ThreatExchange.File.sample_size | Number | The size of the sample. | 
| ThreatExchange.File.sha3_384 | String | The SHA3-384 hash of the file. | 
| ThreatExchange.File.victim_count | Number | A count of known victims infected and/or spreading the malware. | 
| ThreatExchange.File.password | String | The password required to decompress the sample. | 
| ThreatExchange.File.md5 | String | The MD5 hash of the file. | 


#### Command Example
```!file file=cb57e263ab51f8e9b40d6f292bb17512cec0aa701bde14df33dfc06c815be54c```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "cb57e263ab51f8e9b40d6f292bb17512cec0aa701bde14df33dfc06c815be54c",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "ThreatExchange v2"
    },
    "File": {
        "MD5": "f5c3281ed489772c840a137011c76b58",
        "SHA1": "2517620f427f0019e2eee3b36e206567b6e7a74a",
        "SHA256": "cb57e263ab51f8e9b40d6f292bb17512cec0aa701bde14df33dfc06c815be54c",
        "SSDeep": "3:N8RdNcvALtGTmAS3gG9HV6qVJNerWl/DKKIFjnD0SrrVKmTQXQN/:27NFGi79es2TFjnDXrP0i/",
        "Size": 142,
        "Type": "application/octet-stream"
    },
    "ThreatExchange": {
        "File": {
            "added_on": "2014-02-08T10:45:09+0000",
            "description": "New Kilim spam template",
            "id": "760220740669930",
            "md5": "f5c3281ed489772c840a137011c76b58",
            "password": "infected",
            "privacy_type": "VISIBLE",
            "review_status": "REVIEWED_AUTOMATICALLY",
            "sample_size": 142,
            "sample_size_compressed": 142,
            "sample_type": "application/octet-stream",
            "sha1": "2517620f427f0019e2eee3b36e206567b6e7a74a",
            "sha256": "cb57e263ab51f8e9b40d6f292bb17512cec0aa701bde14df33dfc06c815be54c",
            "sha3_384": "bc1ed0a4e634aaa784255bc50fa54fe41839c8763e797d083cefb87b87f7c743bc989c2c80bd6d72239fe86c489e802f",
            "share_level": "GREEN",
            "ssdeep": "3:N8RdNcvALtGTmAS3gG9HV6qVJNerWl/DKKIFjnD0SrrVKmTQXQN/:27NFGi79es2TFjnDXrP0i/",
            "status": "UNKNOWN",
            "victim_count": 0
        }
    }
}
```

#### Human Readable Output

>### ThreatExchange Result for file hash cb57e263ab51f8e9b40d6f292bb17512cec0aa701bde14df33dfc06c815be54c
>|added_on|description|id|md5|password|privacy_type|review_status|sample_size|sample_size_compressed|sample_type|sha1|sha256|sha3_384|share_level|ssdeep|status|victim_count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2014-02-08T10:45:09+0000 | New Kilim spam template | 760220740669930 | f5c3281ed489772c840a137011c76b58 | infected | VISIBLE | REVIEWED_AUTOMATICALLY | 142 | 142 | application/octet-stream | 2517620f427f0019e2eee3b36e206567b6e7a74a | cb57e263ab51f8e9b40d6f292bb17512cec0aa701bde14df33dfc06c815be54c | bc1ed0a4e634aaa784255bc50fa54fe41839c8763e797d083cefb87b87f7c743bc989c2c80bd6d72239fe86c489e802f | GREEN | 3:N8RdNcvALtGTmAS3gG9HV6qVJNerWl/DKKIFjnD0SrrVKmTQXQN/:27NFGi79es2TFjnDXrP0i/ | UNKNOWN | 0 |


### ip
***
Checks the reputation of the given IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 
| headers | A comma-separated list of headers to display in human-readable format. For example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 
| until | The end timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 
| limit | The maximum number of results per page. The maximum is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address found. | 
| IP.Malicious.Vendor | String | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | String | For malicious IP addresses, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.Malicious.Score | Number | For malicious IP addresses, the score from the vendor. | 
| ThreatExchange.IP.share_level | String | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. | 
| ThreatExchange.IP.confidence | Number | A rating, from 0-100, on how confident the publisher is of the threat indicator's status. 0 is the least confident. 100 is the most confident. | 
| ThreatExchange.IP.indicator.id | String | The ID of the threat indicator described by the descriptor. | 
| ThreatExchange.IP.indicator.indicator | String | The threat indicator described by the descriptor. | 
| ThreatExchange.IP.indicator.type | String | The type of the threat indicator described by the descriptor. | 
| ThreatExchange.IP.privacy_type | String | The level of privacy applied to the descriptor. Also known as "visibility". | 
| ThreatExchange.IP.last_updated | Date | Datetime the threat descriptor was last updated. Automatically computed; not directly editable. | 
| ThreatExchange.IP.status | String | If the indicator is known to be malicious. | 
| ThreatExchange.IP.owner.email | String | The email of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.IP.owner.id | String | The ID of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.IP.owner.name | String | The name of the ThreatExchange member that submitted the descriptor. Non-editable | 
| ThreatExchange.IP.raw_indicator | String | A raw, unsanitized string of the indicator being described. | 
| ThreatExchange.IP.review_status | String | Describes how the indicator was vetted. | 
| ThreatExchange.IP.type | String | The type of indicator. | 
| ThreatExchange.IP.id | String | Unique identifier of the threat descriptor. Automatically assigned at create time, and non-editable. | 
| ThreatExchange.IP.description | String | A short summary of the indicator and threat. | 
| ThreatExchange.IP.severity | String | Severity of the threat associated with the indicator. | 
| ThreatExchange.IP.added_on | Date | The datetime this descriptor was first uploaded. Automatically computed; not directly editable. | 


#### Command Example
```!ip ip=8.8.8.8```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "ip",
        "Vendor": "ThreatExchange v2"
    },
    "IP": {
        "Address": "8.8.8.8",
        "DetectionEngines": 2
    },
    "ThreatExchange": {
        "IP": [
            {
                "added_on": "2015-07-07T22:36:04+0000",
                "confidence": 50,
                "description": "Known DNS server",
                "id": "881335228606937",
                "indicator": {
                    "id": "501655576609539",
                    "indicator": "8.8.8.8",
                    "type": "IP_ADDRESS"
                },
                "last_updated": "2020-07-24T05:25:48+0000",
                "owner": {
                    "email": "threatexchange@support.facebook.com",
                    "id": "588498724619612",
                    "name": "Facebook CERT ThreatExchange"
                },
                "privacy_type": "VISIBLE",
                "raw_indicator": "8.8.8.8",
                "review_status": "REVIEWED_AUTOMATICALLY",
                "severity": "INFO",
                "share_level": "GREEN",
                "status": "NON_MALICIOUS",
                "type": "IP_ADDRESS"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatExchange Result for IP 8.8.8.8
>|added_on|confidence|description|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2015-07-07T22:36:04+0000 | 50 | Known DNS server | 881335228606937 | id: 501655576609539<br/>indicator: 8.8.8.8<br/>type: IP_ADDRESS | 2020-07-24T05:25:48+0000 | id: 588498724619612<br/>email: threatexchange@support.facebook.com<br/>name: Facebook CERT ThreatExchange | VISIBLE | 8.8.8.8 | REVIEWED_AUTOMATICALLY | INFO | GREEN | NON_MALICIOUS | IP_ADDRESS |


### url
***
Checks URL Reputation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description**                                                                                                                                                              | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| url               | URL to be checked.                                                                                                                                                           | Required | 
| limit             | The maximum number of results per page. The maximum is 1000. Default is 20.                                                                                                  | Optional | 
| headers           | A comma-separated list of headers to display in human-readable format. For example: header1,header2,header3.                                                                 | Optional | 
| since             | The start timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 
| until             | The end timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago).   | Optional | 
| share_level       | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. Default is RED.                                                             | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL found. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | String | For malicious URLs, the reason for the vendor to make the decision. | 
| URL.Malicious.Score | Number | For malicious URLs, the score from the vendor. | 
| ThreatExchange.URL.share_level | String | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. | 
| ThreatExchange.URL.confidence | Number | A rating, from 0-100, on how confident the publisher is of the threat indicator's status. 0 is the least confident. 100 is the most confident. | 
| ThreatExchange.URL.indicator.id | String | The ID of the threat indicator described by the descriptor. | 
| ThreatExchange.URL.indicator.indicator | String | The threat indicator described by the descriptor. | 
| ThreatExchange.URL.indicator.type | String | The type of the threat indicator described by the descriptor. | 
| ThreatExchange.URL.privacy_type | String | The level of privacy applied to the descriptor. Also known as "visibility". | 
| ThreatExchange.URL.last_updated | Date | Datetime the threat descriptor was last updated. Automatically computed; not directly editable. | 
| ThreatExchange.URL.status | String | If the indicator is known to be malicious. | 
| ThreatExchange.URL.owner.email | String | The email of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.URL.owner.id | String | The ID of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.URL.owner.name | String | The name of the ThreatExchange member that submitted the descriptor. Non-editable | 
| ThreatExchange.URL.raw_indicator | String | A raw, unsanitized string of the indicator being described. | 
| ThreatExchange.URL.review_status | String | Describes how the indicator was vetted. | 
| ThreatExchange.URL.type | String | The type of indicator. | 
| ThreatExchange.URL.id | String | Unique identifier of the threat descriptor. Automatically assigned at create time, and non-editable. | 
| ThreatExchange.URL.description | String | A short summary of the indicator and threat. | 
| ThreatExchange.URL.severity | String | Severity of the threat associated with the indicator. | 
| ThreatExchange.URL.added_on | Date | The datetime this descriptor was first uploaded. Automatically computed; not directly editable. | 


#### Command Example
```!url url=https://www.test.com/```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://www.test.com/",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "url",
        "Vendor": "ThreatExchange v2"
    },
    "ThreatExchange": {
        "URL": [
            {
                "added_on": "2018-07-11T09:50:34+0000",
                "confidence": 25,
                "id": "1904903709602326",
                "indicator": {
                    "id": "838258172933557",
                    "indicator": "https://www.test.com/",
                    "type": "URI"
                },
                "last_updated": "2020-07-24T19:24:35+0000",
                "owner": {
                    "email": "threatexchange@support.facebook.com",
                    "id": "210126779388350",
                    "name": "URLQueryThreatData Feed"
                },
                "privacy_type": "VISIBLE",
                "raw_indicator": "https://www.test.com/",
                "review_status": "REVIEWED_AUTOMATICALLY",
                "severity": "WARNING",
                "share_level": "WHITE",
                "status": "UNKNOWN",
                "type": "URI"
            },
            {
                "added_on": "2015-07-09T03:04:19+0000",
                "confidence": 1,
                "id": "835880593160550",
                "indicator": {
                    "id": "838258172933557",
                    "indicator": "https://www.test.com/",
                    "type": "URI"
                },
                "last_updated": "2020-07-24T03:37:14+0000",
                "owner": {
                    "email": "threatexchange@support.facebook.com",
                    "id": "820763734618599",
                    "name": "Facebook Administrator"
                },
                "privacy_type": "HAS_PRIVACY_GROUP",
                "raw_indicator": "https://www.test.com/",
                "review_status": "REVIEWED_AUTOMATICALLY",
                "severity": "INFO",
                "share_level": "RED",
                "status": "UNKNOWN",
                "type": "URI"
            }
        ]
    },
    "URL": {
        "Data": "https://www.test.com/",
        "DetectionEngines": 2
    }
}
```

#### Human Readable Output

>### ThreatExchange Result for URL https://www.test.com/
>|added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2018-07-11T09:50:34+0000 | 25 | 1904903709602326 | id: 838258172933557<br/>indicator: https://www.test.com/<br/>type: URI | 2020-07-24T19:24:35+0000 | id: 210126779388350<br/>email: threatexchange@support.facebook.com<br/>name: URLQueryThreatData Feed | VISIBLE | https://www.test.com/ | REVIEWED_AUTOMATICALLY | WARNING | WHITE | UNKNOWN | URI |
>| 2015-07-09T03:04:19+0000 | 1 | 835880593160550 | id: 838258172933557<br/>indicator: https://www.test.com/<br/>type: URI | 2020-07-24T03:37:14+0000 | id: 820763734618599<br/>email: threatexchange@support.facebook.com<br/>name: Facebook Administrator | HAS_PRIVACY_GROUP | https://www.test.com/ | REVIEWED_AUTOMATICALLY | INFO | RED | UNKNOWN | URI |


### domain
***
Checks domain reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check reputation. | Required | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. | Optional | 
| headers | A comma-separated list of headers to display in human-readable format. For example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 
| until | The end timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00), and free text (e.g., 24 hours ago). | Optional | 
| share_level       | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. Default is RED.                                                             | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain found. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. | 
| ThreatExchange.Domain.share_level | String | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. | 
| ThreatExchange.Domain.confidence | Number | A rating, from 0-100, on how confident the publisher is of the threat indicator's status. 0 is the least confident. 100 is the most confident. | 
| ThreatExchange.Domain.indicator.id | String | The ID of the threat indicator described by the descriptor. | 
| ThreatExchange.Domain.indicator.indicator | String | The threat indicator described by the descriptor. | 
| ThreatExchange.Domain.indicator.type | String | The type of the threat indicator described by the descriptor. | 
| ThreatExchange.Domain.privacy_type | String | The level of privacy applied to the descriptor. Also known as "visibility". | 
| ThreatExchange.Domain.last_updated | Date | Datetime the threat descriptor was last updated. Automatically computed; not directly editable. | 
| ThreatExchange.Domain.status | String | If the indicator is known to be malicious. | 
| ThreatExchange.Domain.owner.email | String | The email of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.Domain.owner.id | String | The ID of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.Domain.owner.name | String | The name of the ThreatExchange member that submitted the descriptor. Non-editable | 
| ThreatExchange.Domain.raw_indicator | String | A raw, unsanitized string of the indicator being described. | 
| ThreatExchange.Domain.review_status | String | Describes how the indicator was vetted. | 
| ThreatExchange.Domain.type | String | The type of indicator. | 
| ThreatExchange.Domain.id | String | Unique identifier of the threat descriptor. Automatically assigned at create time, and non-editable. | 
| ThreatExchange.Domain.description | String | A short summary of the indicator and threat. | 
| ThreatExchange.Domain.severity | String | Severity of the threat associated with the indicator. | 
| ThreatExchange.Domain.added_on | Date | Datetime the analysis was created. | 


#### Command Example
```!domain domain=google.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "google.com",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "ThreatExchange v2"
    },
    "Domain": {
        "DetectionEngines": 2,
        "Name": "google.com"
    },
    "ThreatExchange": {
        "Domain": [
            {
                "added_on": "2018-05-02T18:05:33+0000",
                "confidence": 75,
                "id": "1688788781168786",
                "indicator": {
                    "id": "826838047363868",
                    "indicator": "google.com",
                    "type": "DOMAIN"
                },
                "last_updated": "2020-07-24T21:13:36+0000",
                "owner": {
                    "email": "threatexchange@support.facebook.com",
                    "id": "1656584897716085",
                    "name": "JoeSandbox Analysis"
                },
                "privacy_type": "HAS_PRIVACY_GROUP",
                "raw_indicator": "google.com",
                "review_status": "UNREVIEWED",
                "severity": "INFO",
                "share_level": "RED",
                "status": "UNKNOWN",
                "type": "DOMAIN"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatExchange Result for domain google.com
>|added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2018-05-02T18:05:33+0000 | 75 | 1688788781168786 | id: 826838047363868<br/>indicator: google.com<br/>type: DOMAIN | 2020-07-24T21:13:36+0000 | id: 1656584897716085<br/>email: threatexchange@support.facebook.com<br/>name: JoeSandbox Analysis | HAS_PRIVACY_GROUP | google.com | UNREVIEWED | INFO | RED | UNKNOWN | DOMAIN |

### threatexchange-query
***
Searches for subjective opinions on indicators of compromise stored in ThreatExchange.


#### Base Command

`threatexchange-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Free-form text field with a value to search for. This can be a file hash or a string found in other fields of the objects. | Required | 
| type | The type of descriptor to search for. Possible values are: ADJUST_TOKEN, API_KEY, AS_NUMBER, BANNER, CMD_LINE, COOKIE_NAME, CRX, DEBUG_STRING, DEST_PORT, DIRECTORY_QUERIED, DOMAIN, EMAIL_ADDRESS, FILE_CREATED, FILE_DELETED, FILE_MOVED, FILE_NAME, FILE_OPENED, FILE_READ, FILE_WRITTEN, GET_PARAM, HASH_IMPHASH, HASH_MD5, HASH_PDQ, HASH_TMK, HASH_SHA1, HASH_SHA256, HASH_SSDEEP, HASH_VIDEO_MD5, HTML_ID, HTTP_REQUEST, IP_ADDRESS, IP_SUBNET, ISP, LATITUDE, LATITUDE, LAUNCH_AGENT, LOCATION, LONGITUDE, MALWARE_NAME, MEMORY_ALLOC, MEMORY_PROTECT, MEMORY_WRITTEN, MUTANT_CREATED, MUTEX, NAME_SERVER, OTHER_FILE_OP, PASSWORD, PASSWORD_SALT, PAYLOAD_DATA, PAYLOAD_TYPE, POST_DATA, PROTOCOL, REFERER, REGISTRAR, REGISTRY_KEY, REG_KEY_CREATED, REG_KEY_DELETED, REG_KEY_ENUMERATED, REG_KEY_MONITORED, REG_KEY_OPENED, REG_KEY_VALUE_CREATED, REG_KEY_VALUE_DELETED, REG_KEY_VALUE_MODIFIED, REG_KEY_VALUE_QUERIED, SIGNATURE, SOURCE_PORT, TELEPHONE, TEXT_STRING, TREND_QUERY, URI, USER_AGENT, VOLUME_QUERIED, WEBSTORAGE_KEY, WEB_PAYLOAD, WHOIS_NAME, WHOIS_ADDR1, WHOIS_ADDR2, XPI. | Required | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. | Optional | 
| headers | A comma-separated list of headers to display in human-readable format. For example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00). and free text (e.g., 24 hours ago). | Optional | 
| until | The end timestamp for collecting malware. Supported time formats: epoch time (e.g., 1619870400), ISO 8601 (e.g., 2021-05-01T12:00:00). and free text (e.g., 24 hours ago). | Optional | 
| strict_text | When set to 'true', the API will not do approximate matching on the value in the text. Default is false. | Optional | 
| before | Returns results collected before this cursor. | Optional | 
| after | Returns results collected after this cursor. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatExchange.Query.data.share_level | String | A designation of how the indicator may be shared, based on the US-CERT's Traffic Light Protocol. | 
| ThreatExchange.Query.data.last_updated | Date | Datetime the threat descriptor was last updated. Automatically computed; not directly editable. | 
| ThreatExchange.Query.data.owner.email | String | The email of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.Query.data.owner.id | String | The ID of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.Query.data.owner.name | String | The name of the ThreatExchange member that submitted the descriptor. Non-editable. | 
| ThreatExchange.Query.data.raw_indicator | String | A raw, unsanitized string of the indicator being described. | 
| ThreatExchange.Query.data.type | String | The type of indicator. | 
| ThreatExchange.Query.data.id | String | Unique identifier of the threat descriptor. Automatically assigned at create time, and non-editable. | 
| ThreatExchange.Query.data.added_on | Date | The datetime this descriptor was first uploaded. Automatically computed; not directly editable. | 
| ThreatExchange.Query.paging.before | String | Paging before cursor. | 
| ThreatExchange.Query.paging.after | String | Paging after cursor. | 


#### Command Example
```!threatexchange-query text=geektime type=URI limit=3```

#### Context Example
```json
{
    "ThreatExchange": {
        "Query": {
            "data": [
                {
                    "added_on": "2018-08-30T07:12:28+0000",
                    "confidence": 50,
                    "id": "2036544083043163",
                    "indicator": {
                        "id": "2036543926376512",
                        "indicator": "http://www.geektime.co.il/wp-content/uploads/2016/09/",
                        "type": "URI"
                    },
                    "last_updated": "2021-03-03T02:41:06+0000",
                    "owner": {
                        "email": "threatexchange@support.facebook.com",
                        "id": "820763734618599",
                        "name": "Facebook Administrator"
                    },
                    "privacy_type": "VISIBLE",
                    "raw_indicator": "http://www.geektime.co.il/wp-content/uploads/2016/09/",
                    "review_status": "REVIEWED_AUTOMATICALLY",
                    "severity": "INFO",
                    "share_level": "GREEN",
                    "status": "UNKNOWN",
                    "type": "URI"
                },
                {
                    "added_on": "2018-08-28T14:59:24+0000",
                    "confidence": 50,
                    "id": "1799344580151062",
                    "indicator": {
                        "id": "1799344400151080",
                        "indicator": "http://www.geektime.co.il/wp-content/uploads/2016/05/",
                        "type": "URI"
                    },
                    "last_updated": "2020-07-24T20:12:26+0000",
                    "owner": {
                        "email": "threatexchange@support.facebook.com",
                        "id": "820763734618599",
                        "name": "Facebook Administrator"
                    },
                    "privacy_type": "VISIBLE",
                    "raw_indicator": "http://www.geektime.co.il/wp-content/uploads/2016/05/",
                    "review_status": "REVIEWED_AUTOMATICALLY",
                    "severity": "INFO",
                    "share_level": "GREEN",
                    "status": "UNKNOWN",
                    "type": "URI"
                },
                {
                    "added_on": "2018-08-24T20:16:16+0000",
                    "confidence": 50,
                    "id": "2265237266824665",
                    "indicator": {
                        "id": "2265236920158033",
                        "indicator": "http://www.geektime.co.il/wp-content/uploads/2016/07/",
                        "type": "URI"
                    },
                    "last_updated": "2020-07-24T18:45:09+0000",
                    "owner": {
                        "email": "threatexchange@support.facebook.com",
                        "id": "820763734618599",
                        "name": "Facebook Administrator"
                    },
                    "privacy_type": "VISIBLE",
                    "raw_indicator": "http://www.geektime.co.il/wp-content/uploads/2016/07/",
                    "review_status": "REVIEWED_AUTOMATICALLY",
                    "severity": "INFO",
                    "share_level": "GREEN",
                    "status": "UNKNOWN",
                    "type": "URI"
                }
            ],
            "paging": {
                "after": "AcGbapTFY3H6ZCEZBYp5gdlibpIrqCJhOm4uk1YgoxkT8nJFgNZCDzzXF04S89kT5ZCPiUUZD",
                "before": "AcFjybJa7Ba5DZBti3wUtysfdqtcOc6lezkjjhRJAMgvCok7nBQUB40uKU5K2xyZBYnF4ZD"
            },
            "text": "geektime",
            "type": "URI"
        }
    }
}
```

#### Human Readable Output

>### ThreatExchange Query Result:
>|added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2018-08-30T07:12:28+0000 | 50 | 2036544083043163 | id: 2036543926376512<br/>indicator: `http://www.geektime.co.il/wp-content/uploads/2016/09/`<br/>type: URI | 2021-03-03T02:41:06+0000 | id: 820763734618599<br/>email: threatexchange@support.facebook.com<br/>name: Facebook Administrator | VISIBLE | `http://www.geektime.co.il/wp-content/uploads/2016/09/` | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI |
>| 2018-08-28T14:59:24+0000 | 50 | 1799344580151062 | id: 1799344400151080<br/>indicator: `http://www.geektime.co.il/wp-content/uploads/2016/05/`<br/>type: URI | 2020-07-24T20:12:26+0000 | id: 820763734618599<br/>email: threatexchange@support.facebook.com<br/>name: Facebook Administrator | VISIBLE | `http://www.geektime.co.il/wp-content/uploads/2016/05/` | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI |
>| 2018-08-24T20:16:16+0000 | 50 | 2265237266824665 | id: 2265236920158033<br/>indicator: `http://www.geektime.co.il/wp-content/uploads/2016/07/`<br/>type: URI | 2020-07-24T18:45:09+0000 | id: 820763734618599<br/>email: threatexchange@support.facebook.com<br/>name: Facebook Administrator | VISIBLE | `http://www.geektime.co.il/wp-content/uploads/2016/07/` | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI |
>### Pagination:
>|after|before|
>|---|---|
>| AcGbapTFY3H6ZCEZBYp5gdlibpIrqCJhOm4uk1YgoxkT8nJFgNZCDzzXF04S89kT5ZCPiUUZD | AcFjybJa7Ba5DZBti3wUtysfdqtcOc6lezkjjhRJAMgvCok7nBQUB40uKU5K2xyZBYnF4ZD |


### threatexchange-members
***
Returns a list of current members of the ThreatExchange, alphabetized by application name. Each application may also include an optional contact email address. You can set this address, if desired, under the settings panel for your application.


#### Base Command

`threatexchange-members`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatExchange.Member.id | String | Member's ID. | 
| ThreatExchange.Member.email | String | Member's email. | 
| ThreatExchange.Member.name | String | Member's name. | 


#### Command Example
```!threatexchange-members```

#### Context Example
```json
{
    "ThreatExchange": {
        "Member": [
            {
                "email": "user@example.com",
                "id": "906975333085907",
                "name": "2U ThreatExchange App"
            }
        ]
    }
}
```

#### Human Readable Output

>### ThreatExchange Members: 
>|id|name|email|
>|---|---|---|
>| 906975333085907 | 2U ThreatExchange App | user@example.com |


### threatexchange-tags-search
***
Enables searching for tags in ThreatExchange.
With this call you can search for ThreatTag objects by text.


#### Base Command

`threatexchange-tags-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Freeform text field with a value to search for.<br/>This value should describe a broader type or class of attack you are interested in. | Required | 
| before | Returns results collected before this cursor. | Optional | 
| after | Returns results collected after this cursor. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatExchange.Tag.data.id | String | The tag's ID. | 
| ThreatExchange.Tag.data.text | String | The tag's text. | 
| ThreatExchange.Tag.paging.before | Unknown | Paging before cursor. | 
| ThreatExchange.Tag.paging.after | String | Paging after cursor. | 


#### Command Example
```!threatexchange-tags-search text=malware```

#### Context Example
```json
{
    "ThreatExchange": {
        "Tag": {
            "data": [
                {
                    "id": "1318516441499594",
                    "text": "malware"
                }
            ],
            "paging": {
                "after": "MAZDZD",
                "before": "MAZDZD"
            },
            "text": "malware"
        }
    }
}
```

#### Human Readable Output

>### ThreatExchange Tags: 
>|id|text|
>|---|---|
>| 1318516441499594 | malware |
>### Pagination:
>|after|before|
>|---|---|
>| MAZDZD | MAZDZD |


### threatexchange-tagged-objects-list
***
Gets a list of tagged objects for a specific ThreatTag.


#### Base Command

`threatexchange-tagged-objects-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | ThreatTag ID to get it's related tagged objects. ThreatTag ID can be retrieved by the threatexchange-tags-search command. | Required | 
| tagged_since | Fetches all objects that have been tagged since this time (inclusive). | Optional | 
| tagged_until | Fetches all objects that have been tagged until this time (inclusive). | Optional | 
| before | Returns results collected before this cursor. | Optional | 
| after | Returns results collected after this cursor. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatExchange.TaggedObject.data.id | String | The ID of the tagged object. | 
| ThreatExchange.TaggedObject.data.type | String | The type of the tagged object. | 
| ThreatExchange.TaggedObject.data.name | String | The name of the tagged object. | 
| ThreatExchange.TaggedObject.paging.before | String | Paging before cursor. | 
| ThreatExchange.TaggedObject.paging.after | String | Paging after cursor. | 


#### Command Example
```!threatexchange-tagged-objects-list tag_id=1318516441499594```

#### Context Example
```json
{
    "ThreatExchange": {
        "TaggedObject": {
            "data": [
                {
                    "id": "1460089820713228",
                    "name": "cafece4c21572473fed821bb64381d0a",
                    "type": "MALWARE_DESCRIPTOR"
                }
            ],
            "paging": {
                "after": "QVFIUmFFOERJZATZAmMW9wRnJwbjFiY2tTdFpHRk9PTVlIYm80bVREdXlIS1pWWmRrSU4zSHpYT2dXUTR0QW1HTkVWal9oalU5dGhyRlZA6U2ZAKWC04T0R0NXVR",
                "before": "QVFIUlhyUENfX2U1UUkyOWxySlpEWVFveEJiM0twRVpGWkc2LWdLME1CU0hYS3hfVzFibjltSUdTYi1LdWlBNF8zenZADaUlZAWm1vQ1RkVm1zc3NnSllza2lB"
            },
            "tag_id": "1318516441499594"
        }
    }
}
```

#### Human Readable Output

>### ThreatExchange Tagged Objects for ThreatTag: 1318516441499594
>|id|name|type|
>|---|---|---|
>| 1460089820713228 | cafece4c21572473fed821bb64381d0a | MALWARE_DESCRIPTOR |
>### Pagination:
>|after|before|
>|---|---|
>| QVFIUmFFOERJZATZAmMW9wRnJwbjFiY2tTdFpHRk9PTVlIYm80bVREdXlIS1pWWmRrSU4zSHpYT2dXUTR0QW1HTkVWal9oalU5dGhyRlZA6U2ZAKWC04T0R0NXVR | QVFIUlhyUENfX2U1UUkyOWxySlpEWVFveEJiM0twRVpGWkc2LWdLME1CU0hYS3hfVzFibjltSUdTYi1LdWlBNF8zenZADaUlZAWm1vQ1RkVm1zc3NnSllza2lB |


### threatexchange-object-get-by-id
***
Gets ThreatExchange object by ID.


#### Base Command

`threatexchange-object-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of a ThreatExchange object. Can be retrieved by ThreatExchange reputation commands and threatexchange-tagged-objects-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatExchange.Object.id | String | ID of a ThreatExchange object. | 


#### Command Example
```!threatexchange-object-get-by-id object_id=1318516441499594```

#### Context Example
```json
{
    "ThreatExchange": {
        "Object": {
            "id": "1318516441499594",
            "text": "malware"
        }
    }
}
```

#### Human Readable Output

>### ThreatExchange Object 1318516441499594:
>|id|text|
>|---|---|
>| 1318516441499594 | malware |
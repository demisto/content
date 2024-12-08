Receive threat intelligence about applications, IP addresses, URLs and hashes, a service by Facebook
## Configure ThreatExchange in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://192.168.0.1) |  | True |
| App ID |  | True |
| App Secret |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Api version |  | True |

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
| file | Hash of the file to query. Supports MD5, SHA1 and SHA256 hashes. | Required | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. Default is 20. | Optional | 
| headers | A comma-separated list of headers to display in human-readable format. For example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware, format: 1391813489. | Optional | 
| until | The end timestamp for collecting malware, format: 1391813489. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | Bad MD5 hash found. | 
| File.SHA1 | unknown | Bad SHA1 hash found. | 
| File.SHA256 | unknown | Bad SHA256 hash found. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 
| File.Malicious.Vendor | unknown | For malicious files, the vendor that made the decision | 
| File.Malicious.Description | unknown | For malicious files, the reason that the vendor made the decision. | 
| File.Malicious.Score | unknown | For malicious files, the score from the vendor. | 


#### Command Example
```!file file=bf4692a98a658dd7fb3599a47b6b48188a12345```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "bf4692a98a658dd7fb3599a47b6b48188a12345",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "hash",
            "Vendor": "ThreatExchange"
        },
        {
            "Indicator": "bf4692a98a658dd7fb3599a47b6b48188a12345",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "file",
            "Vendor": "ThreatExchange"
        }
    ]
}
```

#### Human Readable Output

>ThreatExchange does not have details about bf4692a98a658dd7fb3599a47b6b48188a12345


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | unknown | Bad IP address found. | 
| IP.Malicious.Vendor | unknown | For malicious IPs addresse, the vendor that made the decision. | 
| IP.Malicious.Description | unknown | For malicious IP addresses, the reason that the vendor made the decision. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 
| IP.Malicious.Score | unknown | For malicious IP addresses, the score from the vendor. | 


#### Command Example
```!ip ip=8.8.8.8```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "8.8.8.8",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "ip",
            "Vendor": "ThreatExchange"
        },
        {
            "Indicator": "8.8.8.8",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ThreatExchange"
        }
    ],
    "IP": null
}
```

#### Human Readable Output

>### ThreatExchange IP Reputation
>added_on|confidence|description|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type
>---|---|---|---|---|---|---|---|---|---|---|---|---|---
>2015-07-07T22:36:04+0000 | 50 | Known DNS server | 881335228606937 | {"id":"501655576609539","indicator":"8.8.8.8","type":"IP_ADDRESS"} | 2020-07-24T05:25:48+0000 | {"id":"588498724619612","email":"threatexchange@support.facebook.com","name":"Facebook CERT ThreatExchange"} | VISIBLE | 8.8.8.8 | REVIEWED_AUTOMATICALLY | INFO | GREEN | NON_MALICIOUS | IP_ADDRESS
>2018-04-09T23:00:40+0000 | 50 |   | 1521082241333529 | {"id":"501655576609539","indicator":"8.8.8.8","type":"IP_ADDRESS"} | 2020-07-24T21:52:30+0000 | {"id":"1656584897716085","email":"threatexchange@support.facebook.com","name":"JoeSandbox Analysis"} | HAS_PRIVACY_GROUP | 8.8.8.8 | REVIEWED_AUTOMATICALLY | INFO | RED | UNKNOWN | IP_ADDRESS


### url
***
Check URL Reputation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to be checked. | Required | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. Default is 20. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware, format: 1391813489. | Optional | 
| until | The end timestamp for collecting malware, format: 1391813489. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs found | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason for the vendor to make the decision | 
| URL.Malicious.Score | unknown | For malicious URLs, the score from the vendor | 


#### Command Example
```!url url=https://www.test.com/```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "https://www.test.com/",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "url",
            "Vendor": "ThreatExchange"
        }
    ],
    "URL": null
}
```

#### Human Readable Output

>### ThreatExchange URL Reputation
>added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type
>---|---|---|---|---|---|---|---|---|---|---|---|---
>2018-07-11T09:50:34+0000 | 25 | 1904903709602326 | {"id":"838258172933557","indicator":"https://www.test.com/","type":"URI"} | 2020-07-24T19:24:35+0000 | {"id":"210126779388350","email":"threatexchange@support.facebook.com","name":"URLQueryThreatData Feed"} | VISIBLE | https://www.test.com/ | REVIEWED_AUTOMATICALLY | WARNING | WHITE | UNKNOWN | URI
>2015-07-09T03:04:19+0000 | 1 | 835880593160550 | {"id":"838258172933557","indicator":"https://www.test.com/","type":"URI"} | 2020-07-24T03:37:14+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | HAS_PRIVACY_GROUP | https://www.test.com/ | REVIEWED_AUTOMATICALLY | INFO | RED | UNKNOWN | URI


### domain
***
Check domain reputation


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check reputation. | Required | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. Default is 20. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware, format: 1391813489. | Optional | 
| until | The end timestamp for collecting malware, format: 1391813489. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Bad domain found | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 
| Domain.Malicious.Vendor | unknown | For malicious domains, the vendor that made the decision | 
| Domain.Malicious.Description | unknown | For malicious domains, the reason that the vendor made the decision. | 


#### Command Example
```!domain domain=google.com```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "google.com",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "domain",
            "Vendor": "ThreatExchange"
        },
        {
            "Indicator": "google.com",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ThreatExchange"
        }
    ],
    "Domain": null
}
```

#### Human Readable Output

>### ThreatExchange Domain Reputation
>added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type
>---|---|---|---|---|---|---|---|---|---|---|---|---
>2018-05-02T18:05:33+0000 | 75 | 1688788781168786 | {"id":"826838047363868","indicator":"google.com","type":"DOMAIN"} | 2020-07-24T21:13:36+0000 | {"id":"1656584897716085","email":"threatexchange@support.facebook.com","name":"JoeSandbox Analysis"} | HAS_PRIVACY_GROUP | google.com | UNREVIEWED | INFO | RED | UNKNOWN | DOMAIN
>2015-09-04T22:03:24+0000 | 50 | 955242124521797 | {"id":"826838047363868","indicator":"google.com","type":"DOMAIN"} | 2020-07-24T01:04:11+0000 | {"id":"588498724619612","email":"threatexchange@support.facebook.com","name":"Facebook CERT ThreatExchange"} | VISIBLE | google.com | REVIEWED_MANUALLY | INFO | WHITE | NON_MALICIOUS | DOMAIN


### threatexchange-query
***
 Searches for subjective opinions on indicators of compromise stored in ThreatExchange


#### Base Command

`threatexchange-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Free-form text field with a value to search for. This can be a file hash or a string found in other fields of the objects. | Optional | 
| type | The type of descriptor to search for. For more information see: https://developers.facebook.com/docs/threat-exchange/reference/apis/indicator-type/v2.9. | Optional | 
| limit | The maximum number of results per page. The maximum is 1000. Default is 20. Default is 20. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3. | Optional | 
| since | The start timestamp for collecting malware, format: 1391813489. | Optional | 
| until | The end timestamp for collecting malware, format: 1391813489. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatexchange-query text=geektime type=URI limit=3```

#### Context Example
```json
{
    "queryResult": [
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
        }
    ]
}
```

#### Human Readable Output

>### ThreatExchange Query Result
>added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type
>---|---|---|---|---|---|---|---|---|---|---|---|---
>2018-08-30T07:12:28+0000 | 50 | 2036544083043163 | {"id":"2036543926376512","indicator":"http://www.geektime.co.il/wp-content/uploads/2016/09/","type":"URI"} | 2021-03-03T02:41:06+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | http://www.geektime.co.il/wp-content/uploads/2016/09/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI
>2018-08-28T14:59:24+0000 | 50 | 1799344580151062 | {"id":"1799344400151080","indicator":"http://www.geektime.co.il/wp-content/uploads/2016/05/","type":"URI"} | 2020-07-24T20:12:26+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | http://www.geektime.co.il/wp-content/uploads/2016/05/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI
>2018-08-24T20:16:16+0000 | 50 | 2265237266824665 | {"id":"2265236920158033","indicator":"http://www.geektime.co.il/wp-content/uploads/2016/07/","type":"URI"} | 2020-07-24T18:45:09+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | http://www.geektime.co.il/wp-content/uploads/2016/07/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI


### threatexchange-members
***
Returns a list of current members of the ThreatExchange, alphabetized by application name. Each application may also include an optional contact email address. You can set this address, if desired, under the settings panel for your application


#### Base Command

`threatexchange-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!threatexchange-members```

#### Human Readable Output

>### ThreatExchange Members
>email|id|name
>---|---|---
>example@example.com | example_id_1 | Example Name 1
>example2@example.com | example_id_2 | Example Name 2
>example3@example.com | example_id_3 | Example Name 3
>example4@example.com | example_id_4 | Example Name4


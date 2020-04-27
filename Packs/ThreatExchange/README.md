## Overview
---

Receive threat intelligence about applications, IP addresses, URLs and hashes, a service by Facebook

## Configure ThreatExchange on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ThreatExchange.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://192.168.0.1)__
    * __App ID__
    * __App Secret__
    * __Use system proxy settings__
    * __Trust any certificate (unsecure)__
    * __Api version__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. file
2. ip
3. url
4. domain
5. threatexchange-query
6. threatexchange-members

### 1. file
---
Check file reputation of the given hash

##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA1 and SHA256. | Required | 
| limit | Defines the maximum size of a page of results. The maximum is 1000. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3 | Optional | 
| since |  Returns malware collected after a timestamp, format: 1391813489 | Optional | 
| until | Returns malware collected before a timestamp, format: 1391813489 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | Bad hash found | 
| File.SHA1 | unknown | Bad hash SHA1 | 
| File.SHA256 | unknown | Bad hash SHA256 | 
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| File.Malicious.Vendor | unknown | For malicious files, the vendor that made the decision | 
| File.Malicious.Description | unknown | For malicious files, the reason for the vendor to make the decision | 
| File.Malicious.Score | unknown | For malicious files, the score from the vendor | 


##### Command Example
```!file file=bf4692a98a658dd7fb3599a47b6b48188a12345 using=ThreatExchange_instance_1```

##### Context Example
```
{
    "DBotScore": [
        {
            "Vendor": "ThreatExchange", 
            "Indicator": "bf4692a98a658dd7fb3599a47b6b48188a12345", 
            "Score": 0, 
            "Type": "hash"
        }
    ], 
    "File": []
}
```

##### Human Readable Output
### ThreatExchange Hash Reputation
added_on|description|id|md5|password|privacy_type|review_status|sample_size|sample_size_compressed|sample_type|sha1|sha256|sha3_384|share_level|ssdeep|status|victim_count
---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
2016-05-04T18:41:23+0000 | Retrieved from https://uk.wikipedia.org/wiki/test#.D0.A6.D0.B8.D0.BA.D0.BB_.D0.B7_.D0 | 1086780274727607 | e401ea4b1f2af2c0df325d68212345 | infected | VISIBLE | REVIEWED_AUTOMATICALLY | 127074 | 127074 | text/plain | bf4692a98a658dd7fb3599a47b6b48188a12345 | 7c5c9648680162c123456 |bb96d46a1bab2d23f2027624a0d23604865521c94140d961710047258b715e6712345 | GREEN | 3072:H/ABCD+RmdWEvwqByctY1W2xjL4u4UtoAWBP:1wodWEvwqABCD | UNKNOWN | 0


### 2. ip
---
Check IP Reputation

##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check | Required | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | unknown | Bad IP Address found | 
| IP.Malicious.Vendor | unknown | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | unknown | For malicious IPs, the reason for the vendor to make the decision | 
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| IP.Malicious.Score | unknown | For malicious IPs, the score from the vendor | 


##### Command Example
```!ip ip=8.8.8.8```

##### Context Example
```
{
    "IP": [], 
    "DBotScore": [
        {
            "Vendor": "ThreatExchange", 
            "Indicator": "8.8.8.8", 
            "Score": 1, 
            "Type": "ip"
        }
    ]
}
```

##### Human Readable Output
### ThreatExchange IP Reputation
added_on|confidence|description|id|indicator|last_updated|owner|privacy_type|raw_indicator|reactions|review_status|severity|share_level|status|type
---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
2015-07-07T22:36:04+0000 | 50 | Known DNS server | 123435228606937 | {"id":"123655576609539","indicator":"8.8.8.8","type":"IP_ADDRESS"} | 2019-03-15T16:51:31+0000 | {"id":"123498724619612","email":"threatexchange@support.facebook.com","name":"Facebook CERT ThreatExchange"} | VISIBLE | 8.8.8.8 |   | REVIEWED_AUTOMATICALLY | INFO | GREEN | NON_MALICIOUS | IP_ADDRESS
2015-07-22T01:18:34+0000 | 50 | Known DNS server | 123486438563241 | {"id":"123655576609539","indicator":"8.8.8.8","type":"IP_ADDRESS"} | 2019-03-15T16:50:44+0000 | {"id":"123520067497631","email":"threatexchange@support.facebook.com","name":"Facebook Security Research"} | VISIBLE | 8.8.8.8 | {"key":"HELPFUL","value":"820763734618599"} | REVIEWED_AUTOMATICALLY | INFO | WHITE | NON_MALICIOUS | IP_ADDRESS


### 3. url
---
Check URL Reputation

##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to be checked | Required | 
| limit | Defines the maximum size of a page of results. The maximum is 1000. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3 | Optional | 
| since | Returns malware collected after a timestamp, format: 1391813489 | Optional | 
| until | Returns malware collected before a timestamp, format: 1391813489 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs found | 
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason for the vendor to make the decision | 
| URL.Malicious.Score | unknown | For malicious URLs, the score from the vendor | 


##### Command Example
```!url url=https://www.test.com/```

##### Context Example
```
{
    "URL": [], 
    "DBotScore": [
        {
            "Vendor": "ThreatExchange", 
            "Indicator": "https://www.test.com/", 
            "Score": 0, 
            "Type": "url"
        }
    ]
}
```

##### Human Readable Output
### ThreatExchange URL Reputation
added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type
---|---|---|---|---|---|---|---|---|---|---|---|---
2016-05-26T23:54:09+0000 | 50 | 1234013578450978 | {"id":"1234013565117646","indicator":"https://www.test.com/","type":"URI"} | 2019-02-22T17:21:57+0000 | {"id":"12345634618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | https://www.test.com/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI


### 4. domain
---
Check domain reputation

##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check reputation | Required | 
| limit | Defines the maximum size of a page of results. The maximum is 1000. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3 | Optional | 
| since | Returns malware collected after a timestamp, format: 1391813489 | Optional | 
| until | Returns malware collected before a timestamp, format: 1391813489 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Bad domain found | 
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| Domain.Malicious.Vendor | unknown | For malicious domains, the vendor that made the decision | 
| Domain.Malicious.Description | unknown | For malicious domains, the reason for the vendor to make the decision | 


##### Command Example
```!domain domain=google.com ```

##### Context Example
```
{
    "Domain": [], 
    "DBotScore": [
        {
            "Vendor": "ThreatExchange", 
            "Indicator": "google.com", 
            "Score": 1, 
            "Type": "domain"
        }
    ]
}
```

##### Human Readable Output
### ThreatExchange Domain Reputation
added_on|confidence|description|id|indicator|last_updated|owner|privacy_type|raw_indicator|reactions|review_status|severity|share_level|status|type
---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
2015-09-04T22:03:24+0000 | 50 |   | 123442124521797 | {"id":"123438047363868","indicator":"google.com","type":"DOMAIN"} | 2019-03-14T14:51:45+0000 | {"id":"123498724619612","email":"threatexchange@support.facebook.com","name":"Facebook CERT ThreatExchange"} | VISIBLE | google.com |   | REVIEWED_MANUALLY | INFO | WHITE | NON_MALICIOUS | DOMAIN
2015-11-24T21:22:52+0000 | 75 | Known good domains, typically seen used in advertising. | 123430561511282 | {"id":"123438047363868","indicator":"google.com","type":"DOMAIN"} | 2019-03-14T14:52:03+0000 | {"id":"123420067497631","email":"threatexchange@support.facebook.com","name":"Facebook Security Research"} | VISIBLE | google.com | {"key":"HELPFUL","value":"1234391886293013"},{"key":"SAW_THIS_TOO","value":"1234391886293013"} | REVIEWED_AUTOMATICALLY | INFO | WHITE | NON_MALICIOUS | DOMAIN


### 5. threatexchange-query
---
 Searching for subjective opinions on indicators of compromise stored in ThreatExchange

##### Base Command

`threatexchange-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Freeform text field with a value to search for. This can be a file hash or a string found in other fields of the objects | Optional | 
| type | The type of descriptor to search for, look at: https://developers.facebook.com/docs/threat-exchange/reference/apis/indicator-type/v2.9 | Optional | 
| limit | Defines the maximum size of a page of results. The maximum is 1000. | Optional | 
| headers | Headers to display in Human readable format, comma separated format, for example: header1,header2,header3 | Optional | 
| since | Returns malware collected after a timestamp, format: 1391813489 | Optional | 
| until | Returns malware collected before a timestamp, format: 1391813489 | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!threatexchange-query text=geektime type=URI limit=3 using=ThreatExchange_instance_1```

##### Context Example
```
{
    "queryResult": [
        {
            "status": "UNKNOWN", 
            "confidence": 50, 
            "last_updated": "2018-08-30T07:12:46+0000", 
            "severity": "INFO", 
            "type": "URI", 
            "privacy_type": "VISIBLE", 
            "review_status": "REVIEWED_AUTOMATICALLY", 
            "indicator": {
                "indicator": "http://www.geektime.co.il/wp-content/uploads/2016/09/", 
                "type": "URI", 
                "id": "2036543926376512"
            }, 
            "raw_indicator": "http://www.geektime.co.il/wp-content/uploads/2016/09/", 
            "owner": {
                "email": "threatexchange@support.facebook.com", 
                "name": "Facebook Administrator", 
                "id": "820763734618599"
            }, 
            "share_level": "GREEN", 
            "id": "2036544083043163", 
            "added_on": "2018-08-30T07:12:28+0000"
        }, 
        {
            "status": "UNKNOWN", 
            "confidence": 50, 
            "last_updated": "2018-08-28T14:59:42+0000", 
            "severity": "INFO", 
            "type": "URI", 
            "privacy_type": "VISIBLE", 
            "review_status": "REVIEWED_AUTOMATICALLY", 
            "indicator": {
                "indicator": "http://www.geektime.co.il/wp-content/uploads/2016/05/", 
                "type": "URI", 
                "id": "1799344400151080"
            }, 
            "raw_indicator": "http://www.geektime.co.il/wp-content/uploads/2016/05/", 
            "owner": {
                "email": "threatexchange@support.facebook.com", 
                "name": "Facebook Administrator", 
                "id": "820763734618599"
            }, 
            "share_level": "GREEN", 
            "id": "1799344580151062", 
            "added_on": "2018-08-28T14:59:24+0000"
        }, 
        {
            "status": "UNKNOWN", 
            "confidence": 50, 
            "last_updated": "2018-08-24T20:16:45+0000", 
            "severity": "INFO", 
            "type": "URI", 
            "privacy_type": "VISIBLE", 
            "review_status": "REVIEWED_AUTOMATICALLY", 
            "indicator": {
                "indicator": "http://www.geektime.co.il/wp-content/uploads/2016/07/", 
                "type": "URI", 
                "id": "2265236920158033"
            }, 
            "raw_indicator": "http://www.geektime.co.il/wp-content/uploads/2016/07/", 
            "owner": {
                "email": "threatexchange@support.facebook.com", 
                "name": "Facebook Administrator", 
                "id": "820763734618599"
            }, 
            "share_level": "GREEN", 
            "id": "2265237266824665", 
            "added_on": "2018-08-24T20:16:16+0000"
        }
    ]
}
```

##### Human Readable Output
### ThreatExchange Query Result
added_on|confidence|id|indicator|last_updated|owner|privacy_type|raw_indicator|review_status|severity|share_level|status|type
---|---|---|---|---|---|---|---|---|---|---|---|---
2018-08-30T07:12:28+0000 | 50 | 2036544083043163 | {"id":"2036543926376512","indicator":"http://www.geektime.co.il/wp-content/uploads/2016/09/","type":"URI"} | 2018-08-30T07:12:46+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | http://www.geektime.co.il/wp-content/uploads/2016/09/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI
2018-08-28T14:59:24+0000 | 50 | 1799344580151062 | {"id":"1799344400151080","indicator":"http://www.geektime.co.il/wp-content/uploads/2016/05/","type":"URI"} | 2018-08-28T14:59:42+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | http://www.geektime.co.il/wp-content/uploads/2016/05/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI
2018-08-24T20:16:16+0000 | 50 | 2265237266824665 | {"id":"2265236920158033","indicator":"http://www.geektime.co.il/wp-content/uploads/2016/07/","type":"URI"} | 2018-08-24T20:16:45+0000 | {"id":"820763734618599","email":"threatexchange@support.facebook.com","name":"Facebook Administrator"} | VISIBLE | http://www.geektime.co.il/wp-content/uploads/2016/07/ | REVIEWED_AUTOMATICALLY | INFO | GREEN | UNKNOWN | URI


### 6. threatexchange-members
---
Returns a list of current members of the ThreatExchange, alphabetized by application name. Each application may also include an optional contact email address. You can set this address, if desired, under the settings panel for your application

##### Base Command

`threatexchange-members`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

There is no context output for this command.

##### Command Example
```!threatexchange-members```

##### Human Readable Output
### ThreatExchange Members
email|id|name
---|---|---
a@gmail.com | 12345678 | abc
b@gmail.com | 87654321 | bca
c@gmail.com | 23456789 | cde
d@gmail.com | 98765432 | edc


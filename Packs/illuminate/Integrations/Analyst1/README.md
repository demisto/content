## Overview
---

Analyst1 is an indicator, countermeasure and sensor management tool that enables analysts to collect and analyze evidence of malicious activity. Analyst1’s web based interface provides a single location to collect and analyze evidence of malicious activity and manage indicators then author, test, task and track rules to detect malicious cyber activity. Maintaing traceability between evidence, indicators, rules and sensors, analysts can identify why a rule was created, the type of activity it detects and what sensors are tasked.

This integration utilizes Analyst1's system to enrich Demisto indicators with data provided by the Analyst1 REST API, such as actor and malware information, activity and reported dates, evidence and hit counts, and more.

This integration was integrated and tested with version 1.8.7 of Analyst1
## Analyst1 Playbook
---
Analyst1 Basic Indicator Enrichment: This is a simple playbook that can apply on top of an incident created from an indicator that will determine the indicator type and then properly enrich it with the associated Analyst1 integration command.

## Use Cases
---
* When you wish to have more information on a given indicator
* When you use both Demisto and Analyst1 and wish to have easy linking between the two

## Configure Analyst1 on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Analyst1.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Analyst1 API Credentials (username/password)__
    * __Domain of Analyst1 server to use__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. domain
2. email
3. ip
4. file
5. analyst1-enrich-string
6. analyst1-enrich-ipv6
7. analyst1-enrich-mutex
8. analyst1-enrich-http-request
9. url
### 1. domain
---
Queries the Analyst1 REST API and enriches the given domain with Analyst1 Indicator data
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | string | The domain name, for example, "google.com". | 
| Analyst1.Domain.ID | number | The indicator's unique ID in Analyst1. | 
| Analyst1.Domain.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Domain.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Domain.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Domain.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Domain.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Domain.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Domain.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Domain.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Domain.Malwares.ID | number | Each matched malware unique identifier in Analyst1. | 
| Analyst1.Domain.Malwares.Name | string | Each matched malware name in Analyst1. | 
| Analyst1.Domain.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.Domain.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Domain.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 
| Analyst1.Domain.IpResolution | string | The resolved IP address for this domain. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!domain domain=abc.com```

##### Context Example
```
{
    "Analyst1.Domain": {
        "LastHit": null, 
        "ReportedDates": [
            "2018-06-12"
        ], 
        "Indicator": "abc.com", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [], 
        "EvidenceCount": 1, 
        "Actors": {}, 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/2043650", 
        "ID": 2043650
    }, 
    "Domain": {
        "Malicious": {
            "Vendor": "Analyst1", 
            "Description": "Analyst1 has determined that this indicator is malicious via internal analysis."
        }, 
        "Name": "abc.com"
    }, 
    "DBotScore": {
        "Vendor": "Analyst1", 
        "Indicator": "abc.com", 
        "Score": 3, 
        "Type": "domain"
    }
}
```

##### Human Readable Output
### Analyst1 Domain Information
|Active|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|
| true | 1 | 2043650 | https://partner.cloud.analyst1.com/indicators/2043650 | abc.com | 2018-06-12 |


### 2. email
---
Queries the Analyst1 REST API and enriches the given email with Analyst1 indicator data.
##### Base Command

`email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Email.From | string | The sender of the email. | 
| Analyst1.Email.ID | number | The unique identifier of the given Indicator in Analyst1 | 
| Analyst1.Email.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Email.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Email.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Email.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Email.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Email.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Email.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Email.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Email.Malwares.ID | number | Each matched malware unique identifier in Analyst1. | 
| Analyst1.Email.Malwares.Name | string | Each matched malware name in Analyst1. | 
| Analyst1.Email.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.Email.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Email.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!email email=001toxic@gmail.com```

##### Context Example
```
{
    "DBotScore": {
        "Vendor": "Analyst1", 
        "Indicator": "001toxic@gmail.com", 
        "Score": 3, 
        "Type": "email"
    }, 
    "Analyst1.Email": {
        "LastHit": null, 
        "ReportedDates": [
            "2018-02-05"
        ], 
        "Indicator": "001toxic@gmail.com", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [], 
        "EvidenceCount": 1, 
        "Actors": [
            {
                "id": -2, 
                "name": "Unknown"
            }
        ], 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/1637756", 
        "ID": 1637756
    }, 
    "Email": {
        "Malicious": {
            "Vendor": "Analyst1", 
            "Description": "Analyst1 has determined that this indicator is malicious via internal analysis."
        }, 
        "From": "001toxic@gmail.com"
    }
}
```

##### Human Readable Output
### Analyst1 Email Information
|Active|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | id = -2, name = Unknown | 1 | 1637756 | https://partner.cloud.analyst1.com/indicators/1637756 | 001toxic@gmail.com | 2018-02-05 |


### 3. ip
---
Queries the Analyst1 REST API and enriches the given IP address with Analyst1 indicator data.
##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | The IP address. | 
| Analyst1.Ip.ID | number | The indicator's unique ID in Analyst1. | 
| Analyst1.Ip.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Ip.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Ip.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Ip.FirstHit | date | The first date this this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Ip.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Ip.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Ip.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Ip.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Ip.Malwares.ID | number | Each matched malware unique identifier in Analyst1 | 
| Analyst1.Ip.Malwares.Name | string | Each matched malware name in Analyst1 | 
| Analyst1.Ip.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.Ip.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Ip.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!ip ip=0.154.17.105```

##### Context Example
```
{
    "IP": {
        "Malicious": {
            "Vendor": "Analyst1", 
            "Description": "Analyst1 has determined that this indicator is malicious via internal analysis."
        }, 
        "Address": "0.154.17.105"
    }, 
    "Analyst1.Ip": {
        "LastHit": null, 
        "ReportedDates": [
            "2014-01-04"
        ], 
        "Indicator": "0.154.17.105", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [], 
        "EvidenceCount": 1, 
        "Actors": {}, 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/51469", 
        "ID": 51469
    }, 
    "DBotScore": {
        "Vendor": "Analyst1", 
        "Indicator": "0.154.17.105", 
        "Score": 3, 
        "Type": "ip"
    }
}
```

##### Human Readable Output
### Analyst1 Ip Information
|Active|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|
| true | 1 | 51469 | https://partner.cloud.analyst1.com/indicators/51469 | 0.154.17.105 | 2014-01-04 |


### 4. file
---
Queries the Analyst1 REST API and enriches the given file with Analyst1 indicator data.
##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Analyst1.File.ID | number | The indicator's unique ID in Analyst1. | 
| Analyst1.File.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.File.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.File.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.File.FirstHit | date | The first date this this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.File.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.File.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.File.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.File.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.File.Malwares.ID | number | Each matched malware unique identifier in Analyst1. | 
| Analyst1.File.Malwares.Name | string | Each matched malware name in Analyst1 | 
| Analyst1.File.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.File.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.File.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!file file=00000000000000000000000000000000```

##### Context Example
```
{
    "Analyst1.File": {
        "LastHit": null, 
        "ReportedDates": [
            "2019-06-25", 
            "2020-01-09"
        ], 
        "Indicator": "00000000000000000000000000000000", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [
            "2018-08-02", 
            "2019-09-01"
        ], 
        "EvidenceCount": 2, 
        "Actors": [
            {
                "id": -4, 
                "name": "Multiple Actors Extracted"
            }, 
            {
                "id": 150, 
                "name": "FIN8"
            }
        ], 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/1527155", 
        "ID": 1527155
    }, 
    "DBotScore": {
        "Vendor": "Analyst1", 
        "Indicator": "00000000000000000000000000000000", 
        "Score": 3, 
        "Type": "file"
    }, 
    "File": {
        "Malicious": {
            "Vendor": "Analyst1", 
            "Description": "Analyst1 has determined that this indicator is malicious via internal analysis."
        }, 
        "MD5": "00000000000000000000000000000000"
    }
}
```

##### Human Readable Output
### Analyst1 File Information
|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2018-08-02,<br/>2019-09-01 | id = -4, name = Multiple Actors Extracted,<br/>id = 150, name = FIN8 | 2 | 1527155 | https://partner.cloud.analyst1.com/indicators/1527155 | 00000000000000000000000000000000 | 2019-06-25,<br/>2020-01-09 |


### 5. analyst1-enrich-string
---
Queries the Analyst1 REST API and enriches the given string with Analyst1 indicator data
##### Base Command

`analyst1-enrich-string`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| string | The string for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.String.ID | number | The unique identifier of the given Indicator in Analyst1 | 
| Analyst1.String.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.String.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.String.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.String.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.String.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.String.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.String.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.String.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.String.Malwares.ID | number | Each matched malware unique identifier in Analyst1. | 
| Analyst1.String.Malwares.Name | string | Each matched malware name in Analyst1 | 
| Analyst1.String.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.String.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.String.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 


##### Command Example
```!analyst1-enrich-string string=??```

##### Context Example
```
{
    "Analyst1.String": {
        "LastHit": null, 
        "ReportedDates": [
            "2014-12-12", 
            "2014-12-14", 
            "2014-12-19", 
            "2014-12-20"
        ], 
        "Indicator": "??", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [
            "2014-12-11", 
            "2014-12-14", 
            "2014-12-19", 
            "2014-12-20"
        ], 
        "EvidenceCount": 15, 
        "Actors": [
            {
                "id": -2, 
                "name": "Unknown"
            }
        ], 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/90548", 
        "ID": 90548
    }
}
```

##### Human Readable Output
### Analyst1 String Information
|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2014-12-11,<br/>2014-12-14,<br/>2014-12-19,<br/>2014-12-20 | id = -2, name = Unknown | 15 | 90548 | https://partner.cloud.analyst1.com/indicators/90548 | ?? | 2014-12-12,<br/>2014-12-14,<br/>2014-12-19,<br/>2014-12-20 |


### 6. analyst1-enrich-ipv6
---
Queries the Analyst1 REST API and enriches the given IP address with Analyst1 indicator data.
##### Base Command

`analyst1-enrich-ipv6`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.Ipv6.ID | number | The unique identifier of the given Indicator in Analyst1 | 
| Analyst1.Ipv6.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Ipv6.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Ipv6.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Ipv6.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Ipv6.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Ipv6.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Ipv6.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Ipv6.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Ipv6.Malwares.ID | number | Each matched malware unique identifier in Analyst1. | 
| Analyst1.Ipv6.Malwares.Name | string | Each matched malware name in Analyst1 | 
| Analyst1.Ipv6.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.Ipv6.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Ipv6.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 


##### Command Example
```!analyst1-enrich-ipv6 ip=16::```

##### Context Example
```
{
    "Analyst1.Ipv6": {
        "LastHit": null, 
        "ReportedDates": [
            "2015-05-13"
        ], 
        "Indicator": "16::", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [
            "2018-09-08"
        ], 
        "EvidenceCount": 1, 
        "Actors": {}, 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/2623838", 
        "ID": 2623838
    }
}
```

##### Human Readable Output
### Analyst1 Ipv6 Information
|Active|ActivityDates|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | 2018-09-08 | 1 | 2623838 | https://partner.cloud.analyst1.com/indicators/2623838 | 16:: | 2015-05-13 |


### 7. analyst1-enrich-mutex
---
Queries the Analyst1 REST API and enriches the given mutex with Analyst1 indicator data.
##### Base Command

`analyst1-enrich-mutex`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mutex | The mutex to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.Mutex.ID | number | The unique identifier of the given Indicator in Analyst1 | 
| Analyst1.Mutex.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Mutex.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Mutex.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Mutex.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Mutex.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Mutex.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Mutex.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Mutex.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Mutex.Malwares.ID | number | Each matched malware unique identifier in Analyst1. | 
| Analyst1.Mutex.Malwares.Name | string | Each matched malware name in Analyst1 | 
| Analyst1.Mutex.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.Mutex.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Mutex.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 


##### Command Example
```!analyst1-enrich-mutex mutex=??```

##### Context Example
```
{
    "Analyst1.Mutex": {
        "LastHit": null, 
        "ReportedDates": [
            "2015-01-07", 
            "2015-01-14", 
            "2015-02-23", 
            "2017-08-05", 
            "2017-08-06"
        ], 
        "Indicator": "??", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [
            "2015-01-06", 
            "2015-01-07", 
            "2015-01-14", 
            "2015-02-23", 
            "2017-08-05", 
            "2017-08-06"
        ], 
        "EvidenceCount": 6, 
        "Actors": [
            {
                "id": -2, 
                "name": "Unknown"
            }
        ], 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/95267", 
        "ID": 95267
    }
}
```

##### Human Readable Output
### Analyst1 Mutex Information
|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2015-01-06,<br/>2015-01-07,<br/>2015-01-14,<br/>2015-02-23,<br/>2017-08-05,<br/>2017-08-06 | id = -2, name = Unknown | 6 | 95267 | https://partner.cloud.analyst1.com/indicators/95267 | ?? | 2015-01-07,<br/>2015-01-14,<br/>2015-02-23,<br/>2017-08-05,<br/>2017-08-06 |


### 8. analyst1-enrich-http-request
---
Queries the Analyst1 REST API and enriches the given HTTP request with Analyst1 indicator data.
##### Base Command

`analyst1-enrich-http-request`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| http-request | The HTTP request for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.Httprequest.ID | number | The unique identifier of the given Indicator in Analyst1 | 
| Analyst1.Httprequest.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Httprequest.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Httprequest.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Httprequest.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Httprequest.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Httprequest.HitCount | number | The total number of times this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Httprequest.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Httprequest.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Httprequest.Malwares.ID | number | Each matched malware unique identifier in Analyst1 | 
| Analyst1.Httprequest.Malwares.Name | string | Each matched malware name in Analyst1. | 
| Analyst1.Httprequest.Actors.ID | number | Each matched actor unique identifier in Analyst1. | 
| Analyst1.Httprequest.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Httprequest.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 


##### Command Example
```!analyst1-enrich-http-request http-request=/~```

##### Context Example
```
{
    "Analyst1.Httprequest": {
        "LastHit": null, 
        "ReportedDates": [
            "2020-01-06"
        ], 
        "Indicator": "/~", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [], 
        "EvidenceCount": 1, 
        "Actors": {}, 
        "ConfidenceLevel": "high", 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/2885382", 
        "ID": 2885382
    }
}
```

##### Human Readable Output
### Analyst1 Httprequest Information
|Active|ConfidenceLevel|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | high | 1 | 2885382 | https://partner.cloud.analyst1.com/indicators/2885382 | /~ | 2020-01-06 |


### 9. url
---
Queries the Analyst1 REST API and enriches the given URL with Analyst1 indicator data.
##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. | 
| Analyst1.Url.ID | number | The unique identifier of the given Indicator in Analyst1 | 
| Analyst1.Url.EvidenceCount | number | The number of evidence reports of the given indicator in Analyst1. | 
| Analyst1.Url.Active | boolean | Whether the given indicator is noted as active in Analyst1. | 
| Analyst1.Url.ConfidenceLevel | string | The confidence level of the data in Analyst1. | 
| Analyst1.Url.FirstHit | date | The first date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Url.LastHit | date | The most recent date this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Url.HitCount | number | The total number of this indicator was seen in a source scanned by Analyst1. | 
| Analyst1.Url.ReportedDates | date | The dates this indicator was reported on in Analyst1. | 
| Analyst1.Url.ActivityDates | date | The dates this indicator had reported activity in Analyst1. | 
| Analyst1.Url.Malwares.ID | number | Each matched malware unique identifier in Analyst1 | 
| Analyst1.Url.Malwares.Name | string | Each matched malware name in Analyst1. | 
| Analyst1.Url.Actors.ID | number | Each matched actor unique identifier in Analyst1 | 
| Analyst1.Url.Actors.Name | string | Each matched actor name in Analyst1. | 
| Analyst1.Url.Analyst1Link | string | The URL of the matched indicator in Analyst1. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Numbe | The actual score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!url url=104.218.120.128/check.aspx```

##### Context Example
```
{
    "URL": {
        "Malicious": {
            "Vendor": "Analyst1", 
            "Description": "Analyst1 has determined that this indicator is malicious via internal analysis."
        }, 
        "Data": "104.218.120.128/check.aspx"
    }, 
    "Analyst1.Url": {
        "LastHit": null, 
        "ReportedDates": [
            "2019-07-04"
        ], 
        "Indicator": "104.218.120.128/check.aspx", 
        "Malwares": {}, 
        "FirstHit": null, 
        "ActivityDates": [
            "2018-12-08"
        ], 
        "EvidenceCount": 1, 
        "Actors": [
            {
                "id": 178, 
                "name": "APT33"
            }
        ], 
        "ConfidenceLevel": null, 
        "Active": true, 
        "HitCount": null, 
        "Analyst1Link": "https://partner.cloud.analyst1.com/indicators/2699554", 
        "ID": 2699554
    }, 
    "DBotScore": {
        "Vendor": "Analyst1", 
        "Indicator": "104.218.120.128/check.aspx", 
        "Score": 3, 
        "Type": "url"
    }
}
```

##### Human Readable Output
### Analyst1 Url Information
|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2018-12-08 | id = 178, name = APT33 | 1 | 2699554 | https://partner.cloud.analyst1.com/indicators/2699554 | 104.218.120.128/check.aspx | 2019-07-04 |

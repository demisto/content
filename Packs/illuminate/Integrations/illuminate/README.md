## Overview
---

Deprecated. Use Analyst1 integration instead.

This integration was integrated and tested with version 1.8.7 of illuminate
## illuminate Playbook
---
illuminate Basic Indicator Enrichment: This is a simple playbook that can apply on top of an incident created from an indicator that will determine the indicator type and then properly enrich it with the associated illuminate integration command.

## Use Cases
---
* When you wish to have more information on a given indicator
* When you use both Cortex XSOAR and illuminate and wish to have easy linking between the two

## Configure illuminate on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for illuminate.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __illuminate API Credentials (username/password)__
    * __Domain of illuminate server to use__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. domain
2. email
3. ip
4. file
5. illuminate-enrich-string
6. illuminate-enrich-ipv6
7. illuminate-enrich-mutex
8. illuminate-enrich-http-request
9. url
### 1. domain
---
Queries the illuminate REST API and enriches the given domain with illuminate Indicator data
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
| Illuminate.Domain.ID | number | The indicator's unique ID in illuminate. | 
| Illuminate.Domain.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Domain.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Domain.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Domain.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Domain.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Domain.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Domain.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Domain.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Domain.Malwares.ID | number | Each matched malware unique identifier in illuminate. | 
| Illuminate.Domain.Malwares.Name | string | Each matched malware name in illuminate. | 
| Illuminate.Domain.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.Domain.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Domain.IlluminateLink | string | The URL of the matched indicator in illuminate. | 
| Illuminate.Domain.IpResolution | string | The resolved IP address for this domain. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!domain domain=abc.com```

##### Context Example
```
{
    "Illuminate.Domain": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/2043650", 
        "ID": 2043650
    }, 
    "Domain": {
        "Malicious": {
            "Vendor": "illuminate", 
            "Description": "illuminate has determined that this indicator is malicious via internal analysis."
        }, 
        "Name": "abc.com"
    }, 
    "DBotScore": {
        "Vendor": "illuminate", 
        "Indicator": "abc.com", 
        "Score": 3, 
        "Type": "domain"
    }
}
```

##### Human Readable Output
### illuminate Domain Information
|Active|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|
| true | 1 | 2043650 | https://partner.analystplatform.com/indicators/2043650 | abc.com | 2018-06-12 |


### 2. email
---
Queries the illuminate REST API and enriches the given email with illuminate indicator data.
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
| Illuminate.Email.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Email.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Email.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Email.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Email.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Email.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Email.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Email.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Email.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Email.Malwares.ID | number | Each matched malware unique identifier in illuminate. | 
| Illuminate.Email.Malwares.Name | string | Each matched malware name in illuminate. | 
| Illuminate.Email.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.Email.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Email.IlluminateLink | string | The URL of the matched indicator in illuminate. | 
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
        "Vendor": "illuminate", 
        "Indicator": "001toxic@gmail.com", 
        "Score": 3, 
        "Type": "email"
    }, 
    "Illuminate.Email": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/1637756", 
        "ID": 1637756
    }, 
    "Email": {
        "Malicious": {
            "Vendor": "illuminate", 
            "Description": "illuminate has determined that this indicator is malicious via internal analysis."
        }, 
        "From": "001toxic@gmail.com"
    }
}
```

##### Human Readable Output
### illuminate Email Information
|Active|Actors|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | id = -2, name = Unknown | 1 | 1637756 | https://partner.analystplatform.com/indicators/1637756 | 001toxic@gmail.com | 2018-02-05 |


### 3. ip
---
Queries the illuminate REST API and enriches the given IP address with illuminate indicator data.
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
| Illuminate.Ip.ID | number | The indicator's unique ID in illuminate. | 
| Illuminate.Ip.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Ip.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Ip.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Ip.FirstHit | date | The first date this this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Ip.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Ip.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Ip.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Ip.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Ip.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Ip.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Ip.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.Ip.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Ip.IlluminateLink | string | The URL of the matched indicator in illuminate. | 
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
            "Vendor": "illuminate", 
            "Description": "illuminate has determined that this indicator is malicious via internal analysis."
        }, 
        "Address": "0.154.17.105"
    }, 
    "Illuminate.Ip": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/51469", 
        "ID": 51469
    }, 
    "DBotScore": {
        "Vendor": "illuminate", 
        "Indicator": "0.154.17.105", 
        "Score": 3, 
        "Type": "ip"
    }
}
```

##### Human Readable Output
### illuminate Ip Information
|Active|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|
| true | 1 | 51469 | https://partner.analystplatform.com/indicators/51469 | 0.154.17.105 | 2014-01-04 |


### 4. file
---
Queries the illuminate REST API and enriches the given file with illuminate indicator data.
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
| Illuminate.File.ID | number | The indicator's unique ID in illuminate. | 
| Illuminate.File.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.File.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.File.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.File.FirstHit | date | The first date this this indicator was seen in a source scanned by illuminate. | 
| Illuminate.File.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.File.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.File.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.File.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.File.Malwares.ID | number | Each matched malware unique identifier in illuminate. | 
| Illuminate.File.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.File.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.File.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.File.IlluminateLink | string | The URL of the matched indicator in illuminate. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The type of indicator. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


##### Command Example
```!file file=00000000000000000000000000000000```

##### Context Example
```
{
    "Illuminate.File": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/1527155", 
        "ID": 1527155
    }, 
    "DBotScore": {
        "Vendor": "illuminate", 
        "Indicator": "00000000000000000000000000000000", 
        "Score": 3, 
        "Type": "file"
    }, 
    "File": {
        "Malicious": {
            "Vendor": "illuminate", 
            "Description": "illuminate has determined that this indicator is malicious via internal analysis."
        }, 
        "MD5": "00000000000000000000000000000000"
    }
}
```

##### Human Readable Output
### illuminate File Information
|Active|ActivityDates|Actors|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2018-08-02,<br/>2019-09-01 | id = -4, name = Multiple Actors Extracted,<br/>id = 150, name = FIN8 | 2 | 1527155 | https://partner.analystplatform.com/indicators/1527155 | 00000000000000000000000000000000 | 2019-06-25,<br/>2020-01-09 |


### 5. illuminate-enrich-string
---
Queries the illuminate REST API and enriches the given string with illuminate indicator data
##### Base Command

`illuminate-enrich-string`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| string | The string for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.String.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.String.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.String.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.String.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.String.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.String.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.String.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.String.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.String.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.String.Malwares.ID | number | Each matched malware unique identifier in illuminate. | 
| Illuminate.String.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.String.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.String.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.String.IlluminateLink | string | The URL of the matched indicator in illuminate. | 


##### Command Example
```!illuminate-enrich-string string=??```

##### Context Example
```
{
    "Illuminate.String": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/90548", 
        "ID": 90548
    }
}
```

##### Human Readable Output
### illuminate String Information
|Active|ActivityDates|Actors|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2014-12-11,<br/>2014-12-14,<br/>2014-12-19,<br/>2014-12-20 | id = -2, name = Unknown | 15 | 90548 | https://partner.analystplatform.com/indicators/90548 | ?? | 2014-12-12,<br/>2014-12-14,<br/>2014-12-19,<br/>2014-12-20 |


### 6. illuminate-enrich-ipv6
---
Queries the illuminate REST API and enriches the given IP address with illuminate indicator data.
##### Base Command

`illuminate-enrich-ipv6`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Ipv6.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Ipv6.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Ipv6.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Ipv6.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Ipv6.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Ipv6.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Ipv6.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Ipv6.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Ipv6.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Ipv6.Malwares.ID | number | Each matched malware unique identifier in illuminate. | 
| Illuminate.Ipv6.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Ipv6.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.Ipv6.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Ipv6.IlluminateLink | string | The URL of the matched indicator in illuminate. | 


##### Command Example
```!illuminate-enrich-ipv6 ip=16::```

##### Context Example
```
{
    "Illuminate.Ipv6": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/2623838", 
        "ID": 2623838
    }
}
```

##### Human Readable Output
### illuminate Ipv6 Information
|Active|ActivityDates|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | 2018-09-08 | 1 | 2623838 | https://partner.analystplatform.com/indicators/2623838 | 16:: | 2015-05-13 |


### 7. illuminate-enrich-mutex
---
Queries the illuminate REST API and enriches the given mutex with illuminate indicator data.
##### Base Command

`illuminate-enrich-mutex`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mutex | The mutex to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Mutex.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Mutex.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Mutex.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Mutex.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Mutex.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Mutex.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Mutex.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Mutex.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Mutex.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Mutex.Malwares.ID | number | Each matched malware unique identifier in illuminate. | 
| Illuminate.Mutex.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Mutex.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.Mutex.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Mutex.IlluminateLink | string | The URL of the matched indicator in illuminate. | 


##### Command Example
```!illuminate-enrich-mutex mutex=??```

##### Context Example
```
{
    "Illuminate.Mutex": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/95267", 
        "ID": 95267
    }
}
```

##### Human Readable Output
### illuminate Mutex Information
|Active|ActivityDates|Actors|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2015-01-06,<br/>2015-01-07,<br/>2015-01-14,<br/>2015-02-23,<br/>2017-08-05,<br/>2017-08-06 | id = -2, name = Unknown | 6 | 95267 | https://partner.analystplatform.com/indicators/95267 | ?? | 2015-01-07,<br/>2015-01-14,<br/>2015-02-23,<br/>2017-08-05,<br/>2017-08-06 |


### 8. illuminate-enrich-http-request
---
Queries the illuminate REST API and enriches the given HTTP request with illuminate indicator data.
##### Base Command

`illuminate-enrich-http-request`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| http-request | The HTTP request for which to return information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Httprequest.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Httprequest.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Httprequest.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Httprequest.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Httprequest.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Httprequest.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Httprequest.HitCount | number | The total number of times this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Httprequest.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Httprequest.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Httprequest.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Httprequest.Malwares.Name | string | Each matched malware name in illuminate. | 
| Illuminate.Httprequest.Actors.ID | number | Each matched actor unique identifier in illuminate. | 
| Illuminate.Httprequest.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Httprequest.IlluminateLink | string | The URL of the matched indicator in illuminate. | 


##### Command Example
```!illuminate-enrich-http-request http-request=/~```

##### Context Example
```
{
    "Illuminate.Httprequest": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/2885382", 
        "ID": 2885382
    }
}
```

##### Human Readable Output
### illuminate Httprequest Information
|Active|ConfidenceLevel|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | high | 1 | 2885382 | https://partner.analystplatform.com/indicators/2885382 | /~ | 2020-01-06 |


### 9. url
---
Queries the illuminate REST API and enriches the given URL with illuminate indicator data.
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
| Illuminate.Url.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Url.EvidenceCount | number | The number of evidence reports of the given indicator in illuminate. | 
| Illuminate.Url.Active | boolean | Whether the given indicator is noted as active in illuminate. | 
| Illuminate.Url.ConfidenceLevel | string | The confidence level of the data in illuminate. | 
| Illuminate.Url.FirstHit | date | The first date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Url.LastHit | date | The most recent date this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Url.HitCount | number | The total number of this indicator was seen in a source scanned by illuminate. | 
| Illuminate.Url.ReportedDates | date | The dates this indicator was reported on in illuminate. | 
| Illuminate.Url.ActivityDates | date | The dates this indicator had reported activity in illuminate. | 
| Illuminate.Url.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Url.Malwares.Name | string | Each matched malware name in illuminate. | 
| Illuminate.Url.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Url.Actors.Name | string | Each matched actor name in illuminate. | 
| Illuminate.Url.IlluminateLink | string | The URL of the matched indicator in illuminate. | 
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
            "Vendor": "illuminate", 
            "Description": "illuminate has determined that this indicator is malicious via internal analysis."
        }, 
        "Data": "104.218.120.128/check.aspx"
    }, 
    "Illuminate.Url": {
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
        "IlluminateLink": "https://partner.analystplatform.com/indicators/2699554", 
        "ID": 2699554
    }, 
    "DBotScore": {
        "Vendor": "illuminate", 
        "Indicator": "104.218.120.128/check.aspx", 
        "Score": 3, 
        "Type": "url"
    }
}
```

##### Human Readable Output
### illuminate Url Information
|Active|ActivityDates|Actors|EvidenceCount|ID|IlluminateLink|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2018-12-08 | id = 178, name = APT33 | 1 | 2699554 | https://partner.analystplatform.com/indicators/2699554 | 104.218.120.128/check.aspx | 2019-07-04 |
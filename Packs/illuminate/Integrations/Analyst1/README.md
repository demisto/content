## Overview

---

Analyst1 is an advanced threat intelligence platform (TIP) which simplifies every cybrersecurity analyst's role. This integration with XSOAR presently emphasizes indicator, countermeasure, sensor management, and intelligence collection workflows to enable analysts to collect, analyze, and respond to evidence of malicious activity. Analyst1’s web based interface provides a single location to collect and analyze evidence of malicious activity and manage indicators then author, test, task and track rules to detect malicious cyber activity. Maintaing traceability between evidence, indicators, rules and sensors, analysts can identify why a rule was created, the type of activity it detects and what sensors are tasked.

This integration utilizes Analyst1's system API to: 

1. enrich Cortex XSOAR indicators with data provided by the Analyst1 REST API, such as actor and malware information, activity and reported dates, evidence and hit counts, and more.
2. submit Evidence as content created in XSOAR, downloaded by XSOAR, or a synthesis of both back to Analsyt1 as 'evidence'.
3. access the Analyst1 Sensor records to get indicator and/or signature tasking definitions for deployment to IDS/IPS/Firewall/XDR/other boundary tools.

This integration was integrated and tested with version 2.1.0 of Analyst1.

For full documentation on the Analyst1 API, please access the "Help" or "Guides" section within your Analyst1 instance. For help please contact support@analyst1.com. 

## Analyst1 Playbook

---
Analyst1 Basic Indicator Enrichment: This is a simple playbook that can apply on top of an incident created from an indicator that will determine the indicator type and then properly enrich it with the associated Analyst1 integration command.

For additional example playbooks please contact support@analyst1.com.

## Use Cases

---

* When you wish to have more information on a given indicator
* When you want to look up batch indicator values en mass
* When you want to get indicator metadata from 100s of sources in one call
* When you want to get indicator cached enrichment, like VirusTotal, without rehitting other APIs
* When you use both Cortex XSOAR and Analyst1 and wish to have easy linking between the two
* When you want to submit any form of created or discovered intelligence back to Analyst1
* When you want to get the current Analyst1 created defensive outputs of Indicators and Signatures
* When you want to get iterate diffs of Indicator and Singature sets for proactive defensive configurations

## Configure Analyst1 on Cortex XSOAR

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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
10. analyst1-evidence-submit
11. analyst1-evidence-status
12. analyst1-batch-check
13. analyst1-batch-check-post
14. analyst1-indicator-by-id
15. analyst1-get-sensor-config
16. analyst1-get-sensor-taskings
17. analyst1-get-sensor-diff
18. analyst1-get-sensors


### 1. domain

---
Queries the Analyst1 REST API and enriches the given domain with Analyst1 Indicator data

#### Base Command

`domain`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| domain | The domain for which to return information. | Required | 


#### Context Output

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
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


#### Command Example

```!domain domain=abc.com```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/2043650", 
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

#### Human Readable Output

### Analyst1 Domain Information

|Active|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|
| true | 1 | 2043650 | <https://analyst1instance.domain/indicators/2043650> | abc.com | 2018-06-12 |


### 2. email

---
Queries the Analyst1 REST API and enriches the given email with Analyst1 indicator data.

#### Base Command

`email`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| email | The email for which to return information. | Required | 


#### Context Output

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


#### Command Example

```!email email=001toxic@gmail.com```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/1637756", 
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

#### Human Readable Output

### Analyst1 Email Information

|Active|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | id = -2, name = Unknown | 1 | 1637756 | <https://analyst1instance.domain/indicators/1637756> | 001toxic@gmail.com | 2018-02-05 |


### 3. ip

---
Queries the Analyst1 REST API and enriches the given IP address with Analyst1 indicator data.

#### Base Command

`ip`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| ip | The IP address for which to return information. | Required | 


#### Context Output

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
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


#### Command Example

```!ip ip=0.154.17.105```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/51469", 
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

#### Human Readable Output

### Analyst1 Ip Information

|Active|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|
| true | 1 | 51469 | <https://analyst1instance.domain/indicators/51469> | 0.154.17.105 | 2014-01-04 |


### 4. file

---
Queries the Analyst1 REST API and enriches the given file with Analyst1 indicator data.

#### Base Command

`file`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| file | The file for which to return information. | Required | 


#### Context Output

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
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


#### Command Example

```!file file=00000000000000000000000000000000```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/1527155", 
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

#### Human Readable Output

### Analyst1 File Information

|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2018-08-02,<br/>2019-09-01 | id = -4, name = Multiple Actors Extracted,<br/>id = 150, name = FIN8 | 2 | 1527155 | <https://analyst1instance.domain/indicators/1527155> | 00000000000000000000000000000000 | 2019-06-25,<br/>2020-01-09 |


### 5. analyst1-enrich-string

---
Queries the Analyst1 REST API and enriches the given string with Analyst1 indicator data

#### Base Command

`analyst1-enrich-string`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| string | The string for which to return information. | Required | 


#### Context Output

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


#### Command Example

```!analyst1-enrich-string string=??```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/90548", 
        "ID": 90548
    }
}
```

#### Human Readable Output

### Analyst1 String Information

|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2014-12-11,<br/>2014-12-14,<br/>2014-12-19,<br/>2014-12-20 | id = -2, name = Unknown | 15 | 90548 | <https://analyst1instance.domain/indicators/90548> | ?? | 2014-12-12,<br/>2014-12-14,<br/>2014-12-19,<br/>2014-12-20 |


### 6. analyst1-enrich-ipv6

---
Queries the Analyst1 REST API and enriches the given IP address with Analyst1 indicator data.

#### Base Command

`analyst1-enrich-ipv6`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| ip | The IP address for which to return information. | Required | 


#### Context Output

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


#### Command Example

```!analyst1-enrich-ipv6 ip=16::```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/2623838", 
        "ID": 2623838
    }
}
```

#### Human Readable Output

### Analyst1 Ipv6 Information

|Active|ActivityDates|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | 2018-09-08 | 1 | 2623838 | <https://analyst1instance.domain/indicators/2623838> | 16:: | 2015-05-13 |


### 7. analyst1-enrich-mutex

---
Queries the Analyst1 REST API and enriches the given mutex with Analyst1 indicator data.

#### Base Command

`analyst1-enrich-mutex`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| mutex | The mutex to query information for | Required | 


#### Context Output

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


#### Command Example

```!analyst1-enrich-mutex mutex=??```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/95267", 
        "ID": 95267
    }
}
```

#### Human Readable Output

### Analyst1 Mutex Information

|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2015-01-06,<br/>2015-01-07,<br/>2015-01-14,<br/>2015-02-23,<br/>2017-08-05,<br/>2017-08-06 | id = -2, name = Unknown | 6 | 95267 | <https://analyst1instance.domain/indicators/95267> | ?? | 2015-01-07,<br/>2015-01-14,<br/>2015-02-23,<br/>2017-08-05,<br/>2017-08-06 |


### 8. analyst1-enrich-http-request

---
Queries the Analyst1 REST API and enriches the given HTTP request with Analyst1 indicator data.

#### Base Command

`analyst1-enrich-http-request`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| http-request | The HTTP request for which to return information. | Required | 


#### Context Output

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


#### Command Example

```!analyst1-enrich-http-request http-request=/~```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/2885382", 
        "ID": 2885382
    }
}
```

#### Human Readable Output

### Analyst1 Httprequest Information

|Active|ConfidenceLevel|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|
| true | high | 1 | 2885382 | <https://analyst1instance.domain/indicators/2885382> | /~ | 2020-01-06 |


### 9. url

---
Queries the Analyst1 REST API and enriches the given URL with Analyst1 indicator data.

#### Base Command

`url`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| url | The URL for which to return information. | Required | 


#### Context Output

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
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The AlienVault OTX vendor. | 


#### Command Example

```!url url=104.218.120.128/check.aspx```

#### Context Example

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
        "Analyst1Link": "https://analyst1instance.domain/indicators/2699554", 
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

#### Human Readable Output

### Analyst1 Url Information

|Active|ActivityDates|Actors|EvidenceCount|ID|Analyst1Link|Indicator|ReportedDates|
|---|---|---|---|---|---|---|---|
| true | 2018-12-08 | id = 178, name = APT33 | 1 | 2699554 | <https://analyst1instance.domain/indicators/2699554> | 104.218.120.128/check.aspx | 2019-07-04 |


### 10. analyst1-evidence-submit

***
Submits an 'Evidence' to Analyst1. Submission can be any text or attachment (PDF, JSON,DOCX...). The a1Bot will extract all relevant context. The 'Evidence' can from an external source (email attachment, secure download) or constructed text/JSON within XSOAR to communicate intelligence results back to Analyst1.

#### Base Command

`analyst1-evidence-submit`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| sourceId | Analyst1 ID# of the Source to associate the Evidence. It is a best practice to create a 'Reference' source in Analyst1 to which XSOAR may submit. | Required | 
| fileContent | Content of the Evidence to create within Analyst1. Should be used when content is TXT or JSON. Use fileEntryId for attachments in XSOAR context. One of fileConent or fileEntryId must be included. | Optional | 
| tlp | Traffic Light Protocol (TLP) value for the Evidence. If the Evidence is TLP marked that will override this input as the a1bot finds the TLP markings. . Default is GREEN. | Optional | 
| fileClassification | Government classification of the Evidence. Ignore if not operating in a Military/Government capacity. Default is U. | Optional | 
| fileName | Name of the 'file' as it was received as an attachment/download, or as it should be represented in Analyst1. Will become the default 'title' of the created Evidence record. File extension will be used in MIME type discovery which does influence extraction by a1bot. | Required | 
| fileEntryId | Entry ID in XSOAR context. How the File was acquired matters. For instance, if using the http command, setting saveAsFile=yes is very important or the original, real format will be lost in a {"Body":"encoded file"} wrapping. One of fileConent or fileEntryIdmust be included. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.EvidenceSubmit.uuid | unknown | The unique GUID tracking this specific Evidence's submission. Can be used to monitor to finish extraction. If empty, check 'message'. | 
| Analyst1.EvidenceSubmit.message | unknown | An explanation of the error which occurred that prevented acceptance of the Evidence submission. | 

### 11. analyst1-evidence-status

***
Check on the status of the analyst1-evidence-submit action by using its output UUID.

#### Base Command

`analyst1-evidence-status`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| uuid | Identifier from an Evidence Submission to track status. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.EvidenceStatus.id | unknown | Evidence ID created by the submission. If 'blank' and message is 'blank', indicates the upload is still procesing. | 
| Analyst1.EvidenceStatus.message | unknown | If populated, will communicate errors which occurred with the status check or the upload processing.  | 
| Analyst1.EvidenceStatus.processingComplete | unknown | True or false to indicate if processing of the Evidence upload is done. Determined by evaluating the id or message are present and populated. If an id is returned but blank, this is false, indicating the upload is still in progress. | 

#### Command example

```!analyst1-evidence-status uuid=8b7eee23-d71b-d3da-f66b-b4d3917fdb80```

#### Context Example

```json
{
    "Analyst1": {
        "EvidenceStatus": {
            "id": 1608592,
            "processingComplete": "true"
        }
    }
}
```

#### Human Readable Output

>### Results

>|id|processingComplete|
>|---|---|
>| 1608592 | true |


### 12. analyst1-batch-check

***
Queries the Analyst1 REST API for indicator enrichment data based on a CSV input of multiple indicator values.

#### Base Command

`analyst1-batch-check`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| values | Comma delimited set of possible Indicator or other Observable values. Submit as a basic string input with commas separating each value. For more complex or higher volume batches, use analyst1-batch-check-post. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.BatchResults.ID | unknown | Matched ID values. May not all be Indicators. Could reflect Indicator, Asset, Ignore List, or System records. | 
| Analyst1.BatchResults.matchedValue | unknown | The matched terms from Indicators, Assets, Ignore List, or System CIDR entries. | 
| Analyst1.BatchResults | unknown | Full Batch Check JSON | 

#### Command example

```!analyst1-batch-check values=1.2.3.4,abc.com,google.com```

#### Context Example

```json
{
    "Analyst1": {
        "BatchResults": {
            "actor": [
                {
                    "akas": [
                        "Multiple Actors Extracted"
                    ],
                    "id": -4,
                    "title": "Multiple Actors Extracted"
                }
            ],
            "benign": false,
            "entity": {
                "key": "INDICATOR",
                "title": "Indicator"
            },
            "id": 2043650,
            "malware": [],
            "matchedValue": "abc.com",
            "searchedValue": "abc.com",
            "system": [],
            "type": {
                "key": "domain",
                "title": "Domain"
            }
        }
    }
}
```

#### Human Readable Output

>### Results

>|actor|benign|entity|id|malware|matchedValue|searchedValue|system|type|
>|---|---|---|---|---|---|---|---|---|
>|  |  | key: IGNORED_INDICATOR<br/>title: Ignored Indicator | 10336 |  | google.com | google.com |  | key: domain<br/>title: Domain |
>| {'id': -4, 'title': 'Multiple Actors Extracted', 'akas': ['Multiple Actors Extracted']},<br/>{'id': 4188, 'title': 'waterfox', 'akas': ['waterfox']},<br/>{'id': 4618, 'title': 'UNC3944', 'akas': ['Dev0671', 'Dev0971', 'UNC3944', 'UNC 3944', 'UNC-3944']} |  | key: ASSET<br/>title: Asset | 28869 |  | google.com | google.com | {'id': 918, 'title': 'Google Inc.', 'akas': ['AS15169', 'Google Inc.']} | key: domain<br/>title: Domain |
>|  | false | key: INDICATOR<br/>title: Indicator | 438290 | {'id': 772, 'title': 'AceHash', 'akas': ['AceHash']},<br/>{'id': 875, 'title': '007Keylogger', 'akas': ['007', '007Keylogger']} | 1.2.3.4 | 1.2.3.4 |  | key: ip<br/>title: IPv4 |
>| {'id': -4, 'title': 'Multiple Actors Extracted', 'akas': ['Multiple Actors Extracted']} | false | key: INDICATOR<br/>title: Indicator | 2043650 |  | abc.com | abc.com |  | key: domain<br/>title: Domain |


### 13. analyst1-batch-check-post

***
Similar to analyst1-batch-check, however the inputs can be more complex. The 'values' input is an option for a pre-formatted newline separated file. This allows for more complex Indicators or larger Indicator sets to be searched. The 'valeus_array' allows for preformed array inputs or array-like inputs to be sumitted. Output is the same.

#### Base Command

`analyst1-batch-check-post`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| values | Newline delimited text for many Indicator or other observable inputs. Either valeus_array or values must be provided. | Optional | 
| values_array | Array of text, each being an Indicator or other observable value to search. Either valeus_array or values must be provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1 | unknown | Full Batch Check JSON | 
| Analyst1.ID | unknown | Matched ID values. May not all be Indicators. Could reflect Indicator, Asset, Ignore List, or System records. | 
| Analyst1.matchedValue | unknown | The matched terms from Indicators, Assets, Ignore List, or System CIDR entries. | 


### 14. analyst1-indicator-by-id

***
Gets the full JSON for an Analyst1 Indicator given the internal Analyst1 Indicator ID. Use this when full Indicator context is required for additional processing. This always includes all sources, enrichments, and every piece of information available in the Analyst1 platform, including integrated system's original enrichment JSON or results.

#### Base Command

`analyst1-indicator-by-id`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| indicator_id | Internal Analyst1 Indicator ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.Indicator | unknown | Full Analyst1 native JSON for the Indicator. Will include all attributes, associated sources, enrichment results, and all settings as seen in the Analyst1 UI. | 

#### Command example

```!analyst1-indicator-by-id indicator_id=983```

#### Context Example

```json
{
    "Analyst1": {
        "Indicator": {
            "active": false,
            "activityDates": [
                {
                    "classification": "U",
                    "date": "2012-05-08"
                },
                {
                    "classification": "U",
                    "date": "2012-05-16"
                },
                {
                    "classification": "U",
                    "date": "2012-08-30"
                },
                {
                    "classification": "U",
                    "date": "2012-09-05"
                },
                {
                    "classification": "U",
                    "date": "2012-09-26"
                },
                {
                    "classification": "U",
                    "date": "2012-12-07"
                },
                {
                    "classification": "U",
                    "date": "2013-01-17"
                },
                {
                    "classification": "U",
                    "date": "2013-03-01"
                },
                {
                    "classification": "U",
                    "date": "2013-03-14"
                },
                {
                    "classification": "U",
                    "date": "2013-03-27"
                },
                {
                    "classification": "U",
                    "date": "2013-04-01"
                },
                {
                    "classification": "U",
                    "date": "2013-06-18"
                },
                {
                    "classification": "U",
                    "date": "2014-03-05"
                },
                {
                    "classification": "U",
                    "date": "2014-05-07"
                }
            ],
            "actors": [
                {
                    "classification": "U",
                    "id": 30,
                    "name": "APT41"
                },
                {
                    "classification": "U",
                    "id": 121,
                    "name": "Conimes"
                }
            ],
            "attackPatterns": [],
            "benign": {
                "classification": "U",
                "value": false
            },
            "confidenceLevel": {
                "classification": "U",
                "value": "high"
            },
            "description": null,
            "domainRegistration": {
                "classification": "U",
                "name": "unknown"
            },
            "enrichmentFields": [
                {
                    "classification": "unclass",
                    "name": "IP Resolution (DNS Resolution)",
                    "numeric": null,
                    "type": "ipResolution",
                    "value": "redacted_ip_address"
                },
                {
                    "classification": "unclass",
                    "name": "Reverse IP Lookup (VirusTotal)",
                    "numeric": 13,
                    "type": "reverseIp",
                    "value": "13 resolutions to this domain"
                },
                {
                    "classification": "unclass",
                    "name": "IP Resolution (DomainTools)",
                    "numeric": null,
                    "type": "ipResolution",
                    "value": "redacted_ip_address"
                },
                {
                    "classification": "unclass",
                    "name": "IP Resolution (VirusTotal)",
                    "numeric": null,
                    "type": "ipResolution",
                    "value": "redacted_ip_address"
                }
            ],
            "enrichmentResults": [
                {
                    "date": "2020-04-28",
                    "format": "json",
                    "result": "{ \"status\": \"redacted to protect content provider's actual JSON output that in a live call would be provided\" }"
                    "type": "VIRUS_TOTAL"
                },
                {
                    "date": "2020-12-15",
                    "format": "colonDelimited",
                    "result": "redacted to protected content provider's actual raw text result",
                    "type": "WHOIS_IP_REGISTRATION"
                }
            ],
            "expand": "enrichmentResults,hitStats,sources",
            "exploitStage": {
                "classification": "U",
                "id": 6,
                "name": "Stage 7 - Actions on Objectives"
            },
            "externalhitCount": 0,
            "fileNames": null,
            "fileSize": null,
            "firstExternalHit": null,
            "firstHit": null,
            "hashes": null,
            "hitCount": 0,
            "id": 983,
            "indicatorDerivation": null,
            "integrationSources": [],
            "ipRegistration": null,
            "ipResolution": null,
            "lastExternalHit": null,
            "lastHit": null,
            "links": [
                {
                    "href": "https://analyst1instance.domain/api/1_0/indicator/983",
                    "rel": "self"
                },
                {
                    "href": "https://analyst1instance.domain/api/1_0/indicator/983/evidence",
                    "rel": "evidence"
                },
                {
                    "href": "https://analyst1instance.domain/api/1_0/indicator/983/stix",
                    "rel": "stix"
                }
            ],
            "malwares": [],
            "originatingIps": null,
            "path": null,
            "ports": [
                {
                    "classification": "U",
                    "value": 443
                },
                {
                    "classification": "U",
                    "value": 80
                }
            ],
            "reportCount": 21,
            "reportedDates": [
                {
                    "classification": "U",
                    "date": "2012-05-10"
                },
                {
                    "classification": "U",
                    "date": "2013-04-01"
                },
                {
                    "classification": "U",
                    "date": "2013-06-19"
                },
                {
                    "classification": "U",
                    "date": "2013-09-16"
                },
                {
                    "classification": "U",
                    "date": "2014-05-19"
                },
                {
                    "classification": "U",
                    "date": "2014-08-14"
                },
                {
                    "classification": "U",
                    "date": "2018-09-19"
                },
                {
                    "classification": "U",
                    "date": "2019-10-17"
                },
                {
                    "classification": "U",
                    "date": "2021-07-01"
                }
            ],
            "requestMethods": null,
            "sources": [
                {
                    "category": "INTERNAL",
                    "enabled": false,
                    "id": 0,
                    "title": "Internal",
                    "type": "reference",
                    "url": null
                },
                {
                    "category": "FREE",
                    "enabled": false,
                    "id": 78,
                    "title": "Threat Connect",
                    "type": "rss",
                    "url": "https://feeds.feedburner.com/threatconnect-blogs"
                },
                {
                    "category": "PAID",
                    "enabled": true,
                    "id": 134,
                    "title": "CrowdStrike Premium Paid",
                    "type": "api",
                    "url": "https://api.crowdstrike.com"
                }
            ],
            "status": "rc",
            "stixObjects": null,
            "subjects": null,
            "targets": [
                {
                    "classification": "U",
                    "id": -2,
                    "name": "Unknown"
                },
                {
                    "classification": "U",
                    "id": 100017,
                    "name": "Manufacturing Industry"
                },
                {
                    "classification": "U",
                    "id": 100021,
                    "name": "Energy Industry"
                },
                {
                    "classification": "U",
                    "id": 100026,
                    "name": "Technology Industry"
                }
            ],
            "tasked": true,
            "tlp": "undetermined",
            "tlpCaveats": null,
            "tlpHighestAssociated": "amber",
            "tlpJustification": null,
            "tlpLowestAssociated": "undetermined",
            "tlpResolution": "resolved",
            "type": "domain",
            "value": {
                "classification": "U",
                "name": "conimes.com"
            },
            "verified": true
        }
    }
}
```

#### Human Readable Output

>### Results

>|active|activityDates|actors|attackPatterns|benign|confidenceLevel|description|domainRegistration|enrichmentFields|enrichmentResults|expand|exploitStage|externalhitCount|fileNames|fileSize|firstExternalHit|firstHit|hashes|hitCount|id|indicatorDerivation|integrationSources|ipRegistration|ipResolution|lastExternalHit|lastHit|links|malwares|originatingIps|__Path__|ports|reportCount|reportedDates|requestMethods|sources|status|stixObjects|subjects|targets|tasked|tlp|tlpCaveats|tlpHighestAssociated|tlpJustification|tlpLowestAssociated|tlpResolution|type|value|verified|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | {'date': '2012-05-08', 'classification': 'U'},<br/>{'date': '2012-05-16', 'classification': 'U'},<br/>{'date': '2012-08-30', 'classification': 'U'},<br/>{'date': '2012-09-05', 'classification': 'U'},<br/>{'date': '2012-09-26', 'classification': 'U'},<br/>{'date': '2012-12-07', 'classification': 'U'},<br/>{'date': '2013-01-17', 'classification': 'U'},<br/>{'date': '2013-03-01', 'classification': 'U'},<br/>{'date': '2013-03-14', 'classification': 'U'},<br/>{'date': '2013-03-27', 'classification': 'U'},<br/>{'date': '2013-04-01', 'classification': 'U'},<br/>{'date': '2013-06-18', 'classification': 'U'},<br/>{'date': '2014-03-05', 'classification': 'U'},<br/>{'date': '2014-05-07', 'classification': 'U'} | {'name': 'APT41', 'id': 30, 'classification': 'U'},<br/>{'name': 'Conimes', 'id': 121, 'classification': 'U'} |  | value: false<br/>classification: U | value: high<br/>classification: U |  | name: unknown<br/>classification: U | {'type': 'ipResolution', 'name': 'IP Resolution (DNS Resolution)', 'value': 'redacted_ip_address', 'numeric': None, 'classification': 'unclass'},<br/>{'type': 'reverseIp', 'name': 'Reverse IP Lookup (VirusTotal)', 'value': '13 resolutions to this domain', 'numeric': 13.0, 'classification': 'unclass'},<br/>{'type': 'ipResolution', 'name': 'IP Resolution (DomainTools)', 'value': 'redacted_ip_address', 'numeric': None, 'classification': 'unclass'},<br/>{'type': 'ipResolution', 'name': 'IP Resolution (VirusTotal)', 'value': 'redacted_ip_address', 'numeric': None, 'classification': 'unclass'} | { "date": "2020-04-28", "format": "json", "result": "{ \"status\": \"redacted to protect content provider's actual JSON output that in a live call would be provided\" }" "type": "VIRUS_TOTAL" },<br/>{ "date": "2020-12-15", "format": "colonDelimited", "result": "redacted to protected content provider's actual raw text result", "type": "WHOIS_IP_REGISTRATION" } | enrichmentResults,hitStats,sources | name: Stage 7 - Actions on Objectives<br/>id: 6<br/>classification: U | 0 |  |  |  |  |  | 0 | 983 |  |  |  |  |  |  | {'rel': 'self', 'href': 'https:<span>//</span>analyst1instance.domain/api/1_0/indicator/983'},<br/>{'rel': 'evidence', 'href': 'https:<span>//</span>analyst1instance.domain/api/1_0/indicator/983/evidence'},<br/>{'rel': 'stix', 'href': 'https:<span>//</span>analyst1instance.domain/api/1_0/indicator/983/stix'} |  |  |  | {'value': 443, 'classification': 'U'},<br/>{'value': 80, 'classification': 'U'} | 21 | {'date': '2012-05-10', 'classification': 'U'},<br/>{'date': '2013-04-01', 'classification': 'U'},<br/>{'date': '2013-06-19', 'classification': 'U'},<br/>{'date': '2013-09-16', 'classification': 'U'},<br/>{'date': '2014-05-19', 'classification': 'U'},<br/>{'date': '2014-08-14', 'classification': 'U'},<br/>{'date': '2018-09-19', 'classification': 'U'},<br/>{'date': '2019-10-17', 'classification': 'U'},<br/>{'date': '2021-07-01', 'classification': 'U'} |  | {'type': 'reference', 'enabled': False, 'title': 'Internal', 'url': None, 'category': 'INTERNAL', 'id': 0},<br/>{'type': 'rss', 'enabled': False, 'title': 'Threat Connect', 'url': 'https:<span>//</span>feeds.feedburner.com/threatconnect-blogs', 'category': 'FREE', 'id': 78},<br/>{'type': 'api', 'enabled': True, 'title': 'CrowdStrike Premium Paid', 'url': 'https:<span>//</span>api.crowdstrike.com', 'category': 'PAID', 'id': 134} | rc |  |  | {'name': 'Unknown', 'id': -2, 'classification': 'U'},<br/>{'name': 'Manufacturing Industry', 'id': 100017, 'classification': 'U'},<br/>{'name': 'Energy Industry', 'id': 100021, 'classification': 'U'},<br/>{'name': 'Technology Industry', 'id': 100026, 'classification': 'U'} | true | undetermined |  | amber |  | undetermined | resolved | domain | name: conimes.com<br/>classification: U | true |


### 15. analyst1-get-sensor-config

***
Queries the Analyst1 REST API for the current sensor config given a valid Sensor ID. This config file is meant to be directly provided to a device (IDS, IPS, Firewall, SNORT...) for configuration replacements.

#### Base Command

`analyst1-get-sensor-config`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| sensor_id | Sensor ID number for this Analyst1 instance. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.SensorTaskings.ConfigFile.config_text | unknown | full text of the current configuration file for the Sensor | 
| Analyst1.SensorTaskings.ConfigFile.warRoomEntry.FileID | unknown | FileID from invoking fileResult\(\) in the Common Server Functions. An alternative to the returned config_text in case file processing is preferred. | 
| Analyst1.SensorTaskings.ConfigFile.warRoomEntry.File | unknown | File Name as saved on the War Room file with fileResult\(\)  | 

#### Command example

```!analyst1-get-sensor-config sensor_id=7689```

#### Context Example

```json
{
    "Analyst1": {
        "SensorTaskings": {
            "ConfigFile": {
                "config_text": "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:\"ET TROJAN Win32/0xtaRAT CnC Activity M5 (POST)\"; flow:established,to_server; content:\"POST\"; http_method; content:\".php?GUID=\"; http_uri; pcre:\"/\\.php\\?GUID=[a-zA-Z0-9-]{36}$/U\"; content:\"//\"; http_raw_uri; depth:2; content:\"name=|22|file|22 3b 20|filename=|22|_screenshot_\"; http_client_body; fast_pattern:15,20; content:!\"Referer|3a 20|\"; http_header; reference:md5,a1a39e458977aa512b7ff2ba1995b18d; reference:url,research.checkpoint.com/2023/operation-silent-watch-desktop-surveillance-in-azerbaijan-and-armenia; classtype:trojan-activity; sid:2046186; rev:1; metadata:attack_target Client_Endpoint, created_at 2023_06_09, deployment Perimeter, deployment SSLDecrypt, former_category MALWARE, performance_impact Low, signature_severity Critical, updated_at 2023_06_09;)\nalert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"ET WEB_SPECIFIC_APPS Joomla! SQL Injection Attempt -- categories.php text SELECT\"; flow:established,to_server; content:\"/plugins/search/categories.php?\"; nocase; http_uri; content:\"text=\"; nocase; http_uri; content:\"SELECT\"; nocase; http_uri; pcre:\"/SELECT.+FROM/Ui\"; reference:cve,2007-0373; reference:url,www.securityfocus.com/bid/22122; reference:url,doc.emergingthreats.net/2005438; classtype:web-application-attack; sid:2005438; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, cve CVE_2007_0373, deployment Datacenter, former_category WEB_SPECIFIC_APPS, signature_severity Major, tag SQL_Injection, updated_at 2020_09_11;)\n",
                "warRoomEntry": {
                    "Contents": "",
                    "ContentsFormat": "text",
                    "File": "sensor7689Config.txt",
                    "FileID": "8cca47a1-aef6-46c4-a372-8653f82abed0",
                    "Type": 3
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Results

>|config_text|warRoomEntry|
>|---|---|
>| alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET TROJAN Win32/0xtaRAT CnC Activity M5 (POST)"; flow:established,to_server; content:"POST"; http_method; content:".php?GUID="; http_uri; pcre:"/\.php\?GUID=[a-zA-Z0-9-]{36}$/U"; content:"//"; http_raw_uri; depth:2; content:"name=\|22\|file\|22 3b 20\|filename=\|22\|_screenshot_"; http_client_body; fast_pattern:15,20; content:!"Referer\|3a 20\|"; http_header; reference:md5,a1a39e458977aa512b7ff2ba1995b18d; reference:url,research.checkpoint.com/2023/operation-silent-watch-desktop-surveillance-in-azerbaijan-and-armenia; classtype:trojan-activity; sid:2046186; rev:1; metadata:attack_target Client_Endpoint, created_at 2023_06_09, deployment Perimeter, deployment SSLDecrypt, former_category MALWARE, performance_impact Low, signature_severity Critical, updated_at 2023_06_09;)<br/>alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Joomla! SQL Injection Attempt -- categories.php text SELECT"; flow:established,to_server; content:"/plugins/search/categories.php?"; nocase; http_uri; content:"text="; nocase; http_uri; content:"SELECT"; nocase; http_uri; pcre:"/SELECT.+FROM/Ui"; reference:cve,2007-0373; reference:url,www.securityfocus.com/bid/22122; reference:url,doc.emergingthreats.net/2005438; classtype:web-application-attack; sid:2005438; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, cve CVE_2007_0373, deployment Datacenter, former_category WEB_SPECIFIC_APPS, signature_severity Major, tag SQL_Injection, updated_at 2020_09_11;)<br/> | Contents: <br/>ContentsFormat: text<br/>Type: 3<br/>File: sensor7689Config.txt<br/>FileID: 8cca47a1-aef6-46c4-a372-8653f82abed0 |


### 16. analyst1-get-sensor-taskings

***
Queries the Analyst1 REST API for the current sensor taskings given a valid Sensor ID. This can be used to start subscription to an Sensor ID. The result gives the version (which can later be used to invoke 'diff') and all current taskings. Note: This operation may trigger XSOAR to "oversize" the task built on this automation. If so, you may need to turn off quiet mode explicitly. The analyst1-get-sensor-config can alternatively be used to get a simple text file of current indicators or signatures.

#### Base Command

`analyst1-get-sensor-taskings`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| sensor_id | Sensor ID number for this Analyst1 instance. | Required | 
| timeout | Overrides the XSOAR default of 10s for timeout. Default Analsyt1 app is 200s for this command. Caller may further override as required. Default is 200. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.SensorTaskings | unknown | Root JSON for processing all taskings data.  | 
| Analyst1.SensorTaskings.id | unknown | Sensor ID for this Taskings response. | 
| Analyst1.SensorTaskings.version | unknown | Current version of the Sensor. | 
| Analyst1.SensorTaskings.Indicators | unknown | Current array of Indicators tasked | 
| Analyst1.SensorTaskings.Rules | unknown | Current array of Signatures tasked | 


### 17. analyst1-get-sensor-diff

***
Gets the 'difference' from the last known Analyst1 Sensor version against the current. Returns all differences on the Sensor since the 'version' provided and includes the current version in the reply. Current version should be preserved to be used on next scheduled invocation.

#### Base Command

`analyst1-get-sensor-diff`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| sensor_id | ID# of the Sensor record in Analyst1. | Required | 
| version | Non zero version of the known Sensor. | Required | 
| timeout | Overrides the XSOAR default of 10s for timeout. Default Analsyt1 app is 200s for this command. Caller may further override as required. Default is 200. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Analyst1.SensorTaskings.ID | unknown | Sensor ID | 
| Analyst1.SensorTaskings.latestVersion | unknown | Current version of the Sensor. Meant to be saved and used on subsequent invocations to 'diff' to only get the latest changes. | 
| Analyst1.SensorTaskings.version | unknown | Version which was provided as an input to make this result set. | 
| Analyst1.SensorTaskings.IndicatorsAdded | unknown | Array of Indicators added between version and latestVersion. Type can be used to limit hash values for action. | 
| Analyst1.SensorTaskings.IndicatorsRemoved | unknown | Array of Indicators removed between version and latestVersion. Type can be used to limit hash values for action. | 
| Analyst1.SensorTaskings.RulesAdded | unknown | Array of Rules added between version and latestVersion. | 
| Analyst1.SensorTaskings.RulesRemoved | unknown | Array of Rules removed between version and latestVersion. | 

#### Command example

```!analyst1-get-sensor-diff sensor_id=7682 version=280```

#### Context Example

```json
{
    "Analyst1": {
        "SensorTaskings": {
            "IndicatorsAdded": [
                {
                    "category": "indicator",
                    "id": "2594990-SHA256",
                    "type": "File-SHA256",
                    "value": "267C9CF2597A23AD957C10553EAF1D8B1196700EAFE67C7999B2CDB4E41995AA"
                },
                {
                    "category": "indicator",
                    "id": 2916021,
                    "type": "Domain",
                    "value": "redacted.com"
                },
                {
                    "category": "indicator",
                    "id": 3083418,
                    "type": "IPv4",
                    "value": "redacted_ip_address"
                },
                {
                    "category": "indicator",
                    "id": 3166219,
                    "type": "IPv4",
                    "value": "redacted_ip_address"
                }
            ],
            "IndicatorsRemoved": [
                {
                    "category": "indicator",
                    "id": 1633777,
                    "type": "Domain",
                    "value": "redacted_domain.org"
                },
                {
                    "category": "indicator",
                    "id": 1748796,
                    "type": "Domain",
                    "value": "redacted_domain.com"
                },
                {
                    "category": "indicator",
                    "id": 3935921,
                    "type": "IPv4",
                    "value": "redacted_ip_address"
                }
            ],
            "RulesAdded": null,
            "RulesRemoved": null,
            "id": 7682,
            "latestVersion": 287,
            "version": 280
        }
    }
}
```

#### Human Readable Output

>### Results

>__No entries.__


### 18. analyst1-get-sensors

***
Queries the Analyst1 REST API to retrieve a list of registered sensors.

#### Base Command

`analyst1-get-sensors`

#### Input

| __Argument Name__ | Description | __Required__ |
| --- | --- | --- |
| page | page of Sensors to iterate. Default is 1. | Optional | 
| pageSize | size of each page of Sensors to iterate. Maximum 50. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!analyst1-get-sensors page=1 pageSize=50```

#### Context Example

```json
{
    "Analyst1": {
        "SensorList": [
            {
                "currentVersionNumber": 5,
                "id": 7680,
                "latestConfigVersionNumber": 5,
                "links": [
                    {
                        "href": "https://analyst1instance.domain/api/1_0/sensors/7680",
                        "rel": "details"
                    }
                ],
                "logicalLocation": null,
                "name": "Iterative Change",
                "org": null,
                "type": "OTHER_AUTO"
            },
            {
                "currentVersionNumber": 26,
                "id": 7681,
                "latestConfigVersionNumber": 26,
                "links": [
                    {
                        "href": "https://analyst1instance.domain/api/1_0/sensors/7681",
                        "rel": "details"
                    }
                ],
                "logicalLocation": null,
                "name": "Quick Config Check",
                "org": null,
                "type": "OTHER_AUTO"
            },
            {
                "currentVersionNumber": 2,
                "id": 7689,
                "latestConfigVersionNumber": 2,
                "links": [
                    {
                        "href": "https://analyst1instance.domain/api/1_0/sensors/7689",
                        "rel": "details"
                    }
                ],
                "logicalLocation": null,
                "name": "Barry - Test",
                "org": null,
                "type": "SNORT"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|currentVersionNumber|id|latestConfigVersionNumber|links|logicalLocation|name|org|type|
>|---|---|---|---|---|---|---|---|
>| 5 | 7680 | 5 | {'rel': 'details', 'href': 'https:<span>//</span>analyst1instance.domain/api/1_0/sensors/7680'} |  | Example IOCs 1 |  | OTHER_AUTO |
>| 26 | 7681 | 26 | {'rel': 'details', 'href': 'https:<span>//</span>analyst1instance.domain/api/1_0/sensors/7681'} |  | Example IOCS 2|  | OTHER_AUTO |
>| 2 | 7689 | 2 | {'rel': 'details', 'href': 'https:<span>//</span>analyst1instance.domain/api/1_0/sensors/7689'} |  | Example Signature |  | SNORT |

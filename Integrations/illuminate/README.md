Overview
---

Enriches Demisto indicators with illuminate REST API indicator data.
This integration was integrated and tested with version 1.8.7 of illuminate

Configure illuminate on Demisto
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

Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
| domain | The domain to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Domain.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Domain.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Domain.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Domain.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Domain.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Domain.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Domain.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Domain.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Domain.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Domain.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Domain.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Domain.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Domain.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Domain.IlluminateLink | string | The URL of the matched indicator in illuminate | 
| Illuminate.Domain.IpResolution | string | The resolved IP for this domain | 


##### Command Example
```!domain domain=domain```

### 2. email
---
Queries the illuminate REST API and enriches the given email with illuminate Indicator data
##### Base Command

`email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Email.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Email.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Email.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Email.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Email.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Email.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Email.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Email.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Email.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Email.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Email.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Email.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Email.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Email.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!email email=email```

### 3. ip
---
Queries the illuminate REST API and enriches the given IP with illuminate Indicator data
##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Ip.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Ip.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Ip.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Ip.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Ip.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Ip.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Ip.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Ip.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Ip.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Ip.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Ip.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Ip.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Ip.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Ip.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!ip ip=ip```

##### Human Readable Output


### 4. file
---
Queries the illuminate REST API and enriches the given file with illuminate Indicator data
##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.File.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.File.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.File.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.File.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.File.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.File.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.File.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.File.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.File.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.File.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.File.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.File.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.File.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.File.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!file file=file```

### 5. illuminate-enrich-string
---
Queries the illuminate REST API and enriches the given string with illuminate Indicator data
##### Base Command

`illuminate-enrich-string`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| string | The string to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.String.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.String.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.String.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.String.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.String.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.String.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.String.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.String.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.String.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.String.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.String.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.String.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.String.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.String.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!illuminate-enrich-string string=string```

### 6. illuminate-enrich-ipv6
---
Queries the illuminate REST API and enriches the given IP with illuminate Indicator data
##### Base Command

`illuminate-enrich-ipv6`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Ipv6.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Ipv6.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Ipv6.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Ipv6.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Ipv6.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Ipv6.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Ipv6.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Ipv6.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Ipv6.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Ipv6.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Ipv6.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Ipv6.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Ipv6.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Ipv6.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!illuminate-enrich-ipv6 ip=ip```

### 7. illuminate-enrich-mutex
---
Queries the illuminate REST API and enriches the given mutex with illuminate Indicator data
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
| Illuminate.Mutex.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Mutex.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Mutex.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Mutex.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Mutex.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Mutex.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Mutex.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Mutex.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Mutex.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Mutex.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Mutex.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Mutex.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Mutex.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!illuminate-enrich-mutex mutex=mutex```

### 8. illuminate-enrich-http-request
---
Queries the illuminate REST API and enriches the given HTTP request with illuminate Indicator data
##### Base Command

`illuminate-enrich-http-request`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| http-request | The HTTP request to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Httprequest.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Httprequest.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Httprequest.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Httprequest.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Httprequest.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Httprequest.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Httprequest.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Httprequest.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Httprequest.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Httprequest.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Httprequest.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Httprequest.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Httprequest.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Httprequest.IlluminateLink | string | The URL of the matched indicator in illuminate | 


##### Command Example
```!illuminate-enrich-http-request http-request=http-request```

### 9. url
---
Queries the illuminate REST API and enriches the given URL with illuminate Indicator data
##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The url to query information for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illuminate.Url.ID | number | The unique identifier of the given Indicator in illuminate | 
| Illuminate.Url.EvidenceCount | number | Number of evidence reports of the given Indicator in illuminate | 
| Illuminate.Url.Active | boolean | Whether or not the given indicator is noted as Active in illuminate | 
| Illuminate.Url.ConfidenceLevel | string | Confidence level in the data in illuminate | 
| Illuminate.Url.FirstHit | date | The first date this indicator was hit via illuminate | 
| Illuminate.Url.LastHit | date | The most recent date this indicator was hit via illuminate | 
| Illuminate.Url.HitCount | number | The total number of times this indicate was hit via illuminate | 
| Illuminate.Url.ReportedDates | date | The dates this indicator was reported on in illuminate | 
| Illuminate.Url.ActivityDates | date | The dates this indicator had reported activity in illuminate | 
| Illuminate.Url.Malwares.ID | number | Each matched malware unique identifier in illuminate | 
| Illuminate.Url.Malwares.Name | string | Each matched malware name in illuminate | 
| Illuminate.Url.Actors.ID | number | Each matched actor unique identifier in illuminate | 
| Illuminate.Url.Actors.Name | string | Each matched actor name in illuminate | 
| Illuminate.Url.IlluminateLink | string | The Url of the matched indicator in illuminate | 


##### Command Example
```!url url=url```

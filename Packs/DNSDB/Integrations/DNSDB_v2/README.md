# Farsight Security DNSDB

Farsight Security DNSDB® is the world’s largest DNS intelligence database that
provides a unique, fact-based, multifaceted view of the configuration of the
global Internet infrastructure. DNSDB leverages the richness of Farsight’s
Security Information Exchange (SIE) data-sharing platform and is engineered and
operated by leading DNS experts. Farsight collects Passive DNS data from its
global sensor array. It then filters and verifies the DNS transactions before
inserting them into the DNSDB, along with ICANN-sponsored zone file access
download data. The end result is the highest-quality and most comprehensive DNS
intelligence data service of its kind - with more than 100 billion DNS records
since 2010.

This integration uses Farsight Security’s DNSDB solution to interactively
lookup rich, historical DNS information – either as playbook tasks or through
API calls in the War Room – to access rdata and rrset records.  It was
integrated and tested with version 2 of the DNSDB API.

## Configure DNSDB v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DNSDB v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | True |
| url | DNSDB Service URL | False |
| insecure | Trust any certificate \(not secure\) | False |
| useproxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dnsdb-flex
***
DNSDB flex search


#### Base Command

`dnsdb-flex`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | query value type | Required | 
| key | search over rrnames or rdata | Required | 
| value | query regex or glob | Required | 
| rrtype | query rrtype | Optional | 
| limit | Limit the number of returned records | Optional | 
| time_first_before | Filter results for entries seen for first time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (ISO or UNIX timestamp, relative if negative) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Record.RRName | string | The owner name of the resource record in DNS presentation format. | 
| DNSDB.Record.RRType | string | The resource record type of the resource record, either using the standard DNS type mnemonic, or an RFC 3597 generic type, i.e. the string TYPE immediately followed by the decimal RRtype number.
 | 
| DNSDB.Record.RData | string | The record data value. The Rdata value is converted to the standard presentation format based on the rrtype value. If the encoder lacks a type-specific presentation format for the resource record's type, then the RFC 3597 generic Rdata encoding will be used.
 | 
| DNSDB.Record.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Record.TimeFirst | date | The first time that the resource record was observed. | 
| DNSDB.Record.TimeLast | date | The most recent time that the resource record was observed. | 
| DNSDB.Record.FromZoneFile | bool | False if the resource record was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
```!dnsdb-flex method=regex key=rrnames value=farsightsecurity limit=5```

#### Context Example
```json
{
    "DNSDB": {
        "Record": [
            {
                "FromZoneFile": false,
                "RRName": "farsightsecurity.yahoo.com.au",
                "RRType": "CNAME"
            },
            {
                "FromZoneFile": false,
                "RRName": "farsightsecurity-2432183.starbucks.com.cn",
                "RRType": "A"
            },
            {
                "FromZoneFile": false,
                "RRName": "farsightsecurity.com.cn",
                "RRType": "NS"
            },
            {
                "FromZoneFile": false,
                "RRName": "farsightsecurity.com.cn",
                "RRType": "SOA"
            },
            {
                "FromZoneFile": false,
                "RRName": "farsightsecurity.com.cn",
                "RRType": "CNAME"
            },
            {
                "FromZoneFile": false,
                "RRName": "www.farsightsecurity.com.cn",
                "RRType": "CNAME"
            },
            {
                "FromZoneFile": false,
                "RRName": "farsightsecurity.damai.cn",
                "RRType": "CNAME"
            }
        ]
    }
}
```

#### Human Readable Output

>### Farsight DNSDB Flex Search
>|RRName|RRType|Count|TimeFirst|TimeLast|
>|---|---|---|---|---|
>| farsightsecurity.yahoo.com.au | CNAME |  |  |  |
>| farsightsecurity-2432183.starbucks.com.cn | A |  |  |  |
>| farsightsecurity.com.cn | NS |  |  |  |
>| farsightsecurity.com.cn | SOA |  |  |  |
>| farsightsecurity.com.cn | CNAME |  |  |  |
>| www.farsightsecurity.com.cn | CNAME |  |  |  |
>| farsightsecurity.damai.cn | CNAME |  |  |  |


### dnsdb-rdata
***
Lookup RData records


#### Base Command

`dnsdb-rdata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Query type | Required | 
| value | Query value | Required | 
| rrtype | query rrtype | Optional | 
| limit | Limit the number of returned records | Optional | 
| time_first_before | Filter results for entries seen for first time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| offset | How many rows to offset in the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Record.RRName | string | The owner name of the resource record in DNS presentation format. | 
| DNSDB.Record.RRType | string | The resource record type of the resource record, either using the standard DNS type mnemonic, or an RFC 3597 generic type, i.e. the string TYPE immediately followed by the decimal RRtype number.
 | 
| DNSDB.Record.RData | string | The record data value. The Rdata value is converted to the standard presentation format based on the rrtype value. If the encoder lacks a type-specific presentation format for the resource record's type, then the RFC 3597 generic Rdata encoding will be used.
 | 
| DNSDB.Record.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Record.TimeFirst | date | The first time that the resource record was observed. | 
| DNSDB.Record.TimeLast | date | The most recent time that the resource record was observed. | 
| DNSDB.Record.FromZoneFile | bool | False if the resource record was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
```!dnsdb-rdata type=name value=www.farsightsecurity.com limit=5```

#### Context Example
```json
{
    "DNSDB": {
        "Record": [
            {
                "Count": 606,
                "FromZoneFile": false,
                "RData": [
                    "www.farsightsecurity.com."
                ],
                "RRName": "scout.dnsdb.info",
                "RRType": "CNAME",
                "TimeFirst": "2020-03-27T18:37:24Z",
                "TimeLast": "2020-10-21T18:11:47Z"
            },
            {
                "Count": 121,
                "FromZoneFile": false,
                "RData": [
                    "www.farsightsecurity.com."
                ],
                "RRName": "scout-beta.dnsdb.info",
                "RRType": "CNAME",
                "TimeFirst": "2020-08-20T22:52:29Z",
                "TimeLast": "2020-10-20T17:54:58Z"
            },
            {
                "Count": 546,
                "FromZoneFile": false,
                "RData": [
                    "www.farsightsecurity.com."
                ],
                "RRName": "81.64-26.140.160.66.in-addr.arpa",
                "RRType": "PTR",
                "TimeFirst": "2013-12-10T01:20:08Z",
                "TimeLast": "2020-10-10T15:47:19Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Farsight DNSDB Lookup
>|RRName|RRType|RData|Count|TimeFirst|TimeLast|FromZoneFile|
>|---|---|---|---|---|---|---|
>| scout.dnsdb.info | CNAME | www.farsightsecurity.com. | 606 | 2020-03-27T18:37:24Z | 2020-10-21T18:11:47Z | False |
>| scout-beta.dnsdb.info | CNAME | www.farsightsecurity.com. | 121 | 2020-08-20T22:52:29Z | 2020-10-20T17:54:58Z | False |
>| 81.64-26.140.160.66.in-addr.arpa | PTR | www.farsightsecurity.com. | 546 | 2013-12-10T01:20:08Z | 2020-10-10T15:47:19Z | False |


### dnsdb-summarize-rdata
***
Summarize RData records


#### Base Command

`dnsdb-summarize-rdata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Query type | Required | 
| value | Query value | Required | 
| rrtype | query rrtype | Optional | 
| limit | Limit the number of returned records | Optional | 
| time_first_before | Filter results for entries seen for first time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| max_count | Stop when the summary count is reached | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Summary.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.NumResults | number | The number of results \(resource records\) that would be returned from a Lookup. | 
| DNSDB.Summary.TimeFirst | date | The first time that the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.TimeLast | date | The most recent time that the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.ZoneTimeFirst | date | The first time that the resource record was observed in a zone file. | 
| DNSDB.Summary.ZoneTimeLast | date | The most recent time that the resource record was observed in a zone file. | 


#### Command Example
```!dnsdb-summarize-rdata type=name value=www.farsightsecurity.com limit=5```

#### Context Example
```json
{
    "DNSDB": {
        "Summary": {
            "Count": 1273,
            "FromZoneFile": false,
            "NumResults": 3,
            "TimeFirst": "2013-12-10T01:20:08Z",
            "TimeLast": "2020-10-21T18:11:47Z"
        }
    }
}
```

#### Human Readable Output

>### Farsight DNSDB Summarize
>|Count|NumResults|TimeFirst|TimeLast|
>|---|---|---|---|
>| 1273 | 3 | 2013-12-10T01:20:08Z | 2020-10-21T18:11:47Z |


### dnsdb-rrset
***
Lookup RRset records


#### Base Command

`dnsdb-rrset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner_name | Owner name to query | Required | 
| rrtype | rrtype value to query | Optional | 
| bailiwick | Bailiwick value to query | Optional | 
| limit | Limit the number of returned records | Optional | 
| time_first_before | Filter results for entries seen for first time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| offset | How many rows to offset in the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Record.RRName | string | The owner name of the RRset in DNS presentation format. | 
| DNSDB.Record.RRType | string | The resource record type of the RRset, either using the standard DNS type mnemonic, or an RFC 3597 generic type, i.e. the string TYPE immediately followed by the decimal RRtype number.
 | 
| DNSDB.Record.Bailiwick | string | The closest enclosing zone delegated to a nameserver which served the RRset, or the name of the zone containing the RRset if FromZoneFile is True.
 | 
| DNSDB.Record.RData | string | An array of one or more Rdata values. The Rdata values are converted to the standard presentation format based on the rrtype value. If the encoder lacks a type-specific presentation format for the RRset's rrtype, then the RFC 3597 generic Rdata encoding will be used.
 | 
| DNSDB.Record.Count | number | The number of times the RRset was observed via passive DNS replication. | 
| DNSDB.Record.TimeFirst | date | The first time that the RRset was observed. | 
| DNSDB.Record.TimeLast | date | The most recent time that the RRset was observed. | 
| DNSDB.Record.FromZoneFile | bool | False if the RRset was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
```!dnsdb-rrset owner_name=*.farsightsecurity.com type=NS limit=5```

#### Context Example
```json
{
    "DNSDB": {
        "Record": [
            {
                "Bailiwick": "com",
                "Count": 19,
                "FromZoneFile": true,
                "RData": [
                    "ns.lah1.vix.com.",
                    "ns1.isc-sns.net.",
                    "ns2.isc-sns.com.",
                    "ns3.isc-sns.info."
                ],
                "RRName": "farsightsecurity.com",
                "RRType": "NS",
                "TimeFirst": "2013-06-30T16:21:41Z",
                "TimeLast": "2013-07-18T16:22:47Z"
            },
            {
                "Bailiwick": "com",
                "Count": 157,
                "FromZoneFile": true,
                "RData": [
                    "ns.sjc1.vix.com.",
                    "ns.sql1.vix.com."
                ],
                "RRName": "farsightsecurity.com",
                "RRType": "NS",
                "TimeFirst": "2013-01-24T17:18:05Z",
                "TimeLast": "2013-06-29T16:19:01Z"
            },
            {
                "Bailiwick": "com",
                "Count": 1890,
                "FromZoneFile": true,
                "RData": [
                    "ns5.dnsmadeeasy.com.",
                    "ns6.dnsmadeeasy.com.",
                    "ns7.dnsmadeeasy.com."
                ],
                "RRName": "farsightsecurity.com",
                "RRType": "NS",
                "TimeFirst": "2013-07-19T16:22:00Z",
                "TimeLast": "2020-07-24T16:02:05Z"
            },
            {
                "Bailiwick": "farsightsecurity.com",
                "Count": 6350,
                "FromZoneFile": false,
                "RData": [
                    "66.160.140.81"
                ],
                "RRName": "farsightsecurity.com",
                "RRType": "A",
                "TimeFirst": "2013-09-25T15:37:03Z",
                "TimeLast": "2015-04-01T06:17:25Z"
            },
            {
                "Bailiwick": "farsightsecurity.com",
                "Count": 36770,
                "FromZoneFile": false,
                "RData": [
                    "104.244.13.104"
                ],
                "RRName": "farsightsecurity.com",
                "RRType": "A",
                "TimeFirst": "2015-04-01T14:17:52Z",
                "TimeLast": "2018-09-27T00:29:43Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Farsight DNSDB Lookup
>|RRName|RRType|Bailiwick|RData|Count|TimeFirst|TimeLast|FromZoneFile|
>|---|---|---|---|---|---|---|---|
>| farsightsecurity.com | NS | com | ns.lah1.vix.com.<br/>ns1.isc-sns.net.<br/>ns2.isc-sns.com.<br/>ns3.isc-sns.info. | 19 | 2013-06-30T16:21:41Z | 2013-07-18T16:22:47Z | True |
>| farsightsecurity.com | NS | com | ns.sjc1.vix.com.<br/>ns.sql1.vix.com. | 157 | 2013-01-24T17:18:05Z | 2013-06-29T16:19:01Z | True |
>| farsightsecurity.com | NS | com | ns5.dnsmadeeasy.com.<br/>ns6.dnsmadeeasy.com.<br/>ns7.dnsmadeeasy.com. | 1890 | 2013-07-19T16:22:00Z | 2020-07-24T16:02:05Z | True |
>| farsightsecurity.com | A | farsightsecurity.com | 66.160.140.81 | 6350 | 2013-09-25T15:37:03Z | 2015-04-01T06:17:25Z | False |
>| farsightsecurity.com | A | farsightsecurity.com | 104.244.13.104 | 36770 | 2015-04-01T14:17:52Z | 2018-09-27T00:29:43Z | False |


### dnsdb-summarize-rrset
***
Lookup RRset records


#### Base Command

`dnsdb-summarize-rrset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner_name | Owner name to query | Required | 
| rrtype | rrtype value to query | Optional | 
| bailiwick | Bailiwick value to query | Optional | 
| limit | Limit the number of returned records | Optional | 
| time_first_before | Filter results for entries seen for first time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (ISO or UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (ISO or UNIX timestamp, relative if negative) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| max_count | Stop when the summary count is reached | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Summary.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.NumResults | number | The number of results \(resource records\) that would be returned from a Lookup. | 
| DNSDB.Summary.TimeFirst | date | The first time that the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.TimeLast | date | The most recent time that the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.ZoneTimeFirst | date | The first time that the resource record was observed in a zone file. | 
| DNSDB.Summary.ZoneTimeLast | date | The most recent time that the resource record was observed in a zone file. | 


#### Command Example
```!dnsdb-summarize-rrset owner_name=*.farsightsecurity.com type=NS limit=5```

#### Context Example
```json
{
    "DNSDB": {
        "Summary": {
            "Count": 45186,
            "FromZoneFile": true,
            "NumResults": 5,
            "TimeFirst": "2013-01-24T17:18:05Z",
            "TimeLast": "2020-07-24T16:02:05Z"
        }
    }
}
```

#### Human Readable Output

>### Farsight DNSDB Summarize
>|Count|NumResults|TimeFirst|TimeLast|ZoneTimeFirst|ZoneTimeLast|
>|---|---|---|---|---|---|
>| 45186 | 5 | 2013-09-25T15:37:03Z | 2018-09-27T00:29:43Z | 2013-01-24T17:18:05Z | 2020-07-24T16:02:05Z |


### dnsdb-rate-limit
***
Retrieve service limits


#### Base Command

`dnsdb-rate-limit`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Rate.Limit | number | The maximum number of API lookups that may be performed. This is the initial quota. | 
| DNSDB.Rate.Unlimited | bool | True if there is no maximum number of API lookups that may be performed. | 
| DNSDB.Rate.Remaining | number | For time-based quotas: the remaining number of API lookups that may be performed until the reset time.
For block-based quotas: the remaining number of API lookups in the block quota.
 | 
| DNSDB.Rate.Reset | date | For time-based quotas: When the quota limit will be reset. Usually this is at 00:00 \(midnight\) UTC.
 | 
| DNSDB.Rate.NeverResets | bool | True for block-based quotas that do not reset. | 
| DNSDB.Rate.Expires | date | Only present for block-based quota. When the quota will expire. | 
| DNSDB.Rate.ResultsMax | number | The maximum number of results that can be returned by these lookup methods. This overrides a "limit" query parameter if provided. For example, if "?limit=20000" is appended to the URL path but results_max=1000 then only up to 1000 results will be returned.
 | 
| DNSDB.Rate.OffsetMax | number | The maximum value that the offset query parameter can be. If it is higher then an HTTP 416 "Requested Range Not Satisfiable" response code will be returned with message "Error: offset value greater than maximum allowed."
 | 
| DNSDB.Rate.OffsetNotAllowed | number | True if the offset parameter is not allowed for this API key, and similar 416 error will be generated. | 
| DNSDB.Rate.BurstSize | number | The maximum number of API lookups that may be performed within this burst_window number of seconds. | 
| DNSDB.Rate.BurstWindow | number | The number of seconds over which a burst of queries is measured. | 


#### Command Example
```!dnsdb-rate-limit```

#### Context Example
```json
{
    "DNSDB": {
        "Rate": {
            "Unlimited": true
        }
    }
}
```

#### Human Readable Output

>### Farsight DNSDB Service Limits
>|Unlimited|
>|---|
>| true |


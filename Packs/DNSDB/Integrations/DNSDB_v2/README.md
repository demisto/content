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
integrated and tested with version 1 of the DNSDB API.

## Configure DNSDB on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DNSDB.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | True |
| url | DNSDB Service URL | False |
| useproxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| time_first_before | Filter results for entries seen for first time before (UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (UNIX timestamp, relative if negative) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| offset | How many rows to offset (e.g. skip) in the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Record.RRName | string | The owner name of the resource record in DNS presentation format. | 
| DNSDB.Record.RRType | string | The resource record type of the resource record, either using the standard DNS type mnemonic, or an RFC 3597 generic type, i.e. the string TYPE immediately followed by the decimal RRtype number.
 | 
| DNSDB.Record.RData | string | The record data value. The Rdata value is converted to the standard presentation format based on the rrtype value. If the encoder lacks a type\-specific presentation format for the resource record's type, then the RFC 3597 generic Rdata encoding will be used.
 | 
| DNSDB.Record.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Record.TimeFirst | date | The first time that the resource record was observed. | 
| DNSDB.Record.TimeLast | date | The most recent time that the resource record was observed. | 
| DNSDB.Record.FromZoneFile | bool | False if the resource record was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
``` ```

#### Human Readable Output



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
| time_first_before | Filter results for entries seen for first time before (UNIX timestamp, relative if negative) | Optional | 
| time_last_before | Filter results for entries seen for last time before (UNIX timestamp, relative if negative) | Optional | 
| time_first_after | Filter results for entries seen for first time after (UNIX timestamp, relative if negative) | Optional | 
| time_last_after | Filter results for entries seen for last time after (UNIX timestamp, relative if negative) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| max_count | Stop when the summary count is reached | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Summary.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.NumResults | number | The number of results \(resource records\) that would be returned from a Lookup. | 
| DNSDB.Summary.TimeFirst | date | The first time that the resource record was observed. | 
| DNSDB.Summary.TimeLast | date | The most recent time that the resource record was observed. | 
| DNSDB.Summary.FromZoneFile | bool | False if the resource record was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
``` ```

#### Human Readable Output



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
| time_first_before | Filter results for entries seen for first time before (seconds) | Optional | 
| time_first_after | Filter results for entries seen for first time after (seconds) | Optional | 
| time_last_before | Filter results for entries seen for last time before (seconds) | Optional | 
| time_last_after | Filter results for entries seen for last time after (seconds) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| offset | How many rows to offset (e.g. skip) in the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Record.RRName | string | The owner name of the RRset in DNS presentation format. | 
| DNSDB.Record.RRType | string | The resource record type of the RRset, either using the standard DNS type mnemonic, or an RFC 3597 generic type, i.e. the string TYPE immediately followed by the decimal RRtype number.
 | 
| DNSDB.Record.Bailiwick | string | The closest enclosing zone delegated to a nameserver which served the RRset, or the name of the zone containing the RRset if FromZoneFile is True.
 | 
| DNSDB.Record.RData | string | An array of one or more Rdata values. The Rdata values are converted to the standard presentation format based on the rrtype value. If the encoder lacks a type\-specific presentation format for the RRset's rrtype, then the RFC 3597 generic Rdata encoding will be used.
 | 
| DNSDB.Record.Count | number | The number of times the RRset was observed via passive DNS replication. | 
| DNSDB.Record.TimeFirst | date | The first time that the RRset was observed. | 
| DNSDB.Record.TimeLast | date | The most recent time that the RRset was observed. | 
| DNSDB.Record.FromZoneFile | bool | False if the RRset was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
``` ```

#### Human Readable Output



### dnsdb-summarize-rrset
***
Lookup RRset records


#### Base Command

`dnsdb-summarize-rrset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | Owner name to query | Required | 
| rrtype | rrtype value to query | Optional | 
| bailiwick | Bailiwick value to query | Optional | 
| limit | Limit the number of returned records | Optional | 
| time_first_before | Filter results for entries seen for first time before (seconds) | Optional | 
| time_first_after | Filter results for entries seen for first time after (seconds) | Optional | 
| time_last_before | Filter results for entries seen for last time before (seconds) | Optional | 
| time_last_after | Filter results for entries seen for last time after (seconds) | Optional | 
| aggr | Aggregate identical RRsets | Optional | 
| max_count | Stop when the summary count is reached | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSDB.Summary.Count | number | The number of times the resource record was observed via passive DNS replication. | 
| DNSDB.Summary.NumResults | number | The number of results \(resource records\) that would be returned from a Lookup. | 
| DNSDB.Summary.TimeFirst | date | The first time that the resource record was observed. | 
| DNSDB.Summary.TimeLast | date | The most recent time that the resource record was observed. | 
| DNSDB.Summary.FromZoneFile | bool | False if the resource record was observed via passive DNS replication, True if by zone file import. | 


#### Command Example
``` ```

#### Human Readable Output



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
| DNSDB.Rate.Remaining | number | For time\-based quotas: the remaining number of API lookups that may be performed until the reset time.
For block\-based quotas: the remaining number of API lookups in the block quota.
 | 
| DNSDB.Rate.Reset | date | For time\-based quotas: When the quota limit will be reset. Usually this is at 00:00 \(midnight\) UTC.
 | 
| DNSDB.Rate.NeverResets | bool | True for block\-based quotas that do not reset. | 
| DNSDB.Rate.Expires | date | Only present for block\-based quota. When the quota will expire. | 
| DNSDB.Rate.ResultsMax | number | The maximum number of results that can be returned by these lookup methods. This overrides a "limit" query parameter if provided. For example, if "?limit=20000" is appended to the URL path but results\_max=1000 then only up to 1000 results will be returned.
 | 
| DNSDB.Rate.OffsetMax | number | The maximum value that the offset query parameter can be. If it is higher then an HTTP 416 "Requested Range Not Satisfiable" response code will be returned with message "Error: offset value greater than maximum allowed."
 | 
| DNSDB.Rate.OffsetNotAllowed | number | True if the offset parameter is not allowed for this API key, and similar 416 error will be generated. | 
| DNSDB.Rate.BurstSize | number | The maximum number of API lookups that may be performed within this burst\_window number of seconds. | 
| DNSDB.Rate.BurstWindow | number | The number of seconds over which a burst of queries is measured. | 


#### Command Example
``` ```

#### Human Readable Output



Use the Stairwell integration to enrich data in Cortex XSOAR using Stairwell's knowledge and perform automated variant discovery, file analysis, AI triage, network intelligence lookups, YARA hunting, and file intake. The generic ***file***, ***ip*** and ***domain*** commands return standard indicators with a DBotScore.

Not a customer and interested in signing up? You can request access [here](https://stairwell.com/contact/).

This integration replaces the deprecated **Stairwell Inception** integration. All `inception-*` commands are available as `stairwell-*` commands, and context paths moved from `Inception.*` to `Stairwell.*`.

## Generate the required API key

1. In the Stairwell web UI, generate an API/CLI token [here](https://app.stairwell.com/dashboard?open-modal=auth-token).
2. Copy the token for use in the integration configuration.


## Configure Stairwell in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| Source Reliability | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### file

***
Returns the Stairwell reputation of a file. The DBotScore comes from Stairwell's MalEval verdict. Malicious for PROBABILITY_VERY_HIGH and PROBABILITY_HIGH, suspicious for PROBABILITY_MEDIUM, good for PROBABILITY_LOW, unknown otherwise.

#### Base Command

`file`

#### Command example
```!file file=e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes (MD5, SHA1, or SHA256) to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 
| File.Name | String | The name of the file. | 
| File.Type | String | The MIME type or magic of the file. | 
| File.Tags | Unknown | The YARA rules the file matches. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | The MalEval verdict, severity and labels behind the malicious score. | 
| Stairwell.File.sha256 | String | The SHA256 hash of the file. | 
| Stairwell.File.md5 | String | The MD5 hash of the file. | 
| Stairwell.File.sha1 | String | The SHA1 hash of the file. | 
| Stairwell.File.name | String | The name of the file. | 
| Stairwell.File.size | Number | The size of the file in bytes. | 
| Stairwell.File.mimeType | String | The MIME type of the file. | 
| Stairwell.File.magic | String | The libmagic description of the file. | 
| Stairwell.File.malEval.probabilityBucket | String | The MalEval probability bucket, for example PROBABILITY_HIGH. | 
| Stairwell.File.malEval.severity | String | The MalEval severity, for example SEVERITY_HIGH. | 
| Stairwell.File.malEval.labels | Unknown | The MalEval labels, such as malware family names. | 
| Stairwell.File.yaraRuleMatches | Unknown | The names of the YARA rules the file matches. | 
| Stairwell.File.stairwellFirstSeenTime | Date | When Stairwell first saw the file. | 
| Stairwell.File.networkIndicators | Unknown | The IP addresses, hostnames and URLs extracted from the file. | 

### ip

***
Returns Stairwell network intelligence for an IP address. Stairwell holds no verdict for an IP, so the DBotScore is always unknown; the value is the ASN, geolocation, cloud provider and reverse DNS context.

#### Base Command

`ip`

#### Command example
```!ip ip=8.8.8.8```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | String | The IP address. | 
| IP.ASN | String | The autonomous system number the IP belongs to. | 
| IP.ASOwner | String | The holder of the IP's address prefix from WHOIS. | 
| IP.Geo.Country | String | The country of the IP address. | 
| IP.Geo.Description | String | The city and region of the IP address. | 
| IP.Hostname | String | A hostname that resolves to the IP address. | 
| IP.Tags | Unknown | Cloud provider, datacenter and VPN tags. | 
| Stairwell.IP.ip | String | The IP address. | 
| Stairwell.IP.asns | Unknown | The autonomous system numbers the IP belongs to. | 
| Stairwell.IP.cloudProvider | String | The cloud provider that owns the IP, if any. | 
| Stairwell.IP.isDatacenter | Boolean | Whether the IP is in a datacenter range. | 
| Stairwell.IP.isVpn | Boolean | Whether the IP is a known VPN exit. | 
| Stairwell.IP.geoLocation.country | String | The country code of the IP address. | 
| Stairwell.IP.geoLocation.countryName | String | The country name of the IP address. | 
| Stairwell.IP.geoLocation.city | String | The city of the IP address. | 
| Stairwell.IP.geoLocation.region | String | The region of the IP address. | 
| Stairwell.IP.subnetInfo.cidr | String | The network address of the IP's subnet. | 
| Stairwell.IP.subnetInfo.prefixLength | Number | The prefix length of the IP's subnet. | 
| Stairwell.IP.whoisOrganization | String | The holder of the IP's address prefix from WHOIS. | 
| Stairwell.IP.hostnames | Unknown | The hostnames that resolve to the IP address. | 

### domain

***
Returns Stairwell hostname intelligence for a domain. A hostname on Stairwell's whitelist scores good; any other scores unknown, as Stairwell holds no malicious verdict for a hostname. Includes the DNS resolution history.

#### Base Command

`domain`

#### Command example
```!domain domain=example.com```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | String | The domain name. | 
| Domain.DNS | String | The IP addresses the domain resolves to. | 
| Domain.Tags | Unknown | Whether Stairwell whitelists the domain. | 
| Stairwell.Domain.hostname | String | The hostname. | 
| Stairwell.Domain.etldPlusOne | String | The effective top-level domain plus one of the hostname. | 
| Stairwell.Domain.whitelisted | Boolean | Whether Stairwell lists the hostname as known-good. | 
| Stairwell.Domain.resolutions.recordType | String | The DNS record type of the resolution. | 
| Stairwell.Domain.resolutions.answer | String | The DNS answer of the resolution. | 
| Stairwell.Domain.resolutions.firstSeen | Date | When the resolution was first seen. | 
| Stairwell.Domain.resolutions.lastSeen | Date | When the resolution was last seen. | 
| Stairwell.Domain.resolutions.observationCount | Number | How many times the resolution was observed. | 

### stairwell-variant-discovery

***
Discovers file variants using a SHA256 hash.

#### Base Command

`stairwell-variant-discovery`

#### Command example
```!stairwell-variant-discovery sha256=e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The SHA256 hash of the file. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Variants.sha256 | String | The SHA256 hash that was queried. | 
| Stairwell.Variants.variants | Unknown | The variant files discovered, each with a hash and similarity score. | 

### stairwell-file-enrichment

***
Enriches file details using a file hash (MD5, SHA1, or SHA256).

#### Base Command

`stairwell-file-enrichment`

#### Command example
```!stairwell-file-enrichment file_hash=9fe1ac46f0cdebf03156a6232d771c14559f8daf```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | The file hash (MD5, SHA1, or SHA256) to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.File_Details.sha256 | String | The SHA256 hash of the file. | 
| Stairwell.File_Details.summary.md5 | String | The MD5 hash of the file. | 
| Stairwell.File_Details.summary.sha256 | String | The SHA256 hash of the file. | 
| Stairwell.File_Details.summary.filenames | Unknown | The file names and paths the file was seen with. | 
| Stairwell.File_Details.summary.seen_assets_count | Number | The number of assets on which the file was seen, across all environments. | 
| Stairwell.File_Details.summary.seen_environments.environment_id | String | The ID of an environment in which the file was seen. | 
| Stairwell.File_Details.summary.seen_environments.environment_name | String | The name of an environment in which the file was seen. | 
| Stairwell.File_Details.summary.seen_environments.asset_count | Number | The number of assets in that environment on which the file was seen. | 
| Stairwell.File_Details.summary.seen_environments.assets.id | String | The ID of an asset on which the file was seen. | 
| Stairwell.File_Details.summary.seen_environments.assets.name | String | The name of an asset on which the file was seen. | 
| Stairwell.File_Details.raw | Unknown | The full file reputation response. | 

### stairwell-intake-upload

***
Uploads a file from a War Room entry or a URL to Stairwell for analysis. The file is stored in your Stairwell environment under the given asset. Provide exactly one of entry_id or url. A failed upload returns an error entry.

#### Base Command

`stairwell-intake-upload`

#### Command example
```!stairwell-intake-upload asset_id=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 entry_id=${File.EntryID}```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset to upload the file to. | Required | 
| entry_id | The entry ID of the file from the War Room. | Optional | 
| url | The HTTP or HTTPS URL to download the file from. The host must resolve to a public address, redirects are not followed, and the download is limited to 256 MB. | Optional | 
| sha256 | The SHA256 hash of the file. If not provided, it will be calculated automatically. | Optional | 
| origin_type | The origin type of the file. Can be web or unspecified. Possible values are: web, unspecified. | Optional | 
| origin_referrer_url | The HTTP referrer URL for the file origin. | Optional | 
| origin_host_url | The original host URL for the file origin. | Optional | 
| origin_zone_id | The zone ID (integer) for the file origin. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Intake.sha256 | String | The SHA256 hash of the file. | 
| Stairwell.Intake.result | String | The intake outcome, either uploaded or already_exists. | 
| Stairwell.Intake.upload_status | Number | The HTTP status code returned by the upload. Absent when the file already existed. | 
| Stairwell.Intake.preflight | Unknown | The preflight response from the Stairwell Intake API. | 

### stairwell-object-sightings

***
Lists all sightings for an object across the organization's assets.

#### Base Command

`stairwell-object-sightings`

#### Command example
```!stairwell-object-sightings object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The SHA256 hash or object ID of the object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Sightings.objectId | String | The object ID that was queried. | 
| Stairwell.Sightings.objectSightings | Unknown | The sightings of the object across assets. | 

### stairwell-object-opinions

***
Lists threat intelligence opinions for an object.

#### Base Command

`stairwell-object-opinions`

#### Command example
```!stairwell-object-opinions object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The SHA256 hash or object ID of the object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Opinions | Dictionary | Opinions for the object. | 

### stairwell-run-to-ground-generate

***
Generates a run-to-ground analysis for one or more objects.

#### Base Command

`stairwell-run-to-ground-generate`

#### Command example
```!stairwell-run-to-ground-generate object_ids=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283,e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | A comma-separated list of object IDs or SHA256 hashes. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.RunToGround | Dictionary | Run-to-ground analysis results. | 

### stairwell-ai-triage-summarize

***
Gets an AI-generated summary for a file using Stairwell AI triage.

#### Base Command

`stairwell-ai-triage-summarize`

#### Command example
```!stairwell-ai-triage-summarize object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The SHA256 hash or object ID of the object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.AI_Triage.hash | String | The hash of the analyzed file. | 
| Stairwell.AI_Triage.malicious_likelihood | Number | The likelihood \(0-100\) that the file is malicious. | 
| Stairwell.AI_Triage.confidence | Number | The confidence \(0-100\) of the assessment. | 
| Stairwell.AI_Triage.threat_type | String | The threat type classification. | 
| Stairwell.AI_Triage.tldr | String | The short summary of the analysis. | 
| Stairwell.AI_Triage.summary_points | Unknown | The key findings of the analysis, one sentence each. | 
| Stairwell.AI_Triage.iocs | Unknown | The indicators of compromise extracted from the file, grouped by kind \(URLs, file paths, registry keys, IP addresses, other\). | 
| Stairwell.AI_Triage.raw | Unknown | The full AI triage response, with the report as markdown under summary and its structured form under summaryJson. | 

### stairwell-asn-get-whois

***
Gets WHOIS information for an ASN.

#### Base Command

`stairwell-asn-get-whois`

#### Command example
```!stairwell-asn-get-whois asn=15169```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asn | The ASN number to query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.ASN.WHOIS | Dictionary | ASN WHOIS information. | 

### stairwell-hostname-get

***
Gets a hostname entity with DNS resolution data.

#### Base Command

`stairwell-hostname-get`

#### Command example
```!stairwell-hostname-get hostname=google.com record_type=A```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname to look up. | Required | 
| record_type | The DNS record type to filter by. Can be A, AAAA, or MX. Possible values are: A, AAAA, MX. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Hostname | Dictionary | Hostname entity with DNS resolution data. | 

### stairwell-hostname-get-resolutions

***
Gets all IP addresses resolved to by a hostname over a time range.

#### Base Command

`stairwell-hostname-get-resolutions`

#### Command example
```!stairwell-hostname-get-resolutions hostname=www.google.com```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname to look up. | Required | 
| start_time | The start time of the resolution range in ISO 8601 format. | Optional | 
| end_time | The end time of the resolution range in ISO 8601 format. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Hostname.Resolutions | Dictionary | Hostname resolution history. | 

### stairwell-hostname-batch-get-resolutions

***
Gets DNS resolution summaries for multiple hostnames.

#### Base Command

`stairwell-hostname-batch-get-resolutions`

#### Command example
```!stairwell-hostname-batch-get-resolutions hostnames=www.google.com,www.stairwell.com```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostnames | A comma-separated list of hostnames. | Required | 
| start_time | The start time of the resolution range in ISO 8601 format. | Optional | 
| end_time | The end time of the resolution range in ISO 8601 format. | Optional | 
| record_types | A comma-separated list of DNS record types (A, AAAA, or MX). | Optional | 
| include_errors | Whether to include DNS error responses in the results. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Hostname.BatchResolutions | Dictionary | Batch hostname resolution summaries. | 

### stairwell-ipaddress-get

***
Gets an IP address entity with enrichment data.

#### Base Command

`stairwell-ipaddress-get`

#### Command example
```!stairwell-ipaddress-get ip_address=8.8.8.8```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress | Dictionary | IP address entity with enrichment data. | 

### stairwell-ipaddress-lookup-cloud-provider

***
Checks whether an IP address belongs to a known cloud provider.

#### Base Command

`stairwell-ipaddress-lookup-cloud-provider`

#### Command example
```!stairwell-ipaddress-lookup-cloud-provider ip_address=8.8.8.8```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.CloudProvider | Dictionary | Cloud provider lookup results. | 

### stairwell-ipaddress-get-hostnames-resolving-to-ip

***
Gets all hostnames that resolved to an IP address over a time interval.

#### Base Command

`stairwell-ipaddress-get-hostnames-resolving-to-ip`

#### Command example
```!stairwell-ipaddress-get-hostnames-resolving-to-ip ip_address=104.26.12.236```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address to look up. | Required | 
| start_time | The start time of the resolution range in ISO 8601 format. | Optional | 
| end_time | The end time of the resolution range in ISO 8601 format. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.Hostnames | Dictionary | Hostnames that resolved to the IP address. | 

### stairwell-ipaddress-get-whois

***
Gets WHOIS information for an IP address.

#### Base Command

`stairwell-ipaddress-get-whois`

#### Command example
```!stairwell-ipaddress-get-whois ip_address=8.8.8.8```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.WHOIS | Dictionary | IP address WHOIS information. | 

### stairwell-utilities-get-cloud-ip-ranges

***
Gets IP address ranges for known cloud providers.

#### Base Command

`stairwell-utilities-get-cloud-ip-ranges`

#### Command example
```!stairwell-utilities-get-cloud-ip-ranges provider=AWS```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider | The cloud provider name to filter by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CloudIPRanges | Dictionary | Cloud provider IP address ranges. | 

### stairwell-utilities-batch-canonicalize-hostnames

***
Canonicalizes multiple hostnames in bulk.

#### Base Command

`stairwell-utilities-batch-canonicalize-hostnames`

#### Command example
```!stairwell-utilities-batch-canonicalize-hostnames hostnames=EXAMPLE.COM,WWW.TEST.COM```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostnames | A comma-separated list of hostnames to canonicalize. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedHostnames | Dictionary | Canonicalized hostnames. | 

### stairwell-utilities-batch-compute-etld-plus-one

***
Computes the effective top-level domain plus one for multiple domains.

#### Base Command

`stairwell-utilities-batch-compute-etld-plus-one`

#### Command example
```!stairwell-utilities-batch-compute-etld-plus-one domains=subdomain.example.com,www.test.co.uk```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | A comma-separated list of domains. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.ETLDPlusOne | Dictionary | eTLD\+1 results. | 

### stairwell-utilities-canonicalize-hostname

***
Canonicalizes a single hostname.

#### Base Command

`stairwell-utilities-canonicalize-hostname`

#### Command example
```!stairwell-utilities-canonicalize-hostname hostname=EXAMPLE.COM```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname to canonicalize. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedHostname | Dictionary | Canonicalized hostname. | 

### stairwell-utilities-compute-etld-plus-one

***
Computes the effective top-level domain plus one for a single domain.

#### Base Command

`stairwell-utilities-compute-etld-plus-one`

#### Command example
```!stairwell-utilities-compute-etld-plus-one domain=subdomain.example.com```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to compute the effective top-level domain plus one for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.ETLDPlusOne | Dictionary | eTLD\+1 result. | 

### stairwell-utilities-batch-canonicalize-urls

***
Canonicalizes multiple URLs in bulk.

#### Base Command

`stairwell-utilities-batch-canonicalize-urls`

#### Command example
```!stairwell-utilities-batch-canonicalize-urls urls=https://EXAMPLE.COM/PATH,http://TEST.COM/```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | A comma-separated list of URLs to canonicalize. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedURLs | Dictionary | Canonicalized URLs. | 

### stairwell-utilities-canonicalize-url

***
Canonicalizes a single URL.

#### Base Command

`stairwell-utilities-canonicalize-url`

#### Command example
```!stairwell-utilities-canonicalize-url url=https://EXAMPLE.COM/PATH```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to canonicalize. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedURL | Dictionary | Canonicalized URL. | 

### stairwell-yara-create-rule

***
Creates a new YARA rule in the specified environment. The rule is saved to your Stairwell environment and starts matching files. Multi-line rules must be wrapped in backticks.

#### Base Command

`stairwell-yara-create-rule`

#### Command example
```!stairwell-yara-create-rule environment=YOUR_ENV_ID rule_definition="rule simple_rule { condition: true }"```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | The ID of the environment. | Required | 
| rule_definition | The YARA rule definition text. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.YaraRule | Dictionary | Created YARA rule. | 

### stairwell-yara-get-rule

***
Gets a YARA rule by ID.

#### Base Command

`stairwell-yara-get-rule`

#### Command example
```!stairwell-yara-get-rule environment=YOUR_ENV_ID yara_rule=YOUR_RULE_ID```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | The ID of the environment. | Required | 
| yara_rule | The ID of the YARA rule. | Required | 
| match_count_envs | A comma-separated list of environment IDs to include in match counts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.YaraRule | Dictionary | YARA rule details. | 

### stairwell-yara-query-matches

***
Queries objects that match a YARA rule.

#### Base Command

`stairwell-yara-query-matches`

#### Command example
```!stairwell-yara-query-matches environment=YOUR_ENV_ID yara_rule=YOUR_RULE_ID```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | The ID of the environment. | Required | 
| yara_rule | The ID of the YARA rule. | Required | 
| included_environments | A comma-separated list of environment IDs to search. | Optional | 
| page_size | The maximum number of matches to return. | Optional | 
| page_token | The token for pagination. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.YaraRuleMatches | Dictionary | Objects matching the YARA rule. | 

### stairwell-asset-list

***
Lists all assets in the specified environment.

#### Base Command

`stairwell-asset-list`

#### Command example
```!stairwell-asset-list environment=BJJKNH-MCGB8F-WAED6B-3ELG8CPJ```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | The ID of the environment. | Required | 
| page_size | The maximum number of assets to return. | Optional | 
| page_token | The token for pagination. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Assets | Dictionary | List of assets. | 

### stairwell-asset-create

***
Creates a new asset in the specified environment. The asset's upload token is a credential and is not returned; retrieve it from the Stairwell web UI.

#### Base Command

`stairwell-asset-create`

#### Command example
```!stairwell-asset-create environment=BJJKNH-MCGB8F-WAED6B-3ELG8CPJ label=xSOAR```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | The ID of the environment. | Required | 
| label | The human-readable label for the asset, typically the hostname. | Required | 
| idempotency_key | The client-generated key for idempotent asset creation. Generated when not provided. | Optional | 
| os | The operating system of the asset. Can be Windows, macOS, or Linux. Possible values are: Windows, macOS, Linux. | Optional | 
| os_version | The operating system version string. | Optional | 
| forwarder_version | The forwarder version string. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Asset.name | String | The resource name of the created asset, in the form assets/ID. | 
| Stairwell.Asset.label | String | The label of the created asset. | 

### stairwell-asset-get

***
Gets a specific asset by ID. The asset's upload token is a credential and is not returned.

#### Base Command

`stairwell-asset-get`

#### Command example
```!stairwell-asset-get asset=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset | The ID of the asset. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Asset.name | String | The resource name of the asset, in the form assets/ID. | 
| Stairwell.Asset.label | String | The label of the asset. | 

## Additional Information

### Integration Features

- **Automatic retry logic** with exponential backoff for transient failures
- **HTTP timeout management** (120s for API calls, 600s for uploads)
- **Streaming downloads** for large files (1MB chunks)
- **SSL/TLS verification** (configurable)
- **Proxy support** (respects XSOAR system proxy settings)
- **Automatic temp file cleanup** prevents accumulation

### Common Workflows

**File Analysis Workflow:**

1. Enrich file using hash → `stairwell-file-enrichment`
2. Discover variants → `stairwell-variant-discovery`
3. Get AI analysis → `stairwell-ai-triage-summarize`
4. Check sightings → `stairwell-object-sightings`

**File Upload & Analysis Workflow:**

1. Upload file from War Room → `stairwell-intake-upload entry_id=${File.EntryID}`
2. Wait for processing (files are analyzed automatically)
3. Query for matches → `stairwell-yara-query-matches`
4. Generate Run-To-Ground → `stairwell-run-to-ground-generate`

**Threat Hunting Workflow:**

1. Create YARA rule → `stairwell-yara-create-rule`
2. Query matches → `stairwell-yara-query-matches`
3. Analyze each match → `stairwell-file-enrichment`
4. Check sightings → `stairwell-object-sightings`
5. Investigate with Run-To-Ground → `stairwell-run-to-ground-generate`

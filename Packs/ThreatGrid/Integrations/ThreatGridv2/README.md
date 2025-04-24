Query and upload samples to Cisco threat grid.
This integration was integrated and tested with version 2 of Cisco Secure Malware Analytics (Threat Grid)

## Configure Cisco Secure Malware Analytics (Threat Grid) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://192.168.0.1) |  | True |
| API token |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### threat-grid-sample-list
***
Search samples on the Threat Grid platform. Input parameters are ANDed together. Only finished samples can be searched (that is, the ones that are having a status of succ or fail.)


#### Base Command

`threat-grid-sample-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | The sample ID. | Optional |
| artifact | The artifact to download. Sample ID is required when choosing 'artifact'. Possible values are: video.webm, network-artifacts.zip, report.html, sample.zip, screenshot.png, extracted-artifacts.zip, timeline.json, analysis.json, processes.json, network.pcap. | Optional |
| sha1 | A sha1 of the submitted sample, only matches samples, not their artifacts. | Optional |
| sha256 | A SHA256 of the submitted sample, only matches samples, not their artifacts. | Optional |
| md5 | A MD5 checksum of the submitted sample, only matches samples, not their artifacts. | Optional |
| user_only | It 'True' - Only display samples created by the current user, as determined by the value of api_key. | Optional |
| org_only | It 'True' - Only display samples created by the current user's organization, as determined by the value of api_key. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.id | String | The sample id |
| ThreatGrid.Sample.filename | String | The sample filename |
| ThreatGrid.Sample.state | String | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" |
| ThreatGrid.Sample.status | String | The sample status, one of a stable set of strings "succ, fail" |
| ThreatGrid.Sample.md5 | String | The sample md5 |
| ThreatGrid.Sample.sha1 | String | The sample sha1 |
| ThreatGrid.Sample.sha256 | String | The sample sha256 |
| ThreatGrid.Sample.os | String | The sample os |
| ThreatGrid.Sample.submitted_at | String | The sample submission time |
| ThreatGrid.Sample.started_at | String | The sample analysis starting time |
| ThreatGrid.Sample.completed_at | String | The sample completion time |
| InfoFile.Name | String | The file name |
| InfoFile.EntryID | String |  The ID for locating the file in the War Room |
| InfoFile.Size | String |  The size of the file (in bytes) |
| InfoFile.Type | String |  The file type, as determined by libmagic (same as displayed in file entries) |
| InfoFile.Extension | String |  The file extension |
| InfoFile.Info | String |  Basic information about the file |

#### Command example
```!threat-grid-sample-list```
#### Context Example
```json
{
    "ThreatGrid": {
        "Sample": [
            {
                "completed_at": "ThreatGrid_Sample[0]_completed_at",
                "filename": "md5",
                "id": "id",
                "md5": "md5",
                "os": "os",
                "sha1": "sha1",
                "sha256": "sha256",
                "started_at": "ThreatGrid_Sample[0]_started_at",
                "state": "succ",
                "status": "job_done",
                "submission_id": 1538519424,
                "submitted_at": "ThreatGrid_Sample[0]_submitted_at",
                "tags": [],
                "vm": "win7-x64"
            },
            {
                "completed_at": "ThreatGrid_Sample[1]_completed_at",
                "filename": "sha256",
                "id": "id",
                "md5": "md5",
                "os": "os",
                "sha1": "sha1",
                "sha256": "sha256",
                "started_at": "ThreatGrid_Sample[1]_started_at",
                "state": "succ",
                "status": "job_done",
                "submission_id": 1531508494,
                "submitted_at": "ThreatGrid_Sample[1]_submitted_at",
                "tags": [
                    "s",
                    "talos",
                    "gravity"
                ],
                "vm": "win7-x64"
            },
        ]
    }
}
```

#### Human Readable Output

>### Sample details:
>|Completed At|Filename|Id|Md5|Os|Sha1|Sha256|Started At|State|Status|Submission Id|Submitted At|Tags|Vm|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-12-05T04:17:00Z | md5 | id | md5 | os | sha1 | sha256 | 2022-12-05T04:10:44Z | succ | job_done | 1538519424 | 2022-12-05T04:10:44Z |  | win7-x64 |
>| 2022-11-24T01:04:39Z | sha256 | id | md5 | os | sha1 | sha256 | 2022-11-24T00:58:22Z | succ | job_done | 1531508494 | 2022-11-24T00:58:22Z | s, <br/> talos, <br/> gravity | win7-x64 |



### threat-grid-sample-upload
***
Submits a sample to threat grid for analysis. URL or file, not both.


#### Base Command

`threat-grid-sample-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The file ID. Click on the chain-like icon after you upload a file in d__ to find the file_id. | Optional |
| url | The URL to upload. . | Optional |
| interval_in_seconds | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 10. Default is 10. | Optional |
| timeout_in_seconds | Indicates the time in seconds until the polling sequence timeouts. Default is 60. Default is 60. | Optional |
| sample_id | The uploaded sample ID. | Optional |
| private | Whether to mark the sample as private. | Optional |
| hide_polling_output | Whether to hide the polling result (automatically filled by polling). | Optional |
| vm | a string identifying a specific VM to use. Options: win7-x64: Windows 7 64bit, win7-x64-2: Windows 7 64-bit Profile 2, win10-x64-2-beta: Windows 10 LTSC 2019 (beta), win10-x64-browser: Windows 10 Browser, win10-x64-jp: Windows 10 Japanese, win10-x64-kr: Windows 10 Korean, win10-x64-phishing-beta: Windows 10 (Phishing), win10: Windows 10 (Not available on Threat Grid appliances). NOTE: The standard (English) VMs default to UTF-8 encoding. To support Korean and Japanese character sets, such as S-JIS, submit to the appropriate VM. | Optional |
| playbook | Name of a playbook to apply to this sample run. none: Explicitly disables playbooks, default: Default Playbook, alt_tab_programs: Conduct Active Window Change, open_word_embedded_object: Open Embedded Object in Word Document, use_best_option: allows Malware Analytics to select the best Playbook option based on the submitted sample, visit_site: Visit Website Using Internet Explorer, close_file: Close Active Window. The current list of playbooks endpoints can be obtained by querying /api/v3/configuration/playbooks. | Optional |



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.id | String | The sample id |
| ThreatGrid.Sample.filename | String | The sample filename |
| ThreatGrid.Sample.state | String | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" |
| ThreatGrid.Sample.status | String | The sample status |
| ThreatGrid.Sample.md5 | String | The sample md5 |
| ThreatGrid.Sample.sha1 | String | The sample sha1 |
| ThreatGrid.Sample.sha256 | String | The sample sha256 |
| ThreatGrid.Sample.os | String | The sample os |
| ThreatGrid.Sample.submitted_at | String | The sample submission time |

#### Command example
```!threat-grid-sample-upload url=http://domain_example:80/ private=True```
#### Human Readable Output

>Upload sample is executing

### threat-grid-submissions-search
***
Search threat grid submissions


#### Base Command

`threat-grid-submissions-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query text. If you wish to work with an elasticsearch query please set 'advanced' argument to true. | Optional |
| user_only | Only display submissions created by the current user, as determined by the value of api_key. Possible values are: True, False. | Optional |
| org_only | Only display submissions created by the current user's organization, as determined by the value of api_key. Possible values are: True, False. | Optional |
| term | Restrict matches to a subset of submission fields. The value of 'term' is a comma-delimited list of strings which select groups of fields. Possible values are: antivirus, analysis.artifacts.av_signatures.product, analysis.artifacts.av_signatures.signature, behavior, analysis.behaviors.name, analysis.behaviors.title, analysis.artifacts.av_signatures.signature, domain, analysis.domains.domain, analysis.domains.domain.component, mutant, analysis.processes.mutants, analysis.processes.mutants.whole, analysis.processes.mutants.component, path, filename, analysis.paths.path, analysis.paths.path.whole, analysis.processes.paths, process, analysis.processes.process_name, analysis.processes.startup_info.command_line, analysis.processes.startup_info.image_pathname, analysis.processes.startup_info.window_title, registry_key, analysis.registry_keys.key, analysis.registry_keys.key.whole, analysis.registry_keys.key.component, analysis.processes.registry_keys, analysis.processes.registry_keys.whole, analysis.registry_keys.value_names, sample, filename, url, analysis.urls.url, analysis.urls.url.whole.. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| state | Restrict match to submissions in specific state or states. Possible values are: wait, prep, run, proc, succ, fail. | Optional |
| sort_by | If not specified, results will be sorted by the search score, which is based on which fields match the query most accurately, and their weight. Possible values are: timestamp, submitted_at, analyzed_at, filename, type, state, threat or threat_score, login. | Optional |
| sort_order | desc or asc. Possible values are: desc, asc. | Optional |
| highlight | Provide a 'matches' field in results, indicating which fields were matched. Possible values are: True, False. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Sample.sample | String | The sample ID |
| ThreatGrid.Sample.filename | String | The name of the sample file |
| ThreatGrid.Sample.state | String | The state of the sample, one of a stable set of strings "wait, prep, run, proc, succ, fail" |
| ThreatGrid.Sample.status | String | The status of the sample |
| ThreatGrid.Sample.md5 | String | The MD5 id of the sample |
| ThreatGrid.Sample.sha1 | String | The SHA1 id of the sample |
| ThreatGrid.Sample.sha256 | String | The SHA256 id of the sample |
| ThreatGrid.Sample.submitted_at | Date | Time of submission for the sample |
| ThreatGrid.Sample.threat_score | Number | The threat score of the sample |

#### Command example
```!threat-grid-submissions-search```
#### Context Example
```json
{
    "ThreatGrid": {
        "Sample": [
            {
                "filename": "md5",
                "md5": "md5",
                "private": false,
                "sample": "sample",
                "sha1": "sha1",
                "sha256": "sha256",
                "state": "wait",
                "status": "pending",
                "submitted_at": "ThreatGrid_Sample[0]_submitted_at"
            },
            {
                "filename": "md5",
                "md5": "md5",
                "private": false,
                "sample": "sample",
                "sha1": "sha1",
                "sha256": "sha256",
                "state": "wait",
                "status": "pending",
                "submitted_at": "ThreatGrid_Sample[1]_submitted_at"
            },
        ]
    }
}
```

#### Human Readable Output

>### Samples Submissed :
> Showing page 1.
> Current page size: 50
>|Filename|Md5|Private|Sample|Sha1|Sha256|State|Status|Submitted At|
>|---|---|---|---|---|---|---|---|---|
>| md5 | md5 | false | sample | sha1 | sha256 | wait | pending | 2022-12-22T08:40:47Z |
>| md5 | md5 | false | sample | sha1 | sha256 | wait | pending | 2022-12-22T08:40:47Z |


### threat-grid-sample-summary-get
***
Returns summary analysis information


#### Base Command

`threat-grid-sample-summary-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | The sample id. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.SampleAnalysisSummary.sample | String | The sample ID. |
| ThreatGrid.SampleAnalysisSummary.registry_count | Number | The registry count of the sample. |
| ThreatGrid.SampleAnalysisSummary.filename | String | The Filename of the sample. |
| ThreatGrid.SampleAnalysisSummary.sha256 | String | The SHA256 hash of the sample. |
| ThreatGrid.SampleAnalysisSummary.magic_type | String | The sample type. |
| ThreatGrid.SampleAnalysisSummary.first_seen | Date | The timestamp when the sample was first seen. |
| ThreatGrid.SampleAnalysisSummary.last_seen | Date | The timestamp when the sample was last seen. |

#### Command example
```!threat-grid-sample-summary-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "SampleAnalysisSummary": {
            "artifacts": {
                "disk": 6,
                "memory": 9,
                "network": 1
            },
            "filename": "www.domain_example_.url",
            "first_seen": "ThreatGrid_SampleAnalysisSummary_first_seen",
            "iocs": [
                {
                    "category": [
                        "static-anomaly"
                    ],
                    "confidence": 100,
                    "ioc": "html-small-file-redirect",
                    "score": 50,
                    "severity": 50,
                    "tags": [
                        "html",
                        "redirect"
                    ]
                },
                {
                    "category": [
                        "network-information"
                    ],
                    "confidence": 50,
                    "ioc": "http-response-redirect",
                    "score": 25,
                    "severity": 50,
                    "tags": [
                        "network",
                        "http",
                        "redirect"
                    ]
                },
                {
                    "category": [
                        "domain"
                    ],
                    "confidence": 95,
                    "ioc": "network-only-safe-domains-contacted",
                    "score": 19,
                    "severity": 20,
                    "tags": [
                        "umbrella",
                        "dns"
                    ]
                },
                {
                    "category": [
                        "network-information"
                    ],
                    "confidence": 25,
                    "ioc": "network-communications-http-get-url",
                    "score": 6,
                    "severity": 25,
                    "tags": [
                        "network",
                        "http",
                        "get"
                    ]
                }
            ],
            "last_seen": "ThreatGrid_SampleAnalysisSummary_last_seen",
            "magic_type": "ThreatGrid_SampleAnalysisSummary_magic_type",
            "md5": "md5",
            "registry_count": 143,
            "run_start": "ThreatGrid_SampleAnalysisSummary_run_start",
            "run_stop": "ThreatGrid_SampleAnalysisSummary_run_stop",
            "run_type": "url",
            "sample": "sample_id",
            "sha1": "sha1",
            "sha256": "sha256",
            "stream_count": 44,
            "tags": [],
            "times_seen": 85
        }
    }
}
```

#### Human Readable Output

>### Sample summary:
>|Artifacts|Filename|First Seen|Iocs|Last Seen|Magic Type|Md5|Registry Count|Run Start|Run Stop|Run Type|Sample|Sha1|Sha256|Stream Count|Tags|Times Seen|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| disk: 6 <br/> memory: 9 <br/> network: 1 | www.domain_example_.url | 2021-12-29T15:43:00Z | {'category': ['static-anomaly'], 'confidence': 100, 'ioc': 'html-small-file-redirect', 'severity': 50, 'tags': ['html', 'redirect'], 'score': 50}, <br/> {'category': ['network-information'], 'confidence': 50, 'ioc': 'http-response-redirect', 'severity': 50, 'tags': ['network', 'http', 'redirect'], 'score': 25}, <br/> {'category': ['domain'], 'confidence': 95, 'ioc': 'network-only-safe-domains-contacted', 'severity': 20, 'tags': ['umbrella', 'dns'], 'score': 19}, <br/> {'category': ['network-information'], 'confidence': 25, 'ioc': 'network-communications-http-get-url', 'severity': 25, 'tags': ['network', 'http', 'get'], 'score': 6} | 2022-12-21T12:09:33Z | MS Windows 95 Internet shortcut text (URL=<http:<span>//</span>www.domain_example>), ASCII text | md5 | 143 | 2022-12-21T12:09:33Z | 2022-12-21T12:16:27Z | url | sample_id | sha1 | sha256 | 44 |  | 85 |


### threat-grid-who-am-i
***
Get logged in user


#### Base Command

`threat-grid-who-am-i`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.User.email | string | Current user mail. |
| ThreatGrid.User.login | string | Current user login name. |

#### Command example
```!threat-grid-who-am-i```
#### Context Example
```json
{
    "ThreatGrid": {
        "User": {
            "active": true,
            "api_key": "key",
            "api_only": false,
            "device": false,
            "email": "ThreatGrid_User_email",
            "integration_id": "id",
            "login": "login_name",
            "name": "name",
            "organization_id": 485008,
            "role": "org-admin",
            "title": ""
        }
    }
}
```

#### Human Readable Output

>### Who am I ?
>|Active|Api Key|Api Only|Device|Email|Integration Id|Login|Name|Organization Id|Role|Title|
>|---|---|---|---|---|---|---|---|---|---|---|
>| true | key | false | false | mail | z1ci | login_name | name | id | org-admin |  |


### threat-grid-rate-limit-get
***
Get rate limit for a specific user name. ThreatGrid employs a simple rate limiting method for sample submissions by specifying the number of samples which can be submitted within some variable time period by a user. Multiple rate limits can be employed to form overlapping submission limits. For example, 20 submissions per hour AND 400 per day.


#### Base Command

`threat-grid-rate-limit-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| login | User login name. | Required |
| entity_type | User or Organization. Possible values are: user, organization. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.RateLimit.submission-rate-limit | number | Array of array\(s\) representing submission\(s\) per minute\(s\) or the string"nil" to clear the value. Example: \[\[5, 1440\]\] which represents 5 samples per day. This field represent the number of samples allowed. |
| ThreatGrid.RateLimit.submission-wait-seconds | number | The number of seconds to wait for a submission to get uploaded on the platform. |
| ThreatGrid.RateLimit.submissions-available | number | The number of submissions available for the specified username |

#### Command example
```!threat-grid-rate-limit-get login=login_name entity_type=user```
#### Context Example
```json
{
    "ThreatGrid": {
        "RateLimit": {
            "submission-rate-limit": [],
            "submission-wait-seconds": 0,
            "submissions-available": null
        }
    }
}
```

#### Human Readable Output

>### user rate limit :
>|Submission-rate-limit|Submission-wait-seconds|Submissions-available|
>|---|---|---|
>|  | 0 |  |


### threat-grid-feed-specific-get
***
Gets a specific threat feed


#### Base Command

`threat-grid-feed-specific-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_name | The feed name. Possible values are: autorun-registry, banking-dns, dga-dns, dll-hijacking-dns, doc-net-com-dns, downloaded-pe-dns, dynamic-dns, irc-dns, modified-hosts-dns, parked-dns, public-ip-check-dns, ransomware-dns, rat-dns, scheduled-tasks, sinkholed-ip-dns, stolen-cert-dns. | Required |
| output_type | The output type. Possible values are: json, csv, stix, snort, txt. Default is json. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Feed.sample | String | Feed sample. |
| ThreatGrid.Feed.description | String | Feed description. |

#### Command example
```!threat-grid-feed-specific-get feed_name=doc-net-com-dns```
#### Context Example
```json
{
    "ThreatGrid": {
        "Feed": [
            {
                "description": "DNS response information from requests made by document samples performing network communications.",
                "domain": "login.gogie.com.000000000000.phish.farm",
                "info": "ThreatGrid_Feed[0]_info",
                "ips": [
                    "ThreatGrid_Feed[0]_ips_0",
                    "ThreatGrid_Feed[0]_ips_1"
                ],
                "sample": "ThreatGrid_Feed[0]_sample",
                "sample_md5": "sample_md5",
                "sample_sha1": "sample_sha1",
                "sample_sha256": "sample_sha256",
                "timestamp": "ThreatGrid_Feed[0]_timestamp"
            },
            {
                "description": "DNS response information from requests made by document samples performing network communications.",
                "domain": "spamchallenge.msftemail.com",
                "info": "ThreatGrid_Feed[1]_info",
                "ips": [
                    "ThreatGrid_Feed[1]_ips_0",
                    "ThreatGrid_Feed[1]_ips_1"
                ],
                "sample": "ThreatGrid_Feed[1]_sample",
                "sample_md5": "sample_md5",
                "sample_sha1": "sample_sha1",
                "sample_sha256": "sample_sha256",
                "timestamp": "ThreatGrid_Feed[1]_timestamp"
            },

        ]
    }
}
```

#### Human Readable Output

>### Specific feed :
>|Sample|Description|
>|---|---|
>| https:<span>//</span>panacea.threatgrid.com/feeds/doc-net-com-dns/samples/4007c79d4db4af076e67a32b9aa9eae8 | DNS response information from requests made by document samples performing network communications. |
>| https:<span>//</span>panacea.threatgrid.com/feeds/doc-net-com-dns/samples/9df95de1e738730ea3eb9c2ec122afa7 | DNS response information from requests made by document samples performing network communications. |


### threat-grid-ip-search
***
Search IPs. Please provide a single argument (only one) to use this command, as the API supports 1 filter at a time.


#### Base Command

`threat-grid-ip-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to search for. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.search.ip | string | IP item. |
| ThreatGrid.search.asn | string | IP asn. |
| ThreatGrid.search.location | string | IP location details. |

#### Command example
```!threat-grid-ip-search ip=8.8.8.8```
#### Context Example
```json
{
    "ThreatGrid": {
        "search": {
            "asn": {
                "asn": 15169,
                "org": "Google"
            },
            "flags": [
                {
                    "created_at": "ThreatGrid_search_flags[0]_created_at",
                    "expiration": "ThreatGrid_search_flags[0]_expiration",
                    "flag": 1,
                    "login": "admin",
                    "mine": false,
                    "reason": "Content Delivery Network"
                },
            ],
            "ip": "ThreatGrid_search_ip",
            "location": {
                "city": "Los Angeles",
                "country": "US",
                "region": "CA"
            },
            "rev": "dns.google",
            "tags": []
        }
    }
}
```

#### Human Readable Output

>### ip data:
>|Asn|Flags|Ip|Location|Rev|Tags|
>|---|---|---|---|---|---|
>| org: Google <br/> asn: 15169 | {'created_at': '2013-11-15T18:16:33Z', 'expiration': '2025-01-01T00:00:00Z', 'flag': 1, 'login': 'admin', 'reason': 'Content Delivery Network', 'mine': False}, <br/> {'created_at': '2013-11-15T18:16:34Z', 'expiration': '2025-01-01T00:00:00Z', 'flag': 1, 'login': 'admin', 'reason': 'resolves to google-public-dns-a.domain_example', 'mine': False}, <br/> {'created_at': '2013-07-25T14:08:34Z', 'expiration': '2025-01-01T00:00:00Z', 'flag': 1, 'login': 'dean', 'reason': 'Whitelisted', 'mine': False} | 8.8.8.8 | country: US <br/> region: CA <br/> city: Los Angeles | dns.google |  |


### threat-grid-analysis-annotations-get
***
Returns data regarding the annotations of the analysis


#### Base Command

`threat-grid-analysis-annotations-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | The sample ID. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.SampleAnnotations.network | String | IP address &amp; timestamp in the annotation. |

#### Command example
```!threat-grid-analysis-annotations-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "SampleAnnotations": {
            "network": {
                "ip1": {
                    "ts": "ThreatGrid_SampleAnnotations_network_ip1_ts"
                },
                "ip2": {
                    "asn": 15169,
                    "city": "c",
                    "country": "US",
                    "country_name": "United States",
                    "org": "Google",
                    "region": "NY",
                    "region_name": "New York",
                    "reverse_dns": [
                        "lga34s32-in-f3.1e100.net"
                    ],
                    "ts": "ThreatGrid_SampleAnnotations_network_ip2_ts"
                },
            }
        }
    }
}
```

#### Human Readable Output

>### List of samples analysis:
>|ip1|ip2|
>|---|---|
>| ts: 2022-12-21T12:15:59Z | org: Google <br/> ts: 2022-12-21T12:15:59Z <br/> country: US <br/> city: c <br/> region_name: New York <br/> region: NY <br/> reverse_dns: lga34s32-in-f3.1e100.net <br/> country_name: United States <br/> asn: 15169 | org: Google <br/> ts: 2022-12-21T12:15:59Z <br/> country: US <br/> city: Wantagh <br/> region_name: New York <br/> region: NY <br/> reverse_dns: lga34s34-in-f14.1e100.net <br/> country_name: United States <br/> asn: 15169 | org: Google <br/> ts: 2022-12-21T12:15:59Z <br/> country: US <br/> city: Glen Cove <br/>

### threat-grid-url-search
***
Search urls. Please provide the URL in the format http://example.com:80/ (note that ThreatGrid only support '.com' domains).


#### Base Command

`threat-grid-url-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to search for (please provide the URL in the format http://example.com:80/. note that ThreatGrid only support '.com' domains). | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.search.url | String | URL item |

#### Command example
```!threat-grid-url-search url=http://domain_example:80/```
#### Context Example
```json
{
    "ThreatGrid": {
        "search": {
            "host": "domain_example",
            "path": "/",
            "port": 80,
            "protocol": "http",
            "query": null,
            "query-params": null,
            "reference": null,
            "url": "ThreatGrid_search_url"
        }
    }
}
```

#### Human Readable Output

>### url data:
>|Host|Path|Port|Protocol|Query|Query-params|Reference|Url|
>|---|---|---|---|---|---|---|---|
>| domain_example | / | 80 | http |  |  |  | http:<span>//</span>domain_example:80/ |


### threat-grid-feeds-artifact
***
Get artifacts threat feed


#### Base Command

`threat-grid-feeds-artifact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | Restrict returned records with this sha256. | Optional |
| sha1 | Restrict returned records with this sha1. | Optional |
| md5 | Restrict returned records with this md5. | Optional |
| path | Restrict returned records to this path or path fragment. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The number of items per page. | Optional |
| page | Page number of paginated results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Artifact.confidence | Number | Artifact confidence |
| ThreatGrid.Artifact.severity | Number | Artifact severity |
| ThreatGrid.Artifact.ioc | String | Artifact IOC |
| ThreatGrid.Artifact.artifact_sha256 | String | Artifact sha256 |
| ThreatGrid.Artifact.artifact_md5 | String | Artifact md5 |
| ThreatGrid.Artifact.sample_id | String | Artifact sample ID |

#### Command example
```!threat-grid-feeds-artifact```
#### Context Example
```json
{
    "ThreatGrid": {
        "Artifact": [
            {
                "aid": 1,
                "artifact_md5": "md5",
                "artifact_sha256": "sha256",
                "confidence": 95,
                "ioc": "antivirus-service-flagged-artifact",
                "path": "md5.exe",
                "sample_id": "id",
                "severity": 100,
                "timestamp": "ThreatGrid_Artifact[0]_timestamp"
            },
            {
                "aid": 11,
                "artifact_md5": "artifact_md5",
                "artifact_sha256": "artifact_sha256",
                "confidence": 90,
                "ioc": "sample-pe-modified-on-disk",
                "path": "ThreatGrid_Artifact[1]_path",
                "sample_id": "id",
                "severity": 90,
                "timestamp": "ThreatGrid_Artifact[1]_timestamp"
            },
        ]
    }
}
```

#### Human Readable Output

>### Feeds IOCs list artifact :
> Showing page 1.
> Current page size: 50
>|Aid|Artifact Md5|Artifact Sha256|Confidence|Ioc|Path|Sample Id|Severity|Timestamp|
>|---|---|---|---|---|---|---|---|---|
>| 3 | md5 | sha256 | 90 | antivirus-flagged-artifact | \Users\Administrator\.exe | id | 80 | 2022-12-05T04:10:44Z |
>| 9 | md5 | sha256 | 90 | antivirus-flagged-artifact | 912-.exe | id | 80 | 2022-12-05T04:10:44Z |

### threat-grid-feeds-domain
***
Get domain threat feed


#### Base Command

`threat-grid-feeds-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Restrict returned records to this domain or hostname. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| page | Page number of paginated results. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Domain.confidence | Number | Domain confidence |
| ThreatGrid.Domain.severity | Number | Domain severity |
| ThreatGrid.Domain.ioc | String | Domain IOC |
| ThreatGrid.Domain.sample_sha256 | String | Domain sha256 |
| ThreatGrid.Domain.sample_id | String | Domain sample ID |
| ThreatGrid.Domain.domain | String | The Domain  |

#### Command example
```!threat-grid-feeds-domain```
#### Context Example
```json
{
    "ThreatGrid": {
        "Domain": [
            {
                "confidence": 95,
                "domain": "hookworm.capitaly.ru",
                "ioc": "network-snort-pua",
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 90,
                "timestamp": "ThreatGrid_Domain[0]_timestamp"
            },
            {
                "confidence": 100,
                "domain": "augustawa.com",
                "ioc": "suspicious-user-agent",
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 80,
                "timestamp": "ThreatGrid_Domain[1]_timestamp"
            },

        ]
    }
}
```

#### Human Readable Output

>### Feeds IOCs list domain :
> Showing page 1.
> Current page size: 50
>|Confidence|Domain|Ioc|Sample Id|Sample Sha256|Severity|Timestamp|
>|---|---|---|---|---|---|---|
>| 95 | hookworm.capitaly.ru | network-snort-pua | sample_id | sample_sha256 | 90 | 2022-12-22T07:46:38Z |
>| 100 | augustawa.com | suspicious-user-agent | sample_id | sample_sha256 | 80 | 2022-11-28T23:51:27Z |


### threat-grid-feeds-url
***
Get url threat feed


#### Base Command

`threat-grid-feeds-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Restrict returned records to this url. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| page | Page number of paginated results. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Url.confidence | Number | url confidence |
| ThreatGrid.Url.severity | Number | url severity |
| ThreatGrid.Url.ioc | String | url IOC |
| ThreatGrid.Url.sample_sha256 | String | url sha256 |
| ThreatGrid.Url.sample_id | String | url sample ID |
| ThreatGrid.Url.url | String | The url  |

#### Command example
```!threat-grid-feeds-url```
#### Context Example
```json
{
    "ThreatGrid": {
        "url": [
            {
                "confidence": 95,
                "url": "hookworm.capitaly.ru",
                "ioc": "network-snort-pua",
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 90,
                "timestamp": "ThreatGrid_url[0]_timestamp"
            },
            {
                "confidence": 100,
                "url": "augustawa.com",
                "ioc": "suspicious-user-agent",
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 80,
                "timestamp": "ThreatGrid_url[1]_timestamp"
            },
        ]
    }
}
```

#### Human Readable Output

>### Feeds IOCs list url :
> Showing page 1.
> Current page size: 50
>|Confidence|url|Ioc|Sample Id|Sample Sha256|Severity|Timestamp|
>|---|---|---|---|---|---|---|
>| 95 | hookworm.capitaly.ru | network-snort-pua | sample_id | sample_sha256 | 90 | 2022-12-22T07:46:38Z |
>| 100 | augustawa.com | suspicious-user-agent | sample_id | sample_sha256 | 80 | 2022-11-28T23:51:27Z |

### threat-grid-feeds-ip
***
Get ips threat feed


#### Base Command

`threat-grid-feeds-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Restrict returned records to this IP or CIDR block. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| page | Page number of paginated results. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Ip.confidence | Number | IP confidence |
| ThreatGrid.Ip.severity | Number | IP severity |
| ThreatGrid.Ip.ioc | String | IP IOC |
| ThreatGrid.Ip.sample_sha256 | String | IP sha256 |
| ThreatGrid.Ip.sample_id | String | IP sample ID |
| ThreatGrid.Ip.ip | String | The IP |
| ThreatGrid.Ip.port | Number | The IP port |

#### Command example
```!threat-grid-feeds-ip```
#### Context Example
```json
{
    "ThreatGrid": {
        "Ip": [
            {
                "confidence": 95,
                "ioc": "network-snort-pua",
                "ip": "ThreatGrid_Ip[0]_ip",
                "port": null,
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 90,
                "timestamp": "ThreatGrid_Ip[0]_timestamp"
            },
            {
                "confidence": 90,
                "ioc": "network-snort-indicator-compromise",
                "ip": "ThreatGrid_Ip[1]_ip",
                "port": null,
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 95,
                "timestamp": "ThreatGrid_Ip[1]_timestamp"
            },
        ]
    }
}
```

#### Human Readable Output

>### Feeds IOCs list ip :
> Showing page 1.
> Current page size: 50
>|Confidence|Ioc|Ip|Port|Sample Id|Sample Sha256|Severity|Timestamp|
>|---|---|---|---|---|---|---|---|
>| 95 | network-snort-pua | ip |  | sample_id | sample_sha256 | 90 | 2022-12-22T07:46:38Z |
>| 90 | network-snort-indicator-compromise | 192.168.1.1 |  | sample_id | sample_sha256 | 95 | 2022-12-09T14:22:54Z |


### threat-grid-feeds-network-stream
***
Get network stream threat feed


#### Base Command

`threat-grid-feeds-network-stream`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Restrict returned records to this IP address. | Optional |
| port | Restrict returned records to this port number. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| page | Page number of paginated results. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.NetworkStreams.confidence | Number | Network Streams confidence |
| ThreatGrid.NetworkStreams.severity | Number | Network Streams severity |
| ThreatGrid.NetworkStreams.ioc | String | Network Streams IOC |
| ThreatGrid.NetworkStreams.sample_sha256 | String | Network Streams sha256 |
| ThreatGrid.NetworkStreams.sample_id | String | Network Streams sample ID |
| ThreatGrid.NetworkStreams.src | String | The Network Streams source  |
| ThreatGrid.NetworkStreams.src_port | Number | The Network Streams source port |
| ThreatGrid.NetworkStreams.dst | String | The Network Streams destination  |
| ThreatGrid.NetworkStreams.dst_port | Number | The Network Streams destination port |

#### Command example
```!threat-grid-feeds-network-stream```
#### Context Example
```json
{
    "ThreatGrid": {
        "NetworkStreams": [
            {
                "confidence": 95,
                "dst": "ThreatGrid_NetworkStreams[0]_dst",
                "dst_port": 80,
                "ioc": "network-snort-pua",
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 90,
                "src": "ThreatGrid_NetworkStreams[0]_src",
                "src_port": 49166,
                "timestamp": "ThreatGrid_NetworkStreams[0]_timestamp"
            },
            {
                "confidence": 100,
                "dst": "ThreatGrid_NetworkStreams[1]_dst",
                "dst_port": 80,
                "ioc": "suspicious-user-agent",
                "sample_id": "sample_id",
                "sample_sha256": "sample_sha256",
                "severity": 80,
                "src": "ThreatGrid_NetworkStreams[1]_src",
                "src_port": 49160,
                "timestamp": "ThreatGrid_NetworkStreams[1]_timestamp"
            },

        ]
    }
}
```

#### Human Readable Output

>### Feeds IOCs list network_stream :
> Showing page 1.
> Current page size: 50
>|Confidence|Dst|Dst Port|Ioc|Sample Id|Sample Sha256|Severity|Src|Src Port|Timestamp|
>|---|---|---|---|---|---|---|---|---|---|
>| 95 | ip | 80 | network-snort-pua | sample_id | sample_sha256 | 90 | ip | 49164 | 2022-12-22T07:46:38Z |
>| 95 | ip | 80 | network-snort-pua | sample_id | sample_sha256 | 90 | ip | 49158 | 2022-12-22T07:46:38Z |


### threat-grid-feeds-path
***
Get path threat feed


#### Base Command

`threat-grid-feeds-path`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Restrict returned records to this path or path fragment. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| page | Page number of paginated results. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Path.confidence | Number | Path confidence |
| ThreatGrid.Path.severity | Number | Path severity |
| ThreatGrid.Path.ioc | String | Path IOC |
| ThreatGrid.Path.sample_sha256 | String | Path sha256 |
| ThreatGrid.Path.sample_id | String | Path sample ID |

#### Command example
```!threat-grid-feeds-path```
#### Context Example
```json
{
    "ThreatGrid": {
        "Path": [
            {
                "confidence": 100,
                "ioc": "artifact-pe-no-name",
                "path": "\\Users\\Administrator\\.exe",
                "sample_id": "id",
                "sample_sha256": "sha256",
                "severity": 90,
                "timestamp": "ThreatGrid_Path[0]_timestamp"
            },
            {
                "confidence": 100,
                "ioc": "modified-file-in-system-dir",
                "path": "ThreatGrid_Path[1]_path",
                "sample_id": "id",
                "sample_sha256": "sha256",
                "severity": 85,
                "timestamp": "ThreatGrid_Path[1]_timestamp"
            },
        ]
    }
}
```

#### Human Readable Output

>### Feeds IOCs list path :
> Showing page 1.
> Current page size: 50
>|Confidence|Ioc|Path|Sample Id|Sample Sha256|Severity|Timestamp|
>|---|---|---|---|---|---|---|
>| 90 | antivirus-flagged-artifact | \Users\Administrator\.exe | id | sha256 | 80 | 2022-12-05T04:10:44Z |
>| 90 | antivirus-flagged-artifact | 912-.exe | id | sha256 | 80 | 2022-12-05T04:10:44Z |


### threat-grid-feeds-url
***
Get url threat feed


#### Base Command

`threat-grid-feeds-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Restrict returned records to this URL or URL fragment. | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| confidence | Restrict to IOCs with this confidence score or higher, defaults to 80. Default is 80. | Optional |
| severity | Restrict to IOCs with this severity score or higher, defaults to 80. Default is 80. | Optional |
| ioc | Restrict returned records to events of this type. | Optional |
| org_only | If “true”, will only match against samples submitted by your organization. Possible values are: True, False. | Optional |
| user_only | If “true”, will only match against samples you submitted. Possible values are: True, False. | Optional |
| sample_id | A comma-separated list of sample IDs. Restrict results to these samples. | Optional |
| page | Page number of paginated results. | Optional |
| page_size | The number of items per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.Url.confidence | Number | URL confidence |
| ThreatGrid.Url.severity | Number | URL severity |
| ThreatGrid.Url.ioc | String | URL IOC |
| ThreatGrid.Url.sample_sha256 | String | URL sha256 |
| ThreatGrid.Url.sample_id | String | URL sample ID |
| ThreatGrid.Url.url | String | The URL |

### threat-grid-analysis-artifacts-get
***
Returns the sample id artifact with artifact id


#### Base Command

`threat-grid-analysis-artifacts-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | the sample id. | Required |
| artifact_id | The artifact id requested. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.ArtifactAnalysis.items | Unknown | Analysis files of the sample and the artifact |

#### Command example
```!threat-grid-analysis-artifacts-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "ArtifactAnalysis": {
            "1": {
                "antivirus": {
                    "reversing_labs": {
                        "first_seen": "ThreatGrid_ArtifactAnalysis_1_antivirus_reversing_labs_first_seen",
                        "last_seen": "ThreatGrid_ArtifactAnalysis_1_antivirus_reversing_labs_last_seen",
                        "query_hash": {
                            "sha256": "sha256"
                        },
                        "scanner_count": 25,
                        "scanner_match": 0,
                        "status": "KNOWN",
                        "threat_level": 0,
                        "threat_name": "",
                        "trust_factor": 5
                    },
                    "virustotal": {
                        "engines": 55,
                        "hits": 0,
                        "results": {},
                        "scanned": "ThreatGrid_ArtifactAnalysis_1_antivirus_virustotal_scanned",
                        "score": 0
                    }
                },
                "created-time": 0,
                "created_by": [],
                "entropy": 4.402529762804034,
                "executed_from": [],
                "forensics": {
                    "sections": {
                        "InternetShortcut": {
                            "properties": {
                                "URL": "ThreatGrid_ArtifactAnalysis_1_forensics_sections_InternetShortcut_properties_URL"
                            }
                        }
                    }
                },
                "magic-type": "ThreatGrid_ArtifactAnalysis_1_magic-type",
                "md5": "md5",
                "mime-type": "text/plain; charset=us-ascii",
                "modified_by": [],
                "origin": "submitted",
                "path": "www.domain_example_.url",
                "read_by": [],
                "relation": {
                    "contains": null,
                    "extracted_from": null,
                    "network": null,
                    "process": null
                },
                "sha1": "sha1",
                "sha256": "sha256",
                "size": 45,
                "type": "url",
                "whitelist": []
            },
            "10": {
                "antivirus": {
                    "reversing_labs": {
                        "first_seen": "",
                        "last_seen": "",
                        "query_hash": {
                            "sha256": "sha256"
                        },
                        "scanner_count": 0,
                        "scanner_match": 0,
                        "status": "UNKNOWN",
                        "threat_level": 0,
                        "threat_name": "",
                        "trust_factor": 0
                    }
                },
                "created-time": 1671624958,
                "created_by": [
                    24
                ],
                "entropy": 0,
                "executed_from": [],
                "forensics": null,
                "magic-type": "data",
                "md5": "md5",
                "mime-type": "application/octet-stream; charset=binary",
                "modified_by": [],
                "origin": "disk",
                "path": "path",
                "read_by": [],
                "relation": {
                    "contains": null,
                    "extracted_from": null,
                    "network": null,
                    "process": null
                },
                "sha1": "sha1",
                "sha256": "sha256",
                "size": 276959,
                "type": "",
                "whitelist": []
            },
            "11": {
                "antivirus": {
                    "reversing_labs": {
                        "first_seen": "ThreatGrid_ArtifactAnalysis_11_antivirus_reversing_labs_first_seen",
                        "last_seen": "ThreatGrid_ArtifactAnalysis_11_antivirus_reversing_labs_last_seen",
                        "query_hash": {
                            "sha256": "sha256"
                        },
                        "scanner_count": 42,
                        "scanner_match": 0,
                        "status": "KNOWN",
                        "threat_level": 0,
                        "threat_name": "",
                        "trust_factor": 0
                    }
                },
                "created-time": 1671624958,
                "created_by": [
                    24
                ],
                "entropy": 0,
                "executed_from": [],
                "forensics": null,
                "magic-type": "data",
                "md5": "md5",
                "mime-type": "application/octet-stream; charset=binary",
                "modified_by": [],
                "origin": "disk",
                "path": "path",
                "read_by": [],
                "relation": {
                    "contains": null,
                    "extracted_from": null,
                    "network": null,
                    "process": null
                },
                "sha1": "sha1",
                "sha256": "sha256",
                "size": 21700,
                "type": "",
                "whitelist": []
            },
            "12": {
                "antivirus": {
                    "reversing_labs": {
                        "first_seen": "",
                        "last_seen": "",
                        "query_hash": {
                            "sha256": "sha256"
                        },
                        "scanner_count": 0,
                        "scanner_match": 0,
                        "status": "UNKNOWN",
                        "threat_level": 0,
                        "threat_name": "",
                        "trust_factor": 0
                    }
                },
                "created-time": 1671624958,
                "created_by": [
                    24
                ],
                "entropy": 0.006721586530775835,
                "executed_from": [],
                "forensics": null,
                "magic-type": "data",
                "md5": "md5",
                "mime-type": "application/octet-stream; charset=binary",
                "modified_by": [],
                "origin": "disk",
                "path": "path",
                "read_by": [],
                "relation": {
                    "contains": null,
                    "extracted_from": null,
                    "network": null,
                    "process": null
                },
                "sha1": "sha1",
                "sha256": "sha256",
                "size": 262512,
                "type": "",
                "whitelist": []
            },
        }
    }
}
```

#### Human Readable Output

>### List of samples analysis:
>|1|10
>|---|---|
>| origin: submitted <br/> executed_from:  <br/> path: www.domain_example_.url <br/> mime-type: text/plain; charset=us-ascii <br/> whitelist: <br/> created-time: 0 <br/> read_by:  <br/> created_by:  <br/> sha256: sha256 <br/> sha1: sha1 <br/> md5: md5 <br/> entropy: x <br/> type: url <br/> size: 45 <br/> modified_by:  <br/> magic-type: MS Windows 95 Internet shortcut text (URL=<http:<span>//</span>www.domain_example>), ASCII text <br/> relation: {"contains": null, "extracted_from": null, "network": null, "process": null} | origin: disk <br/> executed_from:  <br/> path: path <br/> mime-type: application/octet-stream; charset=binary <br/> whitelist:  <br/> created-time: 1671624958 <br/> read_by:  <br/> created_by: 24 <br/> sha256: sha256 <br/> sha1: sha1 <br/> md5: md5 <br/> entropy: 0 <br/> type:  <br/> size: 276959 <br/> modified_by:  <br/> magic-type: data <br/> relation: {"contains": null, "extracted_from": null, "network": null, "process": null} | origin: disk <br/> executed_from:  <br/> path: path <br/> mime-type: application/octet-stream; charset=binary <br/> whitelist:  <br/> created-time: 1671624958 <br/> read_by:  <br/> created_by: 24 <br/> sha256: sha256 <br/> sha1: sha1 <br/> md5: md5 <br/> entropy: 0 <br/> type:  <br/> size: 21700 <br/> modified_by:  <br/> magic-type: data <br/> relation: {"contains": null, "extracted_from": null, "network": null, "process": null} | origin: disk <br/> executed_from:  <br/> path: path <br/> mime-type: application/octet-stream; charset=binary <br/> whitelist:  <br/> created-time: 1671624958 <br/> read_by:  <br/> created_by: 24 <br/> sha256: sha256 <br/> sha1: sha1 <br/> md5: md5 <br/> entropy: 0.006721586530775835 <br/> type:  <br/> size: 262512 <br/> modified_by:  <br/> magic-type: data <br/> relation: {"contains": null, "extracted_from": null, "network": null, "process": null} | origin: disk <br/> executed_from:  <br/> path: /Users/Administrator/AppData/Local/Google/Chrome/User Data/Default/Code Cache/js/1500928ccce7b989_0 <br/> mime-type: application/octet-stream; charset=binary <br/> whitelist:  <br/> created-time: 1671624958 <br/> read_by:  <br/> created_by:  <br/> sha256: sha256 <br/> sha1: sha1 <br/> md5: md5 <br/> entropy: 0.09552689517008506 <br/> type:  <br/> size: 1917 <br/> modified_by:  <br/> magic-type: data <br/> relation: {"contains": null, "extracted_from": null, "network": null, "process": null} |


### threat-grid-analysis-iocs-get
***
Returns data regarding the specified Indicator of Compromise


#### Base Command

`threat-grid-analysis-iocs-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | the sample id. | Required |
| ioc | the IOC requested. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.IOCAnalysis.title | String | The title of the IOC |
| ThreatGrid.IOCAnalysis.confidence | Number | The confidence of the IOC |
| ThreatGrid.IOCAnalysis.severity | String | The severity of the IOC |
| ThreatGrid.IOCAnalysis.ioc | String | Threat grid's IOC |
| ThreatGrid.IOCAnalysis.category | String | The IOC category of the IOC |
| ThreatGrid.IOCAnalysis.sha256 | String | The SHA256 value of the IOC |
| ThreatGrid.IOCAnalysis.tags | String | The tags of the IOC |

#### Command example
```!threat-grid-analysis-iocs-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "IOCAnalysis": [
            {
                "analysis-envs": [
                    "win",
                    "mac"
                ],
                "category": [
                    "network-information"
                ],
                "confidence": 50,
                "data": [
                    {
                        "Code": 302,
                        "Method": "GET",
                        "Network_Stream": 11,
                        "Status": "Found",
                        "Trans_ID": 0,
                        "URL": "ThreatGrid_IOCAnalysis[0]_data[0]_URL"
                    }
                ],
                "description": "An HTTP message indicating a redirection notice was detected in a network stream. The HTTP response codes are used as a means of conveying the status of the connection with the server to the client. Items within the 300 range indicate a redirection notice. These occur when a page has been temporarily or permanently moved.",
                "heuristic_coefficient": -0.0987738978328,
                "hits": 1,
                "ioc": "http-response-redirect",
                "mitre": [],
                "mitre-tactics": [],
                "mitre-techniques": [],
                "orbital-queries": [],
                "severity": 50,
                "suspected-sample-categories": [],
                "tags": [
                    "network",
                    "http",
                    "redirect"
                ],
                "title": "HTTP Redirection Response",
                "truncated": false
            },
            {
                "analysis-envs": [
                    "win",
                    "mac",
                    "browser"
                ],
                "category": [
                    "network-information"
                ],
                "confidence": 25,
                "data": [
                    {
                        "Method": "GET",
                        "Network_Stream": 11,
                        "URL": "ThreatGrid_IOCAnalysis[1]_data[0]_URL"
                    }
                ],
                "description": "Outbound HTTP GET to a remote server was detected. This is not inherently suspicious but malware will often use Gets in order to check in to the Command and Control servers upon infection or to download or exfiltrate data. Please view the 'HTTP' section under 'Network Analysis' for the associated traffic/communications. Additionally, the provided network PCAP will provide more details on the traffic stream.",
                "heuristic_coefficient": -26.131188198,
                "hits": 1,
                "ioc": "network-communications-http-get-url",
                "mitre": [
                    {
                        "tactic": "command and control",
                        "techniques": [
                            {
                                "subtechniques": [],
                                "technique": "application layer protocol"
                            }
                        ]
                    }
                ],
                "mitre-tactics": [
                    "command and control"
                ],
                "mitre-techniques": [
                    "application layer protocol"
                ],
                "orbital-queries": [],
                "severity": 25,
                "suspected-sample-categories": [],
                "tags": [
                    "network",
                    "http",
                    "get"
                ],
                "title": "Outbound HTTP GET Request From URL Submission",
                "truncated": false
            },

        ]
    }
}
```

#### Human Readable Output

>### List of samples analysis:
>|Analysis-envs|Category|Confidence|Data|Description|Heuristic Coefficient|Hits|Ioc|Mitre|Mitre-tactics|Mitre-techniques|Orbital-queries|Severity|Suspected-sample-categories|Tags|Title|Truncated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| win, <br/> mac | network-information | 50 | {'Code': 302, 'Method': 'GET', 'Network_Stream': 11, 'Status': 'Found', 'Trans_ID': 0, 'URL': 'http:<span>//</span>www.domain_example:80/'} | An HTTP message indicating a redirection notice was detected in a network stream. The HTTP response codes are used as a means of conveying the status of the connection with the server to the client. Items within the 300 range indicate a redirection notice. These occur when a page has been temporarily or permanently moved. | -0.0987738978328 | 1 | http-response-redirect |  |  |  |  | 50 |  | network, <br/> http, <br/> redirect | HTTP Redirection Response | false |
>| win, <br/> mac, <br/> browser | network-information | 25 | {'Method': 'GET', 'Network_Stream': 11, 'URL': 'http:<span>//</span>www.domain_example:80/'} | Outbound HTTP GET to a remote server was detected. This is not inherently suspicious but malware will often use Gets in order to check in to the Command and Control servers upon infection or to download or exfiltrate data. Please view the 'HTTP' section under 'Network Analysis' for the associated traffic/communications. Additionally, the provided network PCAP will provide more details on the traffic stream. | -26.131188198 | 1 | network-communications-http-get-url | {'tactic': 'command and control', 'techniques': [{'subtechniques': [], 'technique': 'application layer protocol'}]} | command and control | application layer protocol |  | 25 |  | network, <br/> http, <br/> get | Outbound HTTP GET Request From URL Submission | false |


### threat-grid-analysis-metadata-get
***
Returns metadata about the analysis


#### Base Command

`threat-grid-analysis-metadata-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | the sample id. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.AnalysisMetadata.general_details | Unknown | The Metadata Analysis General Details |
| ThreatGrid.AnalysisMetadata.malware_desc | Unknown | The Metadata Analysis Malware Desc |
| ThreatGrid.AnalysisMetadata.sandcastle_env | Unknown | The Metadata Analysis Malware Sandcastle ENV |

#### Command example
```!threat-grid-analysis-metadata-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "AnalysisMetadata": {
            "general_details": {
                "report_created": 1671624987,
                "sandbox_id": "scl-work-004",
                "sandbox_version": "pilot-d"
            },
            "malware_desc": [
                {
                    "filename": "www.domain_example_.url",
                    "magic": "ThreatGrid_AnalysisMetadata_malware_desc[0]_magic",
                    "md5": "md5",
                    "sha1": "sha1",
                    "sha256": "sha256",
                    "size": 45,
                    "type": "url"
                }
            ],
            "sandcastle_env": {
                "analysis_end": 1671624987,
                "analysis_features": [],
                "analysis_start": 1671624573,
                "controlsubject": "win",
                "current_os": "os",
                "display_name": "Windows 10 Browser",
                "run_time": 300,
                "sample_executed": 1671624638,
                "sandcastle": "3.5.124.17776.d4a3b85fe-1",
                "vm": "win10-x64-browser",
                "vm_id": "sample_id"
            }
        }
    }
}
```

#### Human Readable Output

>### List of samples analysis:
>|Filename|Magic|Md5|Sha1|Sha256|Size|Type|
>|---|---|---|---|---|---|---|
>| www.domain_example_.url | MS Windows 95 Internet shortcut text (URL=<http:<span>//</span>www.domain_example>), ASCII text | md5 | sha1 | sha256 | 45 | url |


### threat-grid-analysis-network-streams-get
***
Returns data regarding a specific network stream


#### Base Command

`threat-grid-analysis-network-streams-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | the sample id. | Required |
| network_stream_id | The network stream id. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.NetworkAnalysis.protocol | Number | The network protocol |
| ThreatGrid.NetworkAnalysis.transport | String | The network transport  |
| ThreatGrid.NetworkAnalysis.service | String | The network service |
| ThreatGrid.NetworkAnalysis.client_ip | String | The client IP |
| ThreatGrid.NetworkAnalysis.server_ip | String | The server IP |

#### Command example
```!threat-grid-analysis-network-streams-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "NetworkAnalysis": {
            "0": {
                "bytes": 657,
                "bytes_missed": 0,
                "bytes_orig": 657,
                "bytes_orig_payload": 601,
                "bytes_payload": 601,
                "bytes_resp": 0,
                "bytes_resp_payload": 0,
                "conn_state": "S0",
                "dst": "ThreatGrid_NetworkAnalysis_0_dst",
                "dst_port": 67,
                "duration": 0.000993,
                "history": "D",
                "packets": 2,
                "packets_orig": 2,
                "service": "dhcp",
                "session": 0,
                "src": "ThreatGrid_NetworkAnalysis_0_src",
                "src_port": 68,
                "transport": "UDP",
                "ts_begin": 1671624615.898952,
                "ts_end": 1671624615.899945,
                "uid": "id"
            },
            "1": {
                "bytes": 664,
                "bytes_missed": 0,
                "bytes_orig": 0,
                "bytes_orig_payload": 0,
                "bytes_payload": 608,
                "bytes_resp": 664,
                "bytes_resp_payload": 608,
                "conn_state": "SHR",
                "decoded": [
                    {
                        "client_ip": "ThreatGrid_NetworkAnalysis_1_decoded[0]_client_ip",
                        "client_mac": "00:15:17:22:da:4d",
                        "dns_servers": [
                            "ThreatGrid_NetworkAnalysis_1_decoded[0]_dns_servers_0"
                        ],
                        "lease_time": 1200,
                        "netmask": "ThreatGrid_NetworkAnalysis_1_decoded[0]_netmask",
                        "routers": [
                            "ThreatGrid_NetworkAnalysis_1_decoded[0]_routers_0"
                        ],
                        "server_ip": "ThreatGrid_NetworkAnalysis_1_decoded[0]_server_ip",
                        "type": "DHCP_ACK"
                    }
                ],
                "dst": "ThreatGrid_NetworkAnalysis_1_dst",
                "dst_port": 67,
                "duration": 0.000839,
                "history": "^d",
                "packets": 2,
                "packets_resp": 2,
                "protocol": "DHCP",
                "service": "dhcp",
                "session": 1,
                "src": "ThreatGrid_NetworkAnalysis_1_src",
                "src_port": 68,
                "transport": "UDP",
                "ts_begin": 1671624615.899514,
                "ts_end": 1671624615.900353,
                "uid": "CnmnL8FPcbmixXLv1"
            },

        }
    }
}
```

#### Human Readable Output

>### List of samples analysis:
>|0|1|
>|---|---|
>| transport: UDP  <br/> dst: dst <br/> uid: d <br/> bytes_missed: 0 <br/> src: ip1 <br/> ts_end: 1671624615.899945 <br/> dst_port: 67 <br/> packets_orig: 2 <br/> bytes_orig_payload: 601 <br/> bytes: 657 <br/> bytes_orig: 657 <br/> duration: 0.000993 <br/> history: D <br/> bytes_resp_payload: 0 <br/> conn_state: S0 <br/> service: dhcp <br/> session: 0 <br/> bytes_resp: 0 <br/> ts_begin: 1671624615.898952 <br/> packets: 2 <br/> src_port: 68 <br/> bytes_payload: 601 | decoded: {'client_ip': '192.168.1.28', 'client_mac': '00:15:17:22:da:4d', 'dns_servers': ['192.168.1.1'], 'lease_time': 1200, 'netmask': '255.255.255.0', 'routers': ['192.168.1.1'], 'server_ip': '192.168.1.1', 'type': 'DHCP_ACK'} <br/> transport: UDP <br/> protocol: DHCP <br/> dst: 192.168.1.1 <br/> uid: CnmnL8FPcbmixXLv1 <br/> bytes_missed: 0 <br/> src: 192.168.1.28 <br/> packets_resp: 2 <br/> ts_end: 1671624615.900353 <br/> dst_port: 67 <br/> bytes_orig_payload: 0 <br/> bytes: 664 <br/> bytes_orig: 0 <br/> duration: 0.000839 <br/> history: ^d <br/> bytes_resp_payload: 608 <br/> conn_state: SHR <br/> service: dhcp <br/> session: 1 <br/> bytes_resp: 664 <br/> ts_begin: 1671624615.899514 <br/> packets: 2 <br/> src_port: 68 <br/> bytes_payload: 608 | transport: TCP <br/> dst: dst <br/> uid: CG18zQzbcnKMJ9rYh <br/> bytes_missed: 0 <br/> src: 192.168.1.28 <br/> packets_resp: 10 <br/> ts_end: 1671624761.8172178 <br/> dst_port: 443 <br/> packets_orig: 7 <br/> bytes_orig_payload: 581 <br/> bytes: 5965 <br/> bytes_orig: 873 <br/> duration: 26.85108 <br/> history: ShADadfr <br/> bytes_resp_payload: 4680 <br/> conn_state: RSTR <br/> service: ssl <br/> session: 10 <br/> bytes_resp: 5092 <br/> ts_begin: 1671624734.966138 <br/> packets: 17 <br/> src_port: 49670 <br/> bytes_payload: 5261 | decoded: [{'request_path': '/', 'url': 'http:<span>//</span>www.domain_example:80/', 'ts': 1671624747.411076, 'host': 'www.domain_example', 'method': 'GET', 'request_filename': 'http-www.domain_example-80-11-1', 'sha256': 'sha256', 'port': 80, 'type': 'request', 'version': '1.1', 'body_len': 0, 'actual_content_type': 'application/x-empty', 'decoded_url': 'http:<span>//</span>www.domain_example:80/', 'headers': {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate', 'accept-language': 'en-US,en;q=0.9', 'connection': 'keep-alive', 'host': 'www.domain_example', 'upgrade-insecure-requests': '1', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36'}}, {'ts': 1671624747.505528, 'sha256': 'sha256', 'status_code': 302, 'status': 'Found', 'type': 'response', 'reported_content_type': 'text/html; charset=UTF-8', 'version': '1.1', 'body_len': 231, 'actual_content_type': 'text/html', 'fuids': ['FwgsLG2izIyrPnv7n4'], 'headers': {'server': 'gws', 'origin-trial': 'ot', 'content-type': 'text/html; charset=UTF-8', 'content-length': '231', 'bfcache-opt-in': 'unload', 'permissions-policy': 'unload=()', 'x-frame-options': 'SAMEORIGIN', 'location': 'https:<span>//</span>www.domain_example/?gws_rd=ssl', 'set-cookie': ['1P_JAR=2022-12-21-12; expires=Fri, 20-Jan-2023 12:12:27 GMT; path=/; domain=.domain_example; Secure; SameSite=none', 'x; expires=Mon, 19-Jun-2023 12:12:27 GMT; path=/; domain=.domain_example; Secure; HttpOnly; SameSite=lax'], 'date': 'Wed, 21 Dec 2022 12:12:27 GMT', 'cross-origin-opener-policy-report-only': 'same-origin-allow-popups; report-to="gws"', 'x-xss-protection': '0', 'report-to': '{"group":"gws","max_age":2592000,"endpoints":[{"url":"https:<span>//</span>csp.withdomain_example/csp/report-to/gws/other"}]}', 'cache-control': 'private'}}] <br/> transport: TCP <br/> protocol: HTTP <br/> dst: dst <br/> uid: C1A2px82MwQLhxvg3 <br/> bytes_missed: 0 <br/> src: 192.168.1.28 <br/> packets_resp: 4 <br/> ts_end: 1671624747.7983232 <br/> dst_port: 80 <br/> packets_orig: 4 <br/> bytes_orig_payload: 433 <br/> bytes: 3345 <br/> bytes_orig: 617 <br/> duration: 6.859333 <br/> history: ShADad <br/> bytes_resp_payload: 1278 <br/> conn_state: S1 <br/> service: http <br/> session: 11 <br/> bytes_resp: 2728 <br/> ts_begin: 1671624740.93899 <br/> packets: 8 <br/> src_port: 49671 <br/> bytes_payload: 1711  |


### threat-grid-analysis-processes-get
***
Returns data regarding the specific process id in the analysis


#### Base Command

`threat-grid-analysis-processes-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | the sample id. | Required |
| process_id | the process id requested. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.ProcessAnalysis.process_name | String | The process name |
| ThreatGrid.ProcessAnalysis.process_id | String | The process ID |

#### Command example
```!threat-grid-analysis-processes-get sample_id=sample_id```
#### Context Example
```json
{
    "ThreatGrid": {
        "ProcessAnalysis": {
            "1": {
                "analyzed_because": "Process activity after target sample started.",
                "atoms_added": [
                    "Ud"
                ],
                "kpid": "uid",
                "monitored": true,
                "mutants_created": [
                    "er",
                ],
                "new": false,
                "parent": "",
                "pid": 1692,
                "ppid": 61,
                "proc": false,
                "process_name": "Explorer.EXE",
                "registry_keys_created": [
                    {
                        "access": [
                            "CREATE_SUB_KEY",
                            "READ_CONTROL",
                            "SET_VALUE"
                        ],
                        "name": "REGISTRY",
                        "options": [
                            "REG_OPTION_VOLATILE"
                        ]
                    }
                ],
                "registry_keys_deleted": [
                    "REGISTRY",
                    "REGISTRY",
                ],
                "registry_keys_modified": [
                    {
                        "data": "data",
                        "data_type": "BINARY",
                        "name": "REGISTRY",
                        "value_name": "VirtualDesktop"
                    }
                ],
                "startup_info": {
                    "command_line": "info",
                    "current_directory": "info",
                    "desktop_info": "info",
                    "image_pathname": "info",
                    "incomplete": false,
                    "runtime_data": "",
                    "shell_info": "info",
                    "tid": "id",
                    "upid": 1692,
                    "uthread": 0,
                    "window_title": "Microsoft.Windows.Explorer"
                },
                "threads": [
                    {
                        "client_id": "id",
                        "create_suspended": "0x0",
                        "process": "0x00000000",
                        "process_handle": "0xffffffff",
                        "return": 0,
                        "thread": "0x00000000"
                    },
                ],
                "time": "Wed, 21 Dec 2022 12:10:16 UTC"
            },
            "12": {
                "analyzed_because": "Parent is being analyzed",
                "files_checked": [
                    "-active.pma",
                    "-spare.pma"
                ],
                "files_created": [
                    "-active.pma",
                    ".pma~RF3e02b2be.TMP"
                ],
                "files_deleted": [
                    ".pma",
                    ".pma~RF3e02b2be.TMP"
                ],
                "kpid": "0xffffe00144f57080",
                "monitored": true,
                "new": true,
                "parent": "0xffffe0014409e680",
                "pid": 2680,
                "ppid": 9,
                "proc": false,
                "process_name": "chrome.exe",
                "startup_info": {
                    "command_line": "ThreatGrid_ProcessAnalysis_12_startup_info_command_line",
                    "current_directory": "D:\\",
                    "desktop_info": "info",
                    "image_pathname": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "incomplete": false,
                    "runtime_data": "",
                    "shell_info": "",
                    "tid": "0xffffe00144f62400",
                    "upid": 2680,
                    "uthread": 0,
                    "window_title": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
                },
                "threads": [
                    {
                        "client_id": 6004801706494351000,
                        "create_suspended": "0x0",
                        "process": "0x00000000",
                        "process_handle": "0xffffffff",
                        "return": 0,
                        "thread": "0x00000000"
                    },
                    {
                        "client_id": 6071227511780497000,
                        "create_suspended": "0x0",
                        "process": "0x00000000",
                        "process_handle": "0xffffffff",
                        "return": 0,
                        "thread": "0x00000000"
                    }
                ],
                "time": "Wed, 21 Dec 2022 12:10:41 UTC"
            },
        }
    }
}
```

#### Human Readable Output

>### List of samples analysis:
>|1|12|
>|---|---|
>| threads: {'client_id': "id", 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': "id", 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 39480025973576, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 39480025973576, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 39480025973576, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 39480025973576, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 39480025973576, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 39480025973576, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'} <br/> atoms_added: ImmersiveContextMenuArray_159288160-13, <br/> ImmersiveContextMenuArray_159288160-14, <br/> ImmersiveContextMenuArray_159288448-11, <br/> ImmersiveContextMenuArray_159288448-13, <br/> ImmersiveContextMenuArray_159288448-14, <br/> ImmersiveContextMenuArray_159288448-17, <br/> ImmersiveContextMenuArray_159288736-10, <br/> ImmersiveContextMenuArray_159288736-12, <br/> ImmersiveContextMenuArray_159288736-13, <br/> ImmersiveContextMenuArray_159288736-17, <br/> ImmersiveContextMenuArray_159288832-12, <br/> ImmersiveContextMenuArray_159288832-14, <br/> ImmersiveContextMenuArray_159288832-16, <br/> ImmersiveContextMenuArray_159288832-17, <br/> ImmersiveContextMenuArray_159289024-11, <br/> ImmersiveContextMenuArray_159289024-12, <br/> ImmersiveContextMenuArray_159289600-18, <br/> ImmersiveContextMenuArray_159289696-17, <br/> ImmersiveContextMenuArray_159289696-18, <br/> ImmersiveContextMenuArray_159289888-16, <br/> ImmersiveContextMenuArray_159289888-18, <br/> ImmersiveContextMenuArray_159289984-15, <br/> ImmersiveContextMenuArray_4294967295, <br/> ImmersiveContextMenuArray_60889232-10, <br/> ImmersiveContextMenuArray_60889232-8, <br/> ImmersiveContextMenuArray_60889232-9, <br/> ImmersiveContextMenuArray_60890192-11, <br/> ImmersiveContextMenuArray_60890192-7, <br/> ImmersiveContextMenuArray_60890192-8, <br/> ImmersiveContextMenuArray_60890192-9, <br/> ImmersiveContextMenuArray_60891440-11, <br/> ImmersiveContextMenuArray_60891440-12, <br/> ImmersiveContextMenuArray_60891440-7, <br/> ImmersiveContextMenuArray_60891440-9, <br/> ImmersiveContextMenuArray_60891728-10, <br/> ImmersiveContextMenuArray_60891728-6, <br/> ImmersiveContextMenuArray_60891728-9, <br/> ImmersiveContextMenuArray_60891824-5, <br/> ImmersiveContextMenuArray_60891824-6, <br/> ImmersiveContextMenuArray_60891824-7, <br/> ImmersiveContextMenuArray_60891824-8, <br/> ImmersiveContextMenuArray_60891920-4, <br/> ImmersiveContextMenuArray_60891920-5, <br/> ImmersiveContextMenuArray_60891920-6, <br/> ImmersiveContextMenuArray_60891920-7, <br/> ImmersiveContextMenuArray_61294096-3, <br/> ImmersiveContextMenuArray_61294096-4, <br/> ImmersiveContextMenuArray_61294096-6, <br/> ImmersiveContextMenuArray_61295440-2, <br/> ImmersiveContextMenuArray_61295440-3, <br/> ImmersiveContextMenuArray_61295440-5, <br/> ImmersiveContextMenuArray_61295824-131233, <br/> ImmersiveContextMenuArray_61295824-2, <br/> ImmersiveContextMenuArray_61295824-4, <br/> ImmersiveContextMenuArray_61295824-5, <br/> ImmersiveContextMenuArray_61441088-1, <br/> ImmersiveContextMenuArray_61441088-4001, <br/> ImmersiveContextMenuArray_61441280-4002, <br/> ImmersiveContextMenuArray_61441568-2, <br/> ImmersiveContextMenuArray_61441856-4003, <br/> ImmersiveContextMenuArray_61441952-131233, <br/> ImmersiveContextMenuArray_61442144-4001, <br/> ImmersiveContextMenuArray_61442432-4002, <br/> ImmersiveContextMenuArray_61442528-4000, <br/> ImmersiveContextMenuArray_61442624-4000, <br/> ImmersiveContextMenuArray_61442720-1, <br/> ImmersiveContextMenuArray_61443008-1, <br/> ImmersiveContextMenuArray_61443008-4002, <br/> ImmersiveContextMenuArray_61443296-131233, <br/> ImmersiveContextMenuArray_61443296-4001, <br/> ImmersiveContextMenuArray_61443776-4000, <br/> ImmersiveContextMenuArray_61443968-1, <br/> ImmersiveContextMenuArray_61443968-4003, <br/> ImmersiveContextMenuArray_61444064-4002, <br/> ImmersiveContextMenuArray_61444160-4001, <br/> ImmersiveContextMenuArray_61444256-3, <br/> ImmersiveContextMenuArray_61444256-4000, <br/> ImmersiveContextMenuArray_61444448-2, <br/> ImmersiveContextMenuArray_61444736-131233, <br/> ImmersiveContextMenuArray_61444832-4003, <br/> TrayRaisedWindowProp, <br/> uia <br/> analyzed_because: Process activity after target sample started. <br/> registry_keys_created: {'access': ['CREATE_SUB_KEY', 'READ_CONTROL', 'SET_VALUE'], 'name': 'REGISTRY\\USER\\S-1-5-21-3467368655-986044752-3166994390-500\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SESSIONINFO\\1\\APPLICATIONVIEWMANAGEMENT\\W32:000000000006013C', 'options': ['REG_OPTION_VOLATILE']} <br/> monitored: true <br/> parent:  <br/> new: false <br/> mutants_created: Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_1280.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_16.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_1920.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_256.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_2560.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_32.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_48.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_768.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_96.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_custom_stream.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_exif.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_idx.db!IconCacheInit, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_idx.db!rwReaderRefs, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_idx.db!rwWriterMutex, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_sr.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_wide.db!dfMaintainer, <br/> Global\C::Users:Administrator:AppData:Local:Microsoft:Windows:Explorer:iconcache_wide_alternate.db!dfMaintainer <br/> pid: 1692 <br/> kpid: uid <br/> ppid: 61 <br/> time: Wed, 21 Dec 2022 12:10:16 UTC <br/> registry_keys_deleted: REGISTRY\USER\S-1-5-21-3467368655-986044752-3166994390-500\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\SESSIONINFO\1\APPLICATIONVIEWMANAGEMENT\W32:00000000000A0232, <br/> REGISTRY\USER\S-1-5-21-3467368655-986044752-3166994390-500\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\SESSIONINFO\1\APPLICATIONVIEWMANAGEMENT\W32:0000000000100036, <br/> REGISTRY\USER\S-1-5-21-3467368655-986044752-3166994390-500\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\HOMEGROUP\UISTATUSCACHE <br/> proc: false <br/> process_name: Explorer.EXE <br/> registry_keys_modified: {'data': 'EAAAADAwRFb0BwKtsB1qQ5DP0vmf3UYC', 'data_type': 'BINARY', 'name': 'REGISTRY\\USER\\S-1-5-21-3467368655-986044752-3166994390-500\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SESSIONINFO\\1\\APPLICATIONVIEWMANAGEMENT\\W32:000000000006013C', 'value_name': 'VirtualDesktop'} | files_checked: \Users\Administrator\AppData\Local\Google\Chrome\User Data\CrashpadMetrics-active.pma, <br/> \Users\Administrator\AppData\Local\Google\Chrome\User Data\CrashpadMetrics-spare.pma <br/> files_deleted: \Users\Administrator\AppData\Local\Google\Chrome\User Data\CrashpadMetrics.pma, <br/> \Users\Administrator\AppData\Local\Google\Chrome\User Data\CrashpadMetrics.pma~RF3e02b2be.TMP <br/> threads: {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 0, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 18375121096688828000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 18375121096688828000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6071227511780497000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6071227511780497000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'} <br/> analyzed_because: Parent is being analyzed <br/> files_created: \Users\Administrator\AppData\Local\Google\Chrome\User Data\CrashpadMetrics-active.pma, <br/> \Users\Administrator\AppData\Local\Google\Chrome\User Data\CrashpadMetrics.pma~RF3e02b2be.TMP <br/> monitored: true <br/> parent: 0xffffe0014409e680 <br/> new: true <br/> pid: 2680 <br/> kpid: 0xffffe00144f57080 <br/> ppid: 9 <br/> time: Wed, 21 Dec 2022 12:10:41 UTC <br/> proc: false <br/> process_name: chrome.exe | threads: {'client_id': 7820861427712559000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 7820861427712559000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 7820861427712559000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 7820861427712559000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 7820861427712559000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'} <br/> analyzed_because: Process activity after target sample started. <br/> monitored: true <br/> parent:  <br/> new: false <br/> pid: 840 <br/> kpid: 0xffffe0014497a840 <br/> ppid: 52 <br/> time: Wed, 21 Dec 2022 12:10:42 UTC <br/> proc: false <br/> process_name: svchost.exe | analyzed_because: Process activity after target sample started. <br/> monitored: true <br/> parent:  <br/> new: false <br/> pid: 236 <br/> kpid: 0xffffe001434ea080 <br/> ppid: null <br/> time: Wed, 21 Dec 2022 12:10:47 UTC <br/> proc: false <br/> process_name: svchost.exe | analyzed_because: Process activity after target sample started. <br/> monitored: true <br/> parent:  <br/> new: false <br/> pid: 1284 <br/> kpid: 0xffffe00144a89840 <br/> ppid: 52 <br/> time: Wed, 21 Dec 2022 12:10:48 UTC <br/> proc: false <br/> process_name: svchost.exe | analyzed_because: Process activity after target sample started. <br/> files_created: \Device\NamedPipe\Sessions\1\AppContainerNamedObjects\S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742 <br/> monitored: true <br/> parent:  <br/> new: false <br/> pid: 580 <br/> kpid: 0xffffe0014486e340 <br/> ppid: 52 <br/> time: Wed, 21 Dec 2022 12:10:48 UTC <br/> proc: false <br/> process_name: svchost.exe | analyzed_because: Process activity after target sample started. <br/> monitored: true <br/> parent:  <br/> new: false <br/> sockets: {'file_handle': '0x954', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624708.7818744}, <br/> {'file_handle': '0x9c0', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624708.830168}, <br/> {'file_handle': '0x98c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624714.8858435}, <br/> {'file_handle': '0x98c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624781.8725078}, <br/> {'file_handle': '0x98c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624792.5076175}, <br/> {'file_handle': '0x98c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624814.9515114}, <br/> {'file_handle': '0x98c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624821.0024314}, <br/> {'file_handle': '0x98c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624825.1760237}, <br/> {'file_handle': '0x968', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624835.1903608}, <br/> {'file_handle': '0x95c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624835.7948673}, <br/> {'file_handle': '0x95c', 'protocol': '0', 'state': 1, 'states': [], 'timestamp': 1671624858.605007} <br/> pid: 1100 <br/> kpid: 0xffffe00144cf1080 <br/> ppid: 52 <br/> time: Wed, 21 Dec 2022 12:10:52 UTC <br/> proc: false <br/> process_name: svchost.exe | files_checked: \Program Files\Google\Chrome\Application\88.0.4324.104\SwiftShader.ini <br/> threads: {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 0, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0x80000b48', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 6004801706494351000, 'create_suspended': '0x0', 'process': '0x00000000', 'process_handle': '0xffffffff', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 8397322214375721000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0x80000984', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 8397322214375721000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0x80000b40', 'return': 0, 'thread': '0x00000000'}, <br/> {'client_id': 8397322214375721000, 'create_suspended': '0x1', 'process': '0x00000000', 'process_handle': '0x80000b40', 'return': 0, 'thread': '0x00000000'} <br/> atoms_added: D3D9_IdHot_Ctrl_SnapDesktop <br/> analyzed_because: Parent is being analyzed <br/> monitored: true <br/> parent: 0xffffe0014409e680 <br/> new: true <br/> pid: 2296 <br/> kpid: 0xffffe0014444a840 <br/> ppid: 9 <br/> time: Wed, 21 Dec 2022 12:10:54 UTC <br/> proc: false <br/> process_name: chrome.exe |


### file
***
Checks the file reputation of the specified hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A CSV list of hashes of the file to query. Supports MD5, SHA1, and SHA256. | Required |
| long | Whether to return full response for scans. Default is "false". Possible values are: True, False. | Optional |
| threshold | If the number of positives is higher than the threshold, the file will be considered malicious. If the threshold is not specified, the default file threshold, as configured in the instance settings, will be used. | Optional |
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". Default is 60. | Optional |
| retries | Number of retries for the API rate limit. Default is "0". Default is 0. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | Bad MD5 hash. |
| File.Name | String | File name. |
| File.SHA1 | String | Bad SHA1 hash. |
| File.sha256 | String | Bad SHA256 hash. |
| File.EntryID | String | The entry ID of the file. |
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. |
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| ThreatGrid.File.PositiveDetections | number | Number of engines that positively detected the indicator as malicious. |
| ThreatGrid.File.DetectionEngines | number | Total number of engines that checked the indicator. |
| ThreatGrid.File.tgLink | string | ThreatGrid permanent link. |

### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required |
| long | Whether to return full response for detected URLs. Default is "false". Possible values are: True, False. | Optional |
| threshold | If the number of positives is higher than the threshold, the IP address will be considered malicious. If the threshold is not specified, the default IP threshold, as configured in the instance settings, will be used. | Optional |
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is "10". Default is 10. | Optional |
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". Default is 60. | Optional |
| retries | Number of retries for API rate limit. Default is "0". Default is 0. | Optional |
| fullResponse | Whether to return all results, which can be thousands. Default is "false". We recommend that you don't return full results in playbooks. Possible values are: True, False. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | Bad IP address. |
| IP.ASN | String | Bad IP ASN. |
| IP.Geo.Country | String | Bad IP country. |
| ThreatGrid.IP.indicator | String | IP address. |
| ThreatGrid.IP.confidence | Number | Indicator confidence between 0-99. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |

### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-seperated list of URLs to check. This command will not work properly on URLs containing commas. | Required |
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is 10. | Optional |
| long | Whether to return the full response for the detected URLs. Possible values are: True, False. | Optional |
| threshold | If the number of positives is higher than the threshold, the URL will be considered malicious. If the threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. | Optional |
| submitWait | Time (in seconds) to wait if the URL does not exist and is submitted for scanning. Default is "0". Default is 0. | Optional |
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". Default is 60. | Optional |
| retries | Number of retries for API rate limit. Default is "0". Default is 0. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | Bad URLs found. |
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. |
| URL.Malicious.Description | String | For malicious URLs, the reason that the vendor made the decision. |
| URL.PositiveDetections | Number | Number of engines that positively detected the indicator as malicious. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| ThreatGrid.URL.url | String | The URL. |
| ThreatGrid.URL.detection_engines | Number | Number of engines |
| ThreatGrid.URL.positive_engines | Number | Number of positive engines |

### domain
***
Checks the reputation of a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check. | Required |
| long | Whether to return the full response for detected URLs. Default is "false". Possible values are: True, False. | Optional |
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is 10. | Optional |
| threshold | If the number of positives is higher than the threshold, the domain will be considered malicious. If the threshold is not specified, the default domain threshold, as configured in the instance settings, will be used. | Optional |
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". Default is 60. | Optional |
| retries | Number of retries for API rate limit. Default is "0". Default is 0. | Optional |
| fullResponse | Whether to return all results, which can be thousands. Default is "false". We recommend that you don't return full results in playbooks. Possible values are: True, False. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Bad domain found. |
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. |
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Domain.CreationDate | Date | The date that the domain was created. |
| Domain.DNS | String | A list of IP objects resolved by DNS. |
| Domain.WHOIS.NameServers | String | Name servers of the domain. |
| Domain.WHOIS.Registrar.AbuseEmail | Unknown | The email address of the contact for reporting abuse. |
| Domain.WHOIS.Registrar.AbusePhone | Unknown | The phone number of contact for reporting abuse. |
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy". |
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. |
| Domain.WHOIS.DomainStatus | String | The status of the domain. |
| ThreatGrid.Domain.domain | String | The domain name. |

### threat-grid-domain-samples-list
***
Returns a list of samples associated with a Domain.


#### Base Command

`threat-grid-domain-samples-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to search for. | Required |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The number of items per page. | Optional |
| page | Page number of paginated results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.DomainAssociatedSample.domain | string | The domain. |
| ThreatGrid.DomainAssociatedSample.samples | string | The associated samples. |

#### Command example
```!threat-grid-domain-samples-list domain=domain_example```
#### Context Example
```json
{
    "ThreatGrid": {
        "DomainAssociatedSample": {
            "domain": "domain_example",
            "samples": [
                {
                    "details": "/api/v2/samples/sample_e",
                    "filename": "domain_example_.url",
                    "iocs": [],
                    "login": "login_name",
                    "owner": "self",
                    "private": false,
                    "relation": null,
                    "sample": "sample_e",
                    "sha256": "sha256_example",
                    "timestamp": "ThreatGrid_DomainAssociatedSample_samples[0]_timestamp"
                },
                {
                    "details": "/api/v2/samples/sample_e",
                    "filename": "file_name",
                    "iocs": [],
                    "login": null,
                    "owner": null,
                    "private": false,
                    "relation": null,
                    "sample": "sample_e",
                    "sha256": "sha256_e",
                    "timestamp": "ThreatGrid_DomainAssociatedSample_samples[1]_timestamp"
                },
            ]
        }
    }
}
```

#### Human Readable Output

>### List of samples associated to the domain - domain_example :
> Showing page 1.
> Current page size: 50
>|Filename|Login|Private|Sample|Sha256|Timestamp|
>|---|---|---|---|---|---|
>| domain_example_.url | login_name | false | sample_e | sha256_example | 2022-12-22T08:30:57Z |
>| file_name |  | false | sample_e | sha256_e | 2022-12-22T08:29:38Z |


### threat-grid-ip-samples-list
***
Returns a list of samples associated with an IP.


#### Base Command

`threat-grid-ip-samples-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to search for. | Required |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The number of items per page. | Optional |
| page | Page number of paginated results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.IpAssociatedSample.ip | string | The IP. |
| ThreatGrid.IpAssociatedSample.samples | string | The associated samples. |

#### Command example
```!threat-grid-ip-samples-list ip=8.8.8.8```
#### Context Example
```json
{
    "ThreatGrid": {
        "IpAssociatedSample": {
            "ip": "ThreatGrid_IpAssociatedSample_ip",
            "samples": [
                {
                    "details": "/api/v2/samples/sample_e",
                    "filename": "filename",
                    "iocs": [
                        {
                            "confidence": 60,
                            "ioc": "pe-header-linker-major",
                            "sample": "sample_e",
                            "severity": 5
                        }
                    ],
                    "login": null,
                    "owner": null,
                    "private": false,
                    "relation": null,
                    "sample": "sample_e",
                    "sha256": "sha256_e",
                    "timestamp": "ThreatGrid_IpAssociatedSample_samples[0]_timestamp"
                },
                {
                    "details": "/api/v2/samples/sample_e",
                    "filename": "file_name",
                    "iocs": [
                        {
                            "confidence": 50,
                            "ioc": "file-ini-read",
                            "sample": "sample_e",
                            "severity": 30
                        },
                        {
                            "confidence": 60,
                            "ioc": "pe-resource-lang-romanian",
                            "sample": "sample_e",
                            "severity": 25
                        },
                        {
                            "confidence": 50,
                            "ioc": "network-fast-flux-nameserver",
                            "sample": "sample_e",
                            "severity": 35
                        }
                    ],
                    "login": null,
                    "owner": null,
                    "private": false,
                    "relation": null,
                    "sample": "sample_e",
                    "sha256": "sha256_e",
                    "timestamp": "ThreatGrid_IpAssociatedSample_samples[1]_timestamp"
                },

            ]
        }
    }
}
```

#### Human Readable Output

>### List of samples associated to the ip - 8.8.8.8 :
> Showing page 1.
> Current page size: 50
>|Filename|Login|Private|Sample|Sha256|Timestamp|
>|---|---|---|---|---|---|
>| filename |  | false | sample_e | sha256_e | 2022-12-22T08:09:30Z |
>| file_name |  | false | sample_e | sha256_e | 2022-12-22T08:07:40Z |


### threat-grid-path-samples-list
***
Returns a list of samples associated with a Path.


#### Base Command

`threat-grid-path-samples-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path to search for. A path is a slash-separated list of directory names followed by either a directory name or a file name. Path example: ‘/user/name/file’. | Required |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_zise | The number of items per page. | Optional |
| page | Page number of paginated results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.PathAssociatedSample.path | string | The Path. |
| ThreatGrid.PathAssociatedSample.samples | string | The associated samples. |

#### Command example
```!threat-grid-path-samples-list path=user```
#### Context Example
```json
{
    "ThreatGrid": {
        "PathAssociatedSample": {
            "path": "user",
            "samples": [
                {
                    "details": "/api/v2/samples/sample_e",
                    "filename": "user",
                    "iocs": [
                        {
                            "confidence": 100,
                            "ioc": "html-script-prefix-suffix",
                            "sample": "sample_e",
                            "severity": 85
                        }
                    ],
                    "login": null,
                    "owner": null,
                    "private": false,
                    "relation": null,
                    "sample": "sample_e",
                    "sha256": "sha256_e",
                    "timestamp": "ThreatGrid_PathAssociatedSample_samples[0]_timestamp"
                },
                {
                    "details": "/api/v2/samples/sample_e",
                    "filename": "file_name",
                    "iocs": [
                        {
                            "confidence": 85,
                            "ioc": "pe-invalid-certificate-signature",
                            "sample": "sample_e",
                            "severity": 100
                        },
                        {
                            "confidence": 100,
                            "ioc": "pe-certificate",
                            "sample": "sample_e",
                            "severity": 10
                        }
                    ],
                    "login": null,
                    "owner": null,
                    "private": false,
                    "relation": null,
                    "sample": "sample_e",
                    "sha256": "sha256_e",
                    "timestamp": "ThreatGrid_PathAssociatedSample_samples[1]_timestamp"
                },
            ]
        }
    }
}
```

#### Human Readable Output

>### List of samples associated to the path - user :
> Showing page 1.
> Current page size: 50
>|Filename|Login|Private|Sample|Sha256|Timestamp|
>|---|---|---|---|---|---|
>| user |  | false | sample_e | sha256_e | 2022-11-11T08:26:04Z |
>| file_name |  | false | sample_e | sha256_e | 2022-10-30T13:09:35Z |


### threat-grid-url-samples-list
***
Returns a list of samples associated with an URL.


#### Base Command

`threat-grid-url-samples-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The target URL. Please provide the URL in the format http://example.com:80/ . | Required |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_zise | The number of items per page. | Optional |
| page | Page number of paginated results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.UrlAssociatedSample.url | string | The URL. |
| ThreatGrid.UrlAssociatedSample.samples | string | The associated samples. |

#### Command example
```!threat-grid-url-samples-list url=http://domain_example:80/```
#### Context Example
```json
{
    "ThreatGrid": {
        "UrlAssociatedSample": {
            "samples": [
                {
                    "details": "/api/v2/samples/sample_id",
                    "filename": "file_name",
                    "iocs": [
                        {
                            "confidence": 25,
                            "ioc": "network-communications-http-get-url",
                            "sample": "sample_id",
                            "severity": 25
                        }
                    ],
                    "login": "login_name",
                    "owner": "self",
                    "private": false,
                    "relation": null,
                    "sample": "sample_id",
                    "sha256": "sha256_example",
                    "timestamp": "ThreatGrid_UrlAssociatedSample_samples[0]_timestamp"
                },
                {
                    "details": "/api/v2/samples/sample_id",
                    "filename": "file_name",
                    "iocs": [
                        {
                            "confidence": 90,
                            "ioc": "pe-uses-stealth-packer",
                            "sample": "sample_id",
                            "severity": 90
                        }
                    ],
                    "login": null,
                    "owner": null,
                    "private": false,
                    "relation": null,
                    "sample": "sample_id",
                    "sha256": "sha256_example",
                    "timestamp": "ThreatGrid_UrlAssociatedSample_samples[1]_timestamp"
                },
            ],
            "sha256": "sha256_example",
            "url": "ThreatGrid_UrlAssociatedSample_url"
        }
    }
}
```

#### Human Readable Output

>### List of samples associated to the url - sha256_example :
> Showing page 1.
> Current page size: 50
>|Filename|Login|Private|Sample|Sha256|Timestamp|
>|---|---|---|---|---|---|
>| domain_example_.url | login_name | false | sample_id | sha256_example | 2022-12-22T08:36:44Z |
>| file_name |  | false | sample_id | sha256_example | 2022-12-22T08:35:03Z |
>| file_name |  | false | sample_id | sha256_example | 2022-12-22T08:35:03Z |
>| domain_example_.url | login_name | false | sample_e | sha256_example | 2022-12-22T08:30:57Z |


### threat-grid-registry-key-samples-list
***
Returns a list of samples associated with a specified registry key.


#### Base Command

`threat-grid-registry-key-samples-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| registry_key | The registry key to search for. | Required |
| after | "A date/time (ISO 8601), restricting results to samples submitted after it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| before | "A date/time (ISO 8601), restricting results to samples submitted before it. Please use the following date/time format. YYYY-MM-DD Thhmmss+\|-hhmm e.g. : 2012-04-19T04:00:55-0500". | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The number of items per page. | Optional |
| page | Page number of paginated results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.RegistryKeyAssociatedSample.key | string | The Registry Key. |
| ThreatGrid.RegistryKeyAssociatedSample.samples | string | The associated samples. |

#### Command example
```!threat-grid-registry-key-samples-list registry_key=ChangeNotice```
#### Context Example
```json
{
    "ThreatGrid": {
        "RegistryKeyAssociatedSample": {
            "key": "ChangeNotice",
            "samples": []
        }
    }
}
```

#### Human Readable Output

>### List of samples associated to the registry_key - ChangeNotice :
> Showing page 1.
> Current page size: 50
>**No entries.**


### threat-grid-ip-associated-domains
***
Returns a list of domains associated with the IP.


#### Base Command

`threat-grid-ip-associated-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to search for. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.IpAssociatedDomain.ip | string | The IP. |
| ThreatGrid.IpAssociatedDomain.domains | string | The associated Domain. |

#### Command example
```!threat-grid-ip-associated-domains ip=8.8.8.8```
#### Context Example
```json
{
    "ThreatGrid": {
        "IpAssociatedDomain": {
            "domains": [
                {
                    "details": "/api/v2/domains/domain",
                    "domain": "domain"
                },
                {
                    "details": "/api/v2/domains/domain",
                    "domain": "domain"
                },
            ],
            "ip": "ThreatGrid_IpAssociatedDomain_ip"
        }
    }
}
```

#### Human Readable Output

>### List of domains associated to the ip - 8.8.8.8 :
>|Domain|
>|---|
>| domain2 |
>| domain1 |



### threat-grid-ip-associated-urls
***
Returns a list of URLs associated to the IP.


#### Base Command

`threat-grid-ip-associated-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to search for. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.IpAssociatedUrl.ip | string | The IP. |
| ThreatGrid.IpAssociatedUrl.urls | string | The associated URL. |

#### Command example
```!threat-grid-ip-associated-urls ip=8.8.8.8```
#### Context Example
```json
{
    "ThreatGrid": {
        "IpAssociatedUrl": {
            "ip": "ThreatGrid_IpAssociatedUrl_ip",
            "urls": [
                {
                    "details": "/api/v2/urls/sha256",
                    "sha256": "sha256",
                    "url": "ThreatGrid_IpAssociatedUrl_urls[0]_url"
                },
                {
                    "details": "/api/v2/urls/sha256",
                    "sha256": "sha256",
                    "url": "ThreatGrid_IpAssociatedUrl_urls[1]_url"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### List of urls associated to the ip - 8.8.8.8 :
>|Sha256|Url|
>|---|---|
>| sha256 | ThreatGrid_IpAssociatedUrl_urls[0]_url |
>| sha256 | ThreatGrid_IpAssociatedUrl_urls[1]_url |


### threat-grid-domain-associated-urls
***
Returns a list of URLs associated to the domain.


#### Base Command

`threat-grid-domain-associated-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to search for. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.DomainAssociatedUrl.domain | string | The Domain. |
| ThreatGrid.DomainAssociatedUrl.urls | string | The associated URL. |

#### Command example
```!threat-grid-domain-associated-urls domain=domain_example```
#### Context Example
```json
{
    "ThreatGrid": {
        "DomainAssociatedUrl": {
            "domain": "domain_example",
            "urls": [
                {
                    "details": "/api/v2/urls/sha256",
                    "sha256": "sha256",
                    "url": "ThreatGrid_DomainAssociatedUrl_urls[0]_url"
                },
                {
                    "details": "/api/v2/urls/sha256",
                    "sha256": "sha256",
                    "url": "ThreatGrid_DomainAssociatedUrl_urls[1]_url"
                },
            ]
        }
    }
}
```

#### Human Readable Output

>### List of urls associated to the domain - domain_example :
>|Sha256|Url|
>|---|---|
>| sha256 | some_url |
>| sha256 | some_url |



### threat-grid-domain-associated-ips
***
Returns a list of IPs associated to the domain.


#### Base Command

`threat-grid-domain-associated-ips`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to search for. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGrid.DomainAssociatedIp.domain | String | The Domain. |
| ThreatGrid.DomainAssociatedIp.ips | String | The associated IP. |

#### Command example
```!threat-grid-domain-associated-ips domain=domain_example```
#### Context Example
```json
{
    "ThreatGrid": {
        "DomainAssociatedIp": {
            "domain": "domain_example",
            "ips": [
                {
                    "ip": "ThreatGrid_DomainAssociatedIp_ips[0]_ip"
                },
                {
                    "ip": "ThreatGrid_DomainAssociatedIp_ips[1]_ip"
                },

            ]
        }
    }
}
```

#### Human Readable Output

>### List of ips associated to the domain - domain_example :
>|Ip|
>|---|
>| ip_address |
>| ip_address |
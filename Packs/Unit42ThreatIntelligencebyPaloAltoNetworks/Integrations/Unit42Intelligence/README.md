Enrich indicators with Unit 42 threat intelligence context including verdicts, threat object associations, and relationships.

## Configure Unit 42 Intelligence in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Create relationships | Create relationships between indicators and threat objects | False |
| Create threat objects as separate indicators | Whether to create threat objects \(malware families, actors, campaigns, etc.\) as separate XSOAR indicators | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Enrich an IP address with Unit 42 threat intelligence context.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. |
| IP.Malicious.Vendor | String | The vendor reporting the IP as malicious. |
| IP.Malicious.Description | String | Description of the malicious IP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Unit42.IP.Value | String | The IP address. |
| Unit42.IP.Type | String | The indicator type. |
| Unit42.IP.Counts | Unknown | Counts. |
| Unit42.IP.Verdict | String | The verdict for the IP. |
| Unit42.IP.VerdictCategory | Unknown | The verdict category. |
| Unit42.IP.FirstSeen | Date | First seen date. |
| Unit42.IP.LastSeen | Date | Last seen date. |
| Unit42.IP.SeenBy | Unknown | Sources that have seen this IP. |
| Unit42.IP.EnrichedThreatObjectAssociation | Unknown | Enriched threat object association. |

#### Command example

```!ip ip="8.8.8.8"```

#### Context Example

```json
{
    "Unit42.IP": {
        "Counts": [
            {
                "count_type": "wf_sample",
                "count_values": {
                    "benign": 246022,
                    "grayware": 214,
                    "malware": 3176800
                }
            }
        ],
        "EnrichedThreatObjectAssociation": null,
        "FirstSeen": "",
        "LastSeen": "",
        "SeenBy": [
            "wf_sample"
        ],
        "Type": "IP",
        "Value": "8.8.8.8",
        "Verdict": "malicious",
        "VerdictCategory": null
    }
}
```

#### Human Readable Output

>### Unit 42 Intelligence results for IP: 8.8.8.8
>
>|Value|Verdict|Verdict Category|Seen By|First Seen|Last Seen|
>|---|---|---|---|---|---|
>| 8.8.8.8 | malicious |  | wf_sample |  |  |

### domain

***
Enrich a domain with Unit 42 threat intelligence context.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. |
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. |
| Domain.Malicious.Description | String | Description of the malicious domain. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Unit42.Domain.Value | String | The domain name. |
| Unit42.Domain.Type | String | The indicator type. |
| Unit42.Domain.Counts | Unknown | Counts. |
| Unit42.Domain.Verdict | String | The verdict for the domain. |
| Unit42.Domain.VerdictCategory | Unknown | The verdict category. |
| Unit42.Domain.FirstSeen | Date | First seen date. |
| Unit42.Domain.LastSeen | Date | Last seen date. |
| Unit42.Domain.SeenBy | Unknown | Sources that have seen this domain. |
| Unit42.Domain.EnrichedThreatObjectAssociation | Unknown | Enriched threat object association. |

#### Command example

```!domain domain="example.com"```

#### Context Example

```json
{
    "Unit42.Domain":{
        "Counts": null,
        "EnrichedThreatObjectAssociation": null,
        "FirstSeen": "",
        "LastSeen": "",
        "SeenBy": null,
        "Type": "Domain",
        "Value": "example.com",
        "Verdict": "benign",
        "VerdictCategory": [
            "allowlist_dict_dga"
        ]
    }
}
```

#### Human Readable Output

>### Unit 42 Intelligence results for Domain: example.com
>
>|Value|Verdict|Verdict Category|Seen By|First Seen|Last Seen|
>|---|---|---|---|---|---|
>| example.com | benign | allowlist_dict_dga | wf_sample |  |  |

### url

***
Enrich a URL with Unit 42 threat intelligence context.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. |
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. |
| URL.Malicious.Description | String | Description of the malicious URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Unit42.URL.Value | String | The URL. |
| Unit42.URL.Type | String | The indicator type. |
| Unit42.URL.Counts | Unknown | Counts. |
| Unit42.URL.Verdict | String | The verdict for the URL. |
| Unit42.URL.VerdictCategory | Unknown | The verdict category. |
| Unit42.URL.FirstSeen | Date | First seen date. |
| Unit42.URL.LastSeen | Date | Last seen date. |
| Unit42.URL.SeenBy | Unknown | Sources that have seen this URL. |
| Unit42.URL.EnrichedThreatObjectAssociation | Unknown | Enriched threat object association. |

#### Command example

```!url url="https://en.wikipedia.org/wiki/URL"```

#### Context Example

```json
{
    "Unit42.URL": {
        "Counts": [
            {
                "count_type": "wf_sample",
                "count_values": {
                    "benign": 97,
                    "grayware": 0,
                    "malware": 0
                }
            }
        ],
        "EnrichedThreatObjectAssociation": null,
        "FirstSeen": "",
        "LastSeen": "",
        "SeenBy": [
            "wf_sample"
        ],
        "Type": "URL",
        "Value": "https://en.wikipedia.org/wiki/URL",
        "Verdict": "unknown",
        "VerdictCategory": null
    }
}
```

#### Human Readable Output

>### Unit 42 Intelligence results for URL: https://en.wikipedia.org/wiki/URL
>
>|Value|Verdict|Verdict Category|Seen By|First Seen|Last Seen|
>|---|---|---|---|---|---|
>| https://en.wikipedia.org/wiki/URL | unknown |  | wf_sample |  |  |

### file

***
Enrich a file hash with Unit 42 threat intelligence context.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash to enrich (MD5, SHA1, or SHA256). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Malicious.Vendor | String | The vendor reporting the file as malicious. |
| File.Malicious.Description | String | Description of the malicious file. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Unit42.File.Value | String | The file hash. |
| Unit42.File.Type | String | The indicator type. |
| Unit42.File.Counts | Unknown | Counts. |
| Unit42.File.Verdict | String | The verdict for the file. |
| Unit42.File.VerdictCategory | Unknown | The verdict category. |
| Unit42.File.FirstSeen | Date | First seen date. |
| Unit42.File.LastSeen | Date | Last seen date. |
| Unit42.File.SeenBy | Unknown | Sources that have seen this file. |
| Unit42.File.EnrichedThreatObjectAssociation | Unknown | Enriched threat object association. |

#### Command example

```!file file="123456abcdef"```

#### Context Example

```json
{
    "Unit42.File": {
        "Counts": [
            {
                "count_type": "wf_sample",
                "count_values": {
                    "benign": 0,
                    "grayware": 0,
                    "malware": 3
                }
            }
        ],
        "EnrichedThreatObjectAssociation": null,
        "FirstSeen": "",
        "LastSeen": "",
        "SeenBy": [
            "wf_sample"
        ],
        "Type": "File",
        "Value": "123456abcdef",
        "Verdict": "malicious",
        "VerdictCategory": null
    }
}
```

#### Human Readable Output

>### Unit 42 Intelligence results for File: 123456abcdef
>
>|Value|Verdict|Verdict Category|Seen By|First Seen|Last Seen|
>|---|---|---|---|---|---|
>| 123456abcdef | malicious |  | wf_sample |  |  |

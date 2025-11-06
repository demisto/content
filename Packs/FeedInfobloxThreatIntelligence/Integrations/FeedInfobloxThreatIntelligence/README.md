The Infoblox Threat Intelligence Feed retrieves the discovered indicators from the Infoblox platform based on user-specified filters.
This integration was integrated and tested with version 1.0.0 of InfobloxThreatIntelligenceFeed.

## Configure Infoblox Threat Intelligence Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service API Key | Service API key for Infoblox TIDE API authentication | True |
| Fetch indicators |  | False |
| Indicator Types | The type of indicators to be retrieved. | False |
| First Fetch Time | The date or relative timestamp from where to start fetching indicators.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2025, 01 Mar 2025 04:45:33, 2025-05-17T04:45:33Z<br/><br/>Note: The maximum allowed relative time is 4 hours or 240 minutes. | False |
| Max Indicators Per Fetch | The maximum number of indicators to fetch in each run.<br/><br/>Note: The maximum allowed value is 50000. | False |
| DGA Threat | Filter the indicators having threats originated from dynamically generated algorithms. | False |
| Threat Classes | Filters the indicators according to the selected threat classes. | False |
| Data Providers | Filter indicators by data provider profiles. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator Expiration Method |  | False |
| Feed Fetch Interval | Time interval for fetching indicators.<br/><br/>Note: The maximum allowed interval is 4 hours or 240 minutes. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### infoblox-cloud-get-indicators

***
Fetches a given limit of indicators from the Infoblox platform and displays them in human-readable format in the war room.

#### Base Command

`infoblox-cloud-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to retrieve.<br/><br/>Note: The maximum allowed value is 50000. Default is 50. | Optional |
| indicator_types | The type of indicators to be retrieved. Supports comma-separated values. Possible values are: IP, HOST, URL, EMAIL, HASH. | Optional |
| from_date | The date or relative timestamp from which indicator retrieval begins.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2025, 01 Mar 2025 04:45:33, 2025-05-17T04:45:33Z. | Optional |
| to_date | The date or relative timestamp up to which indicator retrieval ends.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2025, 01 Mar 2025 04:45:33, 2025-05-17T04:45:33Z. | Optional |
| dga_threat | Filter the indicators having threats originated from dynamically generated algorithms. Possible values are: Yes, No. | Optional |
| threat_classes | Filters the indicators according to the provided threat classes. Supports comma-separated values. Possible values are: APT, Bot, CompromisedDomain, CompromisedHost, Cryptocurrency, DDoS, DNSTunnel, ExploitKit, ICS, IllegalContent, InternetInfrastructure, IntrusionAttempt, LimitedDistro, Malicious, MaliciousNameserver, MalwareC2, MalwareC2DGA, MalwareDownload, Parked, Phishing, Policy, PolicyViolation, Proxy, Scam, Sinkhole, Spambot, Suspicious, UncategorizedThreat, Undefined, UnwantedContent, WebAppAttack, Whitelist. | Optional |
| data_provider_profiles | Filters the indicators according to the given data providers. Supports comma-separated values. Possible values are: IID, AISCOMM. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.FeedIndicator.id | String | Unique identifier of the indicator. |
| Infoblox.FeedIndicator.type | String | Type of the indicator \(HOST, IP, URL, EMAIL, HASH\). |
| Infoblox.FeedIndicator.host | String | Hostname of the indicator. |
| Infoblox.FeedIndicator.domain | String | Domain of the indicator. |
| Infoblox.FeedIndicator.ip | String | IP address of the indicator. |
| Infoblox.FeedIndicator.email | String | Email address of the indicator. |
| Infoblox.FeedIndicator.hash | String | Hash of the indicator. |
| Infoblox.FeedIndicator.hash_type | String | Hash type of the indicator. |
| Infoblox.FeedIndicator.url | String | URL of the indicator. |
| Infoblox.FeedIndicator.value | String | The indicator value. |
| Infoblox.FeedIndicator.tld | String | Top-level domain of the indicator. |
| Infoblox.FeedIndicator.threat_level | Number | Threat level of the indicator \(0-100\). |
| Infoblox.FeedIndicator.threat_label | String | Threat label of the indicator. |
| Infoblox.FeedIndicator.confidence | Number | Confidence level of the indicator \(0-100\). |
| Infoblox.FeedIndicator.threat_class | String | Threat class of the indicator. |
| Infoblox.FeedIndicator.property | String | Property of the indicator. |
| Infoblox.FeedIndicator.profile | String | Profile of the indicator. |
| Infoblox.FeedIndicator.detected | Date | Detection timestamp. |
| Infoblox.FeedIndicator.received | Date | Reception timestamp. |
| Infoblox.FeedIndicator.expiration | Date | Expiration timestamp. |
| Infoblox.FeedIndicator.up | String | Status of the indicator. |
| Infoblox.FeedIndicator.dga | String | Domain generation algorithm. |
| Infoblox.FeedIndicator.batch_id | String | Batch ID of the indicator. |
| Infoblox.FeedIndicator.threat_score | Number | Threat score of the indicator. |
| Infoblox.FeedIndicator.threat_score_rating | String | Threat score rating of the indicator. |
| Infoblox.FeedIndicator.threat_score_vector | String | Threat score vector of the indicator. |
| Infoblox.FeedIndicator.confidence_score | Number | Confidence score of the indicator. |
| Infoblox.FeedIndicator.confidence_score_rating | String | Confidence score rating of the indicator. |
| Infoblox.FeedIndicator.confidence_score_vector | String | Confidence score vector of the indicator. |
| Infoblox.FeedIndicator.extended.notes | String | Notes for the indicator. |
| Infoblox.FeedIndicator.extended.comments | String | Comments for the indicator. |
| Infoblox.FeedIndicator.extended.cyberint_guid | String | GUID of the indicator. |
| Infoblox.FeedIndicator.extended.protocol | String | Protocol of the indicator. |
| Infoblox.FeedIndicator.extended.references | String | References of the indicator. |
| Infoblox.FeedIndicator.extended.original_profile | String | Original profile of the indicator. |
| Infoblox.FeedIndicator.extended.attack_chain | String | Attack chain of the indicator. |
| Infoblox.FeedIndicator.extended.sample_sha256 | String | SHA256 of the sample. |

#### Command example

```!infoblox-cloud-get-indicators limit="5" indicator_types="EMAIL,IP,HOST,HASH,URL" from_date="2023-01-01T00:00:00.000Z" to_date="2024-12-31T23:59:59.999Z"```

#### Context Example

```json
{
    "Infoblox": {
        "FeedIndicator": [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "type": "EMAIL",
                "host": "example.com",
                "email": "test@example.com",
                "domain": "example.com",
                "tld": "com",
                "profile": "IID",
                "property": "APT_testC2",
                "threat_class": "APT",
                "threat_level": 80,
                "expiration": "2043-01-06T00:41:57.421Z",
                "detected": "2023-01-11T00:41:57.421Z",
                "received": "2023-01-11T00:46:38.969Z",
                "imported": "2023-01-11T00:46:38.969Z",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000001",
                "threat_score": 9.1,
                "threat_score_rating": "Critical",
                "threat_score_vector": "TSIS:1.0/AV:N/AC:L/PR:L/UI:N/EX:H/MOD:L/AVL:L/CI:N/ASN:N/TLD:N/DOP:N/P:T",
                "risk_score": 9.9,
                "risk_score_rating": "Critical",
                "risk_score_vector": "RSIS:1.0/TSS:C/TLD:N/CVSS:C/EX:H/MOD:L/AVL:L/T:H/DT:H",
                "confidence_score": 8.1,
                "confidence_score_rating": "High",
                "confidence_score_vector": "COSIS:1.0/SR:H/POP:N/TLD:N/CP:T",
                "extended": {
                    "cyberint_guid": "00000000000000000000000000000001",
                    "notes": "The email address is part of a cluster of test domains."
                }
            },
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "type": "IP",
                "ip": "0.0.0.0",
                "profile": "IID",
                "property": "APT_testC2",
                "threat_class": "APT",
                "threat_level": 100,
                "expiration": "2042-11-01T09:29:18.721Z",
                "detected": "2022-11-01T09:29:18.721Z",
                "received": "2022-11-01T09:31:39.329Z",
                "imported": "2022-11-01T09:31:39.329Z",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000002",
                "threat_score": 10,
                "threat_score_rating": "Critical",
                "threat_score_vector": "TSIS:1.0/AV:N/AC:L/PR:L/UI:N/EX:H/MOD:H/AVL:L/CI:N/ASN:N/TLD:N/DOP:N/P:T",
                "risk_score": 9.9,
                "risk_score_rating": "Critical",
                "risk_score_vector": "RSIS:1.0/TSS:C/TLD:N/CVSS:C/EX:H/MOD:H/AVL:L/T:H/DT:H",
                "confidence_score": 0.1,
                "confidence_score_rating": "Unconfirmed",
                "confidence_score_vector": "COSIS:1.0/SR:N/POP:N/TLD:N/CP:T",
                "extended": {
                    "cyberint_guid": "00000000000000000000000000000002",
                    "notes": "test notes for APT testC2."
                }
            },
            {
                "id": "00000000-0000-0000-0000-000000000003",
                "type": "HOST",
                "host": "test.net",
                "domain": "test.net",
                "tld": "net",
                "profile": "IID",
                "property": "MalwareC2_testRAT",
                "threat_class": "MalwareC2",
                "threat_level": 100,
                "threat_label": "LowProfileC2Beacon",
                "expiration": "2026-04-15T23:54:58.665Z",
                "detected": "2024-04-15T23:54:58.665Z",
                "received": "2024-04-17T16:14:57.694Z",
                "imported": "2024-04-17T16:14:57.694Z",
                "dga": "false",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000003",
                "threat_score": 10,
                "threat_score_rating": "Critical",
                "threat_score_vector": "TSIS:1.0/AV:N/AC:L/PR:L/UI:N/EX:H/MOD:H/AVL:L/CI:N/ASN:N/TLD:N/DOP:N/P:T",
                "risk_score": 9.7,
                "risk_score_rating": "Critical",
                "risk_score_vector": "RSIS:1.0/TSS:C/TLD:N/CVSS:M/EX:H/MOD:H/AVL:L/T:H/DT:M",
                "confidence_score": 8.1,
                "confidence_score_rating": "High",
                "confidence_score_vector": "COSIS:1.0/SR:H/POP:N/TLD:N/CP:T",
                "extended": {
                    "cyberint_guid": "00000000000000000000000000000003",
                    "notes": "These domains appear to be set up for the DECOY DOG toolkit identified by Infoblox targeting enterprise infrastructure."
                }
            },
            {
                "id": "00000000-0000-0000-0000-000000000004",
                "type": "HASH",
                "hash": "000000000000000000000000000000000000000000000000000000000000001",
                "hash_type": "SHA256",
                "profile": "IID",
                "property": "MalwareC2_Azorult",
                "threat_class": "MalwareC2",
                "threat_level": 100,
                "expiration": "2025-08-25T20:00:34.12Z",
                "detected": "2024-08-25T20:00:34.12Z",
                "received": "2024-08-25T20:01:35.75Z",
                "imported": "2024-08-25T20:01:35.75Z",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000005",
                "extended": {
                    "cyberint_guid": "00000000000000000000000000000005",
                    "notes": "The file uses Living off the Land (LotL) methods, a malicious technique that involves abusing pre-built software on the victim's machine to execute attacks. This binary matches the threat signature",
                    "sample_sha256": "000000000000000000000000000000000000000000000000000000000000001"
                }
            },
            {
                "id": "00000000-0000-0000-0000-000000000005",
                "type": "URL",
                "ip": "0.0.0.0",
                "url": "http://0.0.0.0/example",
                "profile": "IID",
                "property": "MalwareC2_Generic",
                "threat_class": "MalwareC2",
                "threat_level": 100,
                "expiration": "2025-10-01T10:32:58.891Z",
                "detected": "2025-06-03T10:32:58.891Z",
                "received": "2025-06-03T10:36:37.283Z",
                "imported": "2025-06-03T10:36:37.283Z",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000005",
                "extended": {
                    "attack_chain": "ACIS",
                    "cyberint_guid": "00000000000000000000000000000005",
                    "notes": "Exfiltration target of Cuckoo Stealer for MacOS (SHA256: 00000000000000000000000000000005)",
                    "protocol": "http",
                    "references": "https://www.example.com/gui/file/00000000000000000000000000000005"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Infoblox TIDE Indicators: Found 5 indicators between 2023-01-01T00:00:00.000Z and 2024-12-31T23:59:59.999Z
>
>|Type|Value|Threat Class|Confidence|Threat Level|Expiration|Property|Profile|
>|---|---|---|---|---|---|---|---|
>| Email | test@example.com | APT | 100 | 80 | 2043-01-06T00:41:57.421Z | APT_testC2 | IID |
>| IP | 0.0.0.0 | APT | 100 | 100 | 2042-11-01T09:29:18.721Z | APT_testC2 | IID |
>| Domain | test.net | MalwareC2 | 100 | 100 | 2026-04-15T23:54:58.665Z | MalwareC2_testRAT | IID |
>| File | 000000000000000000000000000000000000000000000000000000000000001 | MalwareC2 | 100 | 100 | 2025-08-25T20:00:34.12Z | MalwareC2_Azorult | IID |
>| URL | http://0.0.0.0/example | MalwareC2 | 100 | 100 | 2025-10-01T10:32:58.891Z | MalwareC2_Generic | IID |

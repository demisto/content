# SOCRadar Rapid Reputation

Enrich indicators (IP, Domain, URL, Hash) by obtaining reputation information via SOCRadar's Rapid Reputation API.

This integration was integrated and tested with the latest version of SOCRadar Rapid Reputation API.

## Configure SOCRadarRapidReputation on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SOCRadarRapidReputation.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key to use for connection to SOCRadar Rapid Reputation API. | True |
    | Trust any certificate (not secure) | Trust any certificate (not secure). | False |
    | Use system proxy settings | Whether to use XSOAR's system proxy settings to connect to the API. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |

4. Click **Test** to validate API key and connection to SOCRadar Rapid Reputation API.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### How to obtain SOCRadar API key?

SOCRadar Rapid Reputation is an **Advanced Intelligence API** optimized for high-volume and fast reputation queries.

* **Licensing Model:** The features of this module are licensed separately from the standard SOCRadar platform package. To use the integration, your API key must be activated with "Rapid Reputation" privileges.
* **Standalone Purchase:** This service can be added to your existing SOCRadar subscription, or it can be purchased as a **standalone key** completely independent of a platform membership.
* **Purchase & Activation:** For API authorization, pricing information, or to purchase a new key, please contact our support team at **support@socradar.io**.

---

---

### socradar-bulk-check

🎯 **NEW FEATURE** - Bulk check reputation for mixed list of indicators with automatic entity type detection.

This powerful command allows you to check reputation for a mixed list of IPs, domains, URLs, and hashes in a single command. The integration automatically detects the type of each indicator and processes it accordingly.

#### Base Command

`socradar-bulk-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Mixed list of indicators to check (IPs, domains, URLs, hashes). Automatically detects entity types. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarRapidReputation.BulkCheck.Entity | String | The queried entity value. |
| SOCRadarRapidReputation.BulkCheck.EntityType | String | Detected type of the entity. |
| SOCRadarRapidReputation.BulkCheck.DetectedType | String | Auto-detected entity type. |
| SOCRadarRapidReputation.BulkCheck.Score | Number | Reputation score of the entity. |
| SOCRadarRapidReputation.BulkCheck.IsWhitelisted | Boolean | Whether the entity is whitelisted. |
| SOCRadarRapidReputation.BulkCheck.FindingSources | Unknown | List of threat sources that detected this entity. |
| SOCRadarRapidReputation.BulkCheckSummary.total | Number | Total number of indicators checked. |
| SOCRadarRapidReputation.BulkCheckSummary.processed | Number | Number of successfully processed indicators. |
| SOCRadarRapidReputation.BulkCheckSummary.failed | Number | Number of failed indicators. |
| SOCRadarRapidReputation.BulkCheckSummary.by_type | Unknown | Breakdown by entity type (ip, hostname, url, hash). |
| SOCRadarRapidReputation.BulkCheckSummary.by_score | Unknown | Breakdown by score classification (malicious, suspicious, good, unknown, whitelisted). |

#### Command Example

```
!socradar-bulk-check indicators="1.1.1.1,malicious.example.com"
```

#### Use Cases for Bulk Check

1. **Incident Response**: Quickly check all IOCs extracted from a security incident

   ```
   !socradar-bulk-check indicators="192.168.1.100,malware.example.com,3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792"
   ```

2. **Threat Intel Feed Processing**: Validate a list of indicators from threat intelligence feeds

   ```
   !socradar-bulk-check indicators="${File.Name}"
   ```

3. **Automated Playbooks**: Use in playbooks to process multiple indicators in one step

   ```
   !socradar-bulk-check indicators="${inputs.indicators}"
   ```

4. **Daily Security Monitoring**: Check a list of suspicious entities identified during monitoring

   ```
   !socradar-bulk-check indicators="suspicious_ip1,suspicious_domain1,suspicious_url1"
   ```

#### Output Features

The bulk check command provides:

1. **Summary Statistics**:
   * Total indicators processed
   * Success/failure counts
   * Breakdown by entity type (IPs, domains, URLs, hashes)
   * Breakdown by threat level (malicious, suspicious, good, unknown, whitelisted)

2. **Individual Results**:
   * Each indicator gets its own detailed result card
   * Includes reputation score, whitelisting status, and threat sources
   * Clear classification (Malicious/Suspicious/Good/Unknown)

3. **Automatic Type Detection**:
   * IPs: Automatically detected (IPv4 and IPv6)
   * Domains: Detected based on domain validation
   * URLs: Detected by http:// or https:// prefix
   * Hashes: Detected (MD5, SHA1, SHA256)

4. **Error Handling**:
   * Invalid indicators are reported with clear error messages
   * Processing continues even if some indicators fail
   * Failed indicators don't stop the entire batch

#### Human Readable Output Example

```
📊 Bulk Check Summary
┌─────────────────────────┬───────┐
│ Metric                  │ Count │
├─────────────────────────┼───────┤
│ Total Indicators        │ 10    │
│ Successfully Processed  │ 9     │
│ Failed                  │ 1     │
│ IPs                     │ 3     │
│ Domains                 │ 4     │
│ URLs                    │ 2     │
│ Hashes                  │ 1     │
│ Malicious               │ 2     │
│ Suspicious              │ 3     │
│ Good                    │ 3     │
│ Unknown                 │ 1     │
│ Whitelisted             │ 0     │
└─────────────────────────┴───────┘

[Followed by detailed results for each indicator]
```

---

## Commands Overview

### ip

Checks reputation of provided IP entities using SOCRadar Rapid Reputation API.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP entities to check reputation. (IPv4 or IPv6). Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarRapidReputation.IP.Entity | String | The queried IP address. |
| SOCRadarRapidReputation.IP.EntityType | String | Type of the entity (ip). |
| SOCRadarRapidReputation.IP.Score | Number | Reputation score of the IP address. |
| SOCRadarRapidReputation.IP.IsWhitelisted | Boolean | Whether the IP is whitelisted. |
| SOCRadarRapidReputation.IP.FindingSources | Unknown | List of threat sources that detected this IP. |
| SOCRadarRapidReputation.IP.FindingSources.SourceName | String | Name of the threat intelligence source. |
| SOCRadarRapidReputation.IP.FindingSources.MainCategory | String | Primary threat category. |
| SOCRadarRapidReputation.IP.FindingSources.MaintainerName | String | Organization maintaining the threat list. |
| SOCRadarRapidReputation.IP.FindingSources.FirstSeenDate | Date | First time the IP was seen on this source. |
| SOCRadarRapidReputation.IP.FindingSources.LastSeenDate | Date | Last time the IP was seen on this source. |
| SOCRadarRapidReputation.IP.FindingSources.SeenCount | Number | Number of times the IP was observed on this source. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| IP.Address | String | IP address |

#### Command Example

```
!ip ip="1.1.1.1"
```

#### Human Readable Output

Example output showing reputation score, whitelisting status, and threat sources that have detected the IP.

---

### domain

Checks reputation of provided domain entities using SOCRadar Rapid Reputation API.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain entities to check reputation. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarRapidReputation.Domain.Entity | String | The queried domain. |
| SOCRadarRapidReputation.Domain.EntityType | String | Type of the entity (hostname). |
| SOCRadarRapidReputation.Domain.Score | Number | Reputation score of the domain. |
| SOCRadarRapidReputation.Domain.IsWhitelisted | Boolean | Whether the domain is whitelisted. |
| SOCRadarRapidReputation.Domain.FindingSources | Unknown | List of threat sources that detected this domain. |
| SOCRadarRapidReputation.Domain.FindingSources.SourceName | String | Name of the threat intelligence source. |
| SOCRadarRapidReputation.Domain.FindingSources.MainCategory | String | Primary threat category. |
| SOCRadarRapidReputation.Domain.FindingSources.MaintainerName | String | Organization maintaining the threat list. |
| SOCRadarRapidReputation.Domain.FindingSources.FirstSeenDate | Date | First time the domain was seen on this source. |
| SOCRadarRapidReputation.Domain.FindingSources.LastSeenDate | Date | Last time the domain was seen on this source. |
| SOCRadarRapidReputation.Domain.FindingSources.SeenCount | Number | Number of times the domain was observed on this source. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| Domain.Name | String | Domain name |

#### Command Example

```
!domain domain="example.com"
```

---

### url

Checks reputation of provided URL entities using SOCRadar Rapid Reputation API.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL entities to check reputation. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarRapidReputation.URL.Entity | String | The queried URL. |
| SOCRadarRapidReputation.URL.EntityType | String | Type of the entity (url). |
| SOCRadarRapidReputation.URL.Score | Number | Reputation score of the URL. |
| SOCRadarRapidReputation.URL.IsWhitelisted | Boolean | Whether the URL is whitelisted. |
| SOCRadarRapidReputation.URL.FindingSources | Unknown | List of threat sources that detected this URL. |
| SOCRadarRapidReputation.URL.FindingSources.SourceName | String | Name of the threat intelligence source. |
| SOCRadarRapidReputation.URL.FindingSources.MainCategory | String | Primary threat category. |
| SOCRadarRapidReputation.URL.FindingSources.MaintainerName | String | Organization maintaining the threat list. |
| SOCRadarRapidReputation.URL.FindingSources.FirstSeenDate | Date | First time the URL was seen on this source. |
| SOCRadarRapidReputation.URL.FindingSources.LastSeenDate | Date | Last time the URL was seen on this source. |
| SOCRadarRapidReputation.URL.FindingSources.SeenCount | Number | Number of times the URL was observed on this source. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| URL.Data | String | URL |

#### Command Example

```
!url url="https://malicious.example.com/file.exe"
```

---

### file

Checks reputation of provided file hash entities using SOCRadar Rapid Reputation API.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash entities to check reputation. (MD5, SHA1, or SHA256). Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarRapidReputation.File.Entity | String | The queried file hash. |
| SOCRadarRapidReputation.File.EntityType | String | Type of the entity (hash). |
| SOCRadarRapidReputation.File.Score | Number | Reputation score of the hash. |
| SOCRadarRapidReputation.File.IsWhitelisted | Boolean | Whether the hash is whitelisted. |
| SOCRadarRapidReputation.File.FindingSources | Unknown | List of threat sources that detected this hash. |
| SOCRadarRapidReputation.File.FindingSources.SourceName | String | Name of the threat intelligence source. |
| SOCRadarRapidReputation.File.FindingSources.MainCategory | String | Primary threat category. |
| SOCRadarRapidReputation.File.FindingSources.MaintainerName | String | Organization maintaining the threat list. |
| SOCRadarRapidReputation.File.FindingSources.FirstSeenDate | Date | First time the hash was seen on this source. |
| SOCRadarRapidReputation.File.FindingSources.LastSeenDate | Date | Last time the hash was seen on this source. |
| SOCRadarRapidReputation.File.FindingSources.SeenCount | Number | Number of times the hash was observed on this source. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| File.MD5 | String | MD5 hash of the file |
| File.SHA1 | String | SHA1 hash of the file |
| File.SHA256 | String | SHA256 hash of the file |

#### Command Example

```
!file file="3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792"
```

---

### socradar-reputation

Checks reputation of any entity type using SOCRadar Rapid Reputation API. This is a generic command that can handle any supported entity type.

#### Base Command

`socradar-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_value | Entity value to check (IP, domain, URL, or hash). | Required |
| entity_type | Type of entity to check. Possible values are: ip, hostname, url, hash. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarRapidReputation.Reputation.Entity | String | The queried entity value. |
| SOCRadarRapidReputation.Reputation.EntityType | String | Type of the entity. |
| SOCRadarRapidReputation.Reputation.Score | Number | Reputation score of the entity. |
| SOCRadarRapidReputation.Reputation.IsWhitelisted | Boolean | Whether the entity is whitelisted. |
| SOCRadarRapidReputation.Reputation.FindingSources | Unknown | List of threat sources that detected this entity. |
| SOCRadarRapidReputation.Reputation.FindingSources.SourceName | String | Name of the threat intelligence source. |
| SOCRadarRapidReputation.Reputation.FindingSources.MainCategory | String | Primary threat category. |
| SOCRadarRapidReputation.Reputation.FindingSources.MaintainerName | String | Organization maintaining the threat list. |
| SOCRadarRapidReputation.Reputation.FindingSources.FirstSeenDate | Date | First time the entity was seen on this source. |
| SOCRadarRapidReputation.Reputation.FindingSources.LastSeenDate | Date | Last time the entity was seen on this source. |
| SOCRadarRapidReputation.Reputation.FindingSources.SeenCount | Number | Number of times the entity was observed on this source. |

#### Command Example

```
!socradar-reputation entity_value="37.46.210.230" entity_type="ip"
!socradar-reputation entity_value="malicious.example.com" entity_type="hostname"
!socradar-reputation entity_value="3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792" entity_type="hash"
```

---

## DBot Score Interpretation

The integration converts SOCRadar reputation scores to DBot scores as follows:

| SOCRadar Score | DBot Score | Classification |
| --- | --- | --- |
| > 80 | 3 | Malicious |
| 40 - 80 | 2 | Suspicious |
| 0 - 40 | 1 | Good |
| None/0 | 0 | Unknown |

Whitelisted entities are always assigned a DBot score of 1 (Good), regardless of their reputation score.

---

## Additional Information

### Threat Intelligence Sources

The Rapid Reputation API aggregates data from multiple threat intelligence sources, including:

* CTU AIPP Blacklist
* Abuse.ch URLhaus
* Malware feeds
* Botnet C&C lists
* And many more

Each finding source provides detailed information about when and how many times the entity was observed.

### Use Cases

1. **Incident Response**: Quickly check if an IP, domain, or URL involved in an incident is known to be malicious
2. **Threat Hunting**: Proactively search for indicators of compromise in your environment
3. **Automated Playbooks**: Integrate reputation checks into your security automation workflows
4. **Alert Enrichment**: Enhance security alerts with threat intelligence context

### Best Practices

* Use the generic `socradar-reputation` command when you need flexibility in entity type
* Use specific commands (`ip`, `domain`, `url`, `file`) when you know the entity type for better context integration
* Monitor the FindingSources field to understand which threat intelligence feeds detected the entity
* Pay attention to the FirstSeenDate and LastSeenDate to understand the timeline of malicious activity

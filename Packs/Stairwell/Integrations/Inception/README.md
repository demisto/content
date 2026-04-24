Use the Stairwell integration to enrich data in XSOAR using Stairwell's knowledge and perform automated variant discovery, file analysis, and threat hunting.

Not a customer and interested in signing up? You can request access [here](https://stairwell.com/contact/).

## Generate required API key

Follow these steps for a self-deployed configuration.

1. Access the Stairwell web UI and generate an API/CLI token [here](https://app.stairwell.com/dashboard?open-modal=auth-token).
2. Copy your API token for the integration configuration usage.

## Configure Stairwell on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Stairwell.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

4. Click **Test** to validate the API key and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

---

## File Analysis Commands

### stairwell-file-enrichment

Enrich files using file hash (MD5, SHA1, or SHA256). Returns hash details, seen assets, matching YARA rules, AV verdicts, and file paths.

**Base Command:** `stairwell-file-enrichment`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | File hash (MD5, SHA1, or SHA256) to lookup. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.File_Details.summary.md5 | String | MD5 hash |
| Stairwell.File_Details.summary.sha256 | String | SHA256 hash |
| Stairwell.File_Details.summary.filenames | Array | List of filenames |
| Stairwell.File_Details.summary.seen_assets_count | Number | Number of assets where file was seen |
| Stairwell.File_Details.raw | Dict | Full API response |

**Command Example**

```
!stairwell-file-enrichment file_hash=9fe1ac46f0cdebf03156a6232d771c14559f8daf
```

---

### stairwell-variant-discovery

Discover variants using a SHA256 hash. Returns similar files with similarity scores for malware family analysis.

**Base Command:** `stairwell-variant-discovery`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | File hash (SHA256). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Variants.variants | Array | List of variant hashes with similarity scores |

**Command Example**

```
!stairwell-variant-discovery sha256=e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d
```

---

### stairwell-ai-triage-summarize

Get AI-generated summary for a file including threat analysis, IOCs, malicious likelihood scoring, and actionable intelligence.

**Base Command:** `stairwell-ai-triage-summarize`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object identifier (SHA256 hash or object ID). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.AI_Triage.hash | String | File hash |
| Stairwell.AI_Triage.malicious_likelihood | Number | Malicious likelihood percentage (0-100) |
| Stairwell.AI_Triage.confidence | Number | Confidence score (0-100) |
| Stairwell.AI_Triage.threat_type | String | Threat type classification |
| Stairwell.AI_Triage.tldr | String | Brief summary |
| Stairwell.AI_Triage.raw | Dict | Full AI analysis including IOCs, API analysis, entropy analysis |

**Command Example**

```
!stairwell-ai-triage-summarize object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

---

## File Intake & Upload

### stairwell-intake-upload

Upload files to Stairwell for analysis with automatic preflight checks, SHA256 calculation, and retry logic. Supports three file source methods.

**Base Command:** `stairwell-intake-upload`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID for the upload. | Required |
| entry_id | Entry ID of the file from the War Room context (XSOAR file entry). One of entry_id, url, or file_path must be provided. | Optional |
| url | HTTP/HTTPS URL to download the file from. One of entry_id, url, or file_path must be provided. | Optional |
| file_path | Direct file path (for development/testing). One of entry_id, url, or file_path must be provided. | Optional |
| sha256 | File hash (SHA256) - Optional, will be auto-calculated if not provided. | Optional |
| detonation_plan | Detonation plan name. | Optional |
| origin_type | Origin type (web or unspecified). | Optional |
| origin_referrer_url | HTTP referer URL. | Optional |
| origin_host_url | Original host URL. | Optional |
| origin_zone_id | Zone ID (integer). | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Intake.preflight | Dict | Preflight response from API |
| Stairwell.Intake.result | String | Result status (already_exists, uploaded) |
| Stairwell.Intake.upload_status | Number | HTTP status code from upload |

**Command Examples**

```
# Upload from War Room (recommended for production)

!stairwell-intake-upload asset_id=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 entry_id=${File.EntryID}

# Upload from URL

!stairwell-intake-upload asset_id=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 url=https://example.com/malware.exe

# Upload from file path (backward compatibility)

!stairwell-intake-upload asset_id=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 file_path=/path/to/file.exe

# Upload with metadata

!stairwell-intake-upload asset_id=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 entry_id=${File.EntryID} origin_type=web origin_host_url=https://malicious-site.com
```

---

## Object Investigation Commands

### stairwell-object-sightings

List all sightings for a specific object across your organization's assets.

**Base Command:** `stairwell-object-sightings`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object identifier (SHA256 hash or object ID). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Sightings.objectId | String | Object identifier |
| Stairwell.Sightings.objectSightings | Array | List of sightings with asset and timestamp details |

**Command Example**

```
!stairwell-object-sightings object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

---

### stairwell-object-detonation-trigger

Trigger a detonation for an object in Stairwell's sandbox environment.

**Base Command:** `stairwell-object-detonation-trigger`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object identifier (SHA256 hash or object ID). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Detonation.Trigger.objectId | String | Object identifier |

**Command Example**

```
!stairwell-object-detonation-trigger object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

---

### stairwell-object-detonation-get

Get detonation details for an object.

**Base Command:** `stairwell-object-detonation-get`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object identifier (SHA256 hash or object ID). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Detonation.objectId | String | Object identifier |
| Stairwell.Detonation | Dict | Detailed detonation results |

**Command Example**

```
!stairwell-object-detonation-get object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

---

### stairwell-object-opinions

List opinions for an object from Stairwell's threat intelligence.

**Base Command:** `stairwell-object-opinions`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object identifier (SHA256 hash or object ID). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Opinions.objectId | String | Object identifier |
| Stairwell.Opinions.opinions | Array | List of opinions and assessments |

**Command Example**

```
!stairwell-object-opinions object_id=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

---

### stairwell-run-to-ground-generate

Generate comprehensive Run-To-Ground analysis for one or more objects.

**Base Command:** `stairwell-run-to-ground-generate`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Comma-separated list of object IDs or hashes. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.RunToGround | Dict | Run-To-Ground analysis results |

**Command Example**

```
!stairwell-run-to-ground-generate object_ids=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283,e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d
```

---

## YARA Rule Management

### stairwell-yara-create-rule

Create a new YARA rule in your Stairwell environment.

**Important:** For multi-line YARA rule definitions, use backticks (`) instead of quotes to prevent parsing errors.

**Base Command:** `stairwell-yara-create-rule`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Environment ID. | Required |
| rule_definition | YARA rule definition text. Use backticks for multi-line rules. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.YaraRule | Dict | Created YARA rule details |

**Command Examples**

```
# Simple rule (single line)

!stairwell-yara-create-rule environment=YOUR_ENV_ID rule_definition="rule simple_rule { condition: true }"

# Complex rule (multi-line with backticks)

!stairwell-yara-create-rule environment=YOUR_ENV_ID rule_definition=`rule Malware_Detection
{
    meta:
        author = "Security Team"
        description = "Detects malware patterns"
    strings:
        $a = "malicious_string"
    condition:
        $a
}`
```

---

### stairwell-yara-get-rule

Get a specific YARA rule by ID.

**Base Command:** `stairwell-yara-get-rule`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Environment ID. | Required |
| yara_rule | YARA rule ID. | Required |
| match_count_envs | Comma-separated list of environment IDs for match counts. | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.YaraRule | Dict | YARA rule details |

**Command Example**

```
!stairwell-yara-get-rule environment=YOUR_ENV_ID yara_rule=YOUR_RULE_ID
```

---

### stairwell-yara-query-matches

Query objects matching a YARA rule.

**Base Command:** `stairwell-yara-query-matches`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Environment ID. | Required |
| yara_rule | YARA rule ID. | Required |
| included_environments | Comma-separated list of environments to search. | Optional |
| page_size | Maximum number of matches to return. | Optional |
| page_token | Token for pagination. | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.YaraRuleMatches.objects | Array | List of matching objects with SHA256, MD5, SHA1, size, and first seen time |

**Command Example**

```
!stairwell-yara-query-matches environment=YOUR_ENV_ID yara_rule=YOUR_RULE_ID included_environments=env1,env2 page_size=100
```

---

## Network Intelligence Commands

### stairwell-asn-get-whois

Get WHOIS information for an Autonomous System Number.

**Base Command:** `stairwell-asn-get-whois`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asn | ASN number. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.ASN.WHOIS.asn | String | ASN number |
| Stairwell.ASN.WHOIS | Dict | WHOIS information |

**Command Example**

```
!stairwell-asn-get-whois asn=15169
```

---

### stairwell-hostname-get

Get hostname entity with DNS resolution data.

**Base Command:** `stairwell-hostname-get`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname to lookup. | Required |
| record_type | DNS record type filter (A, AAAA, or MX). | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Hostname.hostname | String | Hostname |
| Stairwell.Hostname | Dict | DNS resolution data |

**Command Example**

```
!stairwell-hostname-get hostname="google.com" record_type="A"
```

---

### stairwell-hostname-get-resolutions

Get all addresses resolved to by a hostname over a time range.

**Base Command:** `stairwell-hostname-get-resolutions`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname to lookup. | Required |
| start_time | Start time for resolution range (ISO 8601 format). | Optional |
| end_time | End time for resolution range (ISO 8601 format). | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Hostname.Resolutions.hostname | String | Hostname |
| Stairwell.Hostname.Resolutions.resolutions | Array | List of resolutions with timestamps |

**Command Example**

```
!stairwell-hostname-get-resolutions hostname=www.google.com
```

---

### stairwell-hostname-batch-get-resolutions

Get resolution summaries for multiple hostnames.

**Base Command:** `stairwell-hostname-batch-get-resolutions`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostnames | Comma-separated list of hostnames. | Required |
| start_time | Start time for resolution range (ISO 8601 format). | Optional |
| end_time | End time for resolution range (ISO 8601 format). | Optional |
| record_types | Comma-separated DNS record types (A, AAAA, MX). | Optional |
| include_errors | Include DNS error responses (true/false). | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Hostname.BatchResolutions | Dict | Batch hostname resolutions |

**Command Example**

```
!stairwell-hostname-batch-get-resolutions hostnames=www.google.com,www.stairwell.com record_types=A,AAAA
```

---

### stairwell-ipaddress-get

Get IP address entity with enrichment data.

**Base Command:** `stairwell-ipaddress-get`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address to lookup. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.ip | String | IP address |
| Stairwell.IPAddress | Dict | IP address enrichment data |

**Command Example**

```
!stairwell-ipaddress-get ip_address=8.8.8.8
```

---

### stairwell-ipaddress-lookup-cloud-provider

Check if an IP address belongs to a known cloud provider.

**Base Command:** `stairwell-ipaddress-lookup-cloud-provider`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address to check. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.CloudProvider.ip | String | IP address |
| Stairwell.IPAddress.CloudProvider | Dict | Cloud provider information |

**Command Example**

```
!stairwell-ipaddress-lookup-cloud-provider ip_address=8.8.8.8
```

---

### stairwell-ipaddress-get-hostnames-resolving-to-ip

Get all hostnames resolved to by an IP address over a time interval.

**Base Command:** `stairwell-ipaddress-get-hostnames-resolving-to-ip`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address to lookup. | Required |
| start_time | Start time for resolution range (ISO 8601 format). | Optional |
| end_time | End time for resolution range (ISO 8601 format). | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.Hostnames.ip | String | IP address |
| Stairwell.IPAddress.Hostnames.hostnames | Array | List of hostnames |

**Command Example**

```
!stairwell-ipaddress-get-hostnames-resolving-to-ip ip_address=8.8.8.8
```

---

### stairwell-ipaddress-get-whois

Get WHOIS information for an IP address.

**Base Command:** `stairwell-ipaddress-get-whois`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address to lookup. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.IPAddress.WHOIS.ip | String | IP address |
| Stairwell.IPAddress.WHOIS | Dict | WHOIS information |

**Command Example**

```
!stairwell-ipaddress-get-whois ip_address=8.8.8.8
```

---

### stairwell-utilities-get-cloud-ip-ranges

Get IP ranges for known cloud providers.

**Base Command:** `stairwell-utilities-get-cloud-ip-ranges`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider | Cloud provider name (optional filter). | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CloudIPRanges.ranges | Array | List of IP ranges |

**Command Example**

```
!stairwell-utilities-get-cloud-ip-ranges provider=AWS
```

---

### stairwell-utilities-batch-canonicalize-hostnames

Canonicalize multiple hostnames in bulk.

**Base Command:** `stairwell-utilities-batch-canonicalize-hostnames`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostnames | Comma-separated list of hostnames to canonicalize. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedHostnames | Dict | Canonicalized hostnames |

**Command Example**

```
!stairwell-utilities-batch-canonicalize-hostnames hostnames=EXAMPLE.COM,WWW.TEST.COM
```

---

### stairwell-utilities-batch-compute-etld-plus-one

Compute effective top-level domain plus one for multiple domains.

**Base Command:** `stairwell-utilities-batch-compute-etld-plus-one`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domains. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.ETLDPlusOne | Dict | ETLD+1 results |

**Command Example**

```
!stairwell-utilities-batch-compute-etld-plus-one domains=subdomain.example.com,www.test.co.uk
```

---

### stairwell-utilities-canonicalize-hostname

Canonicalize a single hostname.

**Base Command:** `stairwell-utilities-canonicalize-hostname`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname to canonicalize. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedHostname | Dict | Canonicalized hostname |

**Command Example**

```
!stairwell-utilities-canonicalize-hostname hostname=EXAMPLE.COM
```

---

### stairwell-utilities-compute-etld-plus-one

Compute effective top-level domain plus one for a single domain.

**Base Command:** `stairwell-utilities-compute-etld-plus-one`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to compute ETLD+1 for. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.ETLDPlusOne | Dict | ETLD+1 result |

**Command Example**

```
!stairwell-utilities-compute-etld-plus-one domain=subdomain.example.com
```

---

### stairwell-utilities-batch-canonicalize-urls

Canonicalize multiple URLs in bulk.

**Base Command:** `stairwell-utilities-batch-canonicalize-urls`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | Comma-separated list of URLs to canonicalize. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedURLs | Dict | Canonicalized URLs |

**Command Example**

```
!stairwell-utilities-batch-canonicalize-urls urls=https://EXAMPLE.COM/PATH,http://TEST.COM/
```

---

### stairwell-utilities-canonicalize-url

Canonicalize a single URL.

**Base Command:** `stairwell-utilities-canonicalize-url`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to canonicalize. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Utilities.CanonicalizedURL | Dict | Canonicalized URL |

**Command Example**

```
!stairwell-utilities-canonicalize-url url=https://EXAMPLE.COM/PATH
```

---

## Asset Management Commands

### stairwell-asset-list

List all assets in an environment.

**Base Command:** `stairwell-asset-list`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Environment ID. | Required |
| page_size | Maximum number of assets to return. | Optional |
| page_token | Token for pagination. | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Assets.assets | Array | List of assets |

**Command Example**

```
!stairwell-asset-list environment=YOUR_ENV_ID page_size=50
```

---

### stairwell-asset-create

Create a new asset in an environment.

**Base Command:** `stairwell-asset-create`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Environment ID. | Required |
| label | Human-readable identifier (typically hostname). | Required |
| idempotency_key | Client-generated key for idempotent asset creation. | Optional |
| os | Operating system (Windows, macOS, Linux). | Optional |
| os_version | OS version string. | Optional |
| forwarder_version | Forwarder version string. | Optional |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Asset | Dict | Created asset with uploadToken |

**Command Example**

```
!stairwell-asset-create environment=YOUR_ENV_ID label=xSOAR os=Windows os_version="10.0.19041"
```

---

### stairwell-asset-get

Get a specific asset by ID.

**Base Command:** `stairwell-asset-get`

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset | Asset ID. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Stairwell.Asset | Dict | Asset details including uploadToken |

**Command Example**

```
!stairwell-asset-get asset=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6
```

---

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
5. Trigger detonation → `stairwell-object-detonation-trigger`
6. Retrieve results → `stairwell-object-detonation-get`

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

## Stairwell Integration for XSOAR

Stairwell continuously collects, stores, and analyzes threat intelligence, malware and executable files, scripts, and artifacts in a private, out-of-band vault — making it possible to answer security questions faster.

### Key Capabilities
- **Reanalyze files continuously** as new intel drops
- **Connect threat and signal intelligence** with your files
- **Run every alert-to-ground** — even months later
- **Find variant families and connections** others miss
- **Answer definitively**: Has this ever been in your environment? Is this absent from your enterprise?

Not a customer and interested in signing up? You can request access [here](https://stairwell.com/contact/).

---

## File Analysis Commands

### File Enrichment (`stairwell-file-enrichment`)
Instantly enrich files using MD5, SHA1, or SHA256 hashes. Leverages data from your organization and Stairwell's shared malware corpus.

**Returns:**
- Hash details (MD5, SHA1, SHA256)
- Seen assets in your environment
- Matching YARA rules
- AV vendor verdicts
- File path and filename details

**Example:**
```
!stairwell-file-enrichment fileHash=9fe1ac46f0cdebf03156a6232d771c14559f8daf
```

### Variant Discovery (`stairwell-variant-discovery`)
Rapid, DFIR-level variant hunting for malware families. Discovers similar files using advanced similarity analysis across your organization and Stairwell's corpus.

**Returns:**
- Variant file hashes
- Similarity scores
- Relationship mapping

**Example:**
```
!stairwell-variant-discovery sha256=e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d
```

### AI Triage Summarize (`stairwell-ai-triage-summarize`)
AI-generated threat analysis summaries powered by Stairwell's AI Triage engine.

**Returns:**
- Threat type classification
- Malicious likelihood scoring (0-100%)
- Confidence assessment
- Key findings and TL;DR
- **IOCs:**
  - URLs
  - File paths and filenames
  - Registry keys
  - IP addresses
- **Analysis:**
  - API behavior analysis
  - Entropy analysis
  - Prevalence information
- **Threat Intelligence:**
  - Persistence mechanisms
  - Obfuscation/evasion techniques
  - Data exfiltration capabilities

**Example:**
```
!stairwell-ai-triage-summarize objectId=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

---

## File Intake & Upload

### Intake Upload (`stairwell-intake-upload`)
Upload files to Stairwell for analysis with three flexible file source methods. Includes automatic preflight checks, SHA256 calculation, and retry logic.

**File Source Methods:**

1. **Entry ID** (Recommended for Production)
   - Upload files from XSOAR War Room context
   - Most common method in playbooks
   ```
   !stairwell-intake-upload assetId=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 entryID=${File.EntryID}
   ```

2. **URL Download**
   - Download and upload from HTTP/HTTPS URLs
   - Supports streaming for large files
   - Automatic temp file cleanup
   ```
   !stairwell-intake-upload assetId=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 url=https://example.com/malware.exe
   ```

3. **Direct File Path** (Development/Testing)
   - Access files using direct filesystem paths
   - Maintains backward compatibility
   ```
   !stairwell-intake-upload assetId=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 filePath=/path/to/file.exe
   ```

**Features:**
- ✅ Automatic SHA256 calculation
- ✅ Preflight validation (checks if file already exists)
- ✅ Conditional upload (only uploads if needed)
- ✅ Retry logic with exponential backoff
- ✅ Automatic temp file cleanup for URL downloads
- ✅ Support for origin metadata (web origin tracking)

**Optional Metadata Parameters:**
- `sha256` - Pre-computed hash (optional, auto-calculated if not provided)
- `detonationPlan` - Detonation plan name
- `originType` - Origin type (web or unspecified)
- `originReferrerUrl` - HTTP referer URL
- `originHostUrl` - Original host URL
- `originZoneId` - Zone ID (integer)

**Example with Metadata:**
```
!stairwell-intake-upload assetId=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6 entryID=${File.EntryID} originType=web originHostUrl=https://malicious-site.com
```

---

## Object Investigation Commands

### Object Sightings (`stairwell-object-sightings`)
List all sightings for a specific object across your organization's assets. Essential for threat hunting and incident response.

**Use Cases:**
- Track file distribution across your environment
- Identify patient zero
- Assess threat scope

**Example:**
```
!stairwell-object-sightings objectId=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

### Object Detonation (`stairwell-object-detonation-trigger`, `stairwell-object-detonation-get`)
Trigger and retrieve sandbox detonation results. Provides detailed behavioral analysis of file execution in isolated environments.

**Workflow:**
1. Trigger detonation:
   ```
   !stairwell-object-detonation-trigger objectId=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
   ```

2. Get detonation results:
   ```
   !stairwell-object-detonation-get objectId=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
   ```

### Object Opinions (`stairwell-object-opinions`)
Retrieve opinions and threat assessments for objects from Stairwell's threat intelligence.

**Example:**
```
!stairwell-object-opinions objectId=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283
```

### Run-To-Ground (`stairwell-run-to-ground-generate`)
Generate comprehensive Run-To-Ground analysis for one or more objects. Traces files across your environment with complete visibility.

**Features:**
- Multi-object analysis
- Relationship mapping
- Historical tracking
- Complete threat visibility

**Example:**
```
!stairwell-run-to-ground-generate objectIds=357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283,e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d
```

---

## YARA Rule Management

### Create YARA Rule (`stairwell-yara-create-rule`)
Create new YARA rules in your Stairwell environment.

**⚠️ Important: Multi-line Rules**
For multi-line YARA rule definitions, you **must use backticks (`)** instead of quotes to prevent parsing errors.

**Simple Rule (Single Line):**
```
!stairwell-yara-create-rule environment=YOUR_ENV_ID ruleDefinition="rule simple_rule { condition: true }"
```

**Complex Rule (Multi-line with Backticks):**
```
!stairwell-yara-create-rule environment=YOUR_ENV_ID ruleDefinition=`rule Malware_Detection
{
    meta:
        author = "Security Team"
        description = "Detects specific malware patterns"
        date = "2026-01-27"

    strings:
        $string1 = "malicious_pattern"
        $string2 = { 4D 5A 90 00 }

    condition:
        $string1 or $string2
}`
```

### Get YARA Rule (`stairwell-yara-get-rule`)
Retrieve details for a specific YARA rule.

**Examples:**
```
!stairwell-yara-get-rule environment=YOUR_ENV_ID yaraRule=YOUR_RULE_ID
!stairwell-yara-get-rule environment=YOUR_ENV_ID yaraRule=YOUR_RULE_ID matchCountEnvs=env1,env2
```

### Query YARA Matches (`stairwell-yara-query-matches`)
Find all objects matching a specific YARA rule.

**Examples:**
```
!stairwell-yara-query-matches environment=YOUR_ENV_ID yaraRule=YOUR_RULE_ID
!stairwell-yara-query-matches environment=YOUR_ENV_ID yaraRule=YOUR_RULE_ID includedEnvironments=env1,env2 pageSize=100
```

**Returns:**
- SHA256, MD5, SHA1 hashes
- File size
- Global first seen time
- Pagination support for large result sets

---

## Network Intelligence Commands

### ASN WHOIS (`stairwell-asn-get-whois`)
Get WHOIS information for Autonomous System Numbers.

**Example:**
```
!stairwell-asn-get-whois asn=15169
```

### Hostname Commands
- **`stairwell-hostname-get`** - Get hostname entity with DNS resolution data
- **`stairwell-hostname-get-resolutions`** - Get all addresses resolved by a hostname over time
- **`stairwell-hostname-batch-get-resolutions`** - Batch query for multiple hostnames

**Examples:**
```
!stairwell-hostname-get hostname="google.com" recordType="A"
!stairwell-hostname-get-resolutions hostname=www.google.com
!stairwell-hostname-batch-get-resolutions hostnames=www.google.com,www.stairwell.com recordTypes=A,AAAA
```

### IP Address Commands
- **`stairwell-ipaddress-get`** - Get IP address entity with enrichment data
- **`stairwell-ipaddress-lookup-cloud-provider`** - Check if IP belongs to known cloud provider
- **`stairwell-ipaddress-get-hostnames-resolving-to-ip`** - Get hostnames resolving to an IP
- **`stairwell-ipaddress-get-whois`** - Get WHOIS information for IP addresses

**Examples:**
```
!stairwell-ipaddress-get ipAddress=8.8.8.8
!stairwell-ipaddress-lookup-cloud-provider ipAddress=8.8.8.8
!stairwell-ipaddress-get-whois ipAddress=8.8.8.8
```

### Utilities Commands
- **`stairwell-utilities-get-cloud-ip-ranges`** - Get IP ranges for cloud providers
- **`stairwell-utilities-canonicalize-hostname`** - Canonicalize hostnames
- **`stairwell-utilities-canonicalize-url`** - Canonicalize URLs
- **`stairwell-utilities-compute-etld-plus-one`** - Compute effective TLD+1

**Examples:**
```
!stairwell-utilities-get-cloud-ip-ranges provider=AWS
!stairwell-utilities-canonicalize-hostname hostname=EXAMPLE.COM
!stairwell-utilities-canonicalize-url url=https://EXAMPLE.COM/PATH
```

---

## Asset Management

### List Assets (`stairwell-asset-list`)
List all assets in an environment with pagination support.

**Example:**
```
!stairwell-asset-list environment=YOUR_ENV_ID pageSize=50
```

### Create Asset (`stairwell-asset-create`)
Create new assets in your environment. Assets represent endpoints or systems that can upload files to Stairwell.

**Example:**
```
!stairwell-asset-create environment=YOUR_ENV_ID label=xSOAR os=Windows osVersion="10.0.19041"
```

### Get Asset (`stairwell-asset-get`)
Retrieve details for a specific asset including upload tokens.

**Example:**
```
!stairwell-asset-get asset=VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6
```

---

## Integration Features

### Reliability & Performance
- ✅ **Automatic retry logic** with exponential backoff for transient failures
- ✅ **HTTP timeout management** (120s for API calls, 600s for uploads)
- ✅ **Streaming downloads** for large files (1MB chunks)
- ✅ **Connection pooling** with urllib3 for efficient API usage

### Security
- ✅ **SSL/TLS verification** (configurable)
- ✅ **Proxy support** (respects XSOAR system proxy settings)
- ✅ **Secure credential handling** (API key stored encrypted)
- ✅ **URL scheme validation** (only http/https allowed for downloads)
- ✅ **Automatic temp file cleanup** prevents accumulation

### Error Handling
- ✅ **Detailed error messages** for troubleshooting
- ✅ **Graceful degradation** for partial failures
- ✅ **404 handling** for missing objects/files
- ✅ **Validation** of required parameters

---

## Configuration

### Required Settings
1. **API Key** - Obtain from Stairwell platform (Settings → API Keys)

### Optional Settings
- **Use system proxy settings** - Leverage XSOAR proxy configuration
- **Trust any certificate** - Disable SSL verification (not recommended for production)

---

## Common Workflows

### File Analysis Workflow
1. **Enrich** file using hash → `stairwell-file-enrichment`
2. **Discover** variants → `stairwell-variant-discovery`
3. **Get** AI analysis → `stairwell-ai-triage-summarize`
4. **Check** sightings → `stairwell-object-sightings`
5. **Trigger** detonation → `stairwell-object-detonation-trigger`
6. **Retrieve** results → `stairwell-object-detonation-get`

### File Upload & Analysis Workflow
1. **Upload** file from War Room → `stairwell-intake-upload entryID=${File.EntryID}`
2. **Wait** for processing (files are analyzed automatically)
3. **Query** for matches → `stairwell-yara-query-matches`
4. **Generate** Run-To-Ground → `stairwell-run-to-ground-generate`

### Threat Hunting Workflow
1. **Create** YARA rule → `stairwell-yara-create-rule`
2. **Query** matches → `stairwell-yara-query-matches`
3. **Analyze** each match → `stairwell-file-enrichment`
4. **Check** sightings → `stairwell-object-sightings`
5. **Investigate** with Run-To-Ground → `stairwell-run-to-ground-generate`

---

## Support & Documentation

- **Stairwell Documentation**: [docs.stairwell.com](https://docs.stairwell.com)
- **API Reference**: [app.stairwell.com/api](https://app.stairwell.com/api)
- **Contact Sales**: [stairwell.com/contact](https://stairwell.com/contact/)

---

## Version Information

**Docker Image**: `demisto/python3:3.10.10.48392`
**Minimum XSOAR Version**: 6.5.0
**Python Version**: 3.10

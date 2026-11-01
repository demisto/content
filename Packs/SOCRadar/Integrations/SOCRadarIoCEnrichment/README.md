# SOCRadar IoC Enrichment Integration

## Overview

The SOCRadar IoC Enrichment integration provides deep threat intelligence enrichment for indicators of compromise (IoCs). Get comprehensive data including categorization, signal strength, confidence levels, historical events, threat actor attribution, and campaign associations.

### Key Features

- **Rich Threat Context**: Detailed categorization (CDN, Cloud, Malware, ThreatActor, Tor, VPN, etc.)
- **Signal Strength**: IoC reliability assessment (Very Strong to Noisy)
- **Confidence Levels**: Cross-source validation (Very High, High, Medium, Low)
- **Historical Data**: Timeline of indicator activity across threat feeds
- **Threat Attribution**: Associated campaigns, threat actors, malware families
- **Target Intelligence**: Industries and countries targeted
- **Performance Optimized**: AI insights excluded for fast responses

---

## Configuration

### Prerequisites

- SOCRadar API Key with IoC Enrichment access
- Network access to `platform.socradar.com`

### Setup

1. Navigate to **Settings** → **Integrations** → **Servers & Services**
2. Search for "SOCRadar IoC Enrichment"
3. Click **Add Instance**
4. Configure:
   - **Name**: Instance name
   - **API Key**: Your SOCRadar API key
   - **Source Reliability**: B - Usually reliable (recommended)
5. Click **Test** to validate
6. Click **Save & Exit**

---

## Commands

### ip

Enriches IP addresses with threat intelligence data.

#### Input

| **Argument** | **Description** | **Required** |
|---|---|---|
| ip | IP addresses to enrich (IPv4 or IPv6). Supports multiple IPs (comma-separated). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
|---|---|---|
| SOCRadarIoCEnrichment.IP.Indicator | String | The IP address |
| SOCRadarIoCEnrichment.IP.Score | Number | Threat score (0-100) |
| SOCRadarIoCEnrichment.IP.SignalStrength | String | IoC reliability (Very Strong, Strong, Moderate, Slightly Noisy, Noisy) |
| SOCRadarIoCEnrichment.IP.Confidence | String | Cross-source confidence (Very High, High, Medium, Low) |
| SOCRadarIoCEnrichment.IP.Country | String | Country of origin |
| SOCRadarIoCEnrichment.IP.ASN | String | Autonomous System Name |
| SOCRadarIoCEnrichment.IP.FirstSeen | Date | First observed date |
| SOCRadarIoCEnrichment.IP.LastSeen | Date | Last observed date |
| SOCRadarIoCEnrichment.IP.Categorization | Object | Service categorization flags |
| SOCRadarIoCEnrichment.IP.Categorization.Malware | Boolean | Associated with malware |
| SOCRadarIoCEnrichment.IP.Categorization.ThreatActor | Boolean | Associated with threat actors |
| SOCRadarIoCEnrichment.IP.Categorization.Tor | Boolean | Tor exit node |
| SOCRadarIoCEnrichment.IP.Categorization.VPN | Boolean | VPN service |
| SOCRadarIoCEnrichment.IP.Categorization.CDN | Boolean | Content delivery network |
| SOCRadarIoCEnrichment.IP.Categorization.Cloud | Boolean | Cloud hosting |
| SOCRadarIoCEnrichment.IP.Classifications | Object | Threat classifications |
| SOCRadarIoCEnrichment.IP.Classifications.Campaign | String | Associated campaign name |
| SOCRadarIoCEnrichment.IP.Classifications.Malwares | Array | Associated malware families |
| SOCRadarIoCEnrichment.IP.Classifications.ThreatActors | Array | Associated threat actors |
| SOCRadarIoCEnrichment.IP.Classifications.Industries | Array | Targeted industries |
| SOCRadarIoCEnrichment.IP.Classifications.TargetCountries | Array | Targeted countries |
| SOCRadarIoCEnrichment.IP.History | Array | Historical events (last 10) |
| DBotScore.Score | Number | DBot score (0=Unknown, 1=Good, 2=Suspicious, 3=Malicious) |

#### Command Example

```bash
!ip ip="104.251.122.20"
!ip ip="1.1.1.1,8.8.8.8"
```

---

### domain

Enriches domains with threat intelligence data.

#### Input

| **Argument** | **Description** | **Required** |
|---|---|---|
| domain | Domain names to enrich. Supports multiple domains (comma-separated). | Required |

#### Context Output

Similar to IP command, with `SOCRadarIoCEnrichment.Domain.*` prefix.

#### Command Example

```bash
!domain domain="malicious-site.com"
!domain domain="example.com,test.net"
```

---

### url

Enriches URLs with threat intelligence data.

#### Input

| **Argument** | **Description** | **Required** |
|---|---|---|
| url | URLs to enrich. Supports multiple URLs (comma-separated). | Required |

#### Context Output

Similar to IP command, with `SOCRadarIoCEnrichment.URL.*` prefix.

#### Command Example

```bash
!url url="https://malicious-site.com/payload.exe"
!url url="http://phishing.example.com,https://c2.attacker.net"
```

---

### file

Enriches file hashes with threat intelligence data.

#### Input

| **Argument** | **Description** | **Required** |
|---|---|---|
| file | File hashes to enrich (MD5, SHA1, SHA256). Supports multiple hashes. | Required |

#### Context Output

Similar to IP command, with `SOCRadarIoCEnrichment.File.*` prefix.

#### Command Example

```bash
!file file="44d88612fea8a8f36de82e1278abb02f"
!file file="3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792"
```

---

## DBot Score Interpretation

| **DBot Score** | **Meaning** | **Criteria** |
|---|---|---|
| 3 | Malicious | Score > 80 OR Signal Strength = Very Strong/Strong |
| 2 | Suspicious | Score 40-80 OR Signal Strength = Moderate |
| 1 | Good | Score 1-40 |
| 0 | Unknown | Score = 0 or NULL |

---

## Use Cases

### 1. Incident Investigation

```bash
# Enrich suspicious IP from logs
!ip ip="192.168.1.100"

# Check associated domain
!domain domain="suspicious-domain.com"

# Investigate related hash
!file file="abc123def456..."
```

**Output**: Get complete threat context including campaigns, threat actors, target industries, and historical activity.

### 2. Threat Hunting

```bash
# Enrich multiple indicators
!ip ip="1.1.1.1,2.2.2.2,3.3.3.3"
```

**Output**: Batch enrichment with categorization flags to identify Tor nodes, VPNs, malware C2s, etc.

### 3. Playbook Enrichment

```yaml
- id: "1"
  task: Enrich Incident IOCs
  command: ip
  args:
    ip: ${incident.sourceip}

- id: "2"
  task: Check Signal Strength
  condition: ${SOCRadarIoCEnrichment.IP.SignalStrength} == "Very Strong"
  nexttasks:
    "true":
      - Block IP
```

### 4. Threat Intelligence Analysis

```bash
# Get detailed classification
!ip ip="203.0.113.45"
```

**Output**:

- Signal Strength: Very Strong
- Confidence: Very High
- Campaign: APT28 Infrastructure
- Threat Actors: ["APT28", "Fancy Bear"]
- Target Industries: ["Government", "Defense"]
- Malwares: ["CHOPSTICK", "SOURFACE"]

---

## Signal Strength Explained

| **Level** | **Description** | **Recommended Action** |
|---|---|---|
| **Very Strong** | High-confidence malicious indicator, low false positive rate | Block immediately |
| **Strong** | Reliable malicious indicator | Block with review |
| **Moderate** | Potentially malicious, moderate confidence | Monitor/investigate |
| **Slightly Noisy** | Some legitimate use cases exist | Investigate context |
| **Noisy** | High false positive rate | Review carefully before action |

---

## Confidence Levels

| **Level** | **Description** |
|---|---|
| **Very High** | Validated across multiple high-quality sources |
| **High** | Confirmed by multiple sources |
| **Medium** | Moderate source validation |
| **Low** | Limited source validation |

---

## Categorization Flags

| **Flag** | **Meaning** |
|---|---|
| Malware | Associated with malware distribution/C2 |
| ThreatActor | Attributed to known threat actor |
| Tor | Tor network node |
| VPN | VPN service endpoint |
| Proxy | Proxy service |
| CDN | Content delivery network |
| Cloud | Cloud hosting (AWS, Azure, GCP, etc.) |
| Hosting | Web hosting service |
| Honeypot | Honeypot/research environment |
| Cryptocurrency | Crypto mining/wallet |
| Scanner | Port/vulnerability scanner |

---

## Performance Notes

- **AI Insights Excluded**: For optimal performance, AI-generated insights are not requested
- **Fields Requested**: indicator_details, indicator_history, indicator_relations
- **Response Time**: Typically < 2 seconds per indicator
- **Rate Limits**: Check your API key's rate limit with SOCRadar

---

## Troubleshooting

### Test Module Fails

**Error**: "Authorization Error"

- **Solution**: Verify API key is correct and has IoC Enrichment access

**Error**: "Connection failed"

- **Solution**: Check network connectivity to platform.socradar.com

### No Data Returned

**Issue**: Empty response for valid indicator

- **Cause**: Indicator not in SOCRadar database
- **Note**: No data doesn't mean indicator is safe, just unknown to SOCRadar

### Rate Limit Exceeded

**Error**: "Rate limit has been exceeded"

- **Solution**: Contact SOCRadar to increase rate limit or wait for reset

---

## Best Practices

1. **Enrich All IOCs**: Run enrichment on all indicators during investigation
2. **Trust Signal Strength**: Use signal strength for automated blocking decisions
3. **Check Categorization**: Validate if indicator is CDN/Cloud before blocking
4. **Review History**: Examine historical events for pattern analysis
5. **Combine with Other Sources**: Use alongside other TI feeds for validation
6. **Playbook Integration**: Automate enrichment in incident response playbooks

---

## Additional Resources

- **API Documentation**: <https://platform.socradar.com/docs/api/>
- **Support**: operation@socradar.io
- **SOCRadar Platform**: <https://platform.socradar.com>

---

## Version History

- **1.0.0**: Initial release with IP, Domain, URL, and File enrichment

---

**Integration Type**: Data Enrichment & Threat Intelligence
**Vendor**: SOCRadar
**Support**: Community
**Categories**: Threat Intelligence, IoC Enrichment, Reputation

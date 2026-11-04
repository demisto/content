## Stairwell

Stairwell continuously collects, stores, and analyzes threat intelligence and artifacts in a private vault to accelerate security investigations. The Stairwell integration enables you to:

- Reanalyze files continuously as new threat intelligence is identified.
- Correlate threat and signal intelligence with your existing artifacts.
- Perform retrospective analysis to investigate alerts regardless of when they occurred.
- Identify file variants and hidden relationships across your environment.
- Gain definitive visibility into the presence or absence of specific files within your enterprise.

Not a customer and interested in signing up? You can request access [here](https://stairwell.com/contact/).

### Indicator Reputation

The generic `file`, `ip` and `domain` commands return standard indicators with a DBotScore. A file's score comes from Stairwell's MalEval verdict (malicious for PROBABILITY_VERY_HIGH and PROBABILITY_HIGH, suspicious for PROBABILITY_MEDIUM, good for PROBABILITY_LOW). IP results carry ASN, geolocation, cloud-provider and reverse-DNS context; domain results carry whitelist status and DNS resolution history.

### File Enrichment

This command enables instant enrichment of a provided hash. This enrichment leverages data from your organization, along with Stairwell's shared malware corpus.
The results will include:

- Hash details
- Seen asset(s)
- Matching YARA
- AV verdicts
- Path/filename details

### Variant Discovery

This command enables rapid, DFIR-level hunts for variants of a provided hash. This hunt leverages data from your organization, along with Stairwell's shared malware corpus.
The results include any variant file hashes discovered, along with a similarity score.

### File Intake Upload

Upload files to Stairwell for analysis from Cortex XSOAR War Room entries or HTTP/HTTPS URLs. Features automatic preflight checks, SHA256 calculation, retry logic, and temp file cleanup. Perfect for automated playbook workflows.

### AI Triage Summarize

Get AI-generated summaries for files including comprehensive threat analysis, indicators of compromise (IOCs), risk assessment, and actionable guidance.

### Object Sightings

List all sightings for a specific object across your organization's assets. Sightings show where and when files have been observed in your environment.

### Object Opinions

Retrieve opinions and assessments for objects. Opinions provide additional context and analysis from Stairwell's threat intelligence.

### Run-To-Ground

Generate comprehensive run-to-ground analysis for one or more objects. Helps trace files across your environment, identifying all instances and relationships between objects for complete threat visibility.

### YARA Rule Management

Create, retrieve, and query YARA rules for threat hunting. Create custom detection rules, get rule details, and query your environment for matching objects. Note: Multi-line YARA rules require backticks (`) for proper formatting.

### Network Intelligence

Comprehensive network intelligence commands for enriching ASNs, hostnames, and IP addresses. Includes WHOIS lookups, DNS resolution tracking, cloud provider identification, and URL/hostname canonicalization utilities.

### Asset Management

Manage assets in your Stairwell environment. List, create, and retrieve asset details. Assets represent endpoints or systems that can upload files to Stairwell for analysis.

---

## Stairwell
Stairwell continuously collects, stores, and analyzes threat intelligence, malware and executable files, scripts, and artifacts in a private, out-of-band vault — making it possible to answer security questions faster.
- Reanalyze files continuously as new intel drops.
- Connect threat and signal intelligence with your files
- Run every alert-to-ground — even months later.
- Find variant families and connections others miss.
- Answer definitively: Has this ever been in your environment? Is this absent from your enterprise?

Not a customer and interested in signing up? You can request access [here](https://stairwell.com/contact/).

### File Enrichment
This command enables instant enrichment of a provided hash. This enrichment will leverage data from your organization, along with Stairwell's shared malware corpus.
The results will include:
- Hash details
- Seen asset(s)
- Matching YARA 
- AV verdicts
- Path/filename details

### Variant Discovery
- This command enables rapid, DFIR-level hunts for variants of a provided hash. This hunt will leverage data from your organization, along with Stairwell's shared malware corpus.
- The results will include any variant file hashes discovered, along with a `similarity` score.

### File Intake Upload
Upload files to Stairwell for analysis with three flexible file source methods: XSOAR War Room entries (entryID), HTTP/HTTPS URLs, or direct file paths. Features automatic preflight checks, SHA256 calculation, retry logic, and temp file cleanup. Perfect for automated playbook workflows.

### AI Triage Summarize
Get AI-generated summaries for files including comprehensive threat analysis, indicators of compromise (IOCs), risk assessment, and actionable guidance.

### Object Sightings
List all sightings for a specific object across your organization's assets. Sightings show where and when files have been observed in your environment.

### Object Detonation
Trigger and retrieve detonation results for objects in Stairwell's sandbox environment. Provides detailed behavioral analysis of how files execute in isolated environments.

### Object Opinions
Retrieve opinions and assessments for objects. Opinions provide additional context and analysis from Stairwell's threat intelligence.

### Run-To-Ground
Generate comprehensive Run-To-Ground analysis for one or more objects. Helps trace files across your environment, identifying all instances and relationships between objects for complete threat visibility.

### YARA Rule Management
Create, retrieve, and query YARA rules for threat hunting. Create custom detection rules, get rule details, and query your environment for matching objects. Note: Multi-line YARA rules require backticks (`) for proper formatting.

### Network Intelligence
Comprehensive network intelligence commands for enriching ASNs, hostnames, and IP addresses. Includes WHOIS lookups, DNS resolution tracking, cloud provider identification, and URL/hostname canonicalization utilities.

### Asset Management
Manage assets in your Stairwell environment. List, create, and retrieve asset details. Assets represent endpoints or systems that can upload files to Stairwell for analysis.

---

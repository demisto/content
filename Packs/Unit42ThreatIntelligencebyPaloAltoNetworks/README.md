# Unit 42 Threat Intelligence by Palo Alto Networks

This pack provides the Unit 42 Intelligence integration and the Unit 42 Feed integration, delivering high-fidelity threat intelligence curated by the Unit 42 team and derived from telemetry across the Palo Alto Networks product ecosystem.

Built by Unit 42, Palo Alto Networks' threat research organization, this pack brings world-class research, adversary expertise, and at-scale telemetry together to enrich investigations and automate high-quality indicator ingestion.

## What does this pack do?

The Unit 42 Threat Intelligence content pack includes integrations that allow you to:

- **Enrich indicators** with threat intelligence context from the Unit 42 research team
- **Get verdicts** for IP addresses, domains, URLs, and file hashes (SHA256)
- **Surface associations** between indicators and threat objects (actors, malware, campaigns, techniques) as determined by Unit 42 research
- **Optionally create relationships** in your tenant based on returned associations
- **Access comprehensive metadata** including first seen, last seen, and source information

## Integrations

### Unit 42 Intelligence

An enrichment integration that provides threat intelligence lookups for indicators. This integration replaces the deprecated AutoFocus V2 integration with enhanced capabilities and improved context quality.

**Supported Commands:**

- `!ip` - Enrich IP addresses
- `!domain` - Enrich domain names
- `!url` - Enrich URLs
- `!file` - Enrich file hashes (SHA256)

**Key Features:**

- Real-time indicator enrichment
- Threat object associations returned by Unit 42
- Verdict classification (malicious, suspicious, benign, unknown)
- Optional relationship creation based on returned associations
- Comprehensive threat intelligence metadata

### Unit 42 Feed

A read-only feed integration that continuously fetches indicators and threat objects (plus their relationships) from Unit 42 data sources. When relationship creation is enabled, relationships between ingested indicators and threat objects are created in your tenant based on the feed data.

### Prerequisites

- Cortex Threat Intelligence Management (TIM) license

### Setup

1. Install the Unit 42 by Palo Alto Networks content pack
2. Configure the Unit 42 Intelligence integration
3. Configure the Unit 42 Feed integration if you need indicator feeds
4. Test the integrations using the test commands

## Use Cases

- **Incident Response**: Enrich indicators found during investigations with threat intelligence
- **Threat Hunting**: Identify malicious indicators and their associated threat campaigns
- **IOC Management**: Automatically ingest and classify threat indicators
- **Threat Intelligence**: Build a graph of indicators and threat objects with relationships created from returned enrichment and feed data

## Support

This pack is supported by Cortex XSOAR. For technical support, please contact Palo Alto Networks support.

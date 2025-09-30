
# Unit 42 by Palo Alto Networks

This pack provides integrations for Palo Alto Networks Unit 42 threat intelligence services, enabling enrichment of indicators with high-quality threat intelligence data.

## What does this pack do?

The Unit 42 by Palo Alto Networks content pack includes integrations that allow you to:

- **Enrich indicators** with threat intelligence data from Unit 42 research team
- **Get verdicts** for IP addresses, domains, URLs, and file hashes
- **Associate indicators** with threat actors, malware families, campaigns, and attack patterns
- **Create relationships** between indicators and threat objects automatically
- **Access comprehensive metadata** including first seen, last seen, and source information

## Integrations

### Unit 42 Intelligence

An enrichment integration that provides threat intelligence lookups for indicators using the Unit 42 Intelligence API. This integration replaces the deprecated AutoFocus V2 integration with enhanced capabilities and improved data quality.

**Supported Commands:**

- `!ip` - Enrich IP addresses
- `!domain` - Enrich domain names  
- `!url` - Enrich URLs
- `!file` - Enrich file hashes (SHA256)

**Key Features:**

- Real-time indicator enrichment
- Threat object associations
- Verdict classification (malicious, suspicious, benign, unknown)
- Automatic relationship creation
- Comprehensive threat intelligence metadata

### Unit 42 Feed

A feed integration that fetches threat intelligence indicators and associated threat objects from Unit 42 data sources.

### Prerequisites

- Unit 42 Intelligence license
- Network connectivity to Unit 42 Intelligence API endpoints

### Setup

1. Install the Unit 42 by Palo Alto Networks content pack
2. Configure the Unit 42 Intelligence integration
3. Configure the Unit 42 Feed integration if you need indicator feeds
4. Test the integrations using the test commands

## Use Cases

- **Incident Response**: Enrich indicators found during investigations with threat intelligence
- **Threat Hunting**: Identify malicious indicators and their associated threat campaigns
- **IOC Management**: Automatically ingest and classify threat indicators
- **Threat Intelligence**: Build comprehensive threat intelligence databases with relationships

## Support

This pack is supported by Cortex XSOAR. For technical support, please contact Palo Alto Networks support.

## Unit 42 Intelligence

Use the Unit 42 Intelligence integration to enrich indicators with threat intelligence data from Palo Alto Networks Unit 42 research team.

### Authentication

This integration requires a Unit 42 Intelligence API key. Contact your Palo Alto Networks representative to obtain access credentials.

### Configuration Parameters

- **Server URL**: The base URL for the Unit 42 Intelligence API service
- **API Key**: Your Unit 42 Intelligence API authentication key
- **Source Reliability**: Configure the reliability level for threat intelligence data (default: A - Completely reliable)
- **Create Relationships**: Enable automatic creation of relationships between indicators and threat objects

### Supported Indicators

- IP addresses (IPv4)
- Domains
- URLs
- File hashes (SHA256)

### Features

- Real-time indicator enrichment
- Threat object associations (malware families, threat actors, campaigns)
- Verdict classification (malicious, suspicious, benign, unknown)
- Relationship mapping between indicators and threats
- Comprehensive metadata including first/last seen dates and source information

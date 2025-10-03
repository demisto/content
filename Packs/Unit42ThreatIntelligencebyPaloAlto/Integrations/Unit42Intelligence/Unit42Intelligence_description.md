## Unit 42 Intelligence

Use the **Unit 42 Intelligence** integration to enrich indicators with threat intelligence context from Palo Alto Networks Unit 42's research team.

### Prerequisite

This integration requires a Cortex Threat Intelligence Management (TIM) license.

### Configuration Parameters

- **Source Reliability**: Configure the reliability level for threat intelligence context (default: A++ - Reputation script)
- **Create Relationships**: Enable automatic creation of relationships between indicators and threat objects based on returned associations
- **Create Indicators from Relationships**: Enable automatic creation of indicators from relationships

### Supported Indicators

- IP addresses
- Domains
- URLs
- File hashes

## Mandiant Threat Intelligence Enrichment

Enrich Indicators of Compromise using Cortex XSOAR Generic Reputation commands, and create indicators for Threat Actors, Malware Families, and Campaigns from Mandiant Advantage.

### Prerequisites
A Mandiant Advantage Threat Intelligence account.

### Get Credentials
- Log in to `advantage.mandiant.com`.
- Navigate to `Settings`, then scroll down to `APIv4 Access and Key`.
- Click `Get Key ID and Secret`.

### Integration Settings

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Your API Key from Mandiant Advantage Threat Intelligence. | True |
| Secret Key | Your Secret Key from Mandiant Advantage Threat Intelligence. | True |
| Timeout | API calls timeout. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators enriched. | False |
| Tags | Supports CSV values. | False |
| Map Attack Pattern Relationships to Mitre ATT&CK | When enabled the integration will attempt to map Attack Pattern relationships to Attack Pattern Indicators created by the Mitre ATT&CK Integration. | False |
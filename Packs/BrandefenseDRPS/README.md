# Brandefense Digital Risk Protection Services

Brandefense is a leading SaaS platform offering **Digital Risk Protection Services (DRPS)**, **External Attack Surface Management (EASM)**, and **Actionable Threat Intelligence** solutions. The AI-driven technology continuously scans the dark, deep, and surface web to discover unknown events, automatically prioritize risks, and deliver actionable intelligence.

This content pack integrates the Brandefense platform with Cortex XSOAR (and Cortex XSIAM) to automate threat intelligence workflows, incident ingestion, and IoC enrichment.

## What does this pack do?

- Fetches incidents and intelligence reports from Brandefense as Cortex XSOAR incidents (with deduplication).
- Investigates IP addresses, domains, URLs, and file hashes against Brandefense IoC data.
- Manages incidents: view details, indicators, related incidents, and change status.
- Retrieves intelligence reports with indicators and rules.
- Runs CTI-powered threat searches using scheduled polling.
- Lists and searches monitored assets.
- Detects and investigates compromised devices.
- Reviews the Brandefense platform audit trail.
- Retrieves domain risk assessments for third-party risk management.
- Creates confirmed phishing incidents and requests takedowns.
- Retrieves consolidated indicators by type (leak, phishing, credit card, CVE, malicious files, and similar categories).

## Pack Contents

| Component | Count | Details |
|-----------|-------|---------|
| Integration | 1 | Brandefense |
| Commands | 23 | IoC enrichment, incident management, intelligence, indicators, assets, compromised devices, audit logs, phishing response |
| Incident Types | 2 | Brandefense Incident, Brandefense Intelligence |
| Incident Fields | 12 | Custom fields for both incident types (all unsearchable) |
| Layouts | 2 | Brandefense Incident, Brandefense Intelligence |
| Classifier | 1 | Brandefense - Classifier |
| Mapper | 1 | Brandefense - Incoming Mapper |

## Prerequisites

- **Cortex XSOAR** version 6.10.0 or later (also compatible with Cortex XSIAM).
- A **Brandefense account** with API access enabled.
- A **Brandefense API Bearer Token** with the following scopes:
  - Asset Read
  - Incident Read / Incident Create
  - Intelligence Read
  - Threat Intelligence Read
  - Threat Search
  - Indicator Read
  - Referrer Log Create
  - Audit Log Read
  - Compromised Device Read
  - Third Party Risk Management Read

### How to Get Your API Key

1. Log in at [https://app.brandefense.io](https://app.brandefense.io).
2. Navigate to **Settings > API Tokens**.
3. Click **Create New Token** and enable the required scopes.
4. Copy the generated token.

## Configuration

Navigate to **Settings > Integrations > Servers & Services**, search for **Brandefense Digital Risk Protection Services**, and click **Add instance**.

### Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| Server URL | Brandefense API endpoint. | `https://api.brandefense.io` | Yes |
| API Key | Bearer token from Brandefense. | — | Yes |
| Trust any certificate | Skip SSL verification (not recommended). | `false` | No |
| Use system proxy settings | Route through system proxy. | `false` | No |
| Fetch incidents | Enable automatic incident fetching. | — | No |
| Incidents Fetch Interval | Polling interval in minutes. | `30` | No |
| First time fetching | Initial backfill period (for example, `3 days`). | `3 days` | No |
| Incident type | Default Cortex XSOAR incident type. | — | No |
| Max Results | Maximum items per fetch cycle. | `30` | No |
| Incident Category | Filter by incident category. | — | No |
| Incident Module | Filter by incident module. | — | No |
| Incident Status | Filter by incident status. | `OPEN` | No |
| Intelligence Category | Filter by intelligence category. | — | No |
| Intelligence Search | Keyword filter for intelligence tags. | `CVE` | No |
| Fetching Issue Types | Select: Incident, Intelligence, or both. | `Incident,Intelligence` | Yes |
| Incident Rules | Filter by specific detection rules. | — | No |

Click **Test** to verify connectivity.

## Fetch Incidents

When **Fetch incidents** is enabled, the integration periodically polls the Brandefense API for new incidents and intelligence reports.

### Deduplication Strategy

The integration uses a dual-check deduplication approach:

1. **Timestamp-based** — Only processes items newer than or equal to the last fetch timestamp.
2. **Code-based** — Tracks up to 1,000 seen incident/intelligence codes in `last_run` to prevent duplicates when multiple items share the same `created_at` timestamp.

### Classification and Timing

- Each fetched item is tagged with `brandefense_type` = `Incident` or `Intelligence`.
- The classifier routes items to the correct incident type based on this field.
- Default fetch interval: **30 minutes**.
- Default first-fetch lookback: **3 days**.
- Maximum incidents per fetch cycle: configurable (default **30**, hard limit **200**).

## Classifier and Mapper

### Classifier: Brandefense - Classifier

Routes fetched events based on the `brandefense_type` field:

| Key | Incident Type |
|-----|---------------|
| `Incident` | Brandefense Incident |
| `Intelligence` | Brandefense Intelligence |

Default incident type: **Brandefense Incident**.

### Mapper: Brandefense - Incoming Mapper

#### Brandefense Incident Field Mappings

| Cortex XSOAR Field | Source Field |
|---------------------|--------------|
| Name | `title` |
| Severity | `severity` |
| Details | `description` |
| occurred | `created_at` |
| Alert URL | `reference_url` |
| MITRE Tactic ID | `mitre_tactics` |
| Brandefense Incident Code | `code` |
| Brandefense Incident Status | `status` |
| Brandefense Incident Module | `module` |
| Brandefense Incident Module Category | `module_category` |
| Brandefense Incident Type | `brandefense_original_type` |
| Brandefense Incident Tags | `tags` |
| Brandefense Incident Assignee | `assignee` |
| Brandefense Incident Network Type | `network_type` |
| Brandefense Indicators | `indicators` |

#### Brandefense Intelligence Field Mappings

| Cortex XSOAR Field | Source Field |
|---------------------|--------------|
| Name | `title` |
| Severity | `severity` |
| Details | `description` |
| occurred | `created_at` |
| Alert URL | `reference_url` |
| Brandefense Intelligence Code | `code` |
| Brandefense Intelligence Category | `category` |
| Brandefense Intelligence Tags | `tags` |
| Brandefense Indicators | `indicators` |

## Layouts

- **Brandefense Incident** layout — Displays case details, timeline, indicators, and closing information along with the Brandefense-specific fields.
- **Brandefense Intelligence** layout — Displays case details, timeline, and Brandefense intelligence metadata.

## Support

- **Vendor**: Brandefense
- **Website**: [https://www.brandefense.io](https://www.brandefense.io)
- **Contact**: [support@brandefense.io](mailto:support@brandefense.io)

# Haseen Threat Intelligence Integration for Cortex XSOAR

## Overview

The Haseen Threat Intelligence Integration for Cortex XSOAR enables automated ingestion, normalization, processing, and operationalization of cyber threat intelligence received from the Kingdom of Saudi Arabia's national cyber threat intelligence sharing platform, **Haseen**.

The integration was developed to eliminate manual intelligence handling, automate IOC ingestion, and improve intelligence-driven detection and response capabilities across the SOC, through automated consumption of Haseen machine-to-machine threat intelligence feeds.

---

## What is Haseen?

**Haseen (حصين)** is the National Cybersecurity Authority (NCA) cyber threat intelligence sharing platform.

The platform allows participating organizations to:

- Receive national threat intelligence
- Access actionable Indicators of Compromise (IOCs)
- Share cyber threat information
- Consume intelligence in machine-readable formats
- Improve cyber resilience through collective defense

Haseen distributes intelligence through both a web-based portal and machine-to-machine services that allow direct integration with security products such as SIEM, TIP, SOAR, and XDR platforms.

---

## What is DOI?

**DOI (Digital Operations Integration)** is the mechanism used by Haseen to enable automated machine-to-machine sharing of threat intelligence.

Instead of manually downloading intelligence files from the Haseen portal, organizations can consume intelligence feeds directly from designated endpoints using authenticated API access.

This allows:

- Automated IOC collection
- Near real-time intelligence synchronization
- Integration with security platforms
- Reduced operational overhead
- Scalable threat intelligence distribution

---

## Haseen Machine-to-Machine Service

The Haseen Machine-to-Machine (M2M) service provides authenticated access to threat intelligence feeds through export endpoints.

These feeds can be consumed programmatically by security products and custom integrations.

Supported export formats observed during implementation include:

| Format | Description |
| --- | --- |
| STIX v2 | Primary format used by the integration |
| STIX v1.2 | Legacy export format |
| STIX v1.1.1 | Legacy export format |

---

## Requirements to Obtain Access

To consume Haseen threat intelligence feeds, the following prerequisites are required:

### Organizational Requirements

- Active Haseen membership and at least one active account under this organization to generate the API token.
- Public IPs of the organization need to be registered in two places within the Haseen Portal:
  - **Risk → Public IP Addresses**
  - **Entity Management → Entity's IP addresses** (required so XSOAR requests to the Haseen URL are allowed)

### Technical Requirements

- Authentication token
- Feed URL(s)

### Information Required for the Integration

```text
STIX V2 Feed URL
Authentication Token
Polling Interval
Feed Type (STIX v2 Recommended)
```

---

## Threat Intelligence Format

### STIX Version 2

This integration consumes threat intelligence feeds delivered using **STIX Version 2 (Structured Threat Information Expression)**.

STIX is an industry-standard language for exchanging cyber threat intelligence.

The format provides a structured representation of:

- Indicators
- Malware
- Campaigns
- Threat Actors
- Relationships
- Observables
- Sightings
- Tactics, Techniques, and Procedures (TTPs)

---

## Supported Indicator Types

Common indicators observed in Haseen feeds include:

### Network Indicators

- IPv4 Addresses
- IPv6 Addresses
- Domains
- URLs
- FQDNs

### File Indicators

- MD5
- SHA1
- SHA256

### Threat Context

- Malware References
- Campaign Information
- Threat Attribution
- Intelligence Metadata

### Metadata

- Labels
- Confidence
- Created Date
- Modified Date
- Source Information

---

## Why Haseen Intelligence is Valuable

Haseen intelligence provides unique value to organizations operating within the Kingdom of Saudi Arabia because it combines national-level intelligence sharing with regional threat visibility.

### Key Benefits

**National Context** — Intelligence is sourced and curated to address threats relevant to organizations operating within Saudi Arabia.

**Actionable Indicators** — Feeds contain operational IOCs that can immediately be used for detection, threat hunting, incident response, and intelligence correlation.

**Intelligence-Driven Security Operations** — Threat intelligence becomes available directly within security workflows rather than remaining isolated in external portals.

**Reduced Detection Time** — Indicators can be correlated against existing telemetry as soon as they are ingested.

**Complements Commercial Intelligence Sources** — Haseen intelligence can enhance and complement existing commercial feeds and intelligence sources already used by the SOC.

---

## Integration Objectives

The primary purpose of the integration is to operationalize Haseen intelligence inside Cortex XSOAR.

### Objectives

- **Automated Feed Retrieval** — automatically download intelligence feeds from Haseen once new indicators are added/updated.
- **STIX Parsing** — parse STIX content and identify actionable intelligence objects.
- **Indicator Extraction** — extract relevant indicators and observables from STIX bundles.
- **Normalization** — convert Haseen intelligence into XSOAR-native indicator formats.
- **Deduplication** — prevent duplicate indicators from being created within the platform.
- **Enrichment** — apply metadata such as source, feed name, confidence, labels, TLP, and intelligence context.
- **Operationalization** — make threat intelligence immediately available to detection, threat hunting, incident response, and automated correlation use cases.
- **Reduction of Manual Effort** — replace manual intelligence downloads and uploads with a fully automated integration pipeline.

---

## High-Level Architecture

```text
+----------------+
|    Haseen      |
+----------------+
         |
         |  STIX v2
         v
+-------------------------+
| Haseen XSOAR Integration|
+-------------------------+
         |
         v
   STIX Parsing
         |
         v
   IOC Extraction
         |
         v
Indicator Normalization
         |
         v
   Deduplication
         |
         v
+-------------------------+
|      Cortex XSOAR       |
+-------------------------+
             |
 +-----------+-----------+
 |           |           |
 v           v           v
Detection  Threat Hunt  IR Workflows
```

---

## Feed behaviour

- **Full-dump endpoint** — Haseen returns the entire STIX bundle on every request (no `modified_after` server-side delta). The integration deduplicates against its own seen-indicator watermark so each indicator is emitted once.
- **Relationship-aware** — STIX `relationship` objects are parsed into XSOAR indicator relationships (e.g. malware → file hash), in addition to the indicators themselves.
- **Rate limit** — Haseen permits 2 requests per hour per export. Configure the fetch interval to 60 minutes or higher.

---

## Configuration

| Parameter | Required | Description |
| --- | --- | --- |
| Server URL | Yes | The full STIX export URL, including the export ID. Example: `https://share.haseen.gov.sa/api/v1/threat-intelligence/export/1234`. |
| API Token | Yes | The Haseen API token (settings page). Sent as a `token` **query parameter** on every request — not a Bearer header. |
| Basic Auth Credentials | No | For exports that also require Basic authentication. Username = account email, password = API token. |
| First Fetch Time | No | How far back to look on the first fetch (e.g. `7 days`). |
| Indicator Reputation / Source Reliability / TLP | No | Standard feed output controls. |
| Trust any certificate | No | Disable TLS verification (not recommended for production). |
| Use system proxy settings | No | Route requests through the configured system proxy. |

---

## Playbooks

- **Haseen-delta-in-feed-generic playbook** — triggered by the feed fetch (delta-in-feed job). Stages newly-fetched indicators and their relationships, associates them to the incident, prompts an analyst to select IOCs for blocking, then escalates severity and closes the incident. See the playbook README for the flow.

---

## Screenshots

- **Haseen Machine-to-Machine Access** — `docs/images/haseen-m2m-service.png`. Shows the M2M service configuration, export settings, feed availability, and the STIX v2 feed URL.

---

## Commands

This integration is feed-only. It does not expose any CLI commands; indicators are fetched automatically on the configured fetch interval after you mark **Fetch indicators** and save the instance.

# KOI (Agentic Endpoint Security)

## Overview

KOI (AES - Agentic Endpoint Security) is a Palo Alto Networks product for software supply chain governance. It provides visibility and control over browser extensions, IDE extensions, AI coding agents, SaaS applications, and web-based threats across your organization.

This pack includes two integrations:

- **KOI** — Full Koi API v2 coverage with event collection, 48 actionable commands, enrichment with DBot scoring, and EntityRelationship linking for CVEs and file hashes.
- **KOI Feed** — TIM feed integration that populates "Koi Software Item" indicators with risk-based DBot scoring, marketplace filtering, and automatic CVE/hash relationship creation.

## What Does This Pack Do?

- **Indicator Feed (TIM)**: Fetches Koi inventory items as "Koi Software Item" indicators with DBot scoring based on risk assessment. Links indicators to related CVEs and file hashes via EntityRelationships.
- **Event Collection**: Fetches alerts and audit logs from KOI and ingests them into Cortex XSIAM for centralized security monitoring, correlation, and threat analysis.
- **Item Enrichment**: Enriches software items with risk reports, DBot scoring, CVE extraction, and file hash relationships.
- **Inventory Management**: Query and search the software inventory, inspect item details, and list endpoints using specific items.
- **Policy Management**: List, enable, and disable organizational security policies, and manage allowlists and blocklists.
- **Agent Activity**: Monitor agent activity events and sessions across managed endpoints.
- **Approval Workflows**: Create, list, approve, and reject item approval requests.
- **Device Management**: List, archive, and inspect device inventory with group-based organization.
- **Findings and Risk**: List security findings, customize risk levels, and retrieve risk reports from the Koidex engine.
- **Runtime Policies**: Create, update, and manage agent runtime policies (hardening).
- **Remediations**: List, submit, and dismiss remediations for identified risks.
- **Private Items**: Upload and scan private/internal software items for risk assessment.
- **Reports**: Create asynchronous reports and check their status.
- **User Management**: List, create, and delete users.

### Pack Contributors:

---
 - Eric Partington
 - Jon Huebner

Contributions are welcome and appreciated. For more info, visit our [Contribution Guide](https://xsoar.pan.dev/docs/contributing/contributing).
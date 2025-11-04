# Infoblox Threat Intelligence Feed Integration for Cortex XSOAR

The **Infoblox Threat Intelligence Feed** integration enables Cortex XSOAR users to automatically ingest, enrich, and operationalize curated threat indicators from the Infoblox Threat Intelligence Data Exchange (TIDE) platform. This integration ensures your security operations have access to the latest, highly accurate, and prioritized threat data—empowering proactive defense and rapid response to emerging threats.

## What does this pack do?

- **Automated Indicator Ingestion:** Seamlessly fetches and updates threat indicators from Infoblox TIDE into XSOAR.
- **Comprehensive Indicator Support:** Ingests domains, IPs, URLs, emails, and file hashes with rich context.
- **Incremental Fetching:** Efficiently retrieves only new or updated indicators, minimizing API usage.
- **Customizable Fetch Settings:** Control indicator types, fetch intervals, limits, and more.
- **Contextual Enrichment:** Maps Infoblox metadata to XSOAR indicator fields for enhanced investigation.
- **Tagging and TLP:** Auto-apply tags and Traffic Light Protocol (TLP) colors to imported indicators.
- **Manual and Scheduled Fetching:** Fetch indicators on-demand or at scheduled intervals.

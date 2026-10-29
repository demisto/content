# AcmeDemo

This is a demo pack. It collects AcmeDemo audit logs into Cortex XSIAM and includes parsing and modeling rules.

The collector makes no network calls. It generates deterministic synthetic audit events locally, so you can run the full ingestion flow (collect, parse, model) with any non-empty API key.

## What does this pack contain?

- **AcmeDemo AuditLogs Event Collector**: an event collector integration that generates synthetic audit events and sends them to Cortex XSIAM. It also provides the `acmedemo-get-events` command for manual retrieval.
- **AcmeDemo Parsing Rule**: sets the `_time` field from each event's `created_time`.
- **AcmeDemo Modeling Rule**: maps the raw audit events to the Cortex Data Model (XDM).

## Dataset

Events are ingested into the `acmedemo_auditlogs_raw` dataset (vendor `acmedemo`, product `auditlogs`).

## Unified Connector

This pack works with the Unified Connectors (UCC) connector `acmedemo`, which exposes the collector in the Cortex Unified Connectors UI.

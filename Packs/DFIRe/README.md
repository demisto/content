# DFIRe

[DFIRe](https://dfire.fi/) is a self-hosted Digital Forensics and Incident Response (DFIR) case management platform built for security professionals. It provides structured investigation workflows, evidence tracking with full chain of custody, IOC indicator management, and NIST-aligned incident response phases — all running on your own infrastructure with AES-256 encryption.

## What does this pack do?

This pack integrates Cortex XSIAM with a DFIRe instance to automate your forensics and incident response workflows:

- **Case management** — Create, update, list, and close DFIRe cases directly from playbooks. Supports severity levels, assignees, and custom case types.
- **IOC indicator synchronisation** — Push indicators (IPs, domains, hashes, URLs) from XSIAM into DFIRe's global IOC registry, and link them to specific cases.
- **Evidence item tracking** — Create and manage evidence items with type classification and flag tagging to maintain chain of custody.
- **File attachments** — Upload War Room files as encrypted attachments to cases or evidence items.
- **Timeline enrichment** — Add forensic timeline events to DFIRe cases, and retrieve existing timelines for investigation context.
- **Full-text search** — Query across cases, indicators, notes, evidence items, and entities in one call.
- **User & lookup data** — Retrieve users, case types, evidence types, and flag definitions to drive dynamic playbook logic.

## Use Cases

- Automatically open a DFIRe case when a high-severity XSIAM alert fires and assign it to the on-call analyst.
- Enrich a DFIRe case with IOC indicators extracted during triage, keeping the forensics case and the SOAR investigation in sync.
- Upload memory dumps, logs, or forensic artefacts from a War Room investigation directly into DFIRe with a single playbook task.
- Add incident timeline entries from automated response actions so the forensic record reflects the full response lifecycle.

## Configuration

The integration requires a running DFIRe instance (self-hosted) and an API key generated in **System Settings → Integrations** within DFIRe. See the [integration README](Integrations/DFIRe/README.md) for full setup instructions.

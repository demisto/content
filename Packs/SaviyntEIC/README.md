# SaviyntEIC Pack

This pack provides an event collector for Saviynt Enterprise Identity Cloud (EIC) to ingest audit logs into Cortex XSIAM.

## Contents
- Integration: SaviyntEICEventCollector (XSIAM)

## Prerequisites
Follow Saviynt's documentation to:
1. Create an Analytics Record (V2) with the provided SQL query using the `timeFrame` variable.
2. Create a least-privileged service user and assign a SAV role with permissions to call `fetchRuntimeControlsDataV2` and verify the analytics record.

## Useful Links
- Managing Application Audit Logs
- SIEM Integration
- API Reference

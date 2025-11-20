This integration collects events from Vercara UltraDNS (such as audit logs) and forwards them to Cortex XSIAM for analysis and correlation.

Use cases include:
- Centralizing UltraDNS audit and activity logs in XSIAM.
- Enabling detection and correlation with other telemetry sources.
- Historical search, dashboards, and alerting on DNS-related activities.

Key features:
- Supports scheduled event collection via `fetch-events` with robust cursoring.
- Manual preview via `vercara-ultradns-get-events`, with optional push to XSIAM.
- Flexible endpoint configuration to accommodate different UltraDNS deployments.

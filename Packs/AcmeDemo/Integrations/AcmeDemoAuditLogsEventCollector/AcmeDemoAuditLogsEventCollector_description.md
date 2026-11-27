## AcmeDemo AuditLogs Event Collector

This is a **demo** integration. It generates deterministic, synthetic audit log events locally and does not make any network calls.

### Configuration

- **Server URL**: Keep the default value (`https://api.acmedemo.example.com`). It is not contacted.
- **API Key**: Any non-empty value works.
- **First fetch time**: How far back to generate events on the first fetch (for example, `3 days`).
- **Maximum number of events per fetch**: Default is `1000`.

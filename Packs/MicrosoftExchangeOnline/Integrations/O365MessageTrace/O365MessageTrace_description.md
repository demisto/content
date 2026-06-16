## O365 Message Trace Event Collector

Use this integration to collect message trace logs from the Office 365 Reporting Web Service into Cortex XSIAM.

### Prerequisites

- An Office 365 account with permission to access the Reporting Web Service.
- The account must have one of the following roles: **View-Only Recipients**, **Compliance Management**, or **Organization Management**.

### Configuration notes

1. **Server URL** — The Reporting Web Service endpoint. The default value is suitable for most commercial tenants.
2. **Username / Password** — Credentials of the account used to query message trace data.
3. **Maximum number of events per fetch** — Controls how many records are pulled per fetch cycle. Large values may affect performance.
4. **First fetch time** — Defines how far back to look on the first run (for example, `3 days`).

For more information, see the [Office 365 Reporting Web Service documentation](https://learn.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15)).

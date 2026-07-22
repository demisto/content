## Threatmon Threat Feed

The Threatmon Threat Feed integration allows Cortex XSOAR to automatically pull Indicators of Compromise (IOCs) from the Threatmon IOC platform and create them as indicators in Cortex XSOAR.

### Get Your API Token

1. Log in to your Threatmon account at [https://www.threatmon.io](https://www.threatmon.io).
2. Generate an API token for the IOC API.
3. If you do not have an account or an API token, contact the Threatmon team at [integration@threatmonit.io](mailto:integration@threatmonit.io).

### Configuration Notes

- **Server URL** - The Threatmon IOC API base URL. The default is `https://ioc.threatmonit.io`.
- **API Token** - Paste the token you generated into the password field. The username field is not used.
- **Data Type to Fetch** - Limits the fetch to a single IOC type (`ip`, `domain`, `url`) or fetches everything (`all`).
- **Collection IDs** - Optional. A comma-separated list of Threatmon collection IDs, used to fetch only from specific collections (for example, C2 servers or phishing).
- **Maximum number of indicators per fetch** - Controls the page size requested from the API on each run.

This feed is incremental. Each run stores the newest indicator timestamp it has seen and skips indicators that were already ingested in previous runs.

---

**Support**

This integration is community supported. For questions about the Threatmon platform or your API token, contact the Threatmon team at [integration@threatmonit.io](mailto:integration@threatmonit.io).

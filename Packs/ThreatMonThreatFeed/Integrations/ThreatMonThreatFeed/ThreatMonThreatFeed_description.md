## ThreatMon Threat Feed

The ThreatMon Threat Feed integration pulls Indicators of Compromise (IOCs) from the ThreatMon TAXII 2.1 server (`https://ioc.threatmonit.io/taxii/`) and creates them as indicators in Cortex.

### Get Your API Token

1. Log in to your ThreatMon account at [https://www.threatmon.io](https://www.threatmon.io).
2. Generate an API token for the IOC API.
3. If you do not have an account or an API token, contact the ThreatMon team at [support@threatmonit.io](mailto:support@threatmonit.io).

### Configuration Notes

- **Company Name / API Token** - Paste the token into the password field. The company name (username) is optional.
- **Collections** - Keep all collections selected to receive every IOC. The ThreatMon collections are not subsets of each other (for example, most IP indicators are only published in the *IP Address Indicators* collection).
- **First Fetch Time** - How far back the first run goes (default `7 days`). Large first fetches are spread over several runs automatically.
- **Feed Fetch Interval** - 60 minutes is recommended.

### How the Fetch Works

Every collection is read page by page with the TAXII `next` cursor until the server reports that no more data is available. The position is saved after every page, so if a run reaches the **Maximum pages per fetch** limit or fails, the next run continues from exactly the same place. Each new crawl starts slightly before the previous one (**Look-back Window**) so late-published IOCs are not missed, and IOCs read twice are de-duplicated.

---

**Support**

For questions about the ThreatMon platform or your API token, contact the ThreatMon team at [support@threatmonit.io](mailto:support@threatmonit.io).

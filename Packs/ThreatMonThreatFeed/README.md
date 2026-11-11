# ThreatMon Threat Feed

ThreatMon is a threat intelligence platform that publishes Indicators of Compromise (IOCs) collected from its own research and monitoring capabilities.

This pack contains the **ThreatMon Threat Feed** integration, which periodically pulls IOCs from the ThreatMon TAXII 2.1 server and creates them as indicators in Cortex, so they can be used for enrichment, correlation and detection.

## What does this pack do?

- Ingests IP, domain, URL and file hash indicators from the ThreatMon IOC platform.
- Reads every ThreatMon collection completely, using TAXII 2.1 cursor pagination, and resumes interrupted fetches from the last saved page.
- Adds the ThreatMon labels as tags, and keeps the STIX ID, first/last seen and TLP marking of every indicator.
- Applies the configured reputation, source reliability and TLP color to every ingested indicator.

The feed is incremental: each run reads what ThreatMon published since the previous run, with a look-back window so late-published IOCs are not missed.

## Requirements

- A ThreatMon account with access to the IOC TAXII server.
- A ThreatMon API token.
- Network connectivity from your Cortex engine to `https://ioc.threatmonit.io/taxii/`.

---

This pack is community supported. For questions about the ThreatMon platform or your API token, contact the ThreatMon team at [support@threatmonit.io](mailto:support@threatmonit.io).

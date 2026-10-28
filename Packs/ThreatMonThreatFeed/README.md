# ThreatMon Threat Feed

ThreatMon is a threat intelligence platform that publishes Indicators of Compromise (IOCs) collected from its own research and monitoring capabilities.

This pack contains the **ThreatMon Threat Feed** integration, which periodically pulls IOCs from the ThreatMon IOC API and creates them as indicators in Cortex, so they can be used for enrichment, correlation and detection.

## What does this pack do?

- Ingests IP, domain, URL and file hash indicators from the ThreatMon IOC platform.
- Enriches every indicator with the ThreatMon metadata, such as severity, confidence level, ISP, geolocation, resolved IPs, categories and tags.
- Lets you narrow the fetch down to a specific IOC type, or to specific ThreatMon collections.
- Applies the configured reputation, source reliability and TLP color to every ingested indicator.

The feed is incremental, so each run only ingests indicators that ThreatMon published after the previous run.

## Requirements

- A ThreatMon account with access to the IOC API.
- A ThreatMon API token.
- Network connectivity from your Cortex engine to the ThreatMon IOC API.

---

This pack is community supported. For questions about the ThreatMon platform or your API token, contact the ThreatMon team at [integration@threatmonit.io](mailto:integration@threatmonit.io).
